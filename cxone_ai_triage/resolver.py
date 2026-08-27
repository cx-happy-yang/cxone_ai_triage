"""Resolve Jira-ticket-derived identifiers into a Checkmarx One AI Triage
request, then trigger it.

Mapping of what a ticket gives us -> what POST /api/ai-triage/triage needs:

  scan_id            -> scanID                              (given directly)
  scanner_type       -> buckets[].scannerType                (given directly)
  result_hash (SAST) -> similarityId, via GET /api/sast-results?result-id=
  cve_id (SCA)        -> similarityId                        (the CVE ID *is*
                                                               the similarityId)
  similarityId        -> alternateId, via GET /api/results (paged; no
                          similarityId filter exists server-side)
  scan_id             -> projectId, via GET /api/scans/{scanId}

groupId (needed only to later poll GET /api/ai-triage/triage/{projectId}/{groupId},
not for the trigger call itself) is resolved as:
  - SAST: it *is* the similarityId (per AiTriageAPI docstring).
  - SCA: looked up from GET /api/risks rather than hand-built, since the
    "similarityId+packageIdentifier+projectId" concatenation format isn't
    documented anywhere in the SDK/API and /api/risks returns the
    authoritative value directly.
"""
import logging
from typing import Dict, List, Optional, Tuple

from CheckmarxPythonSDK.CxOne import (
    AiTriageAPI,
    RiskOrchestrationAPI,
    SastResultsAPI,
    ScannersResultsAPI,
    ScansAPI,
)
from CheckmarxPythonSDK.CxOne.dto import AiTriageRequest, TriageBucket

from .models import TriageJob, TriageOutcome

logger = logging.getLogger("cxone_ai_triage")

# /api/results has no similarityId filter, so every row for a scan must be
# paged through. Use the largest page size the API allows to minimize
# round-trips.
RESULTS_PAGE_SIZE = 500


class TriageResolver:
    """Resolves each TriageJob and triggers AI Triage for it.

    Caches per-scan and per-project lookups so a batch of tickets pointing
    at the same scan only pays the /api/results pagination cost once.
    """

    def __init__(self):
        self._scans_api = ScansAPI()
        self._sast_results_api = SastResultsAPI()
        self._scanner_results_api = ScannersResultsAPI()
        self._risks_api = RiskOrchestrationAPI()
        self._ai_triage_api = AiTriageAPI()

        self._project_id_by_scan: Dict[str, str] = {}
        self._results_by_scan: Dict[str, list] = {}

    # ---- cached lookups -------------------------------------------------

    def _get_project_id(self, scan_id: str) -> str:
        if scan_id not in self._project_id_by_scan:
            scan = self._scans_api.get_a_scan_by_id(scan_id)
            if not scan.project_id:
                raise LookupError(f"GET /api/scans/{scan_id} did not return a projectId")
            self._project_id_by_scan[scan_id] = scan.project_id
        return self._project_id_by_scan[scan_id]

    def _get_all_results(self, scan_id: str) -> list:
        if scan_id not in self._results_by_scan:
            all_results = []
            offset = 0
            while True:
                page = self._scanner_results_api.get_all_scanners_results_by_scan_id(
                    scan_id=scan_id, offset=offset, limit=RESULTS_PAGE_SIZE
                )
                all_results.extend(page["results"])
                total = page["totalCount"] or 0
                offset += RESULTS_PAGE_SIZE
                if offset >= total:
                    break
            self._results_by_scan[scan_id] = all_results
            logger.info(
                "scan %s: fetched %d rows from /api/results", scan_id, len(all_results)
            )
        return self._results_by_scan[scan_id]

    # ---- per-job resolution steps ----------------------------------------

    def _resolve_similarity_id(self, job: TriageJob) -> str:
        if job.scanner_type == "sca":
            # No separate lookup for SCA: the CVE ID from the ticket is the similarityId.
            return job.cve_id

        resp = self._sast_results_api.get_sast_results_by_scan_id(
            scan_id=job.scan_id, result_id=[job.result_hash], limit=1
        )
        results = resp["results"]
        if not results:
            raise LookupError(
                f"GET /api/sast-results found no result for scan {job.scan_id} "
                f"with result-id {job.result_hash!r}"
            )
        return str(results[0].similarity_id)

    def _find_alternate_id(
        self, job: TriageJob, similarity_id: str
    ) -> Tuple[str, Optional[str]]:
        """Filter the full /api/results page for this scan down to the row
        matching this job's scanner type + similarityId, and return its
        alternateId (and, for SCA, packageIdentifier)."""
        matches = [
            r
            for r in self._get_all_results(job.scan_id)
            if (r.type or "").lower() == job.scanner_type
            and str(r.similarity_id) == str(similarity_id)
        ]

        if job.scanner_type == "sca" and job.package_identifier and len(matches) > 1:
            narrowed = [
                m
                for m in matches
                if isinstance(m.data, dict)
                and m.data.get("packageIdentifier") == job.package_identifier
            ]
            if narrowed:
                matches = narrowed

        if not matches:
            raise LookupError(
                f"GET /api/results has no {job.scanner_type} row for scan {job.scan_id} "
                f"with similarityId {similarity_id!r}"
            )
        if len(matches) > 1:
            packages = sorted(
                {
                    (m.data or {}).get("packageIdentifier")
                    for m in matches
                    if isinstance(m.data, dict) and m.data.get("packageIdentifier")
                }
            )
            raise LookupError(
                f"{len(matches)} {job.scanner_type} rows in scan {job.scan_id} share "
                f"similarityId {similarity_id!r} (packages: {packages}); set "
                "package_identifier on the input row to disambiguate"
            )

        match = matches[0]
        package_identifier = None
        if job.scanner_type == "sca" and isinstance(match.data, dict):
            package_identifier = match.data.get("packageIdentifier")
        return match.alternate_id, package_identifier

    def _resolve_group_id(
        self, job: TriageJob, project_id: str, similarity_id: str
    ) -> Optional[str]:
        if job.scanner_type == "sast":
            return similarity_id

        resp = self._risks_api.get_risks(
            project_id=project_id, engine=["SCA"], risk_name=[job.cve_id], limit=200
        )
        candidates = [r for r in resp.risks if r.scanId == job.scan_id]
        if not candidates:
            logger.warning(
                "GET /api/risks has no entry for CVE %s on scan %s (project %s); "
                "groupId left blank (does not block the trigger call).",
                job.cve_id, job.scan_id, project_id,
            )
            return None
        if len(candidates) > 1:
            logger.warning(
                "GET /api/risks returned %d entries for CVE %s on scan %s; using the first",
                len(candidates), job.cve_id, job.scan_id,
            )
        return candidates[0].groupId

    # ---- public entry point ----------------------------------------------

    def resolve_and_trigger(self, job: TriageJob) -> TriageOutcome:
        outcome = TriageOutcome(job=job)
        try:
            outcome.project_id = self._get_project_id(job.scan_id)
            outcome.similarity_id = self._resolve_similarity_id(job)
            outcome.alternate_id, outcome.package_identifier = self._find_alternate_id(
                job, outcome.similarity_id
            )
            outcome.group_id = self._resolve_group_id(
                job, outcome.project_id, outcome.similarity_id
            )

            request = AiTriageRequest(
                scanID=job.scan_id,
                buckets=[
                    TriageBucket(
                        scannerType=job.scanner_type, resultIDs=[outcome.alternate_id]
                    )
                ],
            )
            response = self._ai_triage_api.trigger_ai_triage(request)
            outcome.triage_id = response.triageID
            outcome.status = response.status or "accepted"
        except Exception as e:  # noqa: BLE001 - keep the batch going on a per-row failure
            outcome.status = "failed"
            outcome.error = str(e)
            logger.error("%s failed: %s", job.ticket_key or job.scan_id, e)
        return outcome

    def resolve_and_trigger_all(self, jobs: List[TriageJob]) -> List[TriageOutcome]:
        return [self.resolve_and_trigger(job) for job in jobs]
