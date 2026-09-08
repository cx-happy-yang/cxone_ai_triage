"""Resolve Jira-ticket-derived identifiers into a Checkmarx One AI Triage
request, then trigger it.

Mapping of what a ticket gives us -> what POST /api/ai-triage/triage needs:

  scan_id            -> scanID                              (given directly)
  scanner_type       -> buckets[].scannerType                (given directly)
  result_hash (SAST) -> similarityId, via GET /api/sast-results?result-id=
  cve_id (SCA)        -> similarityId                        (the CVE ID *is*
                                                               the similarityId)
  similarityId        -> alternateId, via GET /api/results (paged - no
                          similarityId filter exists server-side; see
                          _get_all_results for a confirmed-live quirk in
                          how that pagination actually works)
  scan_id             -> projectId, via GET /api/scans/{scanId}

groupId (needed only to later poll GET /api/ai-triage/triage/{projectId}/{groupId},
not for the trigger call itself) is resolved as:
  - SAST: it *is* the similarityId (per AiTriageAPI docstring).
  - SCA: looked up from GET /api/risks as the authoritative source,
    falling back to the manually-constructed format documented in the API
    reference ("Retrieve AI Triage Results" - "If necessary, you can
    construct the group_id manually"): similarityId#-#packageIdentifier#-#
    projectId, with packageIdentifier taken from the matched /api/results
    row's data. The fallback exists because /api/risks can lag the results
    view - a live tenant showed risks returning no entry at all for a CVE
    whose /api/results rows clearly exist, which left groupId blank and
    made the pipeline skip AI Triage result polling entirely (see
    _resolve_group_id). /api/risks aggregates at the *project* level, not
    per scan, so a scanId match is only used to disambiguate between
    several risks sharing one CVE - never as a hard filter that could
    discard the only match.

Batching: resultID resolution (similarityId -> alternateId, groupId, ...) is
always per-job, since each result has its own distinct groupId to poll
later. But the trigger call itself accepts multiple resultIDs in one
bucket, so jobs sharing the same (scan_id, scanner_type) — e.g. a SAST
ticket with several populated VulnerabilityId fields — are combined into a
single POST /api/ai-triage/triage request instead of one per job, and all
their outcomes get the same triageID back. resultIDs are de-duplicated
within a bucket before sending: two jobs whose findings collapse onto the
same similarityId (see _find_alternate_id's SAST ambiguous-match handling)
resolve to the same alternateId, and only need to be submitted once.

Two or more jobs can end up sharing one groupId — most commonly two
distinct SAST VulnerabilityId values that Checkmarx grouped under the same
similarityId (a vulnerability *pattern*, not a specific occurrence). Since
AI Triage only ever produces one verdict per groupId, these jobs are
triggered once (see the resultID de-duplication above), their existing-
triage pre-check and poll are only ever made once per groupId (see
existing_by_group below and pipeline.run_pipeline's poll de-duplication),
and pipeline.run_pipeline posts one shared Jira comment mentioning every
one of their vulnerability labels rather than a comment per job.

Before triggering, each resolved job (that has a groupId) is checked
against GET /api/ai-triage/triage/{projectId}/{groupId} first. If a result
already exists — whether still IN_PROGRESS from an earlier run or already
finished — the trigger is skipped for that job entirely (outcome.
trigger_skipped_reason is set instead) rather than re-submitting it; the
pipeline's subsequent poll picks up the existing result either way (an
already-terminal result returns on the poll's first call, no waiting). A
prior FAILED status is the one exception: it means AI Triage never actually
produced a verdict, so it's treated the same as no result at all and the
job is re-triggered rather than skipped forever.

All five SDK API classes share one ApiClient (and so one OAuth token/
TokenManager) rather than each building its own — confirmed via live logs
that letting each construct its own via construct_configuration() means a
separate token fetch per class actually used in a run.
"""
import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from CheckmarxPythonSDK.api_client import ApiClient
from CheckmarxPythonSDK.CxOne import (
    AiTriageAPI,
    RiskOrchestrationAPI,
    SastResultsAPI,
    ScannersResultsAPI,
    ScansAPI,
)
from CheckmarxPythonSDK.CxOne.config import construct_configuration
from CheckmarxPythonSDK.CxOne.dto import AiTriageRequest, AiTriageResult, TriageBucket

from .models import TriageJob, TriageOutcome

logger = logging.getLogger("cxone_ai_triage")

# /api/results has no similarityId filter, so every row for a scan must be
# paged through. Use the largest page size the API allows to minimize
# round-trips.
RESULTS_PAGE_SIZE = 500

# AiTriageResult.triageStatus values that mean "still working" per the SDK's
# AiTriageResult docstring; anything else (including FAILED) is terminal.
_IN_PROGRESS_TRIAGE_STATUSES = {"NOT_TRIAGED", "IN_PROGRESS"}

# A 200 whose body has neither triageStatus nor the IN_PROGRESS job-status
# envelope (see _effective_triage_status) is off-schema. Pollers tolerate
# it for this many consecutive rounds in case a real status appears, then
# fail with AiTriageMissingStatusError instead of burning the whole timeout
# window.
_MAX_MISSING_STATUS_ROUNDS = 2
DEFAULT_POLL_TIMEOUT_SECONDS = 180
DEFAULT_POLL_INTERVAL_SECONDS = 15


class AiTriageMissingStatusError(RuntimeError):
    """GET /api/ai-triage/triage returned 200 with no usable triage status.

    The documented response schema requires triageStatus, but a live tenant
    showed the endpoint returning a small job-status envelope instead while
    a triage job is processing: {projectID, groupID, jobStatus:
    IN_PROGRESS}. That envelope is handled as "still in progress" (see
    _effective_triage_status); this error is raised only for bodies that
    have neither triageStatus nor that IN_PROGRESS envelope - bodies the
    pollers genuinely can't interpret. Further polling will not produce a
    verdict from such a body, so pollers fail fast with the raw body in
    the message (for escalation) instead of burning the whole timeout
    window.
    """

    def __init__(self, project_id: str, group_id: str, raw_body):
        super().__init__(
            f"AI Triage returned 200 with no triageStatus for project {project_id} "
            f"group {group_id}; raw response body: {raw_body!r}"
        )


class TriageResolver:
    """Resolves each TriageJob and triggers AI Triage for it.

    Caches per-scan and per-project lookups so a batch of tickets pointing
    at the same scan only pays the /api/results pagination cost once.
    """

    def __init__(self, api_client: Optional[ApiClient] = None):
        # One shared ApiClient (and so one shared token/TokenManager) across
        # all five SDK classes, instead of each building its own via
        # construct_configuration() — confirmed via live logs that letting
        # each construct its own means a separate OAuth token fetch per
        # class actually used (up to 4-5 per run).
        if api_client is None:
            api_client = ApiClient(configuration=construct_configuration())
        self._scans_api = ScansAPI(api_client=api_client)
        self._sast_results_api = SastResultsAPI(api_client=api_client)
        self._scanner_results_api = ScannersResultsAPI(api_client=api_client)
        self._risks_api = RiskOrchestrationAPI(api_client=api_client)
        self._ai_triage_api = AiTriageAPI(api_client=api_client)

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
            page_number = 0
            while True:
                # GET /api/results' `offset` is a PAGE NUMBER (0-indexed),
                # not a row-skip count, despite the SDK's own docstring
                # ("offset: Items to skip") - confirmed empirically against
                # a live tenant: with totalCount=564 and limit=500,
                # offset=500 (the "skip 500 rows" interpretation) returned
                # 0 rows, while offset=1 (the "give me page 1" - i.e. the
                # second page of 500 - interpretation) correctly returned
                # the remaining 64 rows. Advancing by len(page_results) (a
                # row count) instead of by 1 (the next page number) was
                # exactly why an earlier version of this fix still failed
                # for any scan with more than one page of results.
                page = self._scanner_results_api.get_all_scanners_results_by_scan_id(
                    scan_id=scan_id, offset=page_number, limit=RESULTS_PAGE_SIZE
                )
                page_results = page["results"]
                logger.debug(
                    "scan %s: page %d (requested via offset=%d limit=%d) - got %d row(s), "
                    "server-reported totalCount=%s",
                    scan_id, page_number, page_number, RESULTS_PAGE_SIZE, len(page_results),
                    page.get("totalCount"),
                )
                all_results.extend(page_results)
                # Not trusting page["totalCount"] to decide when to stop -
                # the same live tenant also showed a totalCount matching
                # just the first page's size for a scan with far more rows
                # than that. A short page (fewer rows than requested) is
                # what actually means "last page".
                if len(page_results) < RESULTS_PAGE_SIZE:
                    break
                page_number += 1
            self._results_by_scan[scan_id] = all_results
            logger.info(
                "scan %s: fetched %d rows from /api/results across %d page(s)",
                scan_id, len(all_results), page_number + 1,
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
        all_results = self._get_all_results(job.scan_id)
        matches = [
            r
            for r in all_results
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
            # Diagnostic counts, not just "not found" - tells us at a
            # glance whether this looks like a fetch-coverage problem
            # (total_fetched suspiciously small/round) or a genuine
            # mismatch (plenty of same-type rows fetched, just none with
            # this similarityId - e.g. a stale scan_id on the ticket vs.
            # what the UI is showing for a newer scan of the same project).
            same_type_count = sum(1 for r in all_results if (r.type or "").lower() == job.scanner_type)
            raise LookupError(
                f"GET /api/results has no {job.scanner_type} row for scan {job.scan_id} "
                f"with similarityId {similarity_id!r} (fetched {len(all_results)} total row(s), "
                f"{same_type_count} of type {job.scanner_type!r} for this scan)"
            )
        if len(matches) > 1:
            if job.scanner_type == "sca":
                packages = sorted(
                    {
                        (m.data or {}).get("packageIdentifier")
                        for m in matches
                        if isinstance(m.data, dict) and m.data.get("packageIdentifier")
                    }
                )
                raise LookupError(
                    f"{len(matches)} sca rows in scan {job.scan_id} share "
                    f"similarityId {similarity_id!r} (packages: {packages}); set "
                    "package_identifier on the input row to disambiguate"
                )
            # SAST has no equivalent disambiguator (package_identifier is
            # SCA-only) - a live tenant showed 2 distinct VulnerabilityId
            # values (2 different resultHashes) genuinely sharing one
            # similarityId, because Checkmarx groups SAST findings by
            # vulnerability *pattern* rather than by specific occurrence
            # (each /api/results row's `data` was empty, unlike SCA's
            # packageIdentifier). But unlike SCA, this doesn't need to be
            # resolved precisely: groupId *is* the similarityId for SAST
            # (see _resolve_group_id) and AI Triage only ever returns one
            # verdict per groupId, so every row sharing this similarityId
            # is an equally valid representative to submit in the trigger
            # call - any one's alternateId works. resolve_and_trigger_all
            # dedupes the resultIDs actually sent for the trigger call,
            # and pipeline.run_pipeline groups these jobs' comments
            # together (one shared comment naming every VulnerabilityId
            # involved) rather than treating them as independent results.
            # Logging every field on each row in case a real disambiguator
            # (that would let each VulnerabilityId get its own precise
            # verdict again) ever turns up.
            for m in matches:
                logger.info(
                    "%s: %d sast rows share similarityId %r (not failing - "
                    "using %s as the shared representative alternateId) - "
                    "id=%s alternate_id=%s data=%r description=%r "
                    "vulnerability_details=%r first_found_at=%s found_at=%s "
                    "created=%s",
                    job.ticket_key or job.scan_id, len(matches), similarity_id,
                    matches[0].alternate_id, m.id, m.alternate_id, m.data,
                    m.description, m.vulnerability_details, m.first_found_at,
                    m.found_at, m.created,
                )
            matches = matches[:1]

        match = matches[0]
        package_identifier = None
        if job.scanner_type == "sca" and isinstance(match.data, dict):
            package_identifier = match.data.get("packageIdentifier")
        return match.alternate_id, package_identifier

    def _resolve_group_id(
        self,
        job: TriageJob,
        project_id: str,
        similarity_id: str,
        package_identifier: Optional[str] = None,
    ) -> Optional[str]:
        """Resolve the SCA groupId for polling GET /api/ai-triage/triage.

        GET /api/risks is the authoritative source, but its view can lag the
        results view (a live tenant showed no risks entry at all for a CVE
        whose /api/results rows clearly exist - the trigger was accepted but
        groupId stayed blank and the pipeline skipped result polling
        entirely). In that case the groupId is constructed from the format
        documented in the API reference ("If necessary, you can construct
        the group_id manually"): similarityId#-#packageIdentifier#-#projectId
        - with packageIdentifier coming from the matched /api/results row's
        data, not from the ticket. If neither source yields a groupId, the
        trigger still fires (it doesn't need one) but result polling is
        skipped by pipeline.run_pipeline.
        """
        if job.scanner_type == "sast":
            return similarity_id

        resp = self._risks_api.get_risks(
            project_id=project_id, engine=["SCA"], risk_name=[job.cve_id], limit=200
        )
        candidates = resp.risks
        if not candidates:
            if package_identifier:
                group_id = f"{similarity_id}#-#{package_identifier}#-#{project_id}"
                logger.info(
                    "GET /api/risks has no entry for CVE %s in project %s; constructed "
                    "groupId %r from similarityId#-#packageIdentifier#-#projectId",
                    job.cve_id, project_id, group_id,
                )
                return group_id
            logger.warning(
                "GET /api/risks has no entry at all for CVE %s in project %s and no "
                "packageIdentifier to construct the groupId from; groupId left blank "
                "(does not block the trigger call, but skips result polling).",
                job.cve_id, project_id,
            )
            return None

        # GET /api/risks aggregates risks at the *project* level (per its
        # own docstring), not per scan - Risk.scanId reflects some scan
        # that detected it (observed live to drift to whatever scan most
        # recently rediscovered it), not necessarily job.scan_id. A live
        # tenant returned zero candidates for a CVE that was confirmed to
        # already exist, once the project had been rescanned since the
        # ticket's scan_id - so an exact scanId match is only a
        # *preference* for picking the right one when several risks share
        # this CVE, never a hard requirement that discards every result.
        scan_matches = [r for r in candidates if r.scanId == job.scan_id]
        if scan_matches:
            candidates = scan_matches
        else:
            logger.info(
                "GET /api/risks returned %d entr%s for CVE %s in project %s but none tagged "
                "with scan %s (risks are project-level, not scan-level - using them anyway).",
                len(candidates), "y" if len(candidates) == 1 else "ies",
                job.cve_id, project_id, job.scan_id,
            )

        if job.package_identifier and len(candidates) > 1:
            narrowed = [
                r for r in candidates
                if r.assetName and job.package_identifier in r.assetName
            ]
            if narrowed:
                candidates = narrowed

        if len(candidates) > 1:
            logger.warning(
                "GET /api/risks returned %d entries for CVE %s in project %s; using the first",
                len(candidates), job.cve_id, project_id,
            )
        return candidates[0].groupId

    def _resolve_only(self, job: TriageJob) -> TriageOutcome:
        """Resolve one job's projectId/similarityId/alternateId/groupId.
        Does not trigger anything. On failure, returns an outcome with
        status="failed" and .error set instead of raising.
        """
        outcome = TriageOutcome(job=job)
        try:
            outcome.project_id = self._get_project_id(job.scan_id)
            outcome.similarity_id = self._resolve_similarity_id(job)
            outcome.alternate_id, outcome.package_identifier = self._find_alternate_id(
                job, outcome.similarity_id
            )
            outcome.group_id = self._resolve_group_id(
                job, outcome.project_id, outcome.similarity_id, outcome.package_identifier
            )
        except Exception as e:  # noqa: BLE001 - keep the batch going on a per-row failure
            outcome.status = "failed"
            outcome.error = str(e)
            logger.error("%s failed: %s", job.ticket_key or job.scan_id, e)
        return outcome

    def _check_existing_triage(self, project_id: str, group_id: str) -> Optional[AiTriageResult]:
        """GET /api/ai-triage/triage/{projectId}/{groupId} before triggering.

        Returns the existing result if one is already in progress or
        finished, so the caller can skip triggering it again. Returns None
        if there's genuinely no existing result yet, or if the check itself
        fails — a failed check is treated as "no existing result" so
        triggering still proceeds normally rather than blocking on this
        optimization.

        Deliberately permissive rather than an allowlist of AiTriageResult's
        documented triageStatus values (NOT_TRIAGED, IN_PROGRESS, FAILED,
        VULNERABLE, PROPOSED_NOT_EXPLOITABLE, UNCERTAIN, RISK_ACCEPTED): a
        live tenant returned "CONFIRMED" (a SAST/SCA result *state* value,
        not in that enum) for a vulnerability that genuinely had already
        been AI-triaged. Result states have predefined values (TO_VERIFY,
        NOT_EXPLOITABLE, PROPOSED_NOT_EXPLOITABLE, CONFIRMED, URGENT) plus
        whatever custom states a tenant defines — but AI Triage itself only
        ever assigns a predefined one, never a tenant's custom state, so the
        real universe of values this field can hold is still bounded and
        known even though it's broader than AiTriageResult's own docstring
        enum. So anything other than a blank/NOT_TRIAGED/FAILED value
        (normalized for case/whitespace) is treated as "already exists" —
        narrowing this to a strict allowlist would wrongly treat legitimate-
        but-undocumented statuses as "not triaged yet" and re-trigger
        needlessly.

        FAILED and IN_PROGRESS are excluded on purpose too. FAILED means AI
        Triage itself never produced a result, so treating it as "already
        exists" would permanently block a retry on every future run.
        IN_PROGRESS was originally left in as "already exists" (assumed
        merely transient - still actively being processed), but a live
        tenant showed a multi-resultID batch trigger call where only 1 of
        3 resultIDs ended up with a real verdict; the other 2 stayed
        IN_PROGRESS indefinitely (confirmed: still IN_PROGRESS on a
        follow-up run, with no timestamp on AiTriageResult to tell "still
        actively processing" apart from "abandoned/stuck"). Treating a
        stuck IN_PROGRESS as "already exists" meant those 2 could never be
        retried on any future run, ever - so it's treated the same as
        FAILED/blank/NOT_TRIAGED now: safe to re-batch and re-trigger.
        Re-triggering something that's genuinely still in flight is a
        low-cost redundant call, not a correctness problem, unlike
        permanently stranding a result that never finished.

        A 200 whose body has no triageStatus at all (off-schema - the
        field is required per the API docs) is logged as a warning with the
        raw body and treated as "no result", same as a blank status.
        """
        try:
            result, raw_body = self._retrieve_triage_result(project_id, group_id)
        except Exception as e:  # noqa: BLE001 - fail open, just trigger as usual
            logger.debug(
                "Existing-triage check failed for project %s group %s (will trigger normally): %s",
                project_id, group_id, e,
            )
            return None
        status = (result.triageStatus or "").strip().upper()
        if status in ("", "NOT_TRIAGED", "FAILED", "IN_PROGRESS"):
            if not status:
                logger.warning(
                    "Existing-triage check for project %s group %s returned 200 with no "
                    "triageStatus (off-schema response, raw body: %r); treating as no existing result",
                    project_id, group_id, raw_body,
                )
            return None
        return result

    def _trigger_batch(self, scan_id: str, scanner_type: str, outcomes: List[TriageOutcome]) -> None:
        """Trigger one POST /api/ai-triage/triage for every outcome in this
        (scan_id, scanner_type) group, bucketing their alternateIds together.
        Updates each outcome in place; a failure here fails all of them.

        resultIDs are de-duplicated (order preserved) before being sent:
        several outcomes can legitimately share one alternateId when their
        jobs resolved to the same similarityId (see _find_alternate_id's
        SAST ambiguous-match handling) - sending the same resultID twice
        in one bucket would be a pointless duplicate, not two results.
        """
        seen_ids = set()
        result_ids = []
        for o in outcomes:
            if o.alternate_id in seen_ids:
                continue
            seen_ids.add(o.alternate_id)
            result_ids.append(o.alternate_id)
        logger.info(
            "scan %s: POST /api/ai-triage/triage payload - scanID=%s, bucket scannerType=%s "
            "resultIDs=%s (groupIds for reference: %s)",
            scan_id, scan_id, scanner_type, result_ids, [o.group_id for o in outcomes],
        )
        try:
            request = AiTriageRequest(
                scanID=scan_id,
                buckets=[
                    TriageBucket(
                        scannerType=scanner_type,
                        resultIDs=result_ids,
                    )
                ],
            )
            response = self._ai_triage_api.trigger_ai_triage(request)
            logger.info(
                "scan %s: POST /api/ai-triage/triage response - triageID=%s status=%s published=%s",
                scan_id, response.triageID, response.status, getattr(response, "published", None),
            )
            for outcome in outcomes:
                outcome.triage_id = response.triageID
                outcome.status = response.status or "accepted"
        except Exception as e:  # noqa: BLE001 - keep the rest of the run going
            for outcome in outcomes:
                outcome.status = "failed"
                outcome.error = str(e)
            tickets = {o.job.ticket_key or o.job.scan_id for o in outcomes}
            logger.error(
                "batch trigger for scan %s (%s, %d result(s), tickets=%s) failed: %s",
                scan_id, scanner_type, len(outcomes), sorted(tickets), e,
            )

    # ---- public entry points ----------------------------------------------

    def resolve_and_trigger(self, job: TriageJob) -> TriageOutcome:
        """Resolve and trigger a single job. Equivalent to
        resolve_and_trigger_all([job])[0]."""
        return self.resolve_and_trigger_all([job])[0]

    def resolve_and_trigger_all(self, jobs: List[TriageJob]) -> List[TriageOutcome]:
        """Resolve every job, then trigger AI Triage for whichever ones don't
        already have a result — batching jobs that share the same
        (scan_id, scanner_type) into one request each (e.g. a SAST ticket
        with several populated VulnerabilityId fields), rather than one
        request per job.
        """
        outcomes = [self._resolve_only(job) for job in jobs]

        batches: Dict[Tuple[str, str], List[TriageOutcome]] = defaultdict(list)
        # Cached per (project_id, group_id) within this call: several jobs
        # can share one group_id (e.g. multiple VulnerabilityId fields
        # whose findings collapsed onto the same similarityId - see
        # _find_alternate_id's SAST ambiguous-match handling), and there's
        # no need to ask AI Triage about the same groupId more than once.
        existing_by_group: Dict[Tuple[str, str], Optional[AiTriageResult]] = {}
        for job, outcome in zip(jobs, outcomes):
            if outcome.status == "failed":
                continue

            if outcome.project_id and outcome.group_id:
                group_key = (outcome.project_id, outcome.group_id)
                if group_key not in existing_by_group:
                    existing_by_group[group_key] = self._check_existing_triage(*group_key)
                existing = existing_by_group[group_key]
                if existing is not None:
                    outcome.status = "accepted"
                    outcome.trigger_skipped_reason = f"existing triageStatus={existing.triageStatus}"
                    logger.info(
                        "%s: skipping trigger, AI Triage already has a result (status=%s)",
                        job.ticket_key or job.scan_id, existing.triageStatus,
                    )
                    continue

            batches[(job.scan_id, job.scanner_type)].append(outcome)

        for (scan_id, scanner_type), batch_outcomes in batches.items():
            self._trigger_batch(scan_id, scanner_type, batch_outcomes)

        return outcomes

    # ---- polling for the finished result ---------------------------------

    def _retrieve_triage_result(
        self, project_id: str, group_id: str
    ) -> Tuple[AiTriageResult, Optional[dict]]:
        """GET /api/ai-triage/triage/{projectId}/{groupId} and return the
        parsed AiTriageResult plus, when the parsed result has no
        triageStatus at all, the raw response body as a dict (None
        otherwise).

        The documented response schema requires triageStatus, so a parsed
        result without one means the API returned an off-schema body - the
        SDK's AiTriageResult.from_dict silently maps missing keys to None.
        A live tenant showed exactly this: 200 with a ~100-byte job-status
        envelope ({projectID, groupID, jobStatus: IN_PROGRESS}) while the
        triage job was still processing, identical on every poll until the
        job finished. The raw body is only fetched when the parsed result
        has no triageStatus (a normal response costs no extra request), so
        the off-schema payload can be logged, interpreted (see
        _effective_triage_status), and reported instead of being invisible.
        """
        result = self._ai_triage_api.retrieve_ai_triage_results(project_id, group_id)
        raw_body = None
        if not result.triageStatus:
            try:
                url = (
                    f"{self._ai_triage_api.base_url}/triage/{project_id}/"
                    f"{quote(str(group_id), safe='')}"
                )
                response = self._ai_triage_api.api_client.call_api(
                    method="GET",
                    url=url,
                    headers={"Accept": "application/json"},
                )
                raw_body = response.json()
            except Exception:  # noqa: BLE001 - raw body is best-effort diagnosis only
                raw_body = None
        return result, raw_body

    def _effective_triage_status(
        self,
        project_id: str,
        group_id: str,
        result: AiTriageResult,
        raw_body: Optional[dict],
    ) -> Optional[str]:
        """Return the status that drives the poll loop for a polled response.

        Normally that's AiTriageResult.triageStatus. But a live tenant
        showed the endpoint returning a job-status envelope instead while
        the triage job is still processing: {projectID, groupID,
        jobStatus: IN_PROGRESS} (~100 bytes, no triageStatus field - the
        documented schema simply isn't what the API serves for a running
        job). jobStatus=IN_PROGRESS maps to the triageStatus IN_PROGRESS so
        polling keeps waiting for the real result; any other envelope (e.g.
        jobStatus=FAILED) and any body with neither field is off-schema: a
        warning with the raw body is logged and None is returned so the
        caller's missing-status counting can fail fast.
        """
        if result.triageStatus:
            return result.triageStatus
        if isinstance(raw_body, dict) and raw_body.get("jobStatus"):
            job_status = raw_body["jobStatus"]
            if job_status == "IN_PROGRESS":
                return "IN_PROGRESS"
        logger.warning(
            "project %s group %s: AI Triage returned 200 with no triageStatus "
            "(off-schema response, raw body: %r)",
            project_id, group_id, raw_body,
        )
        return None

    def poll_ai_triage_result(
        self,
        project_id: str,
        group_id: str,
        timeout_seconds: int = DEFAULT_POLL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> AiTriageResult:
        """Poll GET /api/ai-triage/triage/{projectId}/{groupId} until the
        analysis leaves NOT_TRIAGED/IN_PROGRESS, or raise TimeoutError.

        The trigger call is async (202 Accepted with no verdict yet), so the
        reachability/exploitability/summary fields this is used for only
        exist after this poll succeeds.

        A 200 whose body has no triageStatus at all (off-schema - the
        documented schema requires the field) is tolerated for one extra
        round in case a real status appears, then raises
        AiTriageMissingStatusError with the raw body instead of burning the
        whole timeout window. Exception: the {projectID, groupID,
        jobStatus: IN_PROGRESS} envelope the API returns while the triage
        job is still running counts as IN_PROGRESS and keeps polling.
        """
        deadline = time.monotonic() + timeout_seconds
        result, raw_body = self._retrieve_triage_result(project_id, group_id)
        status = self._effective_triage_status(project_id, group_id, result, raw_body)
        missing_status_rounds = 1 if status is None else 0
        logger.info(
            "project %s group %s: AI Triage status=%s (waiting up to %ds, checking every %ds)",
            project_id, group_id, status, timeout_seconds, interval_seconds,
        )
        while (status or "NOT_TRIAGED") in _IN_PROGRESS_TRIAGE_STATUSES:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"AI Triage for project {project_id} group {group_id} did not "
                    f"finish within {timeout_seconds}s (last status: {status!r})"
                )
            time.sleep(interval_seconds)
            result, raw_body = self._retrieve_triage_result(project_id, group_id)
            status = self._effective_triage_status(project_id, group_id, result, raw_body)
            missing_status_rounds = missing_status_rounds + 1 if status is None else 0
            logger.info(
                "project %s group %s: AI Triage status=%s", project_id, group_id, status,
            )
            if missing_status_rounds >= _MAX_MISSING_STATUS_ROUNDS:
                raise AiTriageMissingStatusError(project_id, group_id, raw_body)
        return result

    def poll_ai_triage_results(
        self,
        targets: List[Tuple[str, str]],
        timeout_seconds: int = DEFAULT_POLL_TIMEOUT_SECONDS,
        interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> List[object]:
        """Poll several (projectId, groupId) pairs together, one GET per
        still-pending target per round, sleeping once per round rather than
        polling each target's own full wait to completion before starting
        the next. AI Triage can process every result in a batch trigger
        call around the same time server-side, so waiting on them one at a
        time (poll_ai_triage_result in a loop) can take up to
        len(targets) x as long as necessary for no reason - this stops as
        soon as every target has resolved, not after each one individually
        exhausts its own poll loop.

        A target whose responses keep coming back with no triageStatus at
        all (off-schema - the documented schema requires the field) fails
        after _MAX_MISSING_STATUS_ROUNDS consecutive rounds with an
        AiTriageMissingStatusError carrying the raw body, rather than
        dragging the batch to the full timeout - see
        _effective_triage_status. The job-status envelope ({projectID,
        groupID, jobStatus: IN_PROGRESS}) the API serves while a triage
        job is still running is the exception: it counts as IN_PROGRESS
        and keeps polling.

        Returns a list the same length and order as `targets`; each entry
        is either the finished AiTriageResult or an Exception (a
        TimeoutError if timeout_seconds elapses - shared across all
        targets from this call's start, not restarted per remaining one -
        or whatever the result GET itself raised) - callers that want the
        single-target behavior's "raise on failure" should check
        `isinstance(item, Exception)` themselves; this never raises.
        """
        n = len(targets)
        results: List[Optional[AiTriageResult]] = [None] * n
        errors: List[Optional[Exception]] = [None] * n
        missing_status_rounds = [0] * n
        last_statuses: List[Optional[str]] = [None] * n
        pending = set(range(n))

        def poll_round():
            for i in list(pending):
                project_id, group_id = targets[i]
                try:
                    result, raw_body = self._retrieve_triage_result(project_id, group_id)
                except Exception as e:  # noqa: BLE001 - recorded per-target, not raised
                    errors[i] = e
                    pending.discard(i)
                    continue
                results[i] = result
                status = self._effective_triage_status(project_id, group_id, result, raw_body)
                last_statuses[i] = status
                if status is None:
                    missing_status_rounds[i] += 1
                else:
                    missing_status_rounds[i] = 0
                logger.info(
                    "project %s group %s: AI Triage status=%s", project_id, group_id, status,
                )
                if status is None:
                    # Off-schema response: keep waiting in case a real
                    # status appears, but fail fast once the response has
                    # been off-schema for enough consecutive rounds.
                    if missing_status_rounds[i] >= _MAX_MISSING_STATUS_ROUNDS:
                        errors[i] = AiTriageMissingStatusError(project_id, group_id, raw_body)
                        pending.discard(i)
                    continue
                if status not in _IN_PROGRESS_TRIAGE_STATUSES:
                    pending.discard(i)

        deadline = time.monotonic() + timeout_seconds
        poll_round()
        while pending:
            if time.monotonic() >= deadline:
                for i in pending:
                    project_id, group_id = targets[i]
                    errors[i] = TimeoutError(
                        f"AI Triage for project {project_id} group {group_id} did not "
                        f"finish within {timeout_seconds}s (last status: {last_statuses[i]!r})"
                    )
                break
            time.sleep(interval_seconds)
            poll_round()

        return [errors[i] if errors[i] is not None else results[i] for i in range(n)]
