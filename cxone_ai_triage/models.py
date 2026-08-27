"""Data shapes for one Jira-ticket-derived triage request and its outcome."""
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

VALID_SCANNER_TYPES = ("sast", "sca")


@dataclass
class TriageJob:
    """One row of input, derived from a Prudential Jira ticket.

    Attributes:
        scan_id (str): Scan ID from the ticket.
        scanner_type (str): 'sast' or 'sca'.
        ticket_key (str): Optional Jira issue key, carried through for
            traceability in the output report.
        result_hash (str): SAST only. The resultHash / pathSystemId value
            copied from the last column of the SAST-Results page's "All"
            results tab. Used to look up the result's similarityId via
            GET /api/sast-results (filtered by result-id).
        cve_id (str): SCA only. The CVE ID from the ticket. This value
            doubles as the SCA result's similarityId.
        package_identifier (str): SCA only, optional. Disambiguates which
            /api/results row to use when the same CVE affects more than one
            package in the scan.
        jira_meta (dict): Optional passthrough of the Jira issue's other
            structured fields (summary, status, priority, issue_type,
            reporter, assignee, labels, created, updated) for traceability
            in the output report. Not used for identifier resolution.
    """

    scan_id: str
    scanner_type: str
    ticket_key: Optional[str] = None
    result_hash: Optional[str] = None
    cve_id: Optional[str] = None
    package_identifier: Optional[str] = None
    jira_meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.scan_id:
            raise ValueError("scan_id is required")
        self.scanner_type = (self.scanner_type or "").strip().lower()
        if self.scanner_type not in VALID_SCANNER_TYPES:
            raise ValueError(
                f"scanner_type must be one of {VALID_SCANNER_TYPES}, got {self.scanner_type!r}"
            )
        if self.scanner_type == "sast" and not self.result_hash:
            raise ValueError("result_hash is required when scanner_type is 'sast'")
        if self.scanner_type == "sca" and not self.cve_id:
            raise ValueError("cve_id is required when scanner_type is 'sca'")


@dataclass
class TriageOutcome:
    """Resolved identifiers plus the result of triggering AI Triage for one job."""

    job: TriageJob
    project_id: Optional[str] = None
    similarity_id: Optional[str] = None
    alternate_id: Optional[str] = None
    package_identifier: Optional[str] = None
    group_id: Optional[str] = None
    triage_id: Optional[str] = None
    status: str = "pending"  # pending | accepted | failed
    error: Optional[str] = None

    def to_row(self) -> dict:
        row = {
            "ticket_key": self.job.ticket_key,
            "scan_id": self.job.scan_id,
            "scanner_type": self.job.scanner_type,
            "result_hash": self.job.result_hash,
            "cve_id": self.job.cve_id,
            "project_id": self.project_id,
            "similarity_id": self.similarity_id,
            "alternate_id": self.alternate_id,
            "package_identifier": self.package_identifier,
            "group_id": self.group_id,
            "triage_id": self.triage_id,
            "status": self.status,
            "error": self.error,
        }
        for key, value in self.job.jira_meta.items():
            row[f"jira_{key}"] = value
        return row
