"""Load a batch of Jira-ticket-derived rows from JSON/CSV, and write results back."""
import csv
import json
from pathlib import Path
from typing import List

from .models import TriageJob, TriageOutcome

_OUTCOME_FIELDNAMES = [
    "ticket_key", "scan_id", "scanner_type", "result_hash", "cve_id",
    "project_id", "similarity_id", "alternate_id", "package_identifier",
    "group_id", "triage_id", "status", "error", "trigger_skipped_reason",
    "ai_triage_status", "reachability_status", "exploitability_status",
    "attackability_status", "ai_triage_summary", "poll_error",
    "comment_posted", "comment_error",
]


def _clean(value) -> str:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def load_jobs(path: str) -> List[TriageJob]:
    """Read a .json (list of objects) or .csv (header row) file of ticket rows.

    Recognized columns: scan_id, scanner_type, ticket_key, result_hash,
    cve_id, package_identifier.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    suffix = p.suffix.lower()
    if suffix == ".json":
        raw_rows = json.loads(p.read_text(encoding="utf-8"))
    elif suffix == ".csv":
        with p.open(newline="", encoding="utf-8") as f:
            raw_rows = list(csv.DictReader(f))
    else:
        raise ValueError(f"Unsupported input file type {suffix!r}; use .json or .csv")

    jobs = []
    for i, row in enumerate(raw_rows, start=1):
        try:
            jobs.append(
                TriageJob(
                    scan_id=_clean(row.get("scan_id")),
                    scanner_type=_clean(row.get("scanner_type")),
                    ticket_key=_clean(row.get("ticket_key")),
                    result_hash=_clean(row.get("result_hash")),
                    cve_id=_clean(row.get("cve_id")),
                    package_identifier=_clean(row.get("package_identifier")),
                )
            )
        except ValueError as e:
            raise ValueError(f"Row {i} in {path} is invalid: {e}") from e
    return jobs


def _csv_safe(value):
    """csv.writer can't write lists/dicts (e.g. a Jira 'labels' array) directly."""
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value


def write_outcomes(path: str, outcomes: List[TriageOutcome]) -> None:
    """Write resolved identifiers + trigger status to .json or .csv.

    Rows may carry extra `jira_*` columns (see TriageJob.jira_meta) beyond
    the base _OUTCOME_FIELDNAMES; those are appended after the base columns.
    """
    rows = [o.to_row() for o in outcomes]
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".json":
        p.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    elif suffix == ".csv":
        extra_fields = sorted({k for r in rows for k in r if k not in _OUTCOME_FIELDNAMES})
        fieldnames = _OUTCOME_FIELDNAMES + extra_fields
        with p.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, restval="")
            writer.writeheader()
            for row in rows:
                writer.writerow({k: _csv_safe(v) for k, v in row.items()})
    else:
        raise ValueError(f"Unsupported output file type {suffix!r}; use .json or .csv")
