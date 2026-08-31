"""Extract scan/result identifiers out of a Jira ticket's free-text
description (Jira wiki markup, as produced by the Checkmarx Jira
integration).

The Jira Automation "send web request" action that dispatches this ticket
posts client_payload.jira_issue with: key, summary, description, status,
priority, issue_type, project, reporter, assignee, labels, url, created,
updated. Only `key` and `description` are used to resolve identifiers; the
rest are carried straight through as jira_meta for traceability in the
output report (see TriageJob.jira_meta).

Verified against a real SAST ticket description:

    *Checkmarx (SAST):* SQL_Injection
    ...
    *Scan ID:* [d01d7561\\-2bf5\\-48b2\\-bbaa\\-da166c671fc3|https://.../scans?id=d01d7561-2bf5-48b2-bbaa-da166c671fc3&branch=master]
    ...
    Review result in Checkmarx One: [SQL\\_Injection|https://.../results/d01d7561-2bf5-48b2-bbaa-da166c671fc3/1b49ad6f-057f-400c-aa32-f6bc31caf242/sast?result-id=XZBiE9xWT5WiRxxnpMKmKfZUJuA%3D]

For SCA, Prudential's Jira tickets carry each CVE on a *subtask* (summary
line, e.g. "CVE-2021-44228 - log4j-core-2.14.1"), not in the parent ticket's
description, while the Scan ID/scanner-type marker stay on the parent
description exactly like SAST. The parent's `subtasks` field is expected to
be an array as produced by Jira Automation's `{{issue.subtasks.jsonEncode}}`
smart value — i.e. each item shaped like the Jira REST API's issue-link
object (`{"key": ..., "fields": {"summary": ...}}`). This exact field name
and nesting is NOT yet verified against a real payload — treat it as
provisional until confirmed. A ticket with no `subtasks` field falls back to
scanning the parent description directly for a CVE ID (the original,
also-unverified approach), so this only breaks if both shapes turn out wrong.
"""
import logging
import re
from typing import List, Optional
from urllib.parse import unquote

from .models import TriageJob

logger = logging.getLogger("cxone_ai_triage")

# Jira wiki markup escapes characters like "(", ")", "-", "_" with a leading
# backslash in plain text (not inside link targets) to stop Jira's smart
# link/emoji parsing from mangling them.
_SCANNER_TYPE_RE = re.compile(r"Checkmarx\s*\\?\((SAST|SCA|IAC-SECURITY|KICS)\\?\)", re.IGNORECASE)
_SCAN_ID_URL_RE = re.compile(r"[?&]id=([0-9a-fA-F-]{36})")
_RESULT_ID_RE = re.compile(r"result-id=([^\]&\s]+)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Structured jira_issue fields carried straight through into the output
# report for traceability (not used for identifier resolution).
_META_FIELDS = (
    "summary", "status", "priority", "issue_type", "project",
    "reporter", "assignee", "labels", "created", "updated",
)


def parse_jira_issue(jira_issue: dict) -> List[TriageJob]:
    """Turn one Jira ticket's payload into one or more TriageJob objects.

    Raises ValueError if the scanner type, scan ID, or the scanner-specific
    identifier (result hash for SAST, CVE ID for SCA) can't be found.
    """
    ticket_key = jira_issue.get("key")
    description = jira_issue.get("description") or ""
    jira_meta = {k: jira_issue[k] for k in _META_FIELDS if jira_issue.get(k) is not None}

    scanner_match = _SCANNER_TYPE_RE.search(description)
    if not scanner_match:
        raise ValueError(
            f"{ticket_key}: could not find a 'Checkmarx (SAST)' / 'Checkmarx (SCA)' "
            "marker in the ticket description"
        )
    scanner_type = scanner_match.group(1).lower()

    scan_id = _find_scan_id(description)
    if not scan_id:
        raise ValueError(f"{ticket_key}: could not find a Scan ID in the ticket description")

    if scanner_type == "sast":
        return _parse_sast(ticket_key, scan_id, description, jira_meta)
    if scanner_type == "sca":
        return _parse_sca(ticket_key, scan_id, description, jira_meta, jira_issue.get("subtasks"))
    raise ValueError(f"{ticket_key}: unsupported scanner type {scanner_type!r} for AI Triage")


def _find_scan_id(description: str) -> Optional[str]:
    # The "*Scan ID:*" line links to .../scans?id=<scanId>&branch=..., which
    # is unambiguous (unlike the /results/<a>/<b>/<scanner> links, where the
    # scanId/projectId order isn't consistent between the two link styles
    # seen in this template).
    m = _SCAN_ID_URL_RE.search(description)
    return m.group(1) if m else None


def _parse_sast(
    ticket_key: Optional[str], scan_id: str, description: str, jira_meta: dict
) -> List[TriageJob]:
    encoded_ids = _RESULT_ID_RE.findall(description)
    if not encoded_ids:
        raise ValueError(
            f"{ticket_key}: found no 'result-id=' link in the ticket description"
        )
    jobs = []
    for encoded in dict.fromkeys(encoded_ids):  # de-dupe, keep order
        jobs.append(
            TriageJob(
                scan_id=scan_id,
                scanner_type="sast",
                ticket_key=ticket_key,
                result_hash=unquote(encoded),
                jira_meta=dict(jira_meta),
            )
        )
    return jobs


def _parse_sca(
    ticket_key: Optional[str],
    scan_id: str,
    description: str,
    jira_meta: dict,
    subtasks: Optional[list],
) -> List[TriageJob]:
    if subtasks:
        return _parse_sca_subtasks(ticket_key, scan_id, jira_meta, subtasks)
    return _parse_sca_description_fallback(ticket_key, scan_id, description, jira_meta)


def _parse_sca_subtasks(
    ticket_key: Optional[str], scan_id: str, jira_meta: dict, subtasks: list
) -> List[TriageJob]:
    jobs = []
    for subtask in subtasks:
        if not isinstance(subtask, dict):
            continue
        # Jira Automation's {{issue.subtasks.jsonEncode}} yields the REST API's
        # issue-link shape ({"key": ..., "fields": {"summary": ...}}); fall
        # back to a flat "summary" key in case a different smart value was used.
        fields = subtask.get("fields") if isinstance(subtask.get("fields"), dict) else subtask
        summary = fields.get("summary") or ""
        subtask_key = subtask.get("key")

        cve_match = _CVE_RE.search(summary)
        if not cve_match:
            logger.warning(
                "%s: subtask %s has no CVE ID in its summary (%r); skipping",
                ticket_key, subtask_key, summary,
            )
            continue

        meta = dict(jira_meta)
        meta["parent_key"] = ticket_key
        meta["subtask_summary"] = summary
        jobs.append(
            TriageJob(
                scan_id=scan_id,
                scanner_type="sca",
                ticket_key=subtask_key or ticket_key,
                cve_id=cve_match.group(0).upper(),
                jira_meta=meta,
            )
        )

    if not jobs:
        raise ValueError(
            f"{ticket_key}: has subtasks but none of their summaries contain a CVE ID"
        )
    return jobs


def _parse_sca_description_fallback(
    ticket_key: Optional[str], scan_id: str, description: str, jira_meta: dict
) -> List[TriageJob]:
    cve_ids = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(description)))
    if not cve_ids:
        raise ValueError(
            f"{ticket_key}: no subtasks and no CVE ID in the ticket description"
        )
    return [
        TriageJob(
            scan_id=scan_id, scanner_type="sca", ticket_key=ticket_key, cve_id=cve,
            jira_meta=dict(jira_meta),
        )
        for cve in cve_ids
    ]
