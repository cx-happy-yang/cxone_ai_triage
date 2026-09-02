"""Orchestrates the whole run: resolve identifiers + trigger AI Triage for
every job (TriageResolver — batching jobs that share a scan_id/scanner_type
into one trigger request each) -> poll each result -> post it as a Jira
comment (JiraCommentClient). Kept separate from TriageResolver so the
CxOne-only resolution logic stays testable without any Jira dependency.

Polling stays per-job even when triggering was batched, since each result
has its own distinct groupId to poll. Commenting also stays per-job, but
always targets the parent ticket key (job.ticket_key) — never a subtask,
even for SCA jobs resolved from one — so a ticket with several results
(multiple VulnerabilityIds, or multiple SCA subtasks) gets one comment per
result, all on that one parent ticket.
"""
import logging
from typing import List, Optional

from .comment_formatter import format_comment
from .jira_client import JiraCommentClient
from .models import TriageJob, TriageOutcome
from .resolver import DEFAULT_POLL_INTERVAL_SECONDS, DEFAULT_POLL_TIMEOUT_SECONDS, TriageResolver

logger = logging.getLogger("cxone_ai_triage")


def run_pipeline(
    jobs: List[TriageJob],
    resolver: TriageResolver,
    jira_client: Optional[JiraCommentClient],
    poll: bool = True,
    poll_timeout: int = DEFAULT_POLL_TIMEOUT_SECONDS,
    poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
    post_comment: bool = True,
) -> List[TriageOutcome]:
    """Run resolve+trigger (+ poll + comment, unless disabled) for every job.

    A job whose trigger fails is left as-is (status="failed"); polling and
    commenting are best-effort on top of an already-successful trigger and
    never flip a job back to "failed" — see poll_error / comment_error on
    the outcome instead.
    """
    outcomes = resolver.resolve_and_trigger_all(jobs)

    for job, outcome in zip(jobs, outcomes):
        if outcome.status == "failed" or not poll:
            continue

        if not outcome.project_id or not outcome.group_id:
            logger.warning(
                "%s: missing project_id/group_id; skipping AI Triage result polling",
                job.ticket_key or job.scan_id,
            )
            continue

        try:
            result = resolver.poll_ai_triage_result(
                outcome.project_id, outcome.group_id,
                timeout_seconds=poll_timeout, interval_seconds=poll_interval,
            )
        except Exception as e:  # noqa: BLE001 - best-effort, don't abort the batch
            outcome.poll_error = str(e)
            logger.error("%s: polling AI Triage result failed: %s", job.ticket_key, e)
            continue

        outcome.ai_triage_status = result.triageStatus
        outcome.reachability_status = result.reachabilityStatus
        outcome.exploitability_status = result.exploitabilityStatus
        outcome.attackability_status = result.attackabilityStatus
        outcome.ai_triage_summary = result.summary

        if not post_comment or not jira_client:
            continue
        if not job.ticket_key:
            logger.warning(
                "No ticket_key on the job for scan %s; skipping Jira comment", job.scan_id
            )
            continue

        try:
            comment = format_comment(
                result,
                package_name_version=job.jira_meta.get("package_name_version"),
                vulnerability_label=job.cve_id if job.scanner_type == "sca" else job.result_hash,
                vulnerability_label_name="CVE ID" if job.scanner_type == "sca" else "Vulnerability ID",
                subtask_key=job.jira_meta.get("subtask_key"),
            )
            # Always the parent ticket key (job.ticket_key) - never a
            # subtask, even when this job was resolved from one.
            jira_client.add_comment(job.ticket_key, comment)
            outcome.comment_posted = True
        except Exception as e:  # noqa: BLE001 - best-effort, don't abort the batch
            outcome.comment_error = str(e)
            logger.error("%s: posting Jira comment failed: %s", job.ticket_key, e)

    return outcomes
