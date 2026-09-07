"""Orchestrates the whole run: resolve identifiers + trigger AI Triage for
every job (TriageResolver — batching jobs that share a scan_id/scanner_type
into one trigger request each) -> poll every result together -> post each
one as a Jira comment (JiraCommentClient). Kept separate from TriageResolver
so the CxOne-only resolution logic stays testable without any Jira
dependency.

Every job needing a poll (project_id + group_id resolved, trigger not
failed) is polled together via resolver.poll_ai_triage_results, not one at
a time - AI Triage can finish every result in a batch trigger call around
the same time server-side, so waiting on them sequentially (one job's full
poll_ai_triage_result loop to completion before even starting the next)
can take up to N x as long as necessary for no reason. Polling still stops
as soon as *this* pending set is empty - once every job's result has come
back, there's nothing left to wait on. Commenting always targets the
parent ticket key (job.ticket_key) — never a subtask, even for SCA jobs
resolved from one — so a ticket with several results (multiple
VulnerabilityIds, or multiple SCA subtasks) gets one comment per result,
all on that one parent ticket.

Before posting, existing comments on that ticket are checked for the same
"*Vulnerability ID:*"/"*CVE ID:*" marker format_comment always leads with
(see comment_formatter.build_vulnerability_marker) — if one's already
there, posting is skipped rather than adding a duplicate. This covers both
a re-run of the same ticket and multiple results landing on the same
parent within one run, since each job's check sees whatever the previous
job in this same run already posted.
"""
import logging
from typing import List, Optional

from .comment_formatter import build_vulnerability_marker, format_comment
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

    # Poll every job that needs it together (one round of GETs across all
    # of them, not each job's own full poll loop run to completion before
    # the next even starts) - see the module docstring.
    pollable = []
    for job, outcome in zip(jobs, outcomes):
        if outcome.status == "failed":
            continue
        if not outcome.project_id or not outcome.group_id:
            logger.warning(
                "%s: missing project_id/group_id; skipping AI Triage result polling",
                job.ticket_key or job.scan_id,
            )
            continue
        pollable.append((job, outcome))

    poll_results = []
    if poll and pollable:
        poll_results = resolver.poll_ai_triage_results(
            [(o.project_id, o.group_id) for _, o in pollable],
            timeout_seconds=poll_timeout, interval_seconds=poll_interval,
        )

    for (job, outcome), result in zip(pollable, poll_results):
        if isinstance(result, Exception):
            outcome.poll_error = str(result)
            logger.error("%s: polling AI Triage result failed: %s", job.ticket_key, result)
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

        vulnerability_label = job.cve_id if job.scanner_type == "sca" else job.result_hash
        vulnerability_label_name = "CVE ID" if job.scanner_type == "sca" else "Vulnerability ID"

        if vulnerability_label:
            marker = build_vulnerability_marker(vulnerability_label_name, vulnerability_label)
            try:
                existing_bodies = jira_client.get_comment_bodies(job.ticket_key)
            except Exception as e:  # noqa: BLE001 - fail open, post as usual
                logger.debug(
                    "%s: could not check existing comments (will post anyway): %s",
                    job.ticket_key, e,
                )
                existing_bodies = []
            if any(marker in body for body in existing_bodies):
                outcome.comment_skipped_reason = f"duplicate: {job.ticket_key} already has a comment with {marker!r}"
                logger.info(
                    "%s: skipping comment, already has one for %s", job.ticket_key, marker
                )
                continue

        try:
            comment = format_comment(
                result,
                package_name_version=job.jira_meta.get("package_name_version"),
                vulnerability_label=vulnerability_label,
                vulnerability_label_name=vulnerability_label_name,
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
