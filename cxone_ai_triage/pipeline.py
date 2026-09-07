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

Two or more jobs on the same ticket can resolve to the same (project_id,
group_id) — most commonly two distinct SAST VulnerabilityId fields whose
findings collapsed onto the same similarityId (see
resolver._find_alternate_id's SAST ambiguous-match handling). Since AI
Triage only ever produces one verdict per group_id, these are polled only
once (not once per job — see _dedupe_poll_targets) and, when they have 2+
distinct vulnerability labels, posted as a single shared Jira comment
mentioning every one of those labels (see _group_for_comments and
comment_formatter.format_comment's vulnerability_labels parameter) instead
of one comment per job. A group whose members all share the exact same
label (e.g. a literal duplicate input row) isn't treated as a "shared
comment" group — it's left to the ordinary duplicate-marker check below,
unchanged.
"""
import logging
from typing import Dict, List, Optional, Tuple

from .comment_formatter import (
    build_vulnerability_marker,
    build_vulnerability_marker_multi,
    format_comment,
)
from .jira_client import JiraCommentClient
from .models import TriageJob, TriageOutcome
from .resolver import DEFAULT_POLL_INTERVAL_SECONDS, DEFAULT_POLL_TIMEOUT_SECONDS, TriageResolver

logger = logging.getLogger("cxone_ai_triage")

TriagedJob = Tuple[TriageJob, TriageOutcome, object]  # object is an AiTriageResult


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
    # the next even starts) - see the module docstring. Targets are also
    # de-duplicated by (project_id, group_id): 2+ jobs can share a group_id
    # (see the module docstring), and there's no reason to poll it more
    # than once.
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

    unique_targets, poll_index_for = _dedupe_poll_targets(pollable)

    poll_results = []
    if poll and unique_targets:
        poll_results = resolver.poll_ai_triage_results(
            unique_targets, timeout_seconds=poll_timeout, interval_seconds=poll_interval,
        )

    triaged: List[TriagedJob] = []
    if poll_results:
        for (job, outcome), target_index in zip(pollable, poll_index_for):
            result = poll_results[target_index]
            if isinstance(result, Exception):
                outcome.poll_error = str(result)
                logger.error("%s: polling AI Triage result failed: %s", job.ticket_key, result)
                continue

            outcome.ai_triage_status = result.triageStatus
            outcome.reachability_status = result.reachabilityStatus
            outcome.exploitability_status = result.exploitabilityStatus
            outcome.attackability_status = result.attackabilityStatus
            outcome.ai_triage_summary = result.summary
            triaged.append((job, outcome, result))

    if not post_comment or not jira_client:
        return outcomes

    for job, _, _ in triaged:
        if not job.ticket_key:
            logger.warning(
                "No ticket_key on the job for scan %s; skipping Jira comment", job.scan_id
            )

    for members in _group_for_comments(triaged):
        if len(members) > 1:
            _post_grouped_comment(members, jira_client)
        else:
            _post_single_comment(*members[0], jira_client)

    return outcomes


def _dedupe_poll_targets(
    pollable: List[Tuple[TriageJob, TriageOutcome]],
) -> Tuple[List[Tuple[str, str]], List[int]]:
    """Build the de-duplicated (project_id, group_id) target list to poll,
    plus a parallel index into it for each entry in `pollable` (so its
    result can be looked back up after resolver.poll_ai_triage_results
    returns one result per unique target, not one per job)."""
    unique_targets: List[Tuple[str, str]] = []
    target_position: Dict[Tuple[str, str], int] = {}
    poll_index_for: List[int] = []
    for _, outcome in pollable:
        key = (outcome.project_id, outcome.group_id)
        if key not in target_position:
            target_position[key] = len(unique_targets)
            unique_targets.append(key)
        poll_index_for.append(target_position[key])
    return unique_targets, poll_index_for


def _group_for_comments(triaged: List[TriagedJob]) -> List[List[TriagedJob]]:
    """Group triaged (job, outcome, result) entries by (ticket_key,
    group_id) so jobs that share a group_id get one shared comment - but
    only when they have 2+ *distinct* vulnerability labels. A group whose
    members all share the exact same label (e.g. a literal duplicate input
    row), or that has no ticket_key to key a shared comment on, is instead
    split back into its own single-member groups, so each is handled by
    the ordinary per-job duplicate-marker check in _post_single_comment,
    unchanged from before this grouping existed.

    Groups are returned in first-occurrence order (a plain dict preserves
    insertion order in Python 3.7+), which is what keeps per-job duplicate-
    marker checks working: a ticket appearing in more than one group still
    has those groups processed in the order its jobs originally came in,
    so a later group's existing-comments check sees an earlier group's
    freshly-posted comment on the same ticket (see
    test_second_job_in_the_same_run_sees_the_first_jobs_freshly_posted_comment).
    Different tickets' relative order doesn't matter, since each ticket's
    comments/checks are entirely independent of any other ticket's.
    """
    by_key: Dict[Tuple[object, object], List[TriagedJob]] = {}
    for i, (job, outcome, result) in enumerate(triaged):
        # A job with no ticket_key can't share a comment with anything -
        # keyed on its own index so it always ends up alone.
        key = (job.ticket_key, outcome.group_id) if job.ticket_key else ("__no_ticket__", i)
        by_key.setdefault(key, []).append((job, outcome, result))

    groups: List[List[TriagedJob]] = []
    for members in by_key.values():
        if len(_distinct_vulnerability_labels(members)) > 1:
            groups.append(members)
        else:
            groups.extend([member] for member in members)
    return groups


def _distinct_vulnerability_labels(members: List[TriagedJob]) -> List[str]:
    """The distinct vulnerability labels (result_hash for SAST, cve_id for
    SCA) among a group of jobs sharing one group_id, in first-occurrence
    order. Used to decide whether a group needs a combined comment (2+
    distinct labels) or is really just one label repeated (left to the
    ordinary per-job duplicate-marker check instead)."""
    labels: List[str] = []
    seen = set()
    for job, _, _ in members:
        label = job.cve_id if job.scanner_type == "sca" else job.result_hash
        if label and label not in seen:
            seen.add(label)
            labels.append(label)
    return labels


def _post_single_comment(
    job: TriageJob, outcome: TriageOutcome, result: object, jira_client: JiraCommentClient,
) -> None:
    """Post (or skip, if a duplicate) the one comment for a single job -
    the original per-job behavior, unchanged from before grouped comments
    existed."""
    if not job.ticket_key:
        return  # already logged by the caller

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
            return

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


def _post_grouped_comment(members: List[TriagedJob], jira_client: JiraCommentClient) -> None:
    """Post (or skip, if a duplicate) one shared comment for 2+ jobs whose
    outcomes share a group_id and have distinct vulnerability labels (see
    _group_for_comments) - mentioning every one of those labels instead of
    picking just one, since AI Triage produced one verdict that applies to
    all of them equally."""
    job0, _, result = members[0]
    ticket_key = job0.ticket_key
    vulnerability_label_name = "CVE ID" if job0.scanner_type == "sca" else "Vulnerability ID"
    labels = _distinct_vulnerability_labels(members)

    marker = build_vulnerability_marker_multi(vulnerability_label_name, labels)
    try:
        existing_bodies = jira_client.get_comment_bodies(ticket_key)
    except Exception as e:  # noqa: BLE001 - fail open, post as usual
        logger.debug(
            "%s: could not check existing comments (will post anyway): %s", ticket_key, e,
        )
        existing_bodies = []
    if any(marker in body for body in existing_bodies):
        reason = f"duplicate: {ticket_key} already has a comment with {marker!r}"
        for _, outcome, _ in members:
            outcome.comment_skipped_reason = reason
        logger.info("%s: skipping comment, already has one for %s", ticket_key, marker)
        return

    try:
        comment = format_comment(
            result,
            package_name_version=job0.jira_meta.get("package_name_version"),
            vulnerability_labels=labels,
            vulnerability_label_name=vulnerability_label_name,
            subtask_key=job0.jira_meta.get("subtask_key"),
        )
        jira_client.add_comment(ticket_key, comment)
        for _, outcome, _ in members:
            outcome.comment_posted = True
        logger.info(
            "%s: posted one shared comment for %d vulnerability labels sharing group_id %s: %s",
            ticket_key, len(labels), members[0][1].group_id, labels,
        )
    except Exception as e:  # noqa: BLE001 - best-effort, don't abort the batch
        for _, outcome, _ in members:
            outcome.comment_error = str(e)
        logger.error("%s: posting Jira comment failed: %s", ticket_key, e)
