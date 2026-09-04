"""CLI entry point.

Three ways to feed it Jira ticket data:

1. Production (default, zero extra args): reads the Jira ticket out of the
   GitHub Actions `repository_dispatch` event at $GITHUB_EVENT_PATH. Two
   shapes of client_payload are supported (see github_event.py):
     a. `client_payload.jira_issue` — the full structured ticket, built
        field-by-field by the Jira Automation rule.
     b. `client_payload.issue_key` — just the ticket key; this tool fetches
        the full ticket (and its subtasks) itself via the Jira REST API,
        using JiraFieldMapping (JIRA_FIELD_* env vars) to know which custom
        field is which. Lets the Automation rule skip maintaining a
        field-by-field mapping entirely.
   Either way, scan/result identifiers are then parsed out of the
   structured fields (falling back to the free-text description). See
   jira_parser.py.
2. Local testing: `--input <file>` reads a batch JSON/CSV of already
   structured rows (see samples/input.sample.json). Useful for testing
   against a known scan_id/result_hash without wiring up a real dispatch.

For each job it triggers AI Triage, then (unless --no-poll) polls for the
finished verdict, then (unless --no-comment) posts it as a comment on the
originating ticket/subtask — see pipeline.py.

Authentication is read from environment variables (see README.md):

CheckmarxPythonSDK, e.g. for an OAuth client (recommended for CI):
    CXONE_SERVER=https://ast.checkmarx.net
    CXONE_ACCESS_CONTROL_URL=https://iam.checkmarx.net
    CXONE_TENANT_NAME=<tenant>
    CXONE_GRANT_TYPE=client_credentials
    CXONE_CLIENT_ID=<oauth client id>
    CXONE_CLIENT_SECRET=<oauth client secret>

Jira comment posting (optional — omit to resolve/trigger/poll without
posting anything back to Jira):
    JIRA_SERVER=https://your-domain.atlassian.net
    JIRA_EMAIL=<service account email>
    JIRA_API_TOKEN=<API token>
"""
import argparse
import logging
import sys

from .github_event import load_jira_issue_or_key
from .io_utils import load_jobs, write_outcomes
from .jira_client import JiraFieldMapping, build_jira_client_from_env
from .jira_parser import parse_jira_issue
from .pipeline import run_pipeline
from .resolver import DEFAULT_POLL_INTERVAL_SECONDS, DEFAULT_POLL_TIMEOUT_SECONDS, TriageResolver


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cxone-ai-triage",
        description=(
            "Resolve Jira-ticket-derived scan/result identifiers into "
            "Checkmarx One AI Triage requests, trigger them, poll for the "
            "result, and post it back as a Jira comment."
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "-i", "--input",
        help="Path to a batch input file (.json or .csv) of already-structured "
             "rows, for local testing. See samples/input.sample.json.",
    )
    source.add_argument(
        "-e", "--github-event",
        help="Path to a GitHub Actions event JSON containing "
             "client_payload.jira_issue (the full ticket) or "
             "client_payload.issue_key (just the key - this tool fetches "
             "the ticket itself via the Jira REST API; requires "
             "JIRA_SERVER/JIRA_EMAIL/JIRA_API_TOKEN and, usually, "
             "JIRA_FIELD_* to be set). Defaults to $GITHUB_EVENT_PATH when "
             "neither this nor --input is given.",
    )
    parser.add_argument(
        "-o", "--output", default="triage_results.json",
        help="Path to write results to (.json or .csv). Default: triage_results.json",
    )
    parser.add_argument(
        "--no-poll", action="store_true",
        help="Trigger AI Triage but don't poll for the finished result "
             "(implies --no-comment, since there's nothing to comment yet).",
    )
    parser.add_argument(
        "--no-comment", action="store_true",
        help="Poll for the result but don't post it as a Jira comment.",
    )
    parser.add_argument(
        "--poll-timeout", type=int, default=DEFAULT_POLL_TIMEOUT_SECONDS,
        help=f"Max seconds to wait per job for AI Triage to finish. Default: {DEFAULT_POLL_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL_SECONDS,
        help=f"Seconds between poll attempts. Default: {DEFAULT_POLL_INTERVAL_SECONDS}.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging.",
    )
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("cxone_ai_triage")

    jira_client = None
    try:
        if args.input:
            jobs = load_jobs(args.input)
        else:
            jira_issue, issue_key = load_jira_issue_or_key(args.github_event)
            if jira_issue is None:
                # client_payload only had an issue_key - fetch the full
                # ticket ourselves instead of Jira Automation building it
                # field-by-field. Needs Jira creds regardless of --no-comment,
                # since without them there's no ticket data to parse at all.
                jira_client = build_jira_client_from_env()
                if jira_client is None:
                    raise ValueError(
                        f"client_payload.issue_key={issue_key!r} was given instead of "
                        "client_payload.jira_issue, but JIRA_SERVER/JIRA_EMAIL/"
                        "JIRA_API_TOKEN aren't fully set - can't fetch the ticket"
                    )
                logger.info("Fetching Jira ticket %s (issue_key payload)", issue_key)
                jira_issue = jira_client.get_issue_for_triage(issue_key, JiraFieldMapping.from_env())
            logger.info("Parsing Jira ticket %s", jira_issue.get("key"))
            jobs = parse_jira_issue(jira_issue)
    except (FileNotFoundError, ValueError) as e:
        logger.error("Could not load input: %s", e)
        return 2

    if not jobs:
        logger.error("No triage jobs to run")
        return 2

    logger.info("Resolved %d triage job(s)", len(jobs))

    resolver = TriageResolver()
    # Reuse the client built above to fetch the ticket, if any, rather than
    # opening a second Jira connection just to post comments with.
    if jira_client is None and not args.no_comment:
        jira_client = build_jira_client_from_env()
    outcomes = run_pipeline(
        jobs,
        resolver,
        jira_client,
        poll=not args.no_poll,
        poll_timeout=args.poll_timeout,
        poll_interval=args.poll_interval,
        post_comment=not args.no_comment,
    )

    write_outcomes(args.output, outcomes)
    logger.info("Wrote results to %s", args.output)

    failed = [o for o in outcomes if o.status == "failed"]
    for o in outcomes:
        label = o.job.ticket_key or o.job.scan_id
        if o.status == "failed":
            logger.error("%s: FAILED - %s", label, o.error)
        else:
            logger.info(
                "%s: %s (triageID=%s, aiTriageStatus=%s, reachability=%s, "
                "exploitability=%s, commentPosted=%s)",
                label, o.status, o.triage_id, o.ai_triage_status,
                o.reachability_status, o.exploitability_status, o.comment_posted,
            )
            if o.trigger_skipped_reason:
                logger.info("%s: trigger skipped - %s", label, o.trigger_skipped_reason)
            if o.poll_error:
                logger.warning("%s: poll error - %s", label, o.poll_error)
            if o.comment_error:
                logger.warning("%s: comment error - %s", label, o.comment_error)

    if failed:
        logger.error("%d of %d job(s) failed", len(failed), len(outcomes))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
