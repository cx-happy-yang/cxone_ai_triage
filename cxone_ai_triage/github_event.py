"""Load the Jira issue payload out of a GitHub Actions event.

Two shapes of `client_payload` are supported:

1. `client_payload.jira_issue` — Prudential's original Jira Automation rule
   builds the full structured object itself (key, summary, scanId,
   VulnerabilityId1..5, subtasks, ...), one custom field at a time. See
   docs/jira-automation-setup.md.
2. `client_payload.issue_key` — just the ticket key (e.g. "JVL-20"), so the
   Automation rule has nothing to maintain even as fields change.
   `cxone_ai_triage` fetches the full ticket (and its subtasks) itself via
   the Jira REST API and shapes it the same way — see
   jira_client.JiraCommentClient.get_issue_for_triage / JiraFieldMapping.

GitHub writes the full event JSON to a file and points $GITHUB_EVENT_PATH at
it for every workflow run, so that's the default source for either shape.
"""
import json
import os
from pathlib import Path
from typing import Optional, Tuple


def _read_client_payload(event_path: Optional[str] = None) -> dict:
    path = event_path or os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        raise ValueError(
            "No event path given and $GITHUB_EVENT_PATH is not set. "
            "Pass --github-event <file> or run this inside a GitHub Actions job."
        )
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"GitHub event file not found: {path}")

    event = json.loads(p.read_text(encoding="utf-8"))
    return event.get("client_payload") or {}


def load_jira_issue(event_path: Optional[str] = None) -> dict:
    """Read client_payload.jira_issue from a GitHub Actions event JSON file.

    Args:
        event_path: Path to the event JSON. Defaults to $GITHUB_EVENT_PATH.

    Returns:
        dict with (at least) key, summary, project, url, description.
    """
    client_payload = _read_client_payload(event_path)
    jira_issue = client_payload.get("jira_issue")
    if not jira_issue:
        raise ValueError(
            f"{event_path or os.environ.get('GITHUB_EVENT_PATH')} has no "
            "client_payload.jira_issue (expected a repository_dispatch event "
            "carrying a Jira ticket)"
        )
    return jira_issue


def load_jira_issue_or_key(event_path: Optional[str] = None) -> Tuple[Optional[dict], Optional[str]]:
    """Read either client_payload.jira_issue or client_payload.issue_key.

    Returns a (jira_issue, issue_key) pair where exactly one is truthy:
    - (dict, None) if the event already carries the full structured ticket.
    - (None, str) if it only carries the ticket key, meaning the caller
      still needs to fetch the full ticket (see
      JiraCommentClient.get_issue_for_triage).

    Raises ValueError if the event has neither.
    """
    client_payload = _read_client_payload(event_path)
    jira_issue = client_payload.get("jira_issue")
    issue_key = client_payload.get("issue_key")
    if not jira_issue and not issue_key:
        raise ValueError(
            f"{event_path or os.environ.get('GITHUB_EVENT_PATH')} has neither "
            "client_payload.jira_issue nor client_payload.issue_key (expected "
            "a repository_dispatch event carrying a Jira ticket)"
        )
    return jira_issue, issue_key
