"""Load the Jira issue key out of a GitHub Actions event.

Prudential's workflow dispatches on `repository_dispatch` with
`client_payload.issue_key` — just the ticket key (e.g. "JVL-20"), nothing
else. `cxone_ai_triage` fetches the full ticket (and its subtasks) itself
via the Jira REST API and shapes it into what jira_parser.py expects — see
jira_client.JiraCommentClient.get_issue_for_triage / JiraFieldMapping and
docs/jira-automation-setup.md.

GitHub writes the full event JSON to a file and points $GITHUB_EVENT_PATH at
it for every workflow run, so that's the default source.
"""
import json
import os
from pathlib import Path
from typing import Optional


def load_issue_key(event_path: Optional[str] = None) -> str:
    """Read client_payload.issue_key from a GitHub Actions event JSON file.

    Args:
        event_path: Path to the event JSON. Defaults to $GITHUB_EVENT_PATH.

    Returns:
        The Jira ticket key, e.g. "JVL-20".
    """
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
    issue_key = (event.get("client_payload") or {}).get("issue_key")
    if not issue_key:
        raise ValueError(
            f"{path} has no client_payload.issue_key "
            "(expected a repository_dispatch event carrying a Jira ticket key)"
        )
    return issue_key
