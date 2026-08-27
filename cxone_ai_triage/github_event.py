"""Load the Jira issue payload out of a GitHub Actions event.

Prudential's workflow dispatches on `repository_dispatch` with a
`client_payload.jira_issue` object (key, summary, project, url, description).
GitHub writes the full event JSON to a file and points $GITHUB_EVENT_PATH at
it for every workflow run, so that's the default source.
"""
import json
import os
from pathlib import Path
from typing import Optional


def load_jira_issue(event_path: Optional[str] = None) -> dict:
    """Read client_payload.jira_issue from a GitHub Actions event JSON file.

    Args:
        event_path: Path to the event JSON. Defaults to $GITHUB_EVENT_PATH.

    Returns:
        dict with (at least) key, summary, project, url, description.
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
    jira_issue = (event.get("client_payload") or {}).get("jira_issue")
    if not jira_issue:
        raise ValueError(
            f"{path} has no client_payload.jira_issue "
            "(expected a repository_dispatch event carrying a Jira ticket)"
        )
    return jira_issue
