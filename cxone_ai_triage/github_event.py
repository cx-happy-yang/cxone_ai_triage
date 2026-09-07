"""Load the Jira issue key out of a GitHub Actions event.

Prudential's Jira Automation rule dispatches with just the ticket key (e.g.
"JVL-20"), nothing else — but which GitHub event carries it depends on
what the target org's policy allows (some orgs disable
`repository_dispatch` entirely; `workflow_dispatch` is the fallback):

  - `repository_dispatch`: the key is at `client_payload.issue_key`.
  - `workflow_dispatch`: the key is at `inputs.issue_key` (a declared
    workflow input - see the `on.workflow_dispatch.inputs` block in
    examples/prudential-cxone-ai-triage.yaml).

Both are checked, so the same binary works with either without a rebuild —
only the workflow file's `on:` trigger and the Jira Automation rule's
"Send Web Request" URL/body need to change to switch between them (see
docs/jira-automation-setup.md).

`cxone_ai_triage` fetches the full ticket (and its subtasks) itself via the
Jira REST API and shapes it into what jira_parser.py expects — see
jira_client.JiraCommentClient.get_issue_for_triage / JiraFieldMapping.

GitHub writes the full event JSON to a file and points $GITHUB_EVENT_PATH at
it for every workflow run, so that's the default source.
"""
import json
import os
from pathlib import Path
from typing import Optional


def load_issue_key(event_path: Optional[str] = None) -> str:
    """Read the Jira issue key out of a GitHub Actions event JSON file —
    either client_payload.issue_key (repository_dispatch) or
    inputs.issue_key (workflow_dispatch).

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
    issue_key = (
        (event.get("client_payload") or {}).get("issue_key")
        or (event.get("inputs") or {}).get("issue_key")
    )
    if not issue_key:
        raise ValueError(
            f"{path} has neither client_payload.issue_key (repository_dispatch) "
            "nor inputs.issue_key (workflow_dispatch) - expected an event "
            "carrying a Jira ticket key"
        )
    return issue_key
