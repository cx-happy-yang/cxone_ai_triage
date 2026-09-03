"""Posts AI Triage results as comments on the originating Jira ticket/subtask.

Uses the `jira` PyPI package (https://pypi.org/project/jira/) with its
default rest_api_version ("2"). Jira Cloud still serves /rest/api/2/, which
(unlike /rest/api/3/) accepts a plain wiki-markup string as the comment body
instead of requiring an Atlassian Document Format object — verified by
reading jira.client.JIRA.add_comment, which passes `body` straight through
as {"body": body} with no ADF conversion.
"""
import logging
import os
from typing import List, Optional

from jira import JIRA

logger = logging.getLogger("cxone_ai_triage")


class JiraCommentClient:
    """Thin wrapper around the `jira` package, scoped to what this tool
    needs: reading and posting comments on an issue (a ticket or a subtask
    key both work identically)."""

    def __init__(self, server: str, email: str, api_token: str):
        self._client = JIRA(server=server, basic_auth=(email, api_token))

    def add_comment(self, issue_key: str, body: str) -> None:
        self._client.add_comment(issue_key, body)
        logger.info("Posted AI Triage comment to %s", issue_key)

    def get_comment_bodies(self, issue_key: str) -> List[str]:
        """Every existing comment's body text on this issue, for checking
        before posting a new one (see pipeline.py's duplicate check)."""
        return [c.body for c in self._client.comments(issue_key) if getattr(c, "body", None)]


def build_jira_client_from_env() -> Optional[JiraCommentClient]:
    """Build a JiraCommentClient from JIRA_SERVER / JIRA_EMAIL / JIRA_API_TOKEN.

    Returns None (after logging why) if any are missing, so the rest of the
    pipeline (resolving identifiers, triggering AI Triage, polling for the
    result) still runs without posting anything back to Jira.
    """
    server = os.environ.get("JIRA_SERVER")
    email = os.environ.get("JIRA_EMAIL")
    api_token = os.environ.get("JIRA_API_TOKEN")
    if not (server and email and api_token):
        logger.info(
            "JIRA_SERVER/JIRA_EMAIL/JIRA_API_TOKEN not fully set; AI Triage "
            "results will be resolved but not posted as Jira comments."
        )
        return None
    return JiraCommentClient(server=server, email=email, api_token=api_token)
