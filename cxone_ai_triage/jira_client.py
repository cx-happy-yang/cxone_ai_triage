"""Reads Jira tickets and posts AI Triage results back as comments.

Uses the `jira` PyPI package (https://pypi.org/project/jira/) with its
default rest_api_version ("2"). Jira Cloud still serves /rest/api/2/, which
(unlike /rest/api/3/) accepts a plain wiki-markup string as the comment body
instead of requiring an Atlassian Document Format object — verified by
reading jira.client.JIRA.add_comment, which passes `body` straight through
as {"body": body} with no ADF conversion.
"""
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from jira import JIRA

logger = logging.getLogger("cxone_ai_triage")


def _person_email(person) -> Optional[str]:
    return getattr(person, "emailAddress", None) if person else None


def _field_name(field_obj) -> Optional[str]:
    return getattr(field_obj, "name", None) if field_obj else None


@dataclass
class JiraFieldMapping:
    """Which Jira custom field ID holds which piece of structured data this
    tool needs. The Jira Automation rule only ever sends
    client_payload.issue_key; JiraCommentClient.get_issue_for_triage fetches
    the ticket itself and needs this mapping to know which custom field is
    which, so the Automation rule never has to maintain a field-by-field
    mapping of its own.

    Custom field IDs are not portable across Jira sites — see
    docs/jira-automation-setup.md for how to look them up. Any field left
    unset here is simply left out of the fetched jira_issue dict; jira_parser
    already tolerates a missing scanId/VulnerabilityId/packageNameVersion
    (falling back to the description regex, or — for packageNameVersion —
    just omitting it from the comment).
    """

    scan_id: Optional[str] = None
    vulnerability_ids: Tuple[Optional[str], ...] = field(default_factory=lambda: (None,) * 5)
    package_name_version: Optional[str] = None

    @classmethod
    def from_env(cls) -> "JiraFieldMapping":
        """JIRA_FIELD_SCAN_ID, JIRA_FIELD_VULNERABILITY_ID_1..5,
        JIRA_FIELD_PACKAGE_NAME_VERSION - e.g. JIRA_FIELD_SCAN_ID=customfield_10207."""
        return cls(
            scan_id=os.environ.get("JIRA_FIELD_SCAN_ID"),
            vulnerability_ids=tuple(
                os.environ.get(f"JIRA_FIELD_VULNERABILITY_ID_{i}") for i in range(1, 6)
            ),
            package_name_version=os.environ.get("JIRA_FIELD_PACKAGE_NAME_VERSION"),
        )


class JiraCommentClient:
    """Thin wrapper around the `jira` package, scoped to what this tool
    needs: reading a ticket (and its subtasks) and its comments, and
    posting a new comment (a ticket or a subtask key both work identically
    for comments)."""

    def __init__(self, server: str, email: str, api_token: str):
        self._server = server.rstrip("/")
        self._client = JIRA(server=server, basic_auth=(email, api_token))

    def add_comment(self, issue_key: str, body: str) -> None:
        self._client.add_comment(issue_key, body)
        logger.info("Posted AI Triage comment to %s", issue_key)

    def get_comment_bodies(self, issue_key: str) -> List[str]:
        """Every existing comment's body text on this issue, for checking
        before posting a new one (see pipeline.py's duplicate check)."""
        return [c.body for c in self._client.comments(issue_key) if getattr(c, "body", None)]

    def get_issue_for_triage(self, issue_key: str, field_mapping: JiraFieldMapping) -> dict:
        """Fetch one ticket and its subtasks via the Jira REST API, shaped
        into the dict jira_parser.parse_jira_issue expects - this is how
        every ticket gets turned into that shape, since the Jira Automation
        rule only ever dispatches client_payload.issue_key (see
        docs/jira-automation-setup.md).
        """
        issue = self._client.issue(issue_key)
        fields = issue.fields

        jira_issue = {
            "key": issue.key,
            "summary": fields.summary,
            "description": fields.description or "",
            "status": _field_name(fields.status),
            "priority": _field_name(fields.priority),
            "issue_type": _field_name(fields.issuetype),
            "project": getattr(fields.project, "key", None) if fields.project else None,
            "reporter": _person_email(fields.reporter),
            "assignee": _person_email(fields.assignee),
            "labels": list(fields.labels or []),
            "url": f"{self._server}/browse/{issue.key}",
            "created": fields.created,
            "updated": fields.updated,
            "subtasks": self._get_subtasks(issue.key),
        }

        if field_mapping.scan_id:
            jira_issue["scanId"] = getattr(fields, field_mapping.scan_id, None)
        for i, field_id in enumerate(field_mapping.vulnerability_ids, start=1):
            if field_id:
                jira_issue[f"VulnerabilityId{i}"] = getattr(fields, field_id, None)
        if field_mapping.package_name_version:
            jira_issue["packageNameVersion"] = getattr(fields, field_mapping.package_name_version, None)

        # Equivalent to the diagnostic logging the old jira_issue-payload
        # workflow used to do on the GitHub Actions side (see git history
        # of examples/prudential-cxone-ai-triage.yaml) - now done here
        # instead, so it shows up regardless of which workflow calls this.
        logger.info(
            "%s: summary=%r scanId=%s VulnerabilityId1-5=%s packageNameVersion=%s",
            issue.key, jira_issue.get("summary"), jira_issue.get("scanId"),
            [jira_issue.get(f"VulnerabilityId{i}") for i in range(1, 6)],
            jira_issue.get("packageNameVersion"),
        )
        logger.info("%s: fetched %d subtask(s)", issue.key, len(jira_issue["subtasks"]))
        for sub in jira_issue["subtasks"]:
            logger.info(
                "Subtask >> key=%s | summary=%s | status=%s | assignee=%s",
                sub["key"], sub["summary"], sub["status"], sub["assignee"],
            )

        return jira_issue

    def _get_subtasks(self, parent_key: str) -> List[dict]:
        # A parent's own `fields.subtasks` (from GET /rest/api/2/issue) only
        # carries a condensed shape (summary/status/issuetype, no assignee
        # or created) - a JQL search gets the fuller shape jira_parser
        # expects in one extra round-trip instead of one per subtask.
        issues = self._client.search_issues(
            f'parent = "{parent_key}"', fields="summary,status,assignee,created"
        )
        return [
            {
                "key": sub.key,
                "summary": sub.fields.summary,
                "status": _field_name(sub.fields.status),
                "assignee": _person_email(sub.fields.assignee),
                "created": sub.fields.created,
                "url": f"{self._server}/browse/{sub.key}",
            }
            for sub in issues
        ]


def build_jira_client_from_env() -> Optional[JiraCommentClient]:
    """Build a JiraCommentClient from JIRA_SERVER / JIRA_EMAIL / JIRA_API_TOKEN.

    Returns None (after logging why) if any are missing. In --input mode
    (cli.py), that just means the rest of the pipeline (resolving
    identifiers, triggering AI Triage, polling for the result) runs without
    posting anything back to Jira. In the default --github-event mode, the
    caller treats None as fatal instead, since without these there's no way
    to fetch the ticket client_payload.issue_key points at in the first
    place.
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
