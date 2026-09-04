"""Exercises JiraCommentClient.get_issue_for_triage / JiraFieldMapping
against a faked `jira.JIRA`, without hitting a real Jira site. See
jira_client.py's docstring for why this exists: an alternative to Jira
Automation building client_payload.jira_issue field-by-field.
"""
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cxone_ai_triage.jira_client import JiraCommentClient, JiraFieldMapping
from cxone_ai_triage.jira_parser import parse_jira_issue

SAST_DESCRIPTION = (
    r"*Checkmarx \(SAST\):* SQL_Injection" "\n"
    r"*Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|"
    "https://sng.ast.checkmarx.net/projects/x/scans?id=d01d7561-2bf5-48b2-bbaa-da166c671fc3&branch=master]"
)


def _person(email):
    return SimpleNamespace(emailAddress=email) if email else None


def _named(name):
    return SimpleNamespace(name=name) if name else None


def _make_client(issue_obj, subtask_objs=()):
    # Bypasses JiraCommentClient.__init__ (which opens a real JIRA()
    # connection) - same pattern TriageResolver's tests use for the SDK.
    client = JiraCommentClient.__new__(JiraCommentClient)
    client._server = "https://example.atlassian.net"
    client._client = SimpleNamespace(
        issue=lambda key: issue_obj,
        search_issues=lambda jql, fields=None: list(subtask_objs),
    )
    return client


class TestJiraFieldMapping(unittest.TestCase):
    def test_from_env_reads_configured_fields_leaves_others_none(self):
        env = {
            "JIRA_FIELD_SCAN_ID": "customfield_10207",
            "JIRA_FIELD_VULNERABILITY_ID_1": "customfield_10208",
            "JIRA_FIELD_VULNERABILITY_ID_3": "customfield_10210",
            "JIRA_FIELD_PACKAGE_NAME_VERSION": "customfield_10209",
        }
        with patch.dict(os.environ, env, clear=False):
            mapping = JiraFieldMapping.from_env()
        self.assertEqual(mapping.scan_id, "customfield_10207")
        self.assertEqual(
            mapping.vulnerability_ids,
            ("customfield_10208", None, "customfield_10210", None, None),
        )
        self.assertEqual(mapping.package_name_version, "customfield_10209")

    def test_from_env_defaults_to_all_none_when_unset(self):
        env_without_fields = {
            k: v for k, v in os.environ.items()
            if not k.startswith("JIRA_FIELD_")
        }
        with patch.dict(os.environ, env_without_fields, clear=True):
            mapping = JiraFieldMapping.from_env()
        self.assertIsNone(mapping.scan_id)
        self.assertEqual(mapping.vulnerability_ids, (None,) * 5)
        self.assertIsNone(mapping.package_name_version)


class TestGetIssueForTriage(unittest.TestCase):
    def test_maps_standard_and_configured_custom_fields(self):
        fields = SimpleNamespace(
            summary="Sample summary",
            description="some description",
            status=_named("To Do"),
            priority=_named("High"),
            issuetype=_named("Bug"),
            project=SimpleNamespace(key="JVL"),
            reporter=_person("reporter@example.com"),
            assignee=_person("assignee@example.com"),
            labels=["checkmarx", "sast"],
            created="2026-09-01T00:00:00.000+0000",
            updated="2026-09-02T00:00:00.000+0000",
            customfield_10207="d01d7561-2bf5-48b2-bbaa-da166c671fc3",
            customfield_10208="hash-xyz",
            customfield_10209="log4j-core 2.14.1",
        )
        issue = SimpleNamespace(key="JVL-20", fields=fields)
        client = _make_client(issue)
        mapping = JiraFieldMapping(
            scan_id="customfield_10207",
            vulnerability_ids=("customfield_10208", None, None, None, None),
            package_name_version="customfield_10209",
        )

        result = client.get_issue_for_triage("JVL-20", mapping)

        self.assertEqual(result["key"], "JVL-20")
        self.assertEqual(result["summary"], "Sample summary")
        self.assertEqual(result["status"], "To Do")
        self.assertEqual(result["priority"], "High")
        self.assertEqual(result["issue_type"], "Bug")
        self.assertEqual(result["project"], "JVL")
        self.assertEqual(result["reporter"], "reporter@example.com")
        self.assertEqual(result["assignee"], "assignee@example.com")
        self.assertEqual(result["labels"], ["checkmarx", "sast"])
        self.assertEqual(result["url"], "https://example.atlassian.net/browse/JVL-20")
        self.assertEqual(result["scanId"], "d01d7561-2bf5-48b2-bbaa-da166c671fc3")
        self.assertEqual(result["VulnerabilityId1"], "hash-xyz")
        self.assertEqual(result["packageNameVersion"], "log4j-core 2.14.1")
        self.assertEqual(result["subtasks"], [])

    def test_unmapped_fields_are_left_out_entirely(self):
        fields = SimpleNamespace(
            summary="Parent", description="", status=None, priority=None,
            issuetype=None, project=None, reporter=None, assignee=None,
            labels=None, created="c", updated="u",
        )
        issue = SimpleNamespace(key="JVL-2", fields=fields)
        client = _make_client(issue)

        result = client.get_issue_for_triage("JVL-2", JiraFieldMapping())

        self.assertNotIn("scanId", result)
        self.assertNotIn("VulnerabilityId1", result)
        self.assertNotIn("VulnerabilityId5", result)
        self.assertNotIn("packageNameVersion", result)
        # Fields with no value on the ticket still come through as None,
        # not KeyError/AttributeError.
        self.assertIsNone(result["status"])
        self.assertIsNone(result["assignee"])

    def test_fetches_subtasks_via_jql_with_the_fuller_shape(self):
        # A parent's own fields.subtasks (from GET /rest/api/2/issue) has no
        # assignee/created - get_issue_for_triage uses a JQL search instead,
        # which does.
        fields = SimpleNamespace(
            summary="Parent", description="", status=None, priority=None,
            issuetype=None, project=None, reporter=None, assignee=None,
            labels=None, created="c", updated="u",
        )
        issue = SimpleNamespace(key="JVL-20", fields=fields)
        subtask = SimpleNamespace(
            key="JVL-26",
            fields=SimpleNamespace(
                summary="SCA | CVE-2015-4852",
                status=_named("To Do"),
                assignee=_person("dev@example.com"),
                created="2026-08-20T00:00:00.000+0000",
            ),
        )
        client = _make_client(issue, subtask_objs=[subtask])

        result = client.get_issue_for_triage("JVL-20", JiraFieldMapping())

        self.assertEqual(result["subtasks"], [{
            "key": "JVL-26",
            "summary": "SCA | CVE-2015-4852",
            "status": "To Do",
            "assignee": "dev@example.com",
            "created": "2026-08-20T00:00:00.000+0000",
            "url": "https://example.atlassian.net/browse/JVL-26",
        }])

    def test_logs_the_fetched_ticket_and_every_subtask(self):
        # With client_payload only ever carrying issue_key, the old
        # workflow-side diagnostic logging of the ticket's fields and every
        # subtask (see git history of examples/prudential-cxone-ai-triage.yaml)
        # has nowhere else to happen - get_issue_for_triage does it instead,
        # so it's visible regardless of which workflow calls this.
        fields = SimpleNamespace(
            summary="Parent", description="", status=None, priority=None,
            issuetype=None, project=None, reporter=None, assignee=None,
            labels=None, created="c", updated="u",
            customfield_10207="scan-1",
        )
        issue = SimpleNamespace(key="JVL-20", fields=fields)
        subtask = SimpleNamespace(
            key="JVL-26",
            fields=SimpleNamespace(
                summary="SCA | CVE-2015-4852", status=_named("To Do"),
                assignee=_person("dev@example.com"), created="2026-08-20T00:00:00.000+0000",
            ),
        )
        client = _make_client(issue, subtask_objs=[subtask])
        mapping = JiraFieldMapping(scan_id="customfield_10207")

        with self.assertLogs("cxone_ai_triage", level="INFO") as cm:
            client.get_issue_for_triage("JVL-20", mapping)

        joined = "\n".join(cm.output)
        self.assertIn("scanId=scan-1", joined)
        self.assertIn("fetched 1 subtask(s)", joined)
        self.assertIn("key=JVL-26", joined)
        self.assertIn("summary=SCA | CVE-2015-4852", joined)
        self.assertIn("assignee=dev@example.com", joined)

    def test_subtask_with_no_assignee_does_not_raise(self):
        fields = SimpleNamespace(
            summary="Parent", description="", status=None, priority=None,
            issuetype=None, project=None, reporter=None, assignee=None,
            labels=None, created="c", updated="u",
        )
        issue = SimpleNamespace(key="JVL-20", fields=fields)
        subtask = SimpleNamespace(
            key="JVL-27",
            fields=SimpleNamespace(
                summary="SCA | CVE-2015-6420", status=_named("To Do"),
                assignee=None, created="2026-08-20T00:00:00.000+0000",
            ),
        )
        client = _make_client(issue, subtask_objs=[subtask])

        result = client.get_issue_for_triage("JVL-20", JiraFieldMapping())

        self.assertIsNone(result["subtasks"][0]["assignee"])

    def test_round_trips_into_parse_jira_issue_for_a_sast_ticket(self):
        # End-to-end: the dict shape get_issue_for_triage builds is exactly
        # what jira_parser.parse_jira_issue already knows how to read.
        fields = SimpleNamespace(
            summary="SQL_Injection @ forum.jsp",
            description=SAST_DESCRIPTION,
            status=_named("To Do"), priority=_named("Highest"),
            issuetype=_named("Bug"), project=SimpleNamespace(key="JVL"),
            reporter=_person("security-bot@example.com"),
            assignee=_person("dev-owner@example.com"),
            labels=["checkmarx", "sast"],
            created="2026-08-20T09:15:00.000-0000", updated="2026-08-20T09:15:00.000-0000",
            customfield_10208="XZBiE9xWT5WiRxxnpMKmKfZUJuA=",
        )
        issue = SimpleNamespace(key="JVL-2", fields=fields)
        client = _make_client(issue)
        mapping = JiraFieldMapping(vulnerability_ids=("customfield_10208", None, None, None, None))

        jira_issue = client.get_issue_for_triage("JVL-2", mapping)
        jobs = parse_jira_issue(jira_issue)

        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].scanner_type, "sast")
        self.assertEqual(jobs[0].result_hash, "XZBiE9xWT5WiRxxnpMKmKfZUJuA=")
        self.assertEqual(jobs[0].ticket_key, "JVL-2")


if __name__ == "__main__":
    unittest.main()
