"""Exercises cli.main()'s issue_key payload path end to end, with
TriageResolver/run_pipeline/Jira all faked out.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cxone_ai_triage import cli
from cxone_ai_triage.models import TriageJob, TriageOutcome

SAST_JIRA_ISSUE = {
    "key": "JVL-2",
    "description": (
        r"*Checkmarx \(SAST\):* SQL_Injection" "\n"
        r"*Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|"
        "https://sng.ast.checkmarx.net/x/scans?id=d01d7561-2bf5-48b2-bbaa-da166c671fc3&branch=master]"
    ),
    "VulnerabilityId1": "hash-xyz",
}


class TestCliIssueKeyPayload(unittest.TestCase):
    def _run(self, argv, issue_key, jira_client=None):
        with tempfile.TemporaryDirectory() as tmp:
            output_path = str(Path(tmp) / "out.json")
            with patch.object(cli, "load_issue_key", return_value=issue_key), \
                 patch.object(cli, "build_jira_client_from_env", return_value=jira_client), \
                 patch.object(cli, "TriageResolver") as MockResolver, \
                 patch.object(cli, "run_pipeline") as mock_run_pipeline:
                mock_run_pipeline.return_value = [
                    TriageOutcome(job=TriageJob(scan_id="s1", scanner_type="sast", result_hash="hash-xyz"), status="accepted")
                ]
                rc = cli.main(argv + ["-o", output_path])
        return rc, mock_run_pipeline

    def test_issue_key_payload_fetches_via_jira_client_then_parses(self):
        fake_jira_client = MagicMock()
        fake_jira_client.get_issue_for_triage.return_value = SAST_JIRA_ISSUE

        rc, mock_run_pipeline = self._run(
            ["-e", "irrelevant.json"], "JVL-2", jira_client=fake_jira_client,
        )

        self.assertEqual(rc, 0)
        fake_jira_client.get_issue_for_triage.assert_called_once()
        (issue_key_arg, _mapping_arg), _ = fake_jira_client.get_issue_for_triage.call_args
        self.assertEqual(issue_key_arg, "JVL-2")
        jobs_passed = mock_run_pipeline.call_args[0][0]
        self.assertEqual(len(jobs_passed), 1)
        self.assertEqual(jobs_passed[0].result_hash, "hash-xyz")
        # The client used to fetch the ticket is reused for posting comments
        # too, instead of opening a second Jira connection.
        self.assertIs(mock_run_pipeline.call_args[0][2], fake_jira_client)

    def test_issue_key_payload_without_jira_creds_fails_cleanly(self):
        rc, mock_run_pipeline = self._run(
            ["-e", "irrelevant.json"], "JVL-2", jira_client=None,
        )
        self.assertEqual(rc, 2)
        mock_run_pipeline.assert_not_called()

    def test_no_comment_still_needs_jira_client_to_fetch_the_ticket(self):
        # --no-comment only suppresses posting - fetching the ticket in the
        # first place still needs Jira creds, since there's nothing else to
        # parse it from.
        rc, mock_run_pipeline = self._run(
            ["-e", "irrelevant.json", "--no-comment"], "JVL-2", jira_client=None,
        )
        self.assertEqual(rc, 2)
        mock_run_pipeline.assert_not_called()


if __name__ == "__main__":
    unittest.main()
