import unittest

from cxone_ai_triage.models import TriageJob, TriageOutcome


class TestTriageOutcomeToRow(unittest.TestCase):
    def test_jira_meta_is_flattened_with_jira_prefix(self):
        job = TriageJob(
            scan_id="s1", scanner_type="sast", ticket_key="T-1", result_hash="hash-1",
            jira_meta={"status": "To Do", "priority": "Highest", "labels": ["a", "b"]},
        )
        outcome = TriageOutcome(job=job, status="accepted")
        row = outcome.to_row()
        self.assertEqual(row["jira_status"], "To Do")
        self.assertEqual(row["jira_priority"], "Highest")
        self.assertEqual(row["jira_labels"], ["a", "b"])
        self.assertEqual(row["scan_id"], "s1")

    def test_no_jira_meta_means_no_jira_columns(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="T-1", result_hash="hash-1")
        row = TriageOutcome(job=job).to_row()
        self.assertFalse(any(k.startswith("jira_") for k in row))


if __name__ == "__main__":
    unittest.main()
