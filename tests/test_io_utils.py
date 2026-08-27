import csv
import tempfile
import unittest
from pathlib import Path

from cxone_ai_triage.io_utils import write_outcomes
from cxone_ai_triage.models import TriageJob, TriageOutcome


class TestWriteOutcomes(unittest.TestCase):
    def test_csv_output_handles_jira_meta_columns_and_list_values(self):
        job = TriageJob(
            scan_id="s1", scanner_type="sast", ticket_key="T-1", result_hash="hash-1",
            jira_meta={"status": "To Do", "labels": ["checkmarx", "sast"]},
        )
        outcome = TriageOutcome(job=job, status="accepted", triage_id="tri-1")

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "out.csv"
            write_outcomes(str(out_path), [outcome])
            with out_path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_id"], "s1")
        self.assertEqual(rows[0]["jira_status"], "To Do")
        self.assertEqual(rows[0]["jira_labels"], '["checkmarx", "sast"]')

    def test_json_output_round_trips(self):
        job = TriageJob(scan_id="s1", scanner_type="sca", ticket_key="T-2", cve_id="CVE-2021-44228")
        outcome = TriageOutcome(job=job, status="failed", error="boom")

        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "out.json"
            write_outcomes(str(out_path), [outcome])
            import json
            rows = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(rows[0]["status"], "failed")
        self.assertEqual(rows[0]["error"], "boom")
        self.assertEqual(rows[0]["cve_id"], "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
