import json
import tempfile
import unittest
from pathlib import Path

from cxone_ai_triage.github_event import load_jira_issue, load_jira_issue_or_key
from cxone_ai_triage.jira_parser import parse_jira_issue

SAST_DESCRIPTION = (
    r"*Checkmarx \(SAST\):* SQL_Injection" "\n"
    r"*Security Issue:*  [Read More |https://sng.ast.checkmarx.net/results/"
    r"1b49ad6f-057f-400c-aa32-f6bc31caf242/d01d7561-2bf5-48b2-bbaa-da166c671fc3"
    r"/sast/description/89/2621223299958738513] about SQL_Injection" "\n"
    r"*Checkmarx Project:* [JavaVulnerableLab|https://sng.ast.checkmarx.net/"
    r"projects/1b49ad6f-057f-400c-aa32-f6bc31caf242/overview?branch=master]" "\n"
    r"*Branch:* master" "\n"
    r"*Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|https://sng.ast."
    r"checkmarx.net/projects/1b49ad6f-057f-400c-aa32-f6bc31caf242/scans?"
    r"id=d01d7561-2bf5-48b2-bbaa-da166c671fc3&branch=master]" "\n\n----\n"
    r"*Result 1:*" "\n*Severity:* CRITICAL" "\n*State:* CONFIRMED" "\n"
    r"*Status:* RECURRENT" "\n"
    r"Review result in Checkmarx One: [SQL\_Injection|https://sng.ast."
    r"checkmarx.net/results/d01d7561-2bf5-48b2-bbaa-da166c671fc3/"
    r"1b49ad6f-057f-400c-aa32-f6bc31caf242/sast?"
    r"result-id=XZBiE9xWT5WiRxxnpMKmKfZUJuA%3D]" "\n."
)


class TestParseJiraIssue(unittest.TestCase):
    def test_real_sast_ticket(self):
        jobs = parse_jira_issue({"key": "JVL-2", "description": SAST_DESCRIPTION})
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.ticket_key, "JVL-2")
        self.assertEqual(job.scanner_type, "sast")
        self.assertEqual(job.scan_id, "d01d7561-2bf5-48b2-bbaa-da166c671fc3")
        self.assertEqual(job.result_hash, "XZBiE9xWT5WiRxxnpMKmKfZUJuA=")
        self.assertIsNone(job.cve_id)

    def test_sca_ticket_without_subtasks_falls_back_to_description_cve(self):
        description = (
            r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependency" "\n"
            r"*Scan ID:* [x|https://x/scans?id=22222222-2222-2222-2222-222222222222&branch=main]" "\n"
            "Package log4j-core is affected by CVE-2021-44228."
        )
        jobs = parse_jira_issue(
            {"key": "PRUD-9", "description": description, "packageNameVersion": "log4j-core 2.14.1"}
        )
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.jira_meta["package_name_version"], "log4j-core 2.14.1")
        self.assertEqual(job.scanner_type, "sca")
        self.assertEqual(job.scan_id, "22222222-2222-2222-2222-222222222222")
        self.assertEqual(job.cve_id, "CVE-2021-44228")

    def test_sca_ticket_with_subtasks_yields_one_job_per_cve(self):
        description = (
            r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependencies" "\n"
            r"*Scan ID:* [x|https://x/scans?id=22222222-2222-2222-2222-222222222222&branch=main]"
        )
        jobs = parse_jira_issue(
            {
                "key": "JVL-10",
                "description": description,
                "subtasks": [
                    {"key": "JVL-11", "fields": {"summary": "CVE-2021-44228 - log4j-core-2.14.1"}},
                    {"key": "JVL-12", "fields": {"summary": "CVE-2022-23305 - log4j-core-2.14.1"}},
                ],
            }
        )
        self.assertEqual(len(jobs), 2)
        # ticket_key (where the Jira comment is posted) is always the parent,
        # never the subtask; the subtask key is kept in jira_meta instead.
        self.assertEqual({j.ticket_key for j in jobs}, {"JVL-10"})
        self.assertEqual({j.jira_meta["subtask_key"] for j in jobs}, {"JVL-11", "JVL-12"})
        self.assertEqual({j.cve_id for j in jobs}, {"CVE-2021-44228", "CVE-2022-23305"})
        for j in jobs:
            self.assertEqual(j.scan_id, "22222222-2222-2222-2222-222222222222")

    def test_sca_subtask_without_cve_is_skipped_not_fatal(self):
        description = (
            r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependencies" "\n"
            r"*Scan ID:* [x|https://x/scans?id=22222222-2222-2222-2222-222222222222&branch=main]"
        )
        jobs = parse_jira_issue(
            {
                "key": "JVL-10",
                "description": description,
                "subtasks": [
                    {"key": "JVL-11", "fields": {"summary": "CVE-2021-44228 - log4j-core-2.14.1"}},
                    {"key": "JVL-13", "fields": {"summary": "Investigate false positive"}},
                ],
            }
        )
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].ticket_key, "JVL-10")  # parent, not the subtask
        self.assertEqual(jobs[0].jira_meta["subtask_key"], "JVL-11")

    def test_sca_ticket_all_subtasks_without_cve_raises(self):
        description = (
            r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependencies" "\n"
            r"*Scan ID:* [x|https://x/scans?id=22222222-2222-2222-2222-222222222222&branch=main]"
        )
        with self.assertRaises(ValueError):
            parse_jira_issue(
                {
                    "key": "JVL-10",
                    "description": description,
                    "subtasks": [{"key": "JVL-13", "fields": {"summary": "Investigate false positive"}}],
                }
            )

    def test_load_sca_sample_event_with_subtasks(self):
        issue = load_jira_issue("samples/github_event_sca.sample.json")
        jobs = parse_jira_issue(issue)
        self.assertEqual(len(jobs), 2)
        self.assertEqual({j.cve_id for j in jobs}, {"CVE-2021-44228", "CVE-2022-23305"})
        # scanId field takes precedence over the description regex, and the
        # subtasks are the real automation's flat shape (no "fields" nesting).
        for j in jobs:
            self.assertEqual(j.scan_id, "d01d7561-2bf5-48b2-bbaa-da166c671fc3")
            self.assertEqual(j.jira_meta["package_name_version"], "log4j-core 2.14.1")
            self.assertEqual(j.ticket_key, "JVL-10")  # parent, not the subtask

    def test_sca_subtasks_flat_shape_from_real_automation_rule(self):
        # "SCA | CVE-..." is the real subtask summary format (verified);
        # packageNameVersion is a field on the *parent* ticket (verified),
        # not per-subtask, and applies to every CVE/subtask under it.
        jobs = parse_jira_issue(
            {
                "key": "JVL-10",
                "description": r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependencies",
                "scanId": "22222222-2222-2222-2222-222222222222",
                "packageNameVersion": "log4j-core 2.14.1",
                "subtasks": [
                    {"key": "JVL-11", "summary": "SCA | CVE-2025-71329",
                     "status": "To Do", "assignee": "dev@example.com",
                     "created": "2026-08-20T09:16:00.000-0000", "url": "https://x/browse/JVL-11"},
                ],
            }
        )
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].cve_id, "CVE-2025-71329")
        self.assertEqual(jobs[0].scan_id, "22222222-2222-2222-2222-222222222222")
        self.assertEqual(jobs[0].jira_meta["package_name_version"], "log4j-core 2.14.1")
        self.assertEqual(jobs[0].ticket_key, "JVL-10")  # parent, not the subtask
        self.assertEqual(jobs[0].jira_meta["subtask_key"], "JVL-11")

    def test_sca_subtask_without_package_field_has_no_package_in_jira_meta(self):
        jobs = parse_jira_issue(
            {
                "key": "JVL-10",
                "description": r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependencies",
                "scanId": "22222222-2222-2222-2222-222222222222",
                "subtasks": [{"key": "JVL-11", "summary": "SCA | CVE-2025-71329"}],
            }
        )
        self.assertNotIn("package_name_version", jobs[0].jira_meta)

    def test_scan_id_field_takes_precedence_over_description(self):
        # Description points at a different scan id than the scanId field;
        # the field should win.
        jobs = parse_jira_issue(
            {
                "key": "JVL-2",
                "description": SAST_DESCRIPTION,
                "scanId": "99999999-9999-9999-9999-999999999999",
                "VulnerabilityId1": "some-other-hash",
            }
        )
        self.assertEqual(jobs[0].scan_id, "99999999-9999-9999-9999-999999999999")

    def test_vulnerability_id_fields_take_precedence_and_yield_one_job_each(self):
        jobs = parse_jira_issue(
            {
                "key": "JVL-2",
                "description": SAST_DESCRIPTION,  # would otherwise yield a different result_hash
                "VulnerabilityId1": "hash-one",
                "VulnerabilityId2": "hash-two",
                "VulnerabilityId3": "",  # blank fields must be ignored, not treated as a real ID
                "VulnerabilityId4": "",
                "VulnerabilityId5": "",
            }
        )
        self.assertEqual(len(jobs), 2)
        self.assertEqual({j.result_hash for j in jobs}, {"hash-one", "hash-two"})
        for j in jobs:
            self.assertEqual(j.ticket_key, "JVL-2")  # all jobs stay on the parent ticket

    def test_sast_falls_back_to_description_when_no_vulnerability_id_fields(self):
        # No VulnerabilityId1..5 at all -> falls back to the description's result-id=.
        jobs = parse_jira_issue({"key": "JVL-2", "description": SAST_DESCRIPTION})
        self.assertEqual(jobs[0].result_hash, "XZBiE9xWT5WiRxxnpMKmKfZUJuA=")

    def test_missing_scanner_type_raises(self):
        with self.assertRaises(ValueError):
            parse_jira_issue({"key": "X-1", "description": "no scanner marker here"})

    def test_missing_scan_id_raises(self):
        description = r"*Checkmarx \(SAST\):* Foo" "\nno scan id link here"
        with self.assertRaises(ValueError):
            parse_jira_issue({"key": "X-1", "description": description})

    def test_load_jira_issue_from_sample_event_file(self):
        issue = load_jira_issue("samples/github_event.sample.json")
        self.assertEqual(issue["key"], "JVL-2")
        jobs = parse_jira_issue(issue)
        self.assertEqual(jobs[0].scan_id, "d01d7561-2bf5-48b2-bbaa-da166c671fc3")

    def test_load_jira_issue_or_key_returns_the_full_issue_when_present(self):
        jira_issue, issue_key = load_jira_issue_or_key("samples/github_event.sample.json")
        self.assertEqual(jira_issue["key"], "JVL-2")
        self.assertIsNone(issue_key)

    def test_load_jira_issue_or_key_returns_just_the_key_when_thats_all_thats_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            event_path.write_text(json.dumps(
                {"client_payload": {"issue_key": "JVL-20"}}
            ))
            jira_issue, issue_key = load_jira_issue_or_key(str(event_path))
        self.assertIsNone(jira_issue)
        self.assertEqual(issue_key, "JVL-20")

    def test_load_jira_issue_or_key_raises_when_neither_is_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp) / "event.json"
            event_path.write_text(json.dumps({"client_payload": {}}))
            with self.assertRaises(ValueError):
                load_jira_issue_or_key(str(event_path))

    def test_jira_meta_is_carried_through_without_affecting_resolution(self):
        jobs = parse_jira_issue(
            {
                "key": "JVL-2",
                "description": SAST_DESCRIPTION,
                "status": "To Do",
                "priority": "Highest",
                "issue_type": "Bug",
                "project": "JVL",
                "reporter": "security-bot@example.com",
                "assignee": "dev-owner@example.com",
                "labels": ["checkmarx", "sast"],
                "created": "2026-08-20T09:15:00.000-0000",
                "updated": "2026-08-27T14:02:00.000-0000",
                "url": "",  # empty/falsy fields should be dropped, not stored as ""
            }
        )
        job = jobs[0]
        self.assertEqual(job.jira_meta["status"], "To Do")
        self.assertEqual(job.jira_meta["priority"], "Highest")
        self.assertEqual(job.jira_meta["reporter"], "security-bot@example.com")
        self.assertEqual(job.jira_meta["labels"], ["checkmarx", "sast"])
        self.assertNotIn("url", job.jira_meta)  # not in _META_FIELDS
        self.assertNotIn("description", job.jira_meta)  # too large / not useful in a report

        row = job  # sanity: jira_meta doesn't leak into identifier-resolution fields
        self.assertEqual(row.scan_id, "d01d7561-2bf5-48b2-bbaa-da166c671fc3")


if __name__ == "__main__":
    unittest.main()
