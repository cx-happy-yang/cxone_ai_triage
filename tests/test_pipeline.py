import unittest

from CheckmarxPythonSDK.CxOne.dto import AiTriageResult

from cxone_ai_triage.models import TriageJob, TriageOutcome
from cxone_ai_triage.pipeline import run_pipeline


class FakeResolver:
    """Stands in for TriageResolver: resolve_and_trigger_all returns a
    preconfigured outcome per scan_id (batching is TriageResolver's own
    concern, exercised separately in test_resolver.py), poll_ai_triage_result
    returns a preconfigured AiTriageResult or raises, per test."""

    def __init__(self, outcome_by_scan=None, poll_result=None, poll_error=None):
        self.outcome_by_scan = outcome_by_scan or {}
        self.poll_result = poll_result
        self.poll_error = poll_error
        self.poll_calls = []

    def resolve_and_trigger_all(self, jobs) -> list:
        return [self.outcome_by_scan[job.scan_id] for job in jobs]

    def poll_ai_triage_result(self, project_id, group_id, timeout_seconds=600, interval_seconds=15):
        self.poll_calls.append((project_id, group_id))
        if self.poll_error:
            raise self.poll_error
        return self.poll_result


class FakeJiraClient:
    def __init__(self, existing_bodies_by_issue=None):
        self.comments = []
        self._existing_bodies_by_issue = existing_bodies_by_issue or {}

    def add_comment(self, issue_key, body):
        self.comments.append((issue_key, body))
        self._existing_bodies_by_issue.setdefault(issue_key, []).append(body)

    def get_comment_bodies(self, issue_key):
        return list(self._existing_bodies_by_issue.get(issue_key, []))


def make_accepted_outcome(job, project_id="proj-1", group_id="group-1"):
    return TriageOutcome(
        job=job, project_id=project_id, group_id=group_id,
        alternate_id="alt-1", triage_id="tri-1", status="accepted",
    )


class TestRunPipeline(unittest.TestCase):
    def test_successful_trigger_polls_and_posts_comment(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(
            triageStatus="PROPOSED_NOT_EXPLOITABLE",
            reachabilityStatus="NOT_REACHABLE",
            exploitabilityStatus="NOT_EXPLOITABLE",
            summary="Sanitized input.",
        )
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client)

        self.assertEqual(len(outcomes), 1)
        o = outcomes[0]
        self.assertEqual(o.ai_triage_status, "PROPOSED_NOT_EXPLOITABLE")
        self.assertEqual(o.reachability_status, "NOT_REACHABLE")
        self.assertEqual(o.exploitability_status, "NOT_EXPLOITABLE")
        self.assertTrue(o.comment_posted)
        self.assertEqual(resolver.poll_calls, [("proj-1", "group-1")])
        self.assertEqual(len(jira_client.comments), 1)
        self.assertEqual(jira_client.comments[0][0], "JVL-2")
        self.assertIn("PROPOSED_NOT_EXPLOITABLE", jira_client.comments[0][1])

    def test_sca_job_package_name_version_is_passed_into_the_comment(self):
        job = TriageJob(
            scan_id="s1", scanner_type="sca", ticket_key="JVL-11", cve_id="CVE-2025-71329",
            jira_meta={"package_name_version": "log4j-core 2.14.1"},
        )
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient()

        run_pipeline([job], resolver, jira_client)

        self.assertIn("log4j-core 2.14.1", jira_client.comments[0][1])

    def test_sca_comment_posts_to_parent_ticket_not_subtask(self):
        # job.ticket_key is already the parent (jira_parser sets it that way);
        # jira_meta["subtask_key"] is where the subtask lives instead.
        job = TriageJob(
            scan_id="s1", scanner_type="sca", ticket_key="JVL-10", cve_id="CVE-2021-44228",
            jira_meta={"subtask_key": "JVL-11", "package_name_version": "log4j-core 2.14.1"},
        )
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient()

        run_pipeline([job], resolver, jira_client)

        issue_key, comment = jira_client.comments[0]
        self.assertEqual(issue_key, "JVL-10")
        self.assertIn("*CVE ID:* CVE-2021-44228.", comment)
        self.assertIn("*Subtask:* JVL-11.", comment)

    def test_sast_comment_includes_result_hash_as_vulnerability_label(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-xyz")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient()

        run_pipeline([job], resolver, jira_client)

        issue_key, comment = jira_client.comments[0]
        self.assertEqual(issue_key, "JVL-2")
        self.assertIn("*Vulnerability ID:* hash-xyz.", comment)

    def test_skips_posting_a_duplicate_comment_for_the_same_vulnerability(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-xyz")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient(
            existing_bodies_by_issue={"JVL-2": ["*Vulnerability ID:* hash-xyz. *CxOne AI Triage verdict:* VULNERABLE."]}
        )

        outcomes = run_pipeline([job], resolver, jira_client)

        self.assertEqual(jira_client.comments, [])  # no new comment posted
        self.assertFalse(outcomes[0].comment_posted)
        self.assertIn("hash-xyz", outcomes[0].comment_skipped_reason)

    def test_posts_normally_when_existing_comments_are_for_a_different_vulnerability(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-xyz")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient(
            existing_bodies_by_issue={"JVL-2": ["*Vulnerability ID:* some-other-hash. *CxOne AI Triage verdict:* VULNERABLE."]}
        )

        outcomes = run_pipeline([job], resolver, jira_client)

        self.assertEqual(len(jira_client.comments), 1)
        self.assertTrue(outcomes[0].comment_posted)
        self.assertIsNone(outcomes[0].comment_skipped_reason)

    def test_second_job_in_the_same_run_sees_the_first_jobs_freshly_posted_comment(self):
        # Two SAST results on the same parent ticket - the marker check for
        # job 2 must see job 1's comment even though it was only just posted
        # moments earlier in this same run, not from an earlier run.
        job1 = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-one")
        job2 = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-one")  # duplicate on purpose
        outcome1 = make_accepted_outcome(job1, group_id="group-1")
        outcome2 = make_accepted_outcome(job2, group_id="group-1")
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome1}, poll_result=result)
        resolver.resolve_and_trigger_all = lambda jobs: [outcome1, outcome2]
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job1, job2], resolver, jira_client)

        self.assertEqual(len(jira_client.comments), 1)  # only the first posted
        self.assertTrue(outcomes[0].comment_posted)
        self.assertFalse(outcomes[1].comment_posted)
        self.assertIsNotNone(outcomes[1].comment_skipped_reason)

    def test_two_different_vulnerabilities_on_the_same_ticket_each_get_their_own_comment(self):
        # e.g. a ticket with VulnerabilityId1 and VulnerabilityId2 (or two SCA
        # subtasks) both populated - distinct result_hash/cve_id, so neither
        # marker matches the other's comment and both get posted.
        job1 = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-one")
        job2 = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-two")
        outcome1 = make_accepted_outcome(job1, group_id="group-1")
        outcome2 = make_accepted_outcome(job2, group_id="group-2")
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome1}, poll_result=result)
        resolver.resolve_and_trigger_all = lambda jobs: [outcome1, outcome2]
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job1, job2], resolver, jira_client)

        self.assertEqual(len(jira_client.comments), 2)
        self.assertTrue(outcomes[0].comment_posted)
        self.assertTrue(outcomes[1].comment_posted)
        self.assertIsNone(outcomes[0].comment_skipped_reason)
        self.assertIsNone(outcomes[1].comment_skipped_reason)
        self.assertEqual({key for key, _ in jira_client.comments}, {"JVL-2"})
        self.assertIn("*Vulnerability ID:* hash-one.", jira_client.comments[0][1])
        self.assertIn("*Vulnerability ID:* hash-two.", jira_client.comments[1][1])

    def test_posts_normally_when_existing_comment_check_fails(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="hash-xyz")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)

        class BrokenReadJiraClient(FakeJiraClient):
            def get_comment_bodies(self, issue_key):
                raise RuntimeError("503 Service Unavailable")

        jira_client = BrokenReadJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client)

        self.assertEqual(len(jira_client.comments), 1)  # still posted - fails open
        self.assertTrue(outcomes[0].comment_posted)

    def test_failed_trigger_skips_poll_and_comment(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = TriageOutcome(job=job, status="failed", error="boom")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome})
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client)

        self.assertEqual(outcomes[0].status, "failed")
        self.assertEqual(resolver.poll_calls, [])
        self.assertEqual(jira_client.comments, [])

    def test_no_poll_flag_skips_polling_and_commenting(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = make_accepted_outcome(job)
        resolver = FakeResolver(outcome_by_scan={"s1": outcome})
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client, poll=False)

        self.assertIsNone(outcomes[0].ai_triage_status)
        self.assertEqual(resolver.poll_calls, [])
        self.assertEqual(jira_client.comments, [])

    def test_no_comment_flag_polls_but_skips_commenting(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client, post_comment=False)

        self.assertEqual(outcomes[0].ai_triage_status, "VULNERABLE")
        self.assertEqual(jira_client.comments, [])

    def test_missing_group_id_skips_polling(self):
        job = TriageJob(scan_id="s1", scanner_type="sca", ticket_key="JVL-11", cve_id="CVE-2021-44228")
        outcome = make_accepted_outcome(job, group_id=None)
        resolver = FakeResolver(outcome_by_scan={"s1": outcome})
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client)

        self.assertIsNone(outcomes[0].ai_triage_status)
        self.assertEqual(resolver.poll_calls, [])

    def test_poll_timeout_is_recorded_without_failing_the_job(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = make_accepted_outcome(job)
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_error=TimeoutError("timed out"))
        jira_client = FakeJiraClient()

        outcomes = run_pipeline([job], resolver, jira_client)

        o = outcomes[0]
        self.assertEqual(o.status, "accepted")  # trigger itself still succeeded
        self.assertIn("timed out", o.poll_error)
        self.assertFalse(o.comment_posted)

    def test_no_jira_client_skips_commenting_but_still_polls(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)

        outcomes = run_pipeline([job], resolver, jira_client=None)

        self.assertEqual(outcomes[0].ai_triage_status, "VULNERABLE")
        self.assertFalse(outcomes[0].comment_posted)

    def test_comment_failure_is_recorded_without_failing_the_job(self):
        job = TriageJob(scan_id="s1", scanner_type="sast", ticket_key="JVL-2", result_hash="h1")
        outcome = make_accepted_outcome(job)
        result = AiTriageResult(triageStatus="VULNERABLE")
        resolver = FakeResolver(outcome_by_scan={"s1": outcome}, poll_result=result)

        class BrokenJiraClient:
            def add_comment(self, issue_key, body):
                raise RuntimeError("401 Unauthorized")

        outcomes = run_pipeline([job], resolver, BrokenJiraClient())

        o = outcomes[0]
        self.assertEqual(o.status, "accepted")
        self.assertFalse(o.comment_posted)
        self.assertIn("401", o.comment_error)


if __name__ == "__main__":
    unittest.main()
