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
    def __init__(self):
        self.comments = []

    def add_comment(self, issue_key, body):
        self.comments.append((issue_key, body))


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
