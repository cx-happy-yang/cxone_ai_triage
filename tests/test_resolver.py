"""Exercises TriageResolver's matching/caching/group-id logic against a
faked CheckmarxPythonSDK, without hitting a real Checkmarx One tenant.
"""
import unittest
from unittest.mock import patch

from CheckmarxPythonSDK.CxOne.dto import (
    AiTriageResponse,
    AiTriageResult,
    Result,
    Risk,
    RisksMetaData,
    RisksResponse,
    SastResult,
    Scan,
)

from cxone_ai_triage.models import TriageJob
from cxone_ai_triage.resolver import TriageResolver

SCAN_ID = "11111111-1111-1111-1111-111111111111"
PROJECT_ID = "proj-abc"

SAST_ROW = Result(type="sast", id="r1", alternate_id="alt-sast-1", similarity_id="123456", data=None)
SAST_ROW_2 = Result(type="sast", id="r5", alternate_id="alt-sast-2", similarity_id="654321", data=None)
SCA_ROW_A = Result(
    type="sca", id="r2", alternate_id="alt-sca-a", similarity_id="CVE-2021-44228",
    data={"packageIdentifier": "log4j-core-2.14.1"},
)
SCA_ROW_B = Result(
    type="sca", id="r3", alternate_id="alt-sca-b", similarity_id="CVE-2021-44228",
    data={"packageIdentifier": "log4j-api-2.14.1"},
)
SCA_ROW_C = Result(
    type="sca", id="r6", alternate_id="alt-sca-c", similarity_id="CVE-2022-23305",
    data={"packageIdentifier": "log4j-core-2.14.1"},
)
NOISE_ROW = Result(type="sast", id="r4", alternate_id="alt-noise", similarity_id="999999", data=None)
ALL_RESULTS = [SAST_ROW, SAST_ROW_2, SCA_ROW_A, SCA_ROW_B, SCA_ROW_C, NOISE_ROW]

_SAST_RESULTS_BY_HASH = {
    "hash-xyz": SastResult(result_hash="hash-xyz", similarity_id=123456),
    "hash-two": SastResult(result_hash="hash-two", similarity_id=654321),
}


class FakeSdkResolver(TriageResolver):
    """TriageResolver with every network-calling SDK method faked out."""

    def __init__(self):
        super().__init__()
        self.results_call_count = 0
        self.trigger_calls = []  # list of (scanID, [(scannerType, resultIDs), ...])
        self.existing_triage_by_group_id = {}  # group_id -> AiTriageResult, for pre-check tests
        self.existing_triage_check_calls = []  # list of (project_id, group_id)
        self._scans_api.get_a_scan_by_id = self._fake_get_a_scan_by_id
        self._sast_results_api.get_sast_results_by_scan_id = self._fake_get_sast_results
        self._scanner_results_api.get_all_scanners_results_by_scan_id = self._fake_get_all_results
        self._risks_api.get_risks = self._fake_get_risks
        self._ai_triage_api.trigger_ai_triage = self._fake_trigger_ai_triage
        self._ai_triage_api.retrieve_ai_triage_results = self._fake_retrieve_ai_triage_results

    def _fake_retrieve_ai_triage_results(self, project_id, group_id):
        # Default: nothing has ever been triaged, so the pre-check never
        # blocks triggering unless a test opts a specific group_id in via
        # existing_triage_by_group_id.
        self.existing_triage_check_calls.append((project_id, group_id))
        return self.existing_triage_by_group_id.get(
            group_id, AiTriageResult(triageStatus="NOT_TRIAGED")
        )

    def _fake_get_a_scan_by_id(self, scan_id):
        assert scan_id == SCAN_ID
        return Scan(id=scan_id, project_id=PROJECT_ID)

    def _fake_get_sast_results(self, scan_id, result_id=None, limit=1, **kw):
        assert scan_id == SCAN_ID
        hash_ = result_id[0]
        result = _SAST_RESULTS_BY_HASH.get(hash_)
        return {"results": [result] if result else [], "totalCount": 1 if result else 0}

    def _fake_get_all_results(self, scan_id, offset=0, limit=500, **kw):
        assert scan_id == SCAN_ID
        self.results_call_count += 1
        return {"results": ALL_RESULTS[offset:offset + limit], "totalCount": len(ALL_RESULTS)}

    def _fake_get_risks(self, project_id, engine=None, risk_name=None, limit=200, **kw):
        assert project_id == PROJECT_ID
        assert engine == ["SCA"]
        cve = risk_name[0]
        return RisksResponse(
            metaData=RisksMetaData(),
            risks=[Risk(id="riskrow", scanId=SCAN_ID, engine="SCA", groupId=f"groupid-for-{cve}")],
        )

    def _fake_trigger_ai_triage(self, request):
        self.trigger_calls.append(
            (request.scanID, [(b.scannerType, b.resultIDs) for b in request.buckets])
        )
        triage_id = f"triage-{len(self.trigger_calls)}"
        return AiTriageResponse(scanID=request.scanID, status="accepted", triageID=triage_id, published=True)


class TestTriageResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = FakeSdkResolver()

    def test_sast_job_resolves_and_triggers(self):
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(outcome.project_id, PROJECT_ID)
        self.assertEqual(outcome.similarity_id, "123456")
        self.assertEqual(outcome.alternate_id, "alt-sast-1")
        self.assertEqual(outcome.group_id, "123456")  # SAST groupId == similarityId
        self.assertEqual(outcome.triage_id, "triage-1")
        self.assertEqual(
            self.resolver.trigger_calls, [(SCAN_ID, [("sast", ["alt-sast-1"])])]
        )

    def test_sca_job_ambiguous_without_package_identifier_fails(self):
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-2", cve_id="CVE-2021-44228")
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "failed")
        self.assertIn("share similarityId", outcome.error)

    def test_sca_job_disambiguated_by_package_identifier_succeeds(self):
        job = TriageJob(
            scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-3",
            cve_id="CVE-2021-44228", package_identifier="log4j-api-2.14.1",
        )
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(outcome.alternate_id, "alt-sca-b")
        self.assertEqual(outcome.package_identifier, "log4j-api-2.14.1")
        self.assertEqual(outcome.group_id, "groupid-for-CVE-2021-44228")

    def test_results_and_project_id_are_cached_across_jobs_on_same_scan(self):
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz"),
            TriageJob(
                scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-3",
                cve_id="CVE-2021-44228", package_identifier="log4j-api-2.14.1",
            ),
        ]
        self.resolver.resolve_and_trigger_all(jobs)
        self.assertEqual(self.resolver.results_call_count, 1)
        self.assertEqual(self.resolver._project_id_by_scan[SCAN_ID], PROJECT_ID)

    def test_multiple_sast_jobs_on_same_scan_are_batched_into_one_trigger_call(self):
        # e.g. a ticket with VulnerabilityId1 and VulnerabilityId2 both populated.
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz"),
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-two"),
        ]
        outcomes = self.resolver.resolve_and_trigger_all(jobs)

        self.assertEqual([o.status for o in outcomes], ["accepted", "accepted"])
        self.assertEqual({o.alternate_id for o in outcomes}, {"alt-sast-1", "alt-sast-2"})
        # One trigger call, one bucket, both resultIDs together.
        self.assertEqual(len(self.resolver.trigger_calls), 1)
        scan_id, buckets = self.resolver.trigger_calls[0]
        self.assertEqual(scan_id, SCAN_ID)
        self.assertEqual(len(buckets), 1)
        scanner_type, result_ids = buckets[0]
        self.assertEqual(scanner_type, "sast")
        self.assertEqual(set(result_ids), {"alt-sast-1", "alt-sast-2"})
        # Both outcomes share the one triageID the batched call returned.
        self.assertEqual(outcomes[0].triage_id, outcomes[1].triage_id)

    def test_multiple_sca_jobs_on_same_scan_are_batched_into_one_trigger_call(self):
        # e.g. one ticket with two subtasks, each "SCA | CVE-...", same
        # scanId/packageNameVersion per README's "one package per ticket".
        jobs = [
            TriageJob(
                scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-11",
                cve_id="CVE-2021-44228", package_identifier="log4j-core-2.14.1",
            ),
            TriageJob(scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-12", cve_id="CVE-2022-23305"),
        ]
        outcomes = self.resolver.resolve_and_trigger_all(jobs)

        self.assertEqual([o.status for o in outcomes], ["accepted", "accepted"])
        self.assertEqual({o.alternate_id for o in outcomes}, {"alt-sca-a", "alt-sca-c"})
        self.assertEqual(len(self.resolver.trigger_calls), 1)
        scan_id, buckets = self.resolver.trigger_calls[0]
        self.assertEqual(scan_id, SCAN_ID)
        self.assertEqual(len(buckets), 1)
        scanner_type, result_ids = buckets[0]
        self.assertEqual(scanner_type, "sca")
        self.assertEqual(set(result_ids), {"alt-sca-a", "alt-sca-c"})
        self.assertEqual(outcomes[0].triage_id, outcomes[1].triage_id)
        # Each subtask keeps its own groupId for independent polling later.
        self.assertNotEqual(outcomes[0].group_id, outcomes[1].group_id)

    def test_batch_trigger_failure_fails_every_outcome_in_the_batch(self):
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz"),
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-two"),
        ]
        self.resolver._ai_triage_api.trigger_ai_triage = lambda request: (_ for _ in ()).throw(
            RuntimeError("503 Service Unavailable")
        )
        outcomes = self.resolver.resolve_and_trigger_all(jobs)
        self.assertEqual([o.status for o in outcomes], ["failed", "failed"])
        self.assertTrue(all("503" in o.error for o in outcomes))

    def test_job_that_fails_resolution_is_excluded_from_its_batch(self):
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz"),
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="does-not-exist"),
        ]
        outcomes = self.resolver.resolve_and_trigger_all(jobs)
        self.assertEqual(outcomes[0].status, "accepted", outcomes[0].error)
        self.assertEqual(outcomes[1].status, "failed")
        # The batch only ever contained the one resolvable job.
        self.assertEqual(len(self.resolver.trigger_calls), 1)
        self.assertEqual(self.resolver.trigger_calls[0][1], [("sast", ["alt-sast-1"])])

    def test_skips_trigger_when_a_finished_result_already_exists(self):
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        # group_id for this job is the similarityId, "123456" (see test_sast_job_resolves_and_triggers).
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="VULNERABLE")

        outcome = self.resolver.resolve_and_trigger(job)

        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertIsNone(outcome.triage_id)
        self.assertIn("VULNERABLE", outcome.trigger_skipped_reason)
        self.assertEqual(self.resolver.trigger_calls, [])  # no POST was made
        self.assertEqual(self.resolver.existing_triage_check_calls, [(PROJECT_ID, "123456")])

    def test_skips_trigger_when_a_result_is_already_in_progress(self):
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="IN_PROGRESS")

        outcome = self.resolver.resolve_and_trigger(job)

        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertIsNone(outcome.triage_id)
        self.assertEqual(self.resolver.trigger_calls, [])

    def test_skips_trigger_for_an_undocumented_status_value(self):
        # A live tenant returned "CONFIRMED" (a SAST result *state*, not one
        # of AiTriageResult's documented triageStatus values) for a
        # genuinely already-triaged vulnerability. The check must still
        # treat it as "existing" rather than only recognizing the
        # documented enum - see _check_existing_triage's docstring.
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="CONFIRMED")

        outcome = self.resolver.resolve_and_trigger(job)

        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertIsNone(outcome.triage_id)
        self.assertIn("CONFIRMED", outcome.trigger_skipped_reason)
        self.assertEqual(self.resolver.trigger_calls, [])

    def test_not_triaged_status_is_normalized_for_case_and_whitespace(self):
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus=" not_triaged ")

        outcome = self.resolver.resolve_and_trigger(job)

        # Still recognized as "nothing yet" despite the case/whitespace - triggers normally.
        self.assertIsNone(outcome.trigger_skipped_reason)
        self.assertEqual(len(self.resolver.trigger_calls), 1)

    def test_triggers_normally_when_no_existing_result(self):
        # Default fake behavior (NOT_TRIAGED) - regression check that the
        # pre-check doesn't block a genuinely new result.
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(outcome.triage_id, "triage-1")
        self.assertIsNone(outcome.trigger_skipped_reason)
        self.assertEqual(len(self.resolver.trigger_calls), 1)

    def test_triggers_normally_when_existing_triage_check_itself_fails(self):
        # A broken pre-check should fail open (trigger as usual), not block the run.
        def broken_check(project_id, group_id):
            raise RuntimeError("503 Service Unavailable")

        self.resolver._ai_triage_api.retrieve_ai_triage_results = broken_check
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(len(self.resolver.trigger_calls), 1)

    def test_mixed_batch_only_triggers_the_jobs_without_an_existing_result(self):
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="VULNERABLE")
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz"),
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-two"),
        ]
        outcomes = self.resolver.resolve_and_trigger_all(jobs)

        already_done, needs_trigger = outcomes
        self.assertIsNotNone(already_done.trigger_skipped_reason)
        self.assertIsNone(needs_trigger.trigger_skipped_reason)
        self.assertEqual(needs_trigger.triage_id, "triage-1")
        # Only the un-triaged one made it into the batch.
        self.assertEqual(self.resolver.trigger_calls, [(SCAN_ID, [("sast", ["alt-sast-2"])])])

    def test_unknown_result_hash_fails_without_raising(self):
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-4", result_hash="does-not-exist")
        # Make the fake sast-results lookup behave like the real API: no match.
        self.resolver._sast_results_api.get_sast_results_by_scan_id = (
            lambda scan_id, result_id=None, limit=1, **kw: {"results": [], "totalCount": 0}
        )
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "failed")
        self.assertIn("no result", outcome.error)


class TestPollAiTriageResult(unittest.TestCase):
    def setUp(self):
        self.resolver = FakeSdkResolver()

    def test_returns_immediately_when_already_terminal(self):
        terminal = AiTriageResult(triageStatus="VULNERABLE")
        self.resolver._ai_triage_api.retrieve_ai_triage_results = lambda p, g: terminal
        result = self.resolver.poll_ai_triage_result(PROJECT_ID, "group-1")
        self.assertIs(result, terminal)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_polls_until_status_leaves_in_progress(self, mock_sleep):
        responses = iter([
            AiTriageResult(triageStatus="NOT_TRIAGED"),
            AiTriageResult(triageStatus="IN_PROGRESS"),
            AiTriageResult(triageStatus="PROPOSED_NOT_EXPLOITABLE"),
        ])
        calls = []

        def fake_retrieve(project_id, group_id):
            calls.append((project_id, group_id))
            return next(responses)

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        result = self.resolver.poll_ai_triage_result(
            PROJECT_ID, "group-1", timeout_seconds=60, interval_seconds=1
        )
        self.assertEqual(result.triageStatus, "PROPOSED_NOT_EXPLOITABLE")
        self.assertEqual(len(calls), 3)
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_raises_timeout_error_if_never_terminal(self, mock_sleep):
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(triageStatus="IN_PROGRESS")
        )
        # time.monotonic() advances by 1s per call; interval matches so the
        # deadline is exceeded after a couple of iterations without a real sleep.
        with patch("cxone_ai_triage.resolver.time.monotonic", side_effect=[0, 1, 2, 3, 4, 5]):
            with self.assertRaises(TimeoutError):
                self.resolver.poll_ai_triage_result(
                    PROJECT_ID, "group-1", timeout_seconds=2, interval_seconds=1
                )


if __name__ == "__main__":
    unittest.main()
