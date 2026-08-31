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
SCA_ROW_A = Result(
    type="sca", id="r2", alternate_id="alt-sca-a", similarity_id="CVE-2021-44228",
    data={"packageIdentifier": "log4j-core-2.14.1"},
)
SCA_ROW_B = Result(
    type="sca", id="r3", alternate_id="alt-sca-b", similarity_id="CVE-2021-44228",
    data={"packageIdentifier": "log4j-api-2.14.1"},
)
NOISE_ROW = Result(type="sast", id="r4", alternate_id="alt-noise", similarity_id="999999", data=None)
ALL_RESULTS = [SAST_ROW, SCA_ROW_A, SCA_ROW_B, NOISE_ROW]


class FakeSdkResolver(TriageResolver):
    """TriageResolver with every network-calling SDK method faked out."""

    def __init__(self):
        super().__init__()
        self.results_call_count = 0
        self._scans_api.get_a_scan_by_id = self._fake_get_a_scan_by_id
        self._sast_results_api.get_sast_results_by_scan_id = self._fake_get_sast_results
        self._scanner_results_api.get_all_scanners_results_by_scan_id = self._fake_get_all_results
        self._risks_api.get_risks = self._fake_get_risks
        self._ai_triage_api.trigger_ai_triage = self._fake_trigger_ai_triage

    def _fake_get_a_scan_by_id(self, scan_id):
        assert scan_id == SCAN_ID
        return Scan(id=scan_id, project_id=PROJECT_ID)

    def _fake_get_sast_results(self, scan_id, result_id=None, limit=1, **kw):
        assert scan_id == SCAN_ID
        assert result_id == ["hash-xyz"]
        return {"results": [SastResult(result_hash="hash-xyz", similarity_id=123456)], "totalCount": 1}

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
        return AiTriageResponse(scanID=request.scanID, status="accepted", triageID="triage-123", published=True)


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
        self.assertEqual(outcome.triage_id, "triage-123")

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
