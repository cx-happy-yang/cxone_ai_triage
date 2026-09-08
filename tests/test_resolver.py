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
from cxone_ai_triage.resolver import (
    RESULTS_PAGE_SIZE,
    AiTriageMissingStatusError,
    TriageResolver,
)

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


def _fake_raw_body_response(raw):
    """Stand-in for ApiClient.call_api's response when _retrieve_triage_result
    does its best-effort raw-body GET for an off-schema result."""
    from types import SimpleNamespace

    return lambda method, url, headers: SimpleNamespace(json=lambda: raw)


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
        # offset is a PAGE NUMBER here, matching the real (undocumented)
        # API behavior confirmed live - see _get_all_results's docstring.
        assert scan_id == SCAN_ID
        self.results_call_count += 1
        start = offset * limit
        return {"results": ALL_RESULTS[start:start + limit], "totalCount": len(ALL_RESULTS)}

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

    def test_sast_ambiguous_similarity_id_picks_one_row_and_logs_details_instead_of_failing(self):
        # A live tenant showed 2 distinct VulnerabilityId values (2 different
        # resultHashes) genuinely sharing one similarityId - Checkmarx groups
        # by vulnerability *pattern*, not by specific code location. SAST has
        # no package_identifier-style disambiguator, but unlike SCA that's
        # fine: groupId *is* the similarityId for SAST, and AI Triage only
        # ever returns one verdict per groupId, so any one of the ambiguous
        # rows' alternateId is an equally valid representative to submit -
        # this no longer fails the job (see resolve_and_trigger_all's
        # resultID de-duplication and pipeline.run_pipeline's comment
        # grouping for how jobs sharing this groupId end up combined).
        dup_row_a = Result(type="sast", id="dup-a", alternate_id="alt-dup-a", similarity_id="999999999", data=None)
        dup_row_b = Result(type="sast", id="dup-b", alternate_id="alt-dup-b", similarity_id="999999999", data=None)
        self.resolver._scanner_results_api.get_all_scanners_results_by_scan_id = (
            lambda scan_id, offset=0, limit=500, **kw: {"results": [dup_row_a, dup_row_b], "totalCount": 2}
        )
        self.resolver._sast_results_api.get_sast_results_by_scan_id = (
            lambda scan_id, result_id=None, limit=1, **kw: {
                "results": [SastResult(result_hash="hash-ambiguous", similarity_id=999999999)],
                "totalCount": 1,
            }
        )
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-9", result_hash="hash-ambiguous")

        with self.assertLogs("cxone_ai_triage", level="INFO") as cm:
            outcome = self.resolver.resolve_and_trigger(job)

        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(outcome.alternate_id, "alt-dup-a")  # first match, deterministic
        self.assertTrue(any("alt-dup-a" in line for line in cm.output))
        self.assertTrue(any("alt-dup-b" in line for line in cm.output))

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

    def test_sca_group_id_is_constructed_when_risks_view_has_no_entry(self):
        # The AI Triage API reference documents constructing the SCA groupId
        # manually as similarityId#-#packageIdentifier#-#projectId. GET
        # /api/risks can lag the results view (a live tenant showed no risks
        # entry at all for a CVE whose /api/results rows exist), and a blank
        # groupId makes the pipeline skip result polling entirely - so fall
        # back to the documented construction instead.
        self.resolver._risks_api.get_risks = (
            lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
                metaData=RisksMetaData(), risks=[],
            )
        )
        job = TriageJob(
            scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-9",
            cve_id="CVE-2022-23305",
        )
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(
            outcome.group_id,
            "CVE-2022-23305#-#log4j-core-2.14.1#-#proj-abc",
        )

    def test_sca_group_id_stays_blank_when_risks_empty_and_no_package_identifier(self):
        # Without a packageIdentifier on the matched /api/results row there
        # is nothing to construct the documented groupId format from - the
        # blank-groupId path must remain (trigger still fires; the pipeline
        # skips polling).
        row = Result(
            type="sca", id="r9", alternate_id="alt-no-pkg",
            similarity_id="CVE-2023-0001", data=None,
        )
        self.resolver._scanner_results_api.get_all_scanners_results_by_scan_id = (
            lambda scan_id, offset=0, limit=500, **kw: {"results": [row], "totalCount": 1}
        )
        self.resolver._risks_api.get_risks = (
            lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
                metaData=RisksMetaData(), risks=[],
            )
        )
        job = TriageJob(
            scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-9",
            cve_id="CVE-2023-0001",
        )
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertIsNone(outcome.group_id)

    def test_group_id_is_still_resolved_when_the_risk_is_tagged_with_a_different_scan(self):
        # GET /api/risks aggregates at the project level - a live tenant
        # returned zero risks tagged with the ticket's scan_id for a CVE
        # that had genuinely already been AI-triaged, because the project
        # had been rescanned since. A scanId mismatch alone must not
        # discard the only candidate.
        job = TriageJob(
            scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-9",
            cve_id="CVE-2021-44228", package_identifier="log4j-core-2.14.1",
        )
        self.resolver._risks_api.get_risks = lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
            metaData=RisksMetaData(),
            risks=[Risk(id="riskrow", scanId="some-other-later-scan", engine="SCA", groupId="groupid-for-CVE-2021-44228")],
        )
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.group_id, "groupid-for-CVE-2021-44228")

    def test_lookup_sca_risk_state_returns_the_state_of_the_risk_matching_the_group_id(self):
        # The settled state comes from the risks view; the match must be on
        # groupId so a different risk's state (same CVE, other package) is
        # never borrowed.
        self.resolver._risks_api.get_risks = (
            lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
                metaData=RisksMetaData(),
                risks=[
                    Risk(id="r1", engine="SCA", groupId="other-group", state="CONFIRMED"),
                    Risk(
                        id="r2", engine="SCA",
                        groupId="CVE-2021-21345#-#pkg#-#proj",
                        state="PROPOSED_NOT_EXPLOITABLE", stateChangedBy="AI",
                    ),
                ],
            )
        )
        state = self.resolver.lookup_sca_risk_state(
            PROJECT_ID, "CVE-2021-21345", "CVE-2021-21345#-#pkg#-#proj"
        )
        self.assertEqual(state, "PROPOSED_NOT_EXPLOITABLE")

    def test_lookup_sca_risk_state_returns_none_when_there_is_nothing_to_translate_from(self):
        # No risks at all, none with this groupId, or the lookup itself
        # fails: callers keep the triage result as-is.
        self.resolver._risks_api.get_risks = (
            lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
                metaData=RisksMetaData(), risks=[],
            )
        )
        self.assertIsNone(
            self.resolver.lookup_sca_risk_state(PROJECT_ID, "CVE-2021-21345", "group-1")
        )

        self.resolver._risks_api.get_risks = (
            lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
                metaData=RisksMetaData(),
                risks=[Risk(id="r1", engine="SCA", groupId="other", state="CONFIRMED")],
            )
        )
        self.assertIsNone(
            self.resolver.lookup_sca_risk_state(PROJECT_ID, "CVE-2021-21345", "group-1")
        )

        def broken(project_id, engine=None, risk_name=None, limit=200, **kw):
            raise RuntimeError("503 Service Unavailable")

        self.resolver._risks_api.get_risks = broken
        self.assertIsNone(
            self.resolver.lookup_sca_risk_state(PROJECT_ID, "CVE-2021-21345", "group-1")
        )

    def test_multiple_risks_for_the_same_cve_are_disambiguated_by_package_identifier(self):
        # Same idea, but with two risks sharing this CVE (e.g. the package
        # appears in more than one module) and neither tagged with this
        # job's scan_id - package_identifier (matched against assetName)
        # must still pick the right one instead of just taking the first.
        job = TriageJob(
            scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-9",
            cve_id="CVE-2021-44228", package_identifier="log4j-api-2.14.1",
        )
        self.resolver._risks_api.get_risks = lambda project_id, engine=None, risk_name=None, limit=200, **kw: RisksResponse(
            metaData=RisksMetaData(),
            risks=[
                Risk(id="r1", scanId="other-scan", engine="SCA", assetName="pom.xml (log4j-core-2.14.1)", groupId="groupid-core"),
                Risk(id="r2", scanId="other-scan", engine="SCA", assetName="pom.xml (log4j-api-2.14.1)", groupId="groupid-api"),
            ],
        )
        outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.group_id, "groupid-api")

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

    def test_pagination_does_not_trust_a_wrong_totalCount_and_fetches_every_page(self):
        # A live tenant returned totalCount=RESULTS_PAGE_SIZE (matching just
        # the first page) for a scan that actually had far more results -
        # `offset >= totalCount` stopped the whole fetch after page 1.
        # _get_all_results must page until a short page comes back instead,
        # regardless of what totalCount claims.
        row_count = RESULTS_PAGE_SIZE * 2 + 200  # 3 pages: full, full, partial
        all_rows = [
            Result(type="sast", id=f"r{i}", alternate_id=f"alt-{i}", similarity_id=str(i), data=None)
            for i in range(row_count)
        ]

        def fake_get_all_results(scan_id, offset=0, limit=500, **kw):
            # offset is a PAGE NUMBER here, matching the real (undocumented)
            # API behavior confirmed live - see _get_all_results's docstring.
            self.resolver.results_call_count += 1
            start = offset * limit
            return {
                "results": all_rows[start:start + limit],
                "totalCount": RESULTS_PAGE_SIZE,  # deliberately wrong, matches the live bug
            }

        self.resolver._scanner_results_api.get_all_scanners_results_by_scan_id = fake_get_all_results

        fetched = self.resolver._get_all_results(SCAN_ID)

        self.assertEqual(len(fetched), row_count)
        self.assertEqual(self.resolver.results_call_count, 3)

    def test_pagination_uses_offset_as_a_page_number_not_a_row_skip_count(self):
        # The critical, confirmed-live behavior: GET /api/results' `offset`
        # is a page number (0-indexed), not a row-skip count, despite the
        # SDK's own docstring ("offset: Items to skip"). Advancing offset
        # by the number of rows already fetched (the natural reading of
        # "items to skip") - rather than by 1 (the next page number) - was
        # exactly why an earlier version of this fix still failed: it
        # requested offset=500 for page 2 (intending "skip 500 rows"),
        # which the real API instead read as "give me page #500" and
        # correctly-per-that-reading returned nothing.
        row_count = RESULTS_PAGE_SIZE + 64
        all_rows = [
            Result(type="sast", id=f"r{i}", alternate_id=f"alt-{i}", similarity_id=str(i), data=None)
            for i in range(row_count)
        ]
        requested_offsets = []

        def fake_get_all_results(scan_id, offset=0, limit=500, **kw):
            requested_offsets.append(offset)
            # A row-skip interpretation of offset would slice all_rows[offset:...],
            # which for offset=500 (following a first page of 500 rows) would
            # wrongly return nothing here too - so assert on the exact
            # offsets requested instead of just the final row count, to
            # pin down *how* pagination advances, not just whether it
            # eventually stops.
            if offset == 0:
                return {"results": all_rows[:limit], "totalCount": row_count}
            if offset == 1:
                return {"results": all_rows[limit:], "totalCount": row_count}
            return {"results": [], "totalCount": row_count}

        self.resolver._scanner_results_api.get_all_scanners_results_by_scan_id = fake_get_all_results

        fetched = self.resolver._get_all_results(SCAN_ID)

        self.assertEqual(requested_offsets, [0, 1])
        self.assertEqual(len(fetched), row_count)

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

    def test_two_sast_jobs_sharing_a_similarity_id_are_deduped_into_one_trigger_resultid(self):
        # Two distinct VulnerabilityId ticket fields (2 different
        # resultHashes) can resolve to the same similarityId (see
        # test_sast_ambiguous_similarity_id_picks_one_row_and_logs_details_instead_of_failing).
        # Both end up with the same representative alternateId/groupId, so
        # the trigger call should only submit that resultID once.
        dup_row_a = Result(type="sast", id="dup-a", alternate_id="alt-dup-a", similarity_id="999999999", data=None)
        dup_row_b = Result(type="sast", id="dup-b", alternate_id="alt-dup-b", similarity_id="999999999", data=None)
        self.resolver._scanner_results_api.get_all_scanners_results_by_scan_id = (
            lambda scan_id, offset=0, limit=500, **kw: {"results": [dup_row_a, dup_row_b], "totalCount": 2}
        )
        sast_results_by_hash = {
            "hash-a": SastResult(result_hash="hash-a", similarity_id=999999999),
            "hash-b": SastResult(result_hash="hash-b", similarity_id=999999999),
        }
        self.resolver._sast_results_api.get_sast_results_by_scan_id = (
            lambda scan_id, result_id=None, limit=1, **kw: {
                "results": [sast_results_by_hash[result_id[0]]], "totalCount": 1,
            }
        )
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-9", result_hash="hash-a"),
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-9", result_hash="hash-b"),
        ]

        outcomes = self.resolver.resolve_and_trigger_all(jobs)

        self.assertEqual([o.status for o in outcomes], ["accepted", "accepted"])
        self.assertEqual(outcomes[0].alternate_id, "alt-dup-a")
        self.assertEqual(outcomes[1].alternate_id, "alt-dup-a")  # same representative row
        self.assertEqual(outcomes[0].group_id, outcomes[1].group_id)
        self.assertEqual(len(self.resolver.trigger_calls), 1)
        _, buckets = self.resolver.trigger_calls[0]
        _, result_ids = buckets[0]
        self.assertEqual(result_ids, ["alt-dup-a"])  # de-duplicated, not sent twice
        self.assertEqual(outcomes[0].triage_id, outcomes[1].triage_id)
        # The existing-triage pre-check is only made once for the shared groupId too.
        self.assertEqual(len(self.resolver.existing_triage_check_calls), 1)

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

    def test_a_stuck_in_progress_status_does_not_block_a_retry(self):
        # A live tenant showed a multi-resultID batch trigger where only 1
        # of 3 resultIDs ended up with a real verdict - the other 2 stayed
        # IN_PROGRESS indefinitely, confirmed still IN_PROGRESS on a
        # follow-up run. There's no timestamp on AiTriageResult to tell
        # "still actively processing" apart from "stuck forever", so
        # IN_PROGRESS must not block a retry the way FAILED doesn't -
        # otherwise a result stuck like this can never be retried, ever.
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="IN_PROGRESS")

        outcome = self.resolver.resolve_and_trigger(job)

        self.assertIsNone(outcome.trigger_skipped_reason)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(outcome.triage_id, "triage-1")
        self.assertEqual(len(self.resolver.trigger_calls), 1)

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

    def test_a_prior_failed_status_does_not_block_a_retry(self):
        # Unlike other terminal statuses, FAILED means AI Triage itself never
        # produced a verdict - it must not be treated as "already exists",
        # or a genuinely failed attempt could never be retried automatically.
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="FAILED")

        outcome = self.resolver.resolve_and_trigger(job)

        self.assertIsNone(outcome.trigger_skipped_reason)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertEqual(outcome.triage_id, "triage-1")
        self.assertEqual(len(self.resolver.trigger_calls), 1)

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

    def test_off_schema_existing_result_still_triggers_and_logs_the_body(self):
        # A 200 with no triageStatus at all is not a real result - treat it
        # like "nothing yet" (trigger normally) but log the raw body so the
        # off-schema response is visible instead of silently swallowed.
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus=None)
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(
            {"detail": "placeholder"}
        )
        job = TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz")
        with self.assertLogs("cxone_ai_triage", level="WARNING") as cm:
            outcome = self.resolver.resolve_and_trigger(job)
        self.assertEqual(outcome.status, "accepted", outcome.error)
        self.assertIsNone(outcome.trigger_skipped_reason)
        self.assertEqual(len(self.resolver.trigger_calls), 1)
        self.assertTrue(any("placeholder" in line for line in cm.output))

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

    def test_mixed_sca_batch_only_triggers_the_cve_without_an_existing_result(self):
        # Same as test_mixed_batch_only_triggers_the_jobs_without_an_existing_result,
        # but for SCA: each subtask's groupId comes from /api/risks per-CVE
        # (see _fake_get_risks), so the pre-check must still be per-CVE, not
        # per-ticket, when a ticket has multiple "SCA | CVE-..." subtasks.
        self.resolver.existing_triage_by_group_id["groupid-for-CVE-2021-44228"] = AiTriageResult(
            triageStatus="CONFIRMED"
        )
        jobs = [
            TriageJob(
                scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-11",
                cve_id="CVE-2021-44228", package_identifier="log4j-core-2.14.1",
            ),
            TriageJob(scan_id=SCAN_ID, scanner_type="sca", ticket_key="T-11", cve_id="CVE-2022-23305"),
        ]
        outcomes = self.resolver.resolve_and_trigger_all(jobs)

        already_done, needs_trigger = outcomes
        self.assertEqual(already_done.status, "accepted", already_done.error)
        self.assertIsNotNone(already_done.trigger_skipped_reason)
        self.assertIn("CONFIRMED", already_done.trigger_skipped_reason)
        self.assertIsNone(needs_trigger.trigger_skipped_reason)
        self.assertEqual(needs_trigger.status, "accepted", needs_trigger.error)
        # Only the un-triaged CVE made it into the batch.
        self.assertEqual(self.resolver.trigger_calls, [(SCAN_ID, [("sca", ["alt-sca-c"])])])

    def test_batch_call_is_skipped_entirely_when_every_job_already_has_a_result(self):
        # If every job sharing a (scan_id, scanner_type) is already triaged,
        # no POST /api/ai-triage/triage should happen at all for that group -
        # not even with an empty bucket.
        self.resolver.existing_triage_by_group_id["123456"] = AiTriageResult(triageStatus="VULNERABLE")
        self.resolver.existing_triage_by_group_id["654321"] = AiTriageResult(triageStatus="CONFIRMED")
        jobs = [
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-xyz"),
            TriageJob(scan_id=SCAN_ID, scanner_type="sast", ticket_key="T-1", result_hash="hash-two"),
        ]
        outcomes = self.resolver.resolve_and_trigger_all(jobs)

        self.assertTrue(all(o.trigger_skipped_reason for o in outcomes))
        self.assertTrue(all(o.status == "accepted" for o in outcomes))
        self.assertEqual(self.resolver.trigger_calls, [])

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

    def test_logs_each_status_check_so_a_long_wait_is_not_silent(self):
        # A bounded-but-long wait (default timeout 180s) with zero log
        # output in between looks indistinguishable from a hang in a live
        # GitHub Actions log - every check must be visible.
        terminal = AiTriageResult(triageStatus="VULNERABLE")
        self.resolver._ai_triage_api.retrieve_ai_triage_results = lambda p, g: terminal
        with self.assertLogs("cxone_ai_triage", level="INFO") as cm:
            self.resolver.poll_ai_triage_result(PROJECT_ID, "group-1")
        self.assertTrue(any("VULNERABLE" in line for line in cm.output))

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

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_one_off_schema_round_is_tolerated_when_a_real_status_follows(self, mock_sleep):
        # A placeholder body (no triageStatus) could in principle transition
        # to a real status; a single off-schema round must not kill the poll.
        responses = iter([
            AiTriageResult(triageStatus=None),
            AiTriageResult(triageStatus="VULNERABLE"),
        ])
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response({})
        self.resolver._ai_triage_api.retrieve_ai_triage_results = lambda p, g: next(responses)
        result = self.resolver.poll_ai_triage_result(
            PROJECT_ID, "group-1", timeout_seconds=60, interval_seconds=1
        )
        self.assertEqual(result.triageStatus, "VULNERABLE")
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_raises_missing_status_error_instead_of_timing_out_when_response_is_off_schema(self, mock_sleep):
        # A live tenant's API returned 200 with a ~100-byte body that has no
        # triageStatus at all (the field is required per the docs) for a
        # trigger it accepted but never processed - identical on every poll.
        # Polling the full timeout window against that is just a slow
        # timeout; fail fast with the raw body in the error instead.
        raw = {"detail": "placeholder"}
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(raw)
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(triageStatus=None)
        )
        with self.assertRaises(AiTriageMissingStatusError) as cm:
            self.resolver.poll_ai_triage_result(
                PROJECT_ID, "group-1", timeout_seconds=60, interval_seconds=1
            )
        self.assertIn("raw response body", str(cm.exception))
        self.assertIn("placeholder", str(cm.exception))
        self.assertEqual(mock_sleep.call_count, 1)  # one grace round, not the full window

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_job_status_envelope_in_progress_keeps_polling_for_the_real_result(self, mock_sleep):
        # A live tenant's endpoint returns {projectID, groupID, jobStatus:
        # IN_PROGRESS} (no triageStatus) while the triage job is still
        # processing. That must be treated as "in progress" - keep waiting
        # for the real AiTriageResult - not as an off-schema failure.
        responses = iter([
            AiTriageResult(triageStatus=None),
            AiTriageResult(triageStatus=None),
            AiTriageResult(triageStatus="VULNERABLE"),
        ])
        raw = {"projectID": PROJECT_ID, "groupID": "group-1", "jobStatus": "IN_PROGRESS"}
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(raw)
        self.resolver._ai_triage_api.retrieve_ai_triage_results = lambda p, g: next(responses)
        result = self.resolver.poll_ai_triage_result(
            PROJECT_ID, "group-1", timeout_seconds=60, interval_seconds=1
        )
        self.assertEqual(result.triageStatus, "VULNERABLE")
        self.assertEqual(mock_sleep.call_count, 2)  # two IN_PROGRESS rounds, then the real result

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_job_status_envelope_that_never_finishes_times_out_like_in_progress(self, mock_sleep):
        # Same envelope, but the job never completes within the window: the
        # poll must run the full timeout (the job is genuinely running, not
        # off-schema) and end in TimeoutError, not AiTriageMissingStatusError.
        raw = {"projectID": PROJECT_ID, "groupID": "group-1", "jobStatus": "IN_PROGRESS"}
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(raw)
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(triageStatus=None)
        )
        with patch("cxone_ai_triage.resolver.time.monotonic", side_effect=[0, 1, 2, 3, 4, 5]):
            with self.assertRaises(TimeoutError) as cm:
                self.resolver.poll_ai_triage_result(
                    PROJECT_ID, "group-1", timeout_seconds=2, interval_seconds=1
                )
        self.assertIn("IN_PROGRESS", str(cm.exception))

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_polls_past_a_transient_to_verify_status_until_the_settled_verdict(self, mock_sleep):
        # A live tenant showed the API serving triageStatus=TO_VERIFY right
        # after a triage job completed, with the settled verdict (e.g.
        # PROPOSED_NOT_EXPLOITABLE) landing moments later. Posting a Jira
        # comment with the transient state would mislead, so keep polling.
        responses = iter([
            AiTriageResult(triageStatus="TO_VERIFY"),
            AiTriageResult(triageStatus="PROPOSED_NOT_EXPLOITABLE"),
        ])
        self.resolver._ai_triage_api.retrieve_ai_triage_results = lambda p, g: next(responses)
        result = self.resolver.poll_ai_triage_result(
            PROJECT_ID, "group-1", timeout_seconds=60, interval_seconds=1
        )
        self.assertEqual(result.triageStatus, "PROPOSED_NOT_EXPLOITABLE")
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_to_verify_at_the_deadline_is_returned_as_is_instead_of_timing_out(self, mock_sleep):
        # A live tenant's SCA result stayed TO_VERIFY (analysis complete)
        # for the whole poll window while the UI already showed the settled
        # PROPOSED_NOT_EXPLOITABLE state - the endpoint never settled. The
        # completed analysis is still usable: return it at the deadline
        # instead of raising TimeoutError so the run posts the comment.
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(
                triageStatus="TO_VERIFY",
                reachabilityStatus="NOT_REACHABLE",
                exploitabilityStatus="NOT_EXPLOITABLE",
            )
        )
        with patch("cxone_ai_triage.resolver.time.monotonic", side_effect=[0, 1, 2, 3, 4, 5]):
            result = self.resolver.poll_ai_triage_result(
                PROJECT_ID, "group-1", timeout_seconds=2, interval_seconds=1
            )
        self.assertEqual(result.triageStatus, "TO_VERIFY")
        self.assertEqual(result.reachabilityStatus, "NOT_REACHABLE")
        self.assertEqual(result.exploitabilityStatus, "NOT_EXPLOITABLE")

    def test_raw_body_fetch_retries_once_after_a_transient_failure(self):
        # The API has been observed returning the job envelope on one GET
        # and 404 on the identical follow-up GET a moment later; the raw
        # body fetch retries once before giving up.
        from types import SimpleNamespace

        attempts = []

        def flappy(method, url, headers):
            attempts.append(url)
            if len(attempts) == 1:
                raise RuntimeError("transient 404")
            return SimpleNamespace(json=lambda: {"jobStatus": "IN_PROGRESS"})

        self.resolver._ai_triage_api.api_client.call_api = flappy
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(triageStatus=None)
        )
        with patch("cxone_ai_triage.resolver.time.sleep") as mock_sleep:
            result, raw = self.resolver._retrieve_triage_result(PROJECT_ID, "group-1")
        self.assertEqual(raw, {"jobStatus": "IN_PROGRESS"})
        self.assertEqual(len(attempts), 2)
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_job_status_envelope_with_a_non_in_progress_status_fails_fast(self, mock_sleep):
        # An envelope whose jobStatus is not IN_PROGRESS (e.g. FAILED) will
        # never turn into a result on its own - fail fast with the raw body
        # instead of polling the whole timeout window.
        raw = {"projectID": PROJECT_ID, "groupID": "group-1", "jobStatus": "FAILED"}
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(raw)
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(triageStatus=None)
        )
        with self.assertRaises(AiTriageMissingStatusError) as cm:
            self.resolver.poll_ai_triage_result(
                PROJECT_ID, "group-1", timeout_seconds=60, interval_seconds=1
            )
        self.assertIn("FAILED", str(cm.exception))
        self.assertEqual(mock_sleep.call_count, 1)


class TestPollAiTriageResults(unittest.TestCase):
    """poll_ai_triage_results - the batch method pipeline.py actually calls,
    so a ticket's several findings are polled together instead of one
    fully-waited-out job at a time (see resolver.py's docstring)."""

    def setUp(self):
        self.resolver = FakeSdkResolver()

    def test_logs_each_targets_status_check_so_a_long_wait_is_not_silent(self):
        # pipeline.py calls this batch method, not the singular
        # poll_ai_triage_result - a live report of "it never even tries to
        # get the other 2 vulnerability id triage result" turned out to be
        # this method silently checking them every round with zero log
        # output, not an actual skip.
        self.resolver._ai_triage_api.retrieve_ai_triage_results = (
            lambda p, g: AiTriageResult(triageStatus="VULNERABLE")
        )
        with self.assertLogs("cxone_ai_triage", level="INFO") as cm:
            self.resolver.poll_ai_triage_results([(PROJECT_ID, "group-1"), (PROJECT_ID, "group-2")])
        self.assertTrue(any("group-1" in line and "VULNERABLE" in line for line in cm.output))
        self.assertTrue(any("group-2" in line and "VULNERABLE" in line for line in cm.output))

    def test_all_targets_already_terminal_in_one_round(self):
        responses = {
            "group-1": AiTriageResult(triageStatus="VULNERABLE"),
            "group-2": AiTriageResult(triageStatus="PROPOSED_NOT_EXPLOITABLE"),
        }
        calls = []

        def fake_retrieve(project_id, group_id):
            calls.append((project_id, group_id))
            return responses[group_id]

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        results = self.resolver.poll_ai_triage_results(
            [(PROJECT_ID, "group-1"), (PROJECT_ID, "group-2")],
            timeout_seconds=60, interval_seconds=1,
        )
        self.assertEqual([r.triageStatus for r in results], ["VULNERABLE", "PROPOSED_NOT_EXPLOITABLE"])
        self.assertEqual(len(calls), 2)  # one GET per target, no re-polling once resolved

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_stops_querying_a_target_once_it_resolves_while_others_are_still_pending(self, mock_sleep):
        # group-1 finishes on the very first round; group-2 needs a second.
        # group-1 must not be queried again in round 2 - that's the whole
        # point of batching: stop as soon as *that* target has its answer,
        # instead of fully waiting out group-1's own poll loop before even
        # starting group-2's (the old one-job-at-a-time behavior).
        group_1_calls = 0
        group_2_responses = iter([
            AiTriageResult(triageStatus="IN_PROGRESS"),
            AiTriageResult(triageStatus="VULNERABLE"),
        ])

        def fake_retrieve(project_id, group_id):
            nonlocal group_1_calls
            if group_id == "group-1":
                group_1_calls += 1
                return AiTriageResult(triageStatus="VULNERABLE")
            return next(group_2_responses)

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        results = self.resolver.poll_ai_triage_results(
            [(PROJECT_ID, "group-1"), (PROJECT_ID, "group-2")],
            timeout_seconds=60, interval_seconds=1,
        )
        self.assertEqual(results[0].triageStatus, "VULNERABLE")
        self.assertEqual(results[1].triageStatus, "VULNERABLE")
        self.assertEqual(group_1_calls, 1)  # not re-queried once resolved
        self.assertEqual(mock_sleep.call_count, 1)  # one round of waiting, not one per job

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_per_target_timeout_leaves_other_results_intact(self, mock_sleep):
        def fake_retrieve(project_id, group_id):
            if group_id == "group-1":
                return AiTriageResult(triageStatus="VULNERABLE")
            return AiTriageResult(triageStatus="IN_PROGRESS")

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        with patch("cxone_ai_triage.resolver.time.monotonic", side_effect=[0, 1, 2, 3, 4, 5]):
            results = self.resolver.poll_ai_triage_results(
                [(PROJECT_ID, "group-1"), (PROJECT_ID, "group-2")],
                timeout_seconds=2, interval_seconds=1,
            )
        self.assertEqual(results[0].triageStatus, "VULNERABLE")
        self.assertIsInstance(results[1], TimeoutError)

    def test_a_retrieve_exception_for_one_target_does_not_block_the_others(self):
        def fake_retrieve(project_id, group_id):
            if group_id == "group-bad":
                raise RuntimeError("503 Service Unavailable")
            return AiTriageResult(triageStatus="VULNERABLE")

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        results = self.resolver.poll_ai_triage_results(
            [(PROJECT_ID, "group-bad"), (PROJECT_ID, "group-1")],
            timeout_seconds=60, interval_seconds=1,
        )
        self.assertIsInstance(results[0], RuntimeError)
        self.assertEqual(results[1].triageStatus, "VULNERABLE")

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_off_schema_target_fails_fast_while_others_keep_polling(self, mock_sleep):
        # Same live-tenant scenario as the single-target test, but on the
        # batch path pipeline.py uses: the stuck target errors out after 2
        # rounds instead of dragging the whole poll to the timeout, and a
        # healthy target in the same batch still resolves normally.
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(
            {"detail": "placeholder"}
        )

        def fake_retrieve(project_id, group_id):
            if group_id == "group-bad":
                return AiTriageResult(triageStatus=None)
            return AiTriageResult(triageStatus="VULNERABLE")

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        results = self.resolver.poll_ai_triage_results(
            [(PROJECT_ID, "group-bad"), (PROJECT_ID, "group-1")],
            timeout_seconds=60, interval_seconds=1,
        )
        self.assertIsInstance(results[0], AiTriageMissingStatusError)
        self.assertIn("placeholder", str(results[0]))
        self.assertEqual(results[1].triageStatus, "VULNERABLE")
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_to_verify_target_returns_its_result_at_the_deadline_while_others_time_out(self, mock_sleep):
        # Same TO_VERIFY-never-settles case on the batch path: the
        # TO_VERIFY target's completed analysis is returned as-is at the
        # deadline; a still-IN_PROGRESS target still gets a TimeoutError.
        raw = {"projectID": PROJECT_ID, "groupID": "group-ip", "jobStatus": "IN_PROGRESS"}
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(raw)

        def fake_retrieve(project_id, group_id):
            if group_id == "group-tv":
                return AiTriageResult(
                    triageStatus="TO_VERIFY", reachabilityStatus="NOT_REACHABLE"
                )
            return AiTriageResult(triageStatus=None)

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        with patch("cxone_ai_triage.resolver.time.monotonic", side_effect=[0, 1, 2, 3, 4, 5]):
            results = self.resolver.poll_ai_triage_results(
                [(PROJECT_ID, "group-tv"), (PROJECT_ID, "group-ip")],
                timeout_seconds=2, interval_seconds=1,
            )
        self.assertEqual(results[0].triageStatus, "TO_VERIFY")
        self.assertIsInstance(results[1], TimeoutError)

    @patch("cxone_ai_triage.resolver.time.sleep")
    def test_in_progress_job_envelope_target_keeps_polling_while_others_resolve(self, mock_sleep):
        # Same job-status envelope as the single-target test, on the batch
        # path: the enveloped target must keep polling (not fail fast)
        # while a healthy target resolves on round 1.
        raw = {"projectID": PROJECT_ID, "groupID": "group-env", "jobStatus": "IN_PROGRESS"}
        self.resolver._ai_triage_api.api_client.call_api = _fake_raw_body_response(raw)
        env_responses = iter([
            AiTriageResult(triageStatus=None),
            AiTriageResult(triageStatus="PROPOSED_NOT_EXPLOITABLE"),
        ])

        def fake_retrieve(project_id, group_id):
            if group_id == "group-env":
                return next(env_responses)
            return AiTriageResult(triageStatus="VULNERABLE")

        self.resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve
        results = self.resolver.poll_ai_triage_results(
            [(PROJECT_ID, "group-env"), (PROJECT_ID, "group-1")],
            timeout_seconds=60, interval_seconds=1,
        )
        self.assertEqual(results[0].triageStatus, "PROPOSED_NOT_EXPLOITABLE")
        self.assertEqual(results[1].triageStatus, "VULNERABLE")
        self.assertEqual(mock_sleep.call_count, 1)


class _FakeConfiguration:
    server_base_url = "https://fake.ast.checkmarx.net"


class _FakeApiClient:
    """Minimal stand-in for CheckmarxPythonSDK's ApiClient: each CxOne SDK
    class's __init__ reads .configuration.server_base_url to build its
    base_url, so a bare sentinel object isn't enough - identity is what
    this test actually checks."""

    configuration = _FakeConfiguration()


class TestSharedApiClient(unittest.TestCase):
    def test_all_five_sdk_clients_share_one_api_client(self):
        sentinel = _FakeApiClient()
        resolver = TriageResolver(api_client=sentinel)

        clients = {
            resolver._scans_api.api_client,
            resolver._sast_results_api.api_client,
            resolver._scanner_results_api.api_client,
            resolver._risks_api.api_client,
            resolver._ai_triage_api.api_client,
        }
        self.assertEqual(clients, {sentinel})


if __name__ == "__main__":
    unittest.main()
