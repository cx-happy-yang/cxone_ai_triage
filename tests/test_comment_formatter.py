import unittest

from CheckmarxPythonSDK.CxOne.dto import (
    AiTriageResult,
    ConfidenceScore,
    ExploitabilityAnalysis,
    ReachabilityAnalysis,
    ReasoningTrace,
    RepositoryInfo,
    TriageAnalysis,
    VerificationStep,
    VulnerabilityMetadata,
)

from cxone_ai_triage.comment_formatter import build_vulnerability_marker_multi, format_comment


class TestFormatComment(unittest.TestCase):
    def test_minimal_result_does_not_crash_or_print_none(self):
        result = AiTriageResult(triageStatus="VULNERABLE")
        comment = format_comment(result)
        self.assertIn("VULNERABLE", comment)
        self.assertNotIn("None", comment)

    def test_triage_status_override_replaces_the_verdict_in_the_comment(self):
        # The pipeline translates a transient TO_VERIFY into the settled
        # risk state (GET /api/risks) before commenting; the override shows
        # the settled state instead of result.triageStatus.
        result = AiTriageResult(triageStatus="TO_VERIFY", reachabilityStatus="NOT_REACHABLE")
        comment = format_comment(result, triage_status_override="PROPOSED_NOT_EXPLOITABLE")
        self.assertIn("PROPOSED_NOT_EXPLOITABLE", comment)
        self.assertNotIn("TO_VERIFY", comment)

    def test_fully_populated_result_includes_every_field(self):
        result = AiTriageResult(
            resultID="res-1",
            scanner="sast",
            triageStatus="PROPOSED_NOT_EXPLOITABLE",
            reachabilityStatus="NOT_REACHABLE",
            exploitabilityStatus="NOT_EXPLOITABLE",
            attackabilityStatus="NOT_ATTACKABLE",
            summary="The tainted input is sanitized before use.",
            triagedAt="2026-08-28T10:00:00Z",
            analysis=TriageAnalysis(
                confidence=ConfidenceScore(score=87, explanation="Strong evidence of sanitization."),
                reachability=ReachabilityAnalysis(status="NOT_REACHABLE", reasoning="Dead code path."),
                exploitability=ExploitabilityAnalysis(status="NOT_EXPLOITABLE", reasoning="Input is escaped."),
                usage_locations=["src/main/webapp/vulnerability/forum.jsp:48"],
            ),
            metadata=VulnerabilityMetadata(component="log4j-core", version="2.14.1", dependency_type="direct"),
            reasoningTrace=ReasoningTrace(
                verification_steps=[
                    VerificationStep(task="Check sanitization", category="REACHABILITY",
                                      status="VERIFIED", conclusion="Input is escaped via PreparedStatement."),
                ],
                repository_info=RepositoryInfo(
                    path="src/main/webapp", description="Web app root",
                    programming_languages=["Java"], frameworks=["Servlet"], build_system="Maven",
                ),
            ),
            groupId="123456",
            projectId="proj-1",
        )
        comment = format_comment(result)

        for expected in [
            "PROPOSED_NOT_EXPLOITABLE",
            "87/100", "Strong evidence of sanitization.",
            "NOT_REACHABLE", "Dead code path.",
            "NOT_EXPLOITABLE", "Input is escaped.",
            "NOT_ATTACKABLE",
            "src/main/webapp/vulnerability/forum.jsp:48",
            "log4j-core 2.14.1 (direct)",
            "The tainted input is sanitized before use.",
            "Check sanitization -> Input is escaped via PreparedStatement.",
            "src/main/webapp", "Java", "Servlet", "Maven",
            "scanner: sast", "result: res-1", "triaged at: 2026-08-28T10:00:00Z",
        ]:
            self.assertIn(expected, comment, f"missing {expected!r} in comment: {comment}")

    def test_mock_origin_is_flagged(self):
        comment = format_comment(AiTriageResult(triageStatus="VULNERABLE", mockOrigin=True))
        self.assertIn("mock/placeholder", comment)

    def test_jira_package_name_version_is_included_when_given(self):
        comment = format_comment(
            AiTriageResult(triageStatus="VULNERABLE"), package_name_version="log4j-core 2.14.1"
        )
        self.assertIn("*Package:* log4j-core 2.14.1.", comment)

    def test_no_package_name_version_omits_the_clause(self):
        comment = format_comment(AiTriageResult(triageStatus="VULNERABLE"))
        self.assertNotIn("*Package:*", comment)

    def test_vulnerability_label_and_subtask_key_lead_the_comment(self):
        # These identify which result a comment is about when several land
        # on the same parent ticket (comments never go on the subtask itself).
        comment = format_comment(
            AiTriageResult(triageStatus="VULNERABLE"),
            vulnerability_label="CVE-2021-44228",
            vulnerability_label_name="CVE ID",
            subtask_key="JVL-11",
        )
        self.assertTrue(comment.startswith("*CVE ID:* CVE-2021-44228. *Subtask:* JVL-11."))

    def test_vulnerability_label_defaults_to_vulnerability_id_for_sast(self):
        comment = format_comment(
            AiTriageResult(triageStatus="VULNERABLE"), vulnerability_label="hash-xyz"
        )
        self.assertTrue(comment.startswith("*Vulnerability ID:* hash-xyz."))

    def test_no_vulnerability_label_or_subtask_key_omits_those_clauses(self):
        comment = format_comment(AiTriageResult(triageStatus="VULNERABLE"))
        self.assertNotIn("*Vulnerability ID:*", comment)
        self.assertNotIn("*CVE ID:*", comment)
        self.assertNotIn("*Subtask:*", comment)

    def test_vulnerability_labels_plural_lists_every_label_and_notes_the_grouping(self):
        # 2+ VulnerabilityId/CVE values that share one AI Triage verdict
        # (e.g. SAST findings that collapsed onto the same similarityId -
        # see resolver._find_alternate_id and pipeline.run_pipeline).
        comment = format_comment(
            AiTriageResult(triageStatus="VULNERABLE"),
            vulnerability_labels=["hash-one", "hash-two"],
        )
        self.assertTrue(comment.startswith("*Vulnerability IDs:* hash-one, hash-two."))
        self.assertIn("grouped them under the same finding", comment)

    def test_vulnerability_labels_takes_precedence_over_vulnerability_label(self):
        comment = format_comment(
            AiTriageResult(triageStatus="VULNERABLE"),
            vulnerability_label="hash-solo",
            vulnerability_labels=["hash-one", "hash-two"],
        )
        self.assertNotIn("hash-solo", comment)
        self.assertTrue(comment.startswith("*Vulnerability IDs:* hash-one, hash-two."))

    def test_build_vulnerability_marker_multi_pluralizes_the_label_name(self):
        self.assertEqual(
            build_vulnerability_marker_multi("CVE ID", ["CVE-2021-44228", "CVE-2022-23305"]),
            "*CVE IDs:* CVE-2021-44228, CVE-2022-23305.",
        )

    def test_jira_package_and_cxone_metadata_both_shown_when_present(self):
        comment = format_comment(
            AiTriageResult(
                triageStatus="VULNERABLE",
                metadata=VulnerabilityMetadata(component="log4j-core", version="2.14.1"),
            ),
            package_name_version="log4j-core 2.14.1 (from Jira)",
        )
        self.assertIn("*Package:* log4j-core 2.14.1 (from Jira).", comment)
        self.assertIn("*Affected component (CxOne):* log4j-core 2.14.1.", comment)


if __name__ == "__main__":
    unittest.main()
