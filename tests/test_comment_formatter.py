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

from cxone_ai_triage.comment_formatter import format_comment


class TestFormatComment(unittest.TestCase):
    def test_minimal_result_does_not_crash_or_print_none(self):
        result = AiTriageResult(triageStatus="VULNERABLE")
        comment = format_comment(result)
        self.assertIn("VULNERABLE", comment)
        self.assertNotIn("None", comment)

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


if __name__ == "__main__":
    unittest.main()
