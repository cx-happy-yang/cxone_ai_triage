"""Render a completed AiTriageResult into a single Jira-wiki-markup paragraph,
suitable for posting as a comment on the originating ticket/subtask.

Uses every field on AiTriageResult (see CheckmarxPythonSDK.CxOne.dto):
triageStatus, reachabilityStatus/exploitabilityStatus/attackabilityStatus,
summary, analysis (confidence/reachability/exploitability reasoning +
usage_locations), metadata (SCA component/version), reasoningTrace
(verification steps + repository info), scanner/resultID/triagedAt, and
flags a mockOrigin result as a placeholder rather than a live verdict.
"""
from typing import List

from CheckmarxPythonSDK.CxOne.dto import AiTriageResult


def format_comment(result: AiTriageResult) -> str:
    """Build one paragraph (sentence per field group, joined with spaces)."""
    parts: List[str] = []

    if result.mockOrigin:
        parts.append(
            "*Note:* this is a mock/placeholder AI Triage result, not a live verdict."
        )

    parts.append(f"*CxOne AI Triage verdict:* {result.triageStatus or 'UNKNOWN'}.")

    analysis = result.analysis
    confidence = analysis.confidence if analysis else None
    if confidence and (confidence.score or confidence.explanation):
        bits = []
        if confidence.score:
            bits.append(f"{confidence.score}/100")
        if confidence.explanation:
            bits.append(confidence.explanation)
        parts.append(f"*Confidence:* {' - '.join(bits)}.")

    reachability = analysis.reachability if analysis else None
    reach_bit = f"*Reachability:* {result.reachabilityStatus or 'UNSPECIFIED'}"
    if reachability and reachability.reasoning:
        reach_bit += f" - {reachability.reasoning}"
    parts.append(reach_bit + ".")

    exploitability = analysis.exploitability if analysis else None
    exploit_bit = f"*Exploitability:* {result.exploitabilityStatus or 'UNSPECIFIED'}"
    if exploitability and exploitability.reasoning:
        exploit_bit += f" - {exploitability.reasoning}"
    parts.append(exploit_bit + ".")

    if result.attackabilityStatus:
        parts.append(f"*Attackability:* {result.attackabilityStatus}.")

    if analysis and analysis.usage_locations:
        parts.append(f"*Usage locations:* {', '.join(analysis.usage_locations)}.")

    metadata = result.metadata
    if metadata and (metadata.component or metadata.version):
        component_bit = metadata.component or "unknown component"
        if metadata.version:
            component_bit += f" {metadata.version}"
        if metadata.dependency_type:
            component_bit += f" ({metadata.dependency_type})"
        parts.append(f"*Affected component:* {component_bit}.")

    if result.summary:
        parts.append(f"*Summary:* {result.summary}")

    reasoning_trace = result.reasoningTrace
    if reasoning_trace and reasoning_trace.verification_steps:
        steps_text = "; ".join(
            f"{step.task or step.category or 'step'} -> {step.conclusion}"
            for step in reasoning_trace.verification_steps
            if step.conclusion
        )
        if steps_text:
            parts.append(f"*Verification steps:* {steps_text}.")

    repo_info = reasoning_trace.repository_info if reasoning_trace else None
    if repo_info and (repo_info.path or repo_info.description):
        repo_bits = []
        if repo_info.path:
            repo_bits.append(repo_info.path)
        if repo_info.programming_languages:
            repo_bits.append("languages: " + ", ".join(repo_info.programming_languages))
        if repo_info.frameworks:
            repo_bits.append("frameworks: " + ", ".join(repo_info.frameworks))
        if repo_info.build_system:
            repo_bits.append(f"build: {repo_info.build_system}")
        parts.append(f"*Repository:* {' | '.join(repo_bits)}.")

    footer_bits = []
    if result.scanner:
        footer_bits.append(f"scanner: {result.scanner}")
    if result.resultID:
        footer_bits.append(f"result: {result.resultID}")
    if result.triagedAt:
        footer_bits.append(f"triaged at: {result.triagedAt}")
    if footer_bits:
        parts.append(f"_({'; '.join(footer_bits)})_")

    return " ".join(parts)
