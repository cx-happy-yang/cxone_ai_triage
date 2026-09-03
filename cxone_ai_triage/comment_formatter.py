"""Render a completed AiTriageResult into a single Jira-wiki-markup paragraph,
suitable for posting as a comment on the originating ticket.

Comments always go on the parent ticket, never a subtask (see
pipeline.run_pipeline) — for SAST that's already the ticket the
VulnerabilityId field lives on, but for SCA it means every subtask's CVE
gets commented onto their shared parent instead of its own subtask. Since
that means multiple comments can land on one ticket, each comment leads
with which specific vulnerability it's about: "Vulnerability ID" (matching
the ticket's VulnerabilityIdN field name) for SAST, "CVE ID" for SCA — see
vulnerability_label_name/vulnerability_label. subtask_key additionally
cross-references the originating subtask for SCA.

Uses every field on AiTriageResult (see CheckmarxPythonSDK.CxOne.dto):
triageStatus, reachabilityStatus/exploitabilityStatus/attackabilityStatus,
summary, analysis (confidence/reachability/exploitability reasoning +
usage_locations), metadata (SCA component/version), reasoningTrace
(verification steps + repository info), scanner/resultID/triagedAt, and
flags a mockOrigin result as a placeholder rather than a live verdict.

For SCA, also takes the package name/version from the ticket-level
"Package Name/Version" custom field (TriageJob.jira_meta["package_name_version"]
— see docs/jira-automation-setup.md) rather than relying solely on
AiTriageResult.metadata.component/.version, since CxOne doesn't always
populate that.
"""
from typing import List, Optional

from CheckmarxPythonSDK.CxOne.dto import AiTriageResult


def build_vulnerability_marker(vulnerability_label_name: str, vulnerability_label: str) -> str:
    """The leading "*Vulnerability ID:* <value>." / "*CVE ID:* <value>."
    clause format_comment always starts with when given a label. Exposed
    separately so pipeline.py can check existing Jira comments for this
    exact marker before posting a new one, without duplicating the format
    string (and risking it drifting out of sync with format_comment)."""
    return f"*{vulnerability_label_name}:* {vulnerability_label}."


def format_comment(
    result: AiTriageResult,
    package_name_version: Optional[str] = None,
    vulnerability_label: Optional[str] = None,
    vulnerability_label_name: str = "Vulnerability ID",
    subtask_key: Optional[str] = None,
) -> str:
    """Build one paragraph (sentence per field group, joined with spaces).

    Args:
        result: The finished AiTriageResult to render.
        package_name_version: SCA only — from the ticket's "Package Name/
            Version" custom field.
        vulnerability_label: What this specific result is (the CVE ID for
            SCA, the resultHash/pathSystemId for SAST) — identifies this
            comment among others that may land on the same parent ticket.
        vulnerability_label_name: The label to show it under — pass "CVE ID"
            for SCA; defaults to "Vulnerability ID" (matching the ticket's
            VulnerabilityIdN field name) for SAST.
        subtask_key: SCA only — the originating subtask's key, if this job
            came from one, for cross-reference even though the comment
            itself is posted on the parent.
    """
    parts: List[str] = []

    if vulnerability_label:
        parts.append(build_vulnerability_marker(vulnerability_label_name, vulnerability_label))
    if subtask_key:
        parts.append(f"*Subtask:* {subtask_key}.")

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

    if package_name_version:
        parts.append(f"*Package:* {package_name_version}.")

    metadata = result.metadata
    if metadata and (metadata.component or metadata.version):
        component_bit = metadata.component or "unknown component"
        if metadata.version:
            component_bit += f" {metadata.version}"
        if metadata.dependency_type:
            component_bit += f" ({metadata.dependency_type})"
        parts.append(f"*Affected component (CxOne):* {component_bit}.")

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
