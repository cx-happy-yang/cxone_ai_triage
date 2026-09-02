"""Fully-offline demo of the real pipeline: parse_jira_issue -> resolve ->
batch-trigger -> poll -> post Jira comment (comment_formatter.format_comment)
-- with every CxOne SDK call and every Jira API call faked out and logged,
so the whole flow can be inspected without a live tenant.

Run: python examples/demo_offline_run.py

Two tickets sharing one scan (a realistic "one scan, two Jira tickets"
setup): JVL-2 is SAST with VulnerabilityId1 + VulnerabilityId2 populated
(exercises batching + two distinct verdicts); JVL-10 is SCA with two
"SCA | CVE-..." subtasks under one packageNameVersion (exercises batching +
per-subtask comments). All four results get DIFFERENT verdicts on purpose,
to show format_comment handles the full range and that each result gets
its own tailored Jira comment -- not one merged comment per ticket/batch.
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from CheckmarxPythonSDK.CxOne.dto import (
    AiTriageResponse,
    AiTriageResult,
    ConfidenceScore,
    ExploitabilityAnalysis,
    ReachabilityAnalysis,
    Result,
    Risk,
    RisksMetaData,
    RisksResponse,
    SastResult,
    Scan,
    TriageAnalysis,
    VulnerabilityMetadata,
)

from cxone_ai_triage.jira_parser import parse_jira_issue
from cxone_ai_triage.pipeline import run_pipeline
from cxone_ai_triage.resolver import TriageResolver

logging.basicConfig(level=logging.DEBUG, format="%(levelname)-7s %(name)s: %(message)s")
logger = logging.getLogger("demo")
fake_logger = logging.getLogger("demo.fake_api")

SCAN_ID = "d01d7561-2bf5-48b2-bbaa-da166c671fc3"
PROJECT_ID = "1b49ad6f-057f-400c-aa32-f6bc31caf242"

# ---------------------------------------------------------------------------
# 1. Sample jira_issue payloads, shaped exactly like Prudential's real
#    Jira Automation "send web request" body (see docs/jira-automation-setup.md).
# ---------------------------------------------------------------------------

SAST_ISSUE = {
    "key": "JVL-2",
    "summary": "SQL_Injection @ /src/main/webapp/vulnerability/forum.jsp",
    "description": (
        r"*Checkmarx \(SAST\):* SQL_Injection" "\n"
        r"*Checkmarx Project:* [JavaVulnerableLab|https://sng.ast.checkmarx.net/"
        f"projects/{PROJECT_ID}/overview?branch=master]" "\n"
        r"*Branch:* master" "\n"
        r"*Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|https://sng.ast.checkmarx.net/"
        f"projects/{PROJECT_ID}/scans?id={SCAN_ID}&branch=master]"
    ),
    "status": "To Do",
    "priority": "Highest",
    "issue_type": "Bug",
    "project": "JVL",
    "reporter": "security-bot@example.com",
    "assignee": "dev-owner@example.com",
    "labels": ["checkmarx", "sast"],
    "url": "",
    "created": "2026-08-20T09:15:00.000-0000",
    "updated": "2026-08-27T14:02:00.000-0000",
    "scanId": SCAN_ID,
    "VulnerabilityId1": "XZBiE9xWT5WiRxxnpMKmKfZUJuA=",
    "VulnerabilityId2": "N4mYQvKzX8pLr2sTuVwXyZ0abCd=",
}

SCA_ISSUE = {
    "key": "JVL-10",
    "summary": "SCA findings for JavaVulnerableLab scan",
    "description": (
        r"*Checkmarx \(SCA\):* Vulnerable Open Source Dependencies" "\n"
        r"*Checkmarx Project:* [JavaVulnerableLab|https://sng.ast.checkmarx.net/"
        f"projects/{PROJECT_ID}/overview?branch=master]" "\n"
        r"*Branch:* master" "\n"
        r"*Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|https://sng.ast.checkmarx.net/"
        f"projects/{PROJECT_ID}/scans?id={SCAN_ID}&branch=master]"
    ),
    "status": "To Do",
    "priority": "High",
    "issue_type": "Task",
    "project": "JVL",
    "reporter": "security-bot@example.com",
    "assignee": "dev-owner@example.com",
    "labels": ["checkmarx", "sca"],
    "url": "",
    "created": "2026-08-20T09:20:00.000-0000",
    "updated": "2026-08-27T14:05:00.000-0000",
    "scanId": SCAN_ID,
    "packageNameVersion": "log4j-core 2.14.1",
    "subtasks": [
        {
            "key": "JVL-11", "summary": "SCA | CVE-2021-44228", "status": "To Do",
            "assignee": "dev-owner@example.com", "created": "2026-08-20T09:21:00.000-0000",
            "url": "https://sng.ast.checkmarx.net/browse/JVL-11",
        },
        {
            "key": "JVL-12", "summary": "SCA | CVE-2022-23305", "status": "To Do",
            "assignee": "dev-owner@example.com", "created": "2026-08-20T09:22:00.000-0000",
            "url": "https://sng.ast.checkmarx.net/browse/JVL-12",
        },
    ],
}

# ---------------------------------------------------------------------------
# 2. Fake CxOne data: one scan producing both SAST and SCA results (so the
#    /api/results page is fetched once and shared across both tickets).
# ---------------------------------------------------------------------------

ALL_RESULTS = [
    Result(type="sast", id="r1", alternate_id="alt-sast-forum-sqli",
           similarity_id="2621223299958738513", data=None),
    Result(type="sast", id="r2", alternate_id="alt-sast-login-sqli",
           similarity_id="9988776655", data=None),
    Result(type="sca", id="r3", alternate_id="alt-sca-log4shell",
           similarity_id="CVE-2021-44228", data={"packageIdentifier": "log4j-core-2.14.1"}),
    Result(type="sca", id="r4", alternate_id="alt-sca-log4j-2",
           similarity_id="CVE-2022-23305", data={"packageIdentifier": "log4j-core-2.14.1"}),
]

SAST_RESULTS_BY_HASH = {
    "XZBiE9xWT5WiRxxnpMKmKfZUJuA=": SastResult(
        result_hash="XZBiE9xWT5WiRxxnpMKmKfZUJuA=", similarity_id=2621223299958738513),
    "N4mYQvKzX8pLr2sTuVwXyZ0abCd=": SastResult(
        result_hash="N4mYQvKzX8pLr2sTuVwXyZ0abCd=", similarity_id=9988776655),
}

# Deliberately different verdicts per result, to show format_comment handles
# the full range and that each one gets its own comment.
POLL_RESULTS_BY_GROUP_ID = {
    "2621223299958738513": AiTriageResult(
        resultID="r1", scanner="sast", triageStatus="PROPOSED_NOT_EXPLOITABLE",
        reachabilityStatus="NOT_REACHABLE", exploitabilityStatus="NOT_EXPLOITABLE",
        summary="The tainted input is fully sanitized via PreparedStatement before reaching the query.",
        triagedAt="2026-09-02T10:00:00Z",
        analysis=TriageAnalysis(
            confidence=ConfidenceScore(score=91, explanation="Strong static evidence of parameterized query usage."),
            reachability=ReachabilityAnalysis(status="NOT_REACHABLE", reasoning="The vulnerable sink sits behind an admin-only code path never invoked from user input."),
            exploitability=ExploitabilityAnalysis(status="NOT_EXPLOITABLE", reasoning="Input is bound via PreparedStatement parameters, not concatenated."),
            usage_locations=["src/main/webapp/vulnerability/forum.jsp:48"],
        ),
    ),
    "9988776655": AiTriageResult(
        resultID="r2", scanner="sast", triageStatus="VULNERABLE",
        reachabilityStatus="REACHABLE", exploitabilityStatus="EXPLOITABLE",
        summary="Untrusted request parameter flows directly into a raw SQL string without sanitization.",
        triagedAt="2026-09-02T10:01:00Z",
        analysis=TriageAnalysis(
            confidence=ConfidenceScore(score=95, explanation="Direct unsanitized concatenation confirmed via data flow trace."),
            reachability=ReachabilityAnalysis(status="REACHABLE", reasoning="Endpoint is public and directly reachable from the login controller."),
            exploitability=ExploitabilityAnalysis(status="EXPLOITABLE", reasoning="No input validation or escaping present before the query executes."),
            usage_locations=["src/main/webapp/vulnerability/login.jsp:22"],
        ),
    ),
    "groupid-for-CVE-2021-44228": AiTriageResult(
        resultID="r3", scanner="sca", triageStatus="VULNERABLE",
        reachabilityStatus="REACHABLE", exploitabilityStatus="EXPLOITABLE", attackabilityStatus="ATTACKABLE",
        summary="log4j-core 2.14.1 is vulnerable to the Log4Shell JNDI lookup RCE and is actively used for request logging.",
        triagedAt="2026-09-02T10:02:00Z",
        analysis=TriageAnalysis(
            confidence=ConfidenceScore(score=98, explanation="Component version matches the known-vulnerable range and logging calls include user input."),
            reachability=ReachabilityAnalysis(status="REACHABLE", reasoning="Logger.error() calls include unsanitized HTTP header values."),
            exploitability=ExploitabilityAnalysis(status="EXPLOITABLE", reasoning="JNDI lookup pattern substitution is not disabled."),
            usage_locations=["src/main/webapp/filters/RequestLoggingFilter.java:34"],
        ),
        metadata=VulnerabilityMetadata(component="log4j-core", version="2.14.1", dependency_type="direct"),
    ),
    "groupid-for-CVE-2022-23305": AiTriageResult(
        resultID="r4", scanner="sca", triageStatus="UNCERTAIN",
        reachabilityStatus="UNCERTAIN", exploitabilityStatus="UNCERTAIN",
        summary="Insufficient information to confirm whether the vulnerable JDBCAppender class is loaded at runtime.",
        triagedAt="2026-09-02T10:03:00Z",
        analysis=TriageAnalysis(
            confidence=ConfidenceScore(score=40, explanation="No direct usage of JDBCAppender found, but dynamic configuration loading could enable it."),
            reachability=ReachabilityAnalysis(status="UNCERTAIN", reasoning="log4j.properties is loaded from an external, user-writable path in one deployment profile."),
            exploitability=ExploitabilityAnalysis(status="UNCERTAIN", reasoning="Requires attacker-controlled JDBC configuration, which wasn't confirmed reachable."),
        ),
        metadata=VulnerabilityMetadata(component="log4j-core", version="2.14.1", dependency_type="direct"),
    ),
}


# ---------------------------------------------------------------------------
# 3. Fake CxOne SDK + Jira client, logging every "call" as if it were real.
# ---------------------------------------------------------------------------

def install_fakes(resolver: TriageResolver) -> None:
    def fake_get_a_scan_by_id(scan_id):
        fake_logger.info("[FAKE] GET /api/scans/%s", scan_id)
        return Scan(id=scan_id, project_id=PROJECT_ID)

    def fake_get_sast_results_by_scan_id(scan_id, result_id=None, limit=1, **kw):
        fake_logger.info("[FAKE] GET /api/sast-results?scan-id=%s&result-id=%s", scan_id, result_id)
        result = SAST_RESULTS_BY_HASH.get(result_id[0])
        return {"results": [result] if result else [], "totalCount": 1 if result else 0}

    def fake_get_all_scanners_results_by_scan_id(scan_id, offset=0, limit=500, **kw):
        fake_logger.info(
            "[FAKE] GET /api/results?scan-id=%s&offset=%d&limit=%d -> %d row(s)",
            scan_id, offset, limit, len(ALL_RESULTS[offset:offset + limit]),
        )
        return {"results": ALL_RESULTS[offset:offset + limit], "totalCount": len(ALL_RESULTS)}

    def fake_get_risks(project_id, engine=None, risk_name=None, limit=200, **kw):
        cve = risk_name[0]
        fake_logger.info(
            "[FAKE] GET /api/risks?projectId=%s&engine=%s&riskName=%s", project_id, engine, cve
        )
        return RisksResponse(
            metaData=RisksMetaData(),
            risks=[Risk(id=f"risk-{cve}", scanId=SCAN_ID, engine="SCA", groupId=f"groupid-for-{cve}")],
        )

    trigger_call_count = [0]

    def fake_trigger_ai_triage(request):
        trigger_call_count[0] += 1
        for bucket in request.buckets:
            fake_logger.info(
                "[FAKE] POST /api/ai-triage/triage  scanID=%s  scannerType=%s  resultIDs=%s",
                request.scanID, bucket.scannerType, bucket.resultIDs,
            )
        triage_id = f"triage-batch-{trigger_call_count[0]}"
        fake_logger.info("[FAKE]   -> 202 Accepted, triageID=%s", triage_id)
        return AiTriageResponse(scanID=request.scanID, status="accepted", triageID=triage_id, published=True)

    def fake_retrieve_ai_triage_results(project_id, group_id):
        fake_logger.info("[FAKE] GET /api/ai-triage/triage/%s/%s", project_id, group_id)
        result = POLL_RESULTS_BY_GROUP_ID[group_id]
        fake_logger.info(
            "[FAKE]   -> triageStatus=%s reachability=%s exploitability=%s",
            result.triageStatus, result.reachabilityStatus, result.exploitabilityStatus,
        )
        return result

    resolver._scans_api.get_a_scan_by_id = fake_get_a_scan_by_id
    resolver._sast_results_api.get_sast_results_by_scan_id = fake_get_sast_results_by_scan_id
    resolver._scanner_results_api.get_all_scanners_results_by_scan_id = fake_get_all_scanners_results_by_scan_id
    resolver._risks_api.get_risks = fake_get_risks
    resolver._ai_triage_api.trigger_ai_triage = fake_trigger_ai_triage
    resolver._ai_triage_api.retrieve_ai_triage_results = fake_retrieve_ai_triage_results


class FakeJiraClient:
    """Logs what would be posted instead of calling the real Jira API."""

    def __init__(self):
        self.comments = []

    def add_comment(self, issue_key, body):
        self.comments.append((issue_key, body))
        fake_logger.info("[FAKE] POST /rest/api/2/issue/%s/comment", issue_key)
        fake_logger.info("[FAKE]   body: %s", body)


# ---------------------------------------------------------------------------
# 4. Run it.
# ---------------------------------------------------------------------------

def main():
    logger.info("=== Step 1: parse_jira_issue() on both tickets ===")
    sast_jobs = parse_jira_issue(SAST_ISSUE)
    sca_jobs = parse_jira_issue(SCA_ISSUE)
    logger.info("JVL-2 (SAST)  -> %d job(s): %s", len(sast_jobs), [j.result_hash for j in sast_jobs])
    logger.info("JVL-10 (SCA)  -> %d job(s): %s", len(sca_jobs), [(j.ticket_key, j.cve_id) for j in sca_jobs])

    jobs = sast_jobs + sca_jobs

    logger.info("=== Step 2: run_pipeline() — resolve, batch-trigger, poll, comment ===")
    resolver = TriageResolver()
    install_fakes(resolver)
    jira_client = FakeJiraClient()

    outcomes = run_pipeline(jobs, resolver, jira_client, poll=True, post_comment=True)

    logger.info("=== Step 3: final outcomes ===")
    for o in outcomes:
        logger.info(
            "%s  scanner=%s  cve/hash=%s  alternateId=%s  groupId=%s  triageID=%s  "
            "status=%s  aiTriageStatus=%s  commentPosted=%s",
            o.job.ticket_key, o.job.scanner_type, o.job.cve_id or o.job.result_hash,
            o.alternate_id, o.group_id, o.triage_id, o.status, o.ai_triage_status, o.comment_posted,
        )

    print("\n" + "=" * 100)
    print(f"Jira comments actually posted (via FakeJiraClient): {len(jira_client.comments)}")
    print("=" * 100)
    for issue_key, body in jira_client.comments:
        print(f"\n--- comment on {issue_key} ---")
        print(body)


if __name__ == "__main__":
    main()
