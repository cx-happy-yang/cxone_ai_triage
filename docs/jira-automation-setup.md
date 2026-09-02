# Jira Automation rule: dispatching a ticket to cxone-ai-triage

This document configures the Jira Automation rule that fires the
`repository_dispatch` GitHub Actions event `cxone-ai-triage` consumes (see
`cxone_ai_triage/github_event.py` / `jira_parser.py` and
`.github/workflows/` in the repo root). The rule has two actions: **Create
Variable** (builds the subtasks array) and **Send Web Request** (fires the
dispatch).

## Prerequisites

- Edit access to Jira Automation on the project(s) this rule runs against.
- A GitHub personal access token with the **`repo`** scope on
  `happy-cook/JavaVulnerableLab` (required for `POST /repos/.../dispatches`).
  Store it in Jira Automation's secret/connection vault rather than pasting
  it as a literal header value if your Jira plan supports that; otherwise
  keep the raw token out of anywhere the rule's audit log might be shared.
- The Jira **custom field IDs** used below (`customfield_10207`,
  `customfield_10208`, `customfield_10209`) are specific to this Jira
  site/project. Custom field IDs are **not portable across Jira sites** —
  if you're setting this up somewhere else, look up the right IDs first
  (Project settings → Fields, or `GET /rest/api/3/field` on that site)
  rather than reusing these verbatim.

## Step 1 — Trigger

Add whatever trigger fits the workflow this rule is meant to automate (e.g.
a manual trigger for testing, or an issue transitioning into a "Ready for
AI Triage" status). Not covered here since it depends on Prudential's
process — pick the trigger, then continue to Step 2.

## Step 2 — Action: Create Variable

| Field | Value |
|---|---|
| Variable name | `subtasksJsonArr` |
| Smart value | see below |

```
[{{#issue.subtasks}} {   "key":"{{key.jsonEncode}}",   "summary":"{{summary.jsonEncode}}",   "status":"{{status.name.jsonEncode}}",   "assignee":"{{assignee.emailAddress.jsonEncode}}",   "created":"{{created.jsonEncode}}",   "url":"{{url.jsonEncode}}" }{{^last}},{{/}} {{/}}]
```

**What this does:** `{{#issue.subtasks}} ... {{/}}` iterates every subtask
on the ticket. For each one it emits a JSON object with `key`, `summary`,
`status` (the subtask's own status name), `assignee` (email), `created`,
and `url`; `{{^last}},{{/}}` appends a comma after every item except the
last one. The whole thing is wrapped in literal `[` `]` brackets, so the
variable's value is a ready-to-use **JSON array string**, e.g.:

```json
[{"key":"JVL-11","summary":"SCA | CVE-2025-71329","status":"To Do","assignee":"dev-owner@example.com","created":"2026-08-20T09:15:00.000-0000","url":"https://.../browse/JVL-11"},{"key":"JVL-12","summary":"SCA | CVE-2022-23305","status":"To Do","assignee":"dev-owner@example.com","created":"2026-08-20T09:16:00.000-0000","url":"https://.../browse/JVL-12"}]
```

This is the shape `cxone_ai_triage/jira_parser.py` expects for SCA tickets:
a flat `{"key": ..., "summary": ..., ...}` object per subtask (not nested
under a `fields` key), with the CVE ID embedded in `summary` (format
verified against a real subtask: `"SCA | CVE-2025-71329"`). Note the
package name/version is **not** in here — see `packageNameVersion` below,
which lives on the parent ticket instead.

**Caveat to test:** if a subtask has no assignee, confirm what
`{{assignee.emailAddress.jsonEncode}}` renders as (likely an empty string)
rather than breaking the JSON — check a real unassigned subtask before
relying on this in production.

## Step 3 — Action: Send Web Request

| Field | Value |
|---|---|
| Web request URL | `https://api.github.com/repos/happy-cook/JavaVulnerableLab/dispatches` |
| HTTP method | `POST` |
| Headers | `Authorization: Bearer <github-token>`<br>`Accept: application/vnd.github+json`<br>`Content-Type: application/json` |
| Web request body | Custom data |

Custom data:

```json
{
  "event_type": "cxone-ai-triage",
  "client_payload": {
    "jira_issue": {
      "key": "{{issue.key.jsonEncode}}",
      "summary": "{{issue.summary.jsonEncode}}",
      "description": "{{issue.description.jsonEncode}}",
      "status": "{{issue.status.name.jsonEncode}}",
      "priority": "{{issue.priority.name.jsonEncode}}",
      "issue_type": "{{issue.issuetype.name.jsonEncode}}",
      "project": "{{issue.project.key.jsonEncode}}",
      "reporter": "{{issue.reporter.emailAddress.jsonEncode}}",
      "assignee": "{{issue.assignee.emailAddress.jsonEncode}}",
      "labels": "{{issue.labels.jsonEncode}}",
      "url": "{{issue.url.jsonEncode}}",
      "created": "{{issue.created.jsonEncode}}",
      "updated": "{{issue.updated.jsonEncode}}",
      "subtasks": {{subtasksJsonArr}},
      "scanId": "{{issue.customfield_10207.jsonEncode}}",
      "VulnerabilityId1": "{{issue.customfield_10208.jsonEncode}}",
      "packageNameVersion": "{{issue.customfield_10209.jsonEncode}}"
    }
  }
}
```

Field-by-field:

| Field | Source | Notes |
|---|---|---|
| `key`, `summary`, `status`, `priority`, `issue_type`, `project`, `reporter`, `assignee`, `labels`, `url`, `created`, `updated` | standard ticket fields | passed through as-is; `cxone_ai_triage` carries these into its output report as `jira_*` columns for traceability, not used to resolve identifiers |
| `description` | ticket description | for SAST, this is where the scan ID and `result-id=` are regex-extracted from (Jira wiki markup produced by the Checkmarx Jira integration) — see the README's "Why this exists" section |
| `subtasks` | the `subtasksJsonArr` variable from Step 2 | **note it is `{{subtasksJsonArr}}` with no surrounding quotes** — it's already a JSON array, quoting it would turn the array into a string literal and break parsing on the receiving end |
| `scanId` | custom field `customfield_10207` | preferred over the description regex by `jira_parser.py`; falls back to the description's `scans?id=` link only if this field is blank |
| `VulnerabilityId1` | custom field `customfield_10208` (SAST tickets only) | the SAST resultHash/pathSystemId. `jira_parser.py` also supports `VulnerabilityId2`–`VulnerabilityId5` (add them the same way, on additional custom fields, if a ticket ever needs more than one SAST result) — falls back to regex-extracting `result-id=` from the description only if none are set. When more than one is populated, `TriageResolver` batches all of them into a single trigger call rather than one per result (see README's "Batching the trigger call") |
| `packageNameVersion` | custom field `customfield_10209`, **on the parent ticket** (SCA tickets only) | applies to every CVE/subtask under this ticket — the expected structure is one package per ticket, with each of its CVEs as a subtask. Read by `jira_parser.py` into `jira_meta["package_name_version"]` and included in the AI Triage Jira comment (`comment_formatter.py`), since CxOne's own AI Triage response doesn't always populate a component/version |

## Step 4 — Validate

1. Use Jira Automation's rule execution/audit log to confirm the built
   request body is valid JSON (a malformed `subtasksJsonArr` — e.g. a
   trailing comma from a single-subtask edge case — will show up here).
2. Trigger the rule on a real test ticket and confirm the GitHub Actions
   run fires: check the Actions tab of `happy-cook/JavaVulnerableLab` for a
   `cxone-ai-triage` `repository_dispatch` run.
3. Common failure causes: the GitHub token lacks `repo` scope (403/404 on
   dispatch), the repo owner/name in the URL is wrong, or the custom field
   IDs don't match this Jira site's actual field configuration.

## Field resolution order in `cxone_ai_triage`

`jira_parser.py` prefers the structured fields above over the description:
`scanId` for the scan ID, `VulnerabilityId1..5` for SAST result identifiers
(one triage job per populated field, all on the parent ticket key). The
description regex fallback (see the README's "Why this exists" section)
only kicks in when the corresponding structured field is absent — e.g. for
tickets predating this automation rule. SCA still always uses `subtasks`
for the CVE (or, absent that, a bare `CVE-\d{4}-\d+` match in the
description) since there's no VulnerabilityId equivalent for CVEs;
`packageNameVersion` is applied to every SCA job from a ticket regardless
of which path found the CVE.
