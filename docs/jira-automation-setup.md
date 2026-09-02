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
  `customfield_10208`) are specific to this Jira site/project. Custom field
  IDs are **not portable across Jira sites** — if you're setting this up
  somewhere else, look up the right IDs first (Project settings → Fields, or
  `GET /rest/api/3/field` on that site) rather than reusing these verbatim.

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
[{"key":"JVL-11","summary":"CVE-2021-44228 - log4j-core-2.14.1","status":"To Do","assignee":"dev-owner@example.com","created":"2026-08-20T09:15:00.000-0000","url":"https://.../browse/JVL-11"},{"key":"JVL-12","summary":"CVE-2022-23305 - log4j-core-2.14.1","status":"To Do","assignee":"dev-owner@example.com","created":"2026-08-20T09:16:00.000-0000","url":"https://.../browse/JVL-12"}]
```

This is the shape `cxone_ai_triage/jira_parser.py` expects for SCA tickets:
a flat `{"key": ..., "summary": ..., ...}` object per subtask (not nested
under a `fields` key), with the CVE ID embedded in `summary`.

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
      "VulnerabilityId1": "{{issue.customfield_10208.jsonEncode}}"
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
| `scanId` | custom field `customfield_10207` | sent directly rather than only being embedded in `description`; **not yet consumed by `jira_parser.py`**, which still regex-extracts the scan ID from `description` — see "Next step" below |
| `VulnerabilityId1` | custom field `customfield_10208` | **not yet consumed anywhere in `cxone_ai_triage`** — purpose/shape (e.g. is this the SAST `result-id`, meant to replace the description regex?) needs confirming before wiring it in |

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

## Next step (not yet done)

`cxone_ai_triage/jira_parser.py` currently gets the scan ID and SAST
`result-id` by regex-parsing `description`, and only uses `subtasks` for
SCA CVE extraction. Now that `scanId` (and possibly `VulnerabilityId1`) are
sent as their own structured fields, the parser could prefer those directly
and fall back to the description regex only if they're absent — more robust
than parsing wiki markup. Confirm what `VulnerabilityId1` is meant to hold,
and let's wire this in.
