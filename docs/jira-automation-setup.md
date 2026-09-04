# Jira Automation rule: dispatching a ticket to cxone-ai-triage

This document configures the Jira Automation rule that fires the
`repository_dispatch` GitHub Actions event `cxone-ai-triage` consumes (see
`cxone_ai_triage/github_event.py` / `jira_parser.py` and
`.github/workflows/` in the repo root).

The rule only ever needs to send the ticket's **key** — nothing else.
`cxone_ai_triage` fetches the full ticket (and its subtasks) itself via the
Jira REST API and does the field mapping on its own side
(`JiraCommentClient.get_issue_for_triage` / `JiraFieldMapping` in
`cxone_ai_triage/jira_client.py`), so this rule never needs updating again
for a new/changed custom field — that mapping lives in `JIRA_FIELD_*`
environment variables on whatever runs `cxone-ai-triage` instead (see the
README's "Authentication" section).

## Prerequisites

- Edit access to Jira Automation on the project(s) this rule runs against.
- A GitHub personal access token with the **`repo`** scope on
  `happy-cook/JavaVulnerableLab` (required for `POST /repos/.../dispatches`).
  Store it in Jira Automation's secret/connection vault rather than pasting
  it as a literal header value if your Jira plan supports that; otherwise
  keep the raw token out of anywhere the rule's audit log might be shared.
- The Jira **custom field IDs** this tool needs — in this Jira site/project:
  `customfield_10207` (scan ID), `customfield_10208`/`customfield_10210`/
  `customfield_10211`/`customfield_10212`/`customfield_10213` (the five
  SAST result ID fields, `VulnerabilityId1`-`5` — note they aren't
  sequential field IDs), `customfield_10209` (SCA package name/version) —
  are configured as `JIRA_FIELD_*` env vars where `cxone-ai-triage` runs,
  **not** in this Automation rule. Custom field IDs are **not portable
  across Jira sites** — if you're setting this up somewhere else, look up
  the right IDs first (Project settings → Fields, or
  `GET /rest/api/3/field` on that site) rather than reusing these verbatim.

## Step 1 — Trigger

Add whatever trigger fits the workflow this rule is meant to automate (e.g.
a manual trigger for testing, or an issue transitioning into a "Ready for
AI Triage" status). Not covered here since it depends on Prudential's
process — pick the trigger, then continue to Step 2.

## Step 2 — Action: Send Web Request

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
    "issue_key": "{{issue.key.jsonEncode}}"
  }
}
```

That's the entire payload — no per-field mapping, no subtasks array to
build. `cxone_ai_triage` fetches the ticket (`GET /rest/api/2/issue/{key}`)
and its subtasks (a JQL search for `parent = "{key}"`, which returns the
fuller shape including assignee/created that a parent's own
`fields.subtasks` doesn't carry) itself, then shapes them into the
`jira_issue` dict `jira_parser.py` expects — see `get_issue_for_triage`'s
docstring for the exact mapping.

The corresponding env vars on whatever runs `cxone-ai-triage` (see the
README's "Authentication" section) are what tell it which custom field is
which:

```bash
JIRA_FIELD_SCAN_ID=customfield_10207
JIRA_FIELD_VULNERABILITY_ID_1=customfield_10208
JIRA_FIELD_VULNERABILITY_ID_2=customfield_10210
JIRA_FIELD_VULNERABILITY_ID_3=customfield_10211
JIRA_FIELD_VULNERABILITY_ID_4=customfield_10212
JIRA_FIELD_VULNERABILITY_ID_5=customfield_10213
JIRA_FIELD_PACKAGE_NAME_VERSION=customfield_10209
```

`JIRA_SERVER`/`JIRA_EMAIL`/`JIRA_API_TOKEN` are required unconditionally
for this to work — they're how the ticket gets fetched at all, not just how
a comment gets posted back. `--no-comment` still needs Jira *read* access
to fetch the ticket in the first place.

## Step 3 — Validate

1. Use Jira Automation's rule execution/audit log to confirm the built
   request body is valid JSON.
2. Trigger the rule on a real test ticket and confirm the GitHub Actions
   run fires: check the Actions tab of `happy-cook/JavaVulnerableLab` for a
   `cxone-ai-triage` `repository_dispatch` run.
3. Common failure causes: the GitHub token lacks `repo` scope (403/404 on
   dispatch), the repo owner/name in the URL is wrong, the `JIRA_FIELD_*`
   custom field IDs don't match this Jira site's actual field
   configuration, or `JIRA_SERVER`/`JIRA_EMAIL`/`JIRA_API_TOKEN` aren't set
   where `cxone-ai-triage` runs (see
   [`docs/jira-minimum-permissions.md`](jira-minimum-permissions.md) for
   what that account needs).

## Field resolution order in `cxone_ai_triage`

Once the ticket is fetched, `jira_parser.py` prefers the structured fields
above over the description: `scanId` for the scan ID, `VulnerabilityId1..5`
for SAST result identifiers (one triage job per populated field, all on the
parent ticket key). The description regex fallback (see the README's "Why
this exists" section) only kicks in when the corresponding structured
field is absent — e.g. a `JIRA_FIELD_*` env var wasn't configured, or the
underlying custom field is blank on that ticket. SCA still always uses
`subtasks` for the CVE (or, absent that, a bare `CVE-\d{4}-\d+` match in
the description) since there's no VulnerabilityId equivalent for CVEs;
`packageNameVersion` is applied to every SCA job from a ticket regardless
of which path found the CVE.
