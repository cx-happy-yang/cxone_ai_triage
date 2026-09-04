# Checkmarx One: minimum role/permissions for the OAuth client

This tool authenticates to Checkmarx One as an OAuth client (`CXONE_CLIENT_ID`
/ `CXONE_CLIENT_SECRET`, `client_credentials` grant — see README.md
"Authentication"). This document is about **what to grant that OAuth
client** in Checkmarx One's Identity and Access Management (IAM), based on
[Managing Roles](https://docs.checkmarx.com/en/34965-68603-managing-roles.html)
and the linked
[Predefined Roles and Permissions List](https://docs.checkmarx.com/en/34965-338142-predefined-roles-and-permissions-list.html).

## What this tool actually calls

| `resolver.py` call | Checkmarx One API | Read or write |
|---|---|---|
| `ScansAPI.get_a_scan_by_id` | `GET /api/scans/{scanId}` | read |
| `SastResultsAPI.get_sast_results_by_scan_id` | `GET /api/sast-results` | read |
| `ScannersResultsAPI.get_all_scanners_results_by_scan_id` | `GET /api/results` | read |
| `RiskOrchestrationAPI.get_risks` | `GET /api/risks` | read |
| `AiTriageAPI.trigger_ai_triage` | `POST /api/ai-triage/triage` | **write** |
| `AiTriageAPI.retrieve_ai_triage_results` | `GET /api/ai-triage/triage/{projectId}/{groupId}` | read |

It never creates, deletes, or scans a project, never changes a result's
severity/state itself, and never touches presets, queries, reports, or
tenant settings. Only one call is a write: triggering AI Triage.

## Confirmed minimum (live-tested)

Prudential has confirmed empirically (2026-09, against a real tenant) that
Checkmarx One's AI Triage actually requires a noticeably broader set than
this tool's own read/write call list (above) suggested — it's not just
"read the data + `update-risk-management`" (see "Earlier guess" below for
that narrower attempt, superseded by this). The confirmed working minimum:

Assign the **`ai-triage-assist` composite role**, which bundles:

- `view-projects`
- `view-results`
- `update-result`
- `update-result-states`
- `update-result-severity`
- `update-result-not-exploitable`
- `update-result-state-not-exploitable`
- `update-result-state-propose-not-exploitable`
- `add-notes`

...plus grant these individually, since they're **not** part of that
composite role:

- `view-scans`
- `view-risk-management`
- `view-risk-management-dashboard`
- `view-risk-management-tab`
- `update-risk-management`
- `access-iam`

Notably, most of what `ai-triage-assist` bundles are result-*state*-changing
permissions (`update-result-severity`, `update-result-not-exploitable`,
`update-result-state-*`, `add-notes`), not read-only or risk-management
permissions — AI Triage evidently updates the underlying result's state
directly (not just a separate risk-management record) when it assigns a
verdict, which the earlier guess below didn't anticipate.

## Earlier (unconfirmed) guess — superseded by the list above

Before live testing, this tool's own read/write call list (above) suggested
a much narrower custom role would suffice:

| Permission | Why it was guessed |
|---|---|
| `view-projects` | resolving a scan's project |
| `view-scans` | `GET /api/scans/{scanId}` |
| `view-results` | `GET /api/sast-results`, `GET /api/results` |
| `view-risk-management` | `GET /api/risks`, polling `GET /api/ai-triage/triage/{projectId}/{groupId}` |
| `update-risk-management` | triggering AI Triage (`POST /api/ai-triage/triage`) |

This was wrong (or at least badly incomplete) — the confirmed list above is
what actually works. Left here only so it's clear what changed and why;
don't use this shorter list.

## Built-in roles compared

- **`ast-viewer`** — read-only: `view-applications`, `view-engines`,
  `view-preset`, `view-project-params`, `view-projects`, `view-queries`,
  `view-results`, `view-risk-management`, `view-scans`,
  `view-tenant-params`, plus some analytics/report permissions. Covers the
  view-only items in the confirmed list above, but not `ai-triage-assist`
  or any of the `update-*`/`add-notes`/`access-iam` items — expect `403`
  on `POST /api/ai-triage/triage` with only this role.
- **`ast-risk-manager`** — read/write, includes `view-risk-management` and
  `update-risk-management` plus a lot this tool never uses:
  `create-project`, `delete-project`, `create-scan`, `delete-scan`,
  `update-scan`, `create-preset`/`delete-preset`, `update-sca-license`,
  `update-sca-state`, etc. Still doesn't include `ai-triage-assist` or
  `access-iam`. Broader than necessary in some directions (it could delete
  scans and projects) and still short in others.
- **`plugin-scanner`** / **`ast-scanner`** — for CI/CD plugins that trigger
  scans and read results; irrelevant here since this tool never scans
  anything.

None of the predefined roles line up exactly with the confirmed list — a
custom role (or `ai-triage-assist` plus the remaining individual
permissions listed above) is the practical way to grant exactly this set.

## Resource-level authorization (if your tenant has this enabled)

If your tenant has Checkmarx One's newer access-management model enabled,
an OAuth client also needs an explicit resource-level grant (tenant,
application, or project) in addition to its role — a role by itself isn't
enough to see any project's data. Grant it at whatever level covers every
project Prudential's Jira tickets might reference (tenant-wide is simplest
for a POC; narrow to specific applications/projects for production once
the set of in-scope projects is known).

## Verifying the grant

Run the tool (or `python main.py -i samples/input.sample.json -o /tmp/out.json --no-comment`
against a real ticket/scan) with `-v` and confirm:
1. No `401`/`403` on any of the six calls listed above.
2. `POST /api/ai-triage/triage` specifically returns `202 Accepted`, not `403`.

## References

- [Managing Roles](https://docs.checkmarx.com/en/34965-68603-managing-roles.html)
- [Predefined Roles and Permissions List](https://docs.checkmarx.com/en/34965-338142-predefined-roles-and-permissions-list.html)
- [Permissions in Access Management](https://docs.checkmarx.com/en/34965-338143-permissions-in-access-management.html)
- [Creating an OAuth Client for Checkmarx One Integrations](https://docs.checkmarx.com/en/34965-188033-creating-an-oauth-client-for-checkmarx-one-integrations.html)
