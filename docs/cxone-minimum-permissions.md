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

## Recommended: a custom role with exactly these permissions

Checkmarx One's [Predefined Roles and Permissions List](https://docs.checkmarx.com/en/34965-338142-predefined-roles-and-permissions-list.html)
don't include a role scoped this narrowly — the built-in roles are meant
for human users doing much more than this tool does (see "Built-in roles
compared" below). Create a **custom role** in the IAM console (Managing
Roles → New Role) with just:

| Permission | Why |
|---|---|
| `view-projects` | resolving a scan's project (`GET /api/scans/{scanId}` returns a project ID; some result/risk lookups are project-scoped) |
| `view-scans` | `GET /api/scans/{scanId}` |
| `view-results` | `GET /api/sast-results`, `GET /api/results` |
| `view-risk-management` | `GET /api/risks`, and reading back a triage verdict via `GET /api/ai-triage/triage/{projectId}/{groupId}` |
| `update-risk-management` | triggering AI Triage (`POST /api/ai-triage/triage`) — see caveat below |

Assign this role to the OAuth client (or to the user identity backing it,
depending on how your tenant issues OAuth clients).

**Caveat on `update-risk-management`:** as of this writing, Checkmarx's
public docs don't list a permission named specifically for AI Triage —
triggering it is inferred to need a *write* permission on risk data, since
it assigns a triage verdict to a vulnerability (the same category of action
as changing a result's state), and `update-risk-management` is the closest
documented match (it's part of the `ast-risk-manager` role, alongside
`update-result-states` and similar). **Verify this empirically**: run the
tool with just the five permissions above; if `POST /api/ai-triage/triage`
comes back `403`, that's the signal this assumption was wrong and the role
needs broadening (see the built-in `ast-risk-manager` role below as the
next thing to try).

## Built-in roles compared

If a custom role isn't an option on your tenant, here's how the closest
predefined roles compare (broader than necessary, but documented):

- **`ast-viewer`** — read-only: `view-applications`, `view-engines`,
  `view-preset`, `view-project-params`, `view-projects`, `view-queries`,
  `view-results`, `view-risk-management`, `view-scans`,
  `view-tenant-params`, plus some analytics/report permissions. Covers
  every *read* call this tool makes, but **not** the trigger call — expect
  `403` on `POST /api/ai-triage/triage` with only this role.
- **`ast-risk-manager`** — read/write, includes `view-risk-management` and
  `update-risk-management` plus a lot this tool never uses:
  `create-project`, `delete-project`, `create-scan`, `delete-scan`,
  `update-scan`, `create-preset`/`delete-preset`, `update-severity`,
  `update-result-states`, `update-sca-license`, `update-sca-state`, etc.
  This is the safest documented fallback if the custom role above turns
  out to be missing a permission — it's a superset, not a mismatch — but
  it grants this OAuth client far more than it needs (e.g. it could delete
  scans and projects).
- **`plugin-scanner`** / **`ast-scanner`** — for CI/CD plugins that trigger
  scans and read results; irrelevant here since this tool never scans
  anything, and unnecessarily broad for what it does.

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
