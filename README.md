# cxone-ai-triage

POC tool that turns a Prudential Jira ticket's scan/result identifiers into a
successful Checkmarx One AI Triage API call, using
[CheckmarxPythonSDK](https://pypi.org/project/CheckmarxPythonSDK/), then polls
for the finished verdict and posts it back as a comment on the ticket using
the [`jira`](https://pypi.org/project/jira/) package.

## Why this exists

Prudential dispatches this tool as a GitHub Actions event carrying just the
ticket key — either `workflow_dispatch`'s `inputs.issue_key`, or
`repository_dispatch`'s `client_payload.issue_key`, whichever an org's
policy allows (`github_event.py` reads either shape automatically; some
orgs' policies disable `repository_dispatch` entirely, which is why
`workflow_dispatch` is the primary path documented in
[`docs/jira-automation-setup.md`](docs/jira-automation-setup.md)). This
tool fetches the full ticket (and its subtasks) itself via the Jira REST
API (`JiraCommentClient.get_issue_for_triage`), using `JIRA_FIELD_*` env
vars to know which custom field is which (see "Authentication" below) — so
the Jira Automation rule that dispatches this event never has to maintain
a field-by-field mapping, or be touched again when a new custom field is
needed.

The identifiers `cxone_ai_triage/jira_parser.py` needs then come from two
places in the resulting structured object, checked in this order:

1. **Structured fields on the payload**, when present:
   - `scanId` — a custom field holding the scan ID directly.
   - `VulnerabilityId1` .. `VulnerabilityId5` — up to five custom fields
     (only `VulnerabilityId1` is required; 2–5 are optional), each
     optionally holding one SAST resultHash/pathSystemId; one triage job is
     created per populated field, all on the parent ticket key. When more
     than one is populated, `TriageResolver` batches them into a single
     `POST /api/ai-triage/triage` call (one bucket, multiple resultIDs)
     instead of one request per result — see "Batching" below.
   - `subtasks` — for SCA, each CVE lives on a subtask's summary line (e.g.
     `"SCA | CVE-2025-71329"`), not a VulnerabilityId field. One triage job
     per subtask that has a CVE in its summary; the Jira comment for each
     always goes on the **parent ticket key**, not the subtask (Jira
     comments belong on the parent for both SAST and SCA) — the subtask key
     and CVE are included in the comment body so multiple CVEs commented on
     one parent ticket stay distinguishable. Subtasks without a CVE are
     skipped with a warning, not fatal.
   - `packageNameVersion` — a custom field **on the parent ticket** (not
     per-subtask), applied to every CVE/subtask under it: the expected
     structure is one package per ticket, with each of its CVEs as a
     subtask. Carried into the output report and the AI Triage Jira comment.
2. **The ticket's free-text `description`** (Jira wiki markup produced by
   the Checkmarx Jira integration), used as a fallback whenever the field
   above is absent — e.g. for tickets predating this automation rule, or a
   scanId/VulnerabilityId field that wasn't populated:

   ```
   *Checkmarx (SAST):* SQL_Injection
   ...
   *Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|https://.../scans?id=d01d7561-2bf5-48b2-bbaa-da166c671fc3&branch=master]
   ...
   Review result in Checkmarx One: [SQL\_Injection|https://.../results/d01d7561-2bf5-48b2-bbaa-da166c671fc3/1b49ad6f-.../sast?result-id=XZBiE9xWT5WiRxxnpMKmKfZUJuA%3D]
   ```

   The scan ID comes from the `scans?id=` link (unambiguous — the
   `/results/<a>/<b>/sast` links elsewhere in the template don't put scan ID
   and project ID in a consistent order); the SAST result identifier from
   the `result-id=` value (URL-decoded); the SCA CVE ID from a bare
   `CVE-\d{4}-\d+` pattern anywhere in the text.

   The scanner type itself also prefers structured fields first: any
   populated `VulnerabilityId` field means SAST, a populated
   `packageNameVersion` or `subtasks` means SCA — the `Checkmarx (SAST)` /
   `Checkmarx (SCA)` description marker is only checked as a last resort,
   for tickets whose template doesn't populate any of those structured
   fields at all (confirmed live on a real ticket whose description had no
   such marker anywhere in it, but did have `VulnerabilityId1` set).

From there, `POST /api/ai-triage/triage` needs more than what the ticket gives us:

| Needed              | Where it comes from |
|---------------------|----------------------|
| `scanID`             | given directly |
| `scannerType`        | given directly (`sast` / `sca`) |
| `resultIDs` (alternateId) | `GET /api/results`, filtered client-side by `similarityId` (no server-side filter exists) |
| `similarityId` (SAST) | `GET /api/sast-results?result-id=<resultHash>` |
| `similarityId` (SCA)  | the CVE ID itself |
| `projectId`          | `GET /api/scans/{scanId}` |
| `groupId` (SAST)     | equal to `similarityId` |
| `groupId` (SCA)      | `GET /api/risks?projectId=...&engine=SCA&riskName=<cveId>` (looked up, not hand-built — see note below) |

`projectId` / `groupId` aren't required by the trigger call itself (only by
polling `GET /api/ai-triage/triage/{projectId}/{groupId}` afterwards), but
this tool resolves and reports them anyway for traceability.

**Note on SCA `groupId`:** an earlier plan was to build it by concatenating
`similarityId` (CVE ID) + `data.packageIdentifier` + `projectId`, but that
exact format isn't documented anywhere in the SDK or API. `GET /api/risks`
returns the real `groupId` directly, so this tool uses that instead of
guessing a delimiter/order.

`GET /api/risks` (per its own docstring) aggregates risks at the *project*
level, not per scan — `Risk.scanId` reflects some scan that detected it,
not necessarily the scan_id on the ticket, and was observed live to drift
to a different scan once the project had been rescanned since the ticket
was filed. So a `scanId` match is only used as a *preference* for picking
the right risk when several share the same CVE (falling back to
`package_identifier` matched against `assetName` if still ambiguous),
never as a hard filter — an exact-`scanId`-only match would have wrongly
discarded the only real candidate and left `groupId` blank for an already-
triaged CVE.

`GET /api/results` has no `similarityId` filter, so every row for a scan is
paged through (500 at a time) and cached per scan — unavoidable, but paid
once per scan even across many ticket rows in the same batch. Two things
about that pagination, both confirmed against a live tenant rather than
documented anywhere:

- **`offset` is a page number (0-indexed), not a row-skip count** — despite
  the SDK's own docstring ("offset: Items to skip"). With a real scan of
  564 results and `limit=500`, `offset=500` (the "skip 500 rows" reading)
  returned **0** rows; `offset=1` (the "give me page 1" reading — i.e. the
  second page of 500) correctly returned the remaining 64. Advancing by
  the number of rows already fetched — the natural reading of "items to
  skip" — silently truncated every scan with more than one page.
- Pagination stops on the first short page (fewer rows returned than
  requested), not by comparing against the response's `totalCount` — the
  same tenant returned a `totalCount` matching just the first page's size
  for a scan with far more actual results, which would otherwise stop the
  fetch after page 1 if the loop trusted it.

### Checking for an existing result before triggering

Before batching a job for triggering, `resolver.resolve_and_trigger_all`
first checks `GET /api/ai-triage/triage/{projectId}/{groupId}` (the same
call `poll_ai_triage_result`/`poll_ai_triage_results` use). If that result
already exists, the trigger is skipped for that job entirely
(`outcome.trigger_skipped_reason` is set, `triage_id` stays `None`)
instead of re-submitting it. This matters most on re-runs/retries of the
same ticket: nothing gets re-triggered, but polling and commenting still
happen normally, since polling returns immediately when the status is
already terminal. A failed check (e.g. a transient error) fails open — it
triggers as usual rather than blocking the run. A job with no `groupId`
yet (e.g. the SCA `/api/risks` lookup found nothing) skips the check and
triggers as before.

**Any status other than a blank/`NOT_TRIAGED`/`FAILED`/`IN_PROGRESS` value
(case/whitespace normalized) counts as "already exists"** — this is
deliberately permissive rather than an allowlist of `AiTriageResult`'s
documented `triageStatus` values (`NOT_TRIAGED`, `IN_PROGRESS`, `FAILED`,
`VULNERABLE`, `PROPOSED_NOT_EXPLOITABLE`, `UNCERTAIN`, `RISK_ACCEPTED`).
Live testing hit `CONFIRMED` (a SAST/SCA result *state* value, not in that
enum) for a vulnerability that had genuinely already been AI-triaged.
Result states have predefined values (`TO_VERIFY`, `NOT_EXPLOITABLE`,
`PROPOSED_NOT_EXPLOITABLE`, `CONFIRMED`, `URGENT`) plus whatever custom
states a tenant defines — but AI Triage itself only ever assigns a
predefined one, never a custom state, so this field's real universe of
values is still bounded even though it's broader than the SDK's own
docstring enum. A strict allowlist would have wrongly treated `CONFIRMED`
as "not triaged yet" and re-triggered needlessly.

`IN_PROGRESS` doesn't count as "already exists" either, for the same
reason `FAILED` doesn't: a live tenant showed a multi-`resultID` batch
trigger call where only 1 of 3 ended up with a real verdict, and the other
2 stayed `IN_PROGRESS` indefinitely across multiple follow-up runs.
`AiTriageResult` has no timestamp to tell "still actively processing"
apart from "stuck forever", so treating a stuck `IN_PROGRESS` as existing
would mean those 2 could never be retried — it's now safe to re-batch and
re-trigger instead, the same as blank/`NOT_TRIAGED`/`FAILED`.

`FAILED` is the one deliberate exception to "already exists": it means AI
Triage itself never produced a verdict, so treating it the same as a real
result would permanently block a retry on every future run. It's treated
the same as blank/`NOT_TRIAGED` instead, so a previously failed job gets
re-batched and re-triggered on the next run.

### Batching the trigger call

Each job's identifiers (`similarityId`, `alternateId`, `groupId`, ...) are
always resolved individually — every result has its own distinct `groupId`
to poll later regardless of how the trigger was submitted. But jobs that
still need triggering (i.e. didn't already have an existing result, per
above) and share the same `(scan_id, scanner_type)` are grouped into a
**single** `POST /api/ai-triage/triage` request (one bucket, multiple
`resultIDs`) instead of one request per result; all outcomes in that batch
get back the same `triageID`. This covers both: a SAST ticket with
`VulnerabilityId1` and `VulnerabilityId2` both populated, and an SCA ticket
with multiple `"SCA | CVE-..."` subtasks (they share the ticket's one
`scanId`, so they group together the same way). A batch's trigger call
failing fails every outcome in it; a job that fails identifier *resolution*
is excluded from its batch rather than blocking the others. Polling and
Jira commenting stay per-job either way (see below) — each result (and, for
SCA, each subtask) still gets its own verdict and its own comment.

**A SAST ticket's `VulnerabilityId` fields can share one `similarityId`.**
Checkmarx groups SAST findings by vulnerability *pattern* (e.g. the same
SQL injection query pattern found at two different code locations), not by
specific occurrence — a live tenant hit exactly this: 2 distinct
`VulnerabilityId` values (2 different resultHashes) resolved to the same
`similarityId`, and `/api/results` had no other field to tell those two
rows apart (unlike SCA, which disambiguates via
`package_identifier`/`assetName`). Rather than failing, this is treated as
a legitimate grouping: since `groupId` *is* the `similarityId` for SAST and
AI Triage only ever returns one verdict per `groupId`, both
`VulnerabilityId`s are, from CxOne's point of view, the exact same result.
`_find_alternate_id` picks one matching `/api/results` row as the shared
representative (logging every field on each ambiguous row for visibility),
`_trigger_batch` de-duplicates so that representative's resultID is only
submitted once, and both jobs' existing-triage pre-check and poll only
happen once for the shared `groupId` (see below) — with one shared Jira
comment naming every `VulnerabilityId` involved, rather than one comment
per job.

### Polling the result and posting it back to Jira

`POST /api/ai-triage/triage` is async (`202 Accepted`, no verdict yet), so
after triggering, `cxone_ai_triage/pipeline.py` polls
`GET /api/ai-triage/triage/{projectId}/{groupId}` for every job needing it
**together** (`resolver.poll_ai_triage_results` — one round of GETs across
all of them per `--poll-interval`, not each job's own full poll loop run to
completion before the next even starts) until each one's `triageStatus`
leaves `NOT_TRIAGED`/`IN_PROGRESS` (or times out — `--poll-timeout`, default
180s, counted from the same start for every job in the batch, not restarted
per remaining one). A job drops out of that polling as soon as its own
result is ready, so a ticket with several results (multiple
`VulnerabilityId`s, multiple SCA subtasks) finishes as fast as the slowest
one, not the sum of all of them — AI Triage can finish every result in a
batch trigger call around the same time server-side, so waiting on them one
at a time wasted time for no reason. Once a result's ready, every field on
the response gets rendered (`AiTriageResult`: verdict, reachability + reasoning, exploitability +
reasoning, attackability, confidence score + explanation, usage locations,
SCA component/version, verification steps, repository info, scanner/result/
triagedAt) — plus, for SCA, the package name/version from the ticket-level
`packageNameVersion` field (`jira_meta["package_name_version"]`, since CxOne
doesn't always populate `metadata.component`/`.version`), and (for jobs
resolved from a subtask) the CVE and subtask key so the comment stays
attributable — into one paragraph (`comment_formatter.format_comment`) and
posts it as a comment on **the parent ticket key** (`job.ticket_key`) via
`jira_client.py`. This holds for both SAST and SCA: even when a ticket has
several results (multiple `VulnerabilityId`s, or multiple SCA subtasks),
every one of their comments lands on that one parent ticket, not on a
subtask.

Jobs are polled and commented on individually **except** when 2+ of them
resolve to the exact same `(project_id, group_id)` — the SAST
`similarityId`-collision case above being the common source of this.
`pipeline.run_pipeline` de-duplicates the poll targets it sends to
`resolver.poll_ai_triage_results` (one GET per unique `group_id`, not one
per job), and groups those jobs' comments together: when they have 2+
distinct vulnerability labels (`VulnerabilityId`/CVE ID values), it posts
one shared comment listing all of them (`*Vulnerability IDs:* hash-one,
hash-two.` — see `comment_formatter.build_vulnerability_marker_multi`)
instead of a comment each, since they share one AI Triage verdict anyway. A
group whose members all have the *same* label (e.g. a literal duplicate
input row) isn't treated as a "shared comment" group — it's left to the
ordinary duplicate-marker check, unchanged.

A failure at either step (timeout polling, or the Jira API call itself)
is recorded on the output row (`poll_error` / `comment_error`) but never
flips an already-successful trigger back to "failed" — see
`pipeline.run_pipeline`. Skip either step with `--no-poll` / `--no-comment`.

### Avoiding duplicate comments

Before posting, `pipeline.py` fetches the ticket's existing comments
(`jira_client.get_comment_bodies`) and checks whether any of them already
contain the same `"*Vulnerability ID:*"` / `"*CVE ID:*"` marker
`format_comment` leads with (`comment_formatter.build_vulnerability_marker`
— exposed separately so the check can't drift out of sync with what's
actually posted). If one's already there, posting is skipped
(`outcome.comment_skipped_reason` is set) instead of adding a duplicate.
This covers both a re-run of the same ticket and multiple results landing
on the same parent within one run — each job's check sees whatever the
previous job in that same run already posted, since it re-fetches comments
fresh each time. A failed check fails open (posts as usual) rather than
blocking on this optimization.

## Install

```bash
pip install -r requirements.txt
```

## Authentication

See [`docs/cxone-minimum-permissions.md`](docs/cxone-minimum-permissions.md)
and [`docs/jira-minimum-permissions.md`](docs/jira-minimum-permissions.md)
for what to actually grant the CxOne OAuth client and the Jira account
behind these credentials — least-privilege, not "give it admin".

Read by `CheckmarxPythonSDK` from environment variables. Recommended for
CI (OAuth client / client-credentials grant):

```bash
export CXONE_SERVER=https://ast.checkmarx.net
export CXONE_ACCESS_CONTROL_URL=https://iam.checkmarx.net
export CXONE_TENANT_NAME=<tenant>
export CXONE_GRANT_TYPE=client_credentials
export CXONE_CLIENT_ID=<oauth client id>
export CXONE_CLIENT_SECRET=<oauth client secret>
```

(`CXONE_GRANT_TYPE` must be set to something other than the SDK's default
`refresh_token` or it will ignore the client id/secret. Adjust `CXONE_SERVER`
/ `CXONE_ACCESS_CONTROL_URL` for your Checkmarx One region.)

`TriageResolver` builds one shared `ApiClient` (and so one OAuth token) and
passes it into all five `CheckmarxPythonSDK.CxOne` classes it uses
(`ScansAPI`, `SastResultsAPI`, `ScannersResultsAPI`, `RiskOrchestrationAPI`,
`AiTriageAPI`) instead of letting each build its own — confirmed via live
logs that the default (each class calling `construct_configuration()`
itself) means a separate token fetch per class actually used in a run (up
to 4–5 extra round-trips).

Read by `jira_client.py`:

```bash
export JIRA_SERVER=https://your-domain.atlassian.net
export JIRA_EMAIL=<service account email>
export JIRA_API_TOKEN=<API token, from id.atlassian.com/manage-profile/security/api-tokens>
```

**Required** in the default `--github-event` mode (`client_payload` only
ever carries `issue_key`, never the full ticket — without these there's no
way to fetch it, and the run fails fast with a clear error rather than
silently finding zero jobs). Only optional with `--input` (local batch
testing, see "Usage" below): if unset there, the tool still resolves
identifiers, triggers AI Triage, and polls for the result — it just skips
posting a comment (`comment_posted: false` in the output, no error).

`JIRA_FIELD_*` — maps this tool's own field names onto this Jira site's
custom field IDs (`JiraFieldMapping` in `jira_client.py`; unset ones are
simply left out of the fetched ticket, same as if the field were blank):

```bash
export JIRA_FIELD_SCAN_ID=customfield_10207
export JIRA_FIELD_VULNERABILITY_ID_1=customfield_10208
# ...VULNERABILITY_ID_2 through _5, if this ticket template uses them
export JIRA_FIELD_PACKAGE_NAME_VERSION=customfield_10209
```

Custom field IDs aren't portable across Jira sites — see
[`docs/jira-automation-setup.md`](docs/jira-automation-setup.md) for how to
look them up on a given site.

## Usage

Production mode — no arguments needed. Reads the issue key from the GitHub
Actions event at `$GITHUB_EVENT_PATH` (every job gets this env var
automatically) — either `inputs.issue_key` (`workflow_dispatch`) or
`client_payload.issue_key` (`repository_dispatch`) — then fetches the
ticket itself. Needs `JIRA_SERVER`/`JIRA_EMAIL`/`JIRA_API_TOKEN` (and
usually `JIRA_FIELD_*`) set first:

```bash
python main.py -o triage_results.json
```

Or point at an event file explicitly (e.g. to replay a real dispatch payload
locally):

```bash
python main.py -e samples/github_event_workflow_dispatch.sample.json -o triage_results.json
# or, if your org's policy allows repository_dispatch instead:
python main.py -e samples/github_event_repository_dispatch.sample.json -o triage_results.json
```

Local/manual testing mode — a batch JSON/CSV of already-structured rows,
bypassing Jira-description parsing entirely:

```bash
python main.py -i samples/input.sample.json -o triage_results.json
```

| column | required | meaning |
|---|---|---|
| `scan_id` | yes | Scan ID from the ticket |
| `scanner_type` | yes | `sast` or `sca` |
| `ticket_key` | no | Jira issue key, carried through to the output for traceability |
| `result_hash` | SAST only | resultHash/pathSystemId column value from the ticket |
| `cve_id` | SCA only | CVE ID from the ticket |
| `package_identifier` | SCA only, optional | disambiguates when the same CVE hits more than one package in the scan |

See `samples/input.sample.json` / `samples/input.sample.csv` /
`samples/github_event_workflow_dispatch.sample.json` /
`samples/github_event_repository_dispatch.sample.json`.

Output is a JSON/CSV report with the resolved `project_id`, `similarity_id`,
`alternate_id`, `group_id`, the `triage_id` returned by the trigger call (or
`null` with `trigger_skipped_reason` set if an existing result meant
triggering was skipped — see "Checking for an existing result before
triggering" above), `status` (`accepted` or `failed` with an `error`
message), the polled `ai_triage_status`/`reachability_status`/
`exploitability_status`/`attackability_status`/`ai_triage_summary`
(`poll_error` if polling failed), and `comment_posted` (`comment_error` if
posting failed). The CLI exits non-zero only if a **trigger** failed —
poll/comment failures are best-effort and reported but don't affect the
exit code.

Flags: `--no-poll` (trigger only, skip polling/commenting entirely),
`--no-comment` (poll but don't post to Jira), `--poll-timeout` /
`--poll-interval` (seconds, default 180 / 15).

## Tests

```bash
python -m unittest discover -s tests -v
```

Covers Jira-description/subtask parsing (including the real SAST ticket
sample), the resolver's matching/caching/disambiguation/group-id/polling
logic, the comment formatter, and the trigger→poll→comment pipeline — all
against faked SDK/Jira clients, no live Checkmarx One or Jira tenant needed.
Runs on every push/PR via `.github/workflows/test.yml`.

## Building the binary

```bash
pip install -r requirements-dev.txt
pyinstaller --onefile --name cxone-ai-triage main.py
# binary at dist/cxone-ai-triage (dist/cxone-ai-triage.exe on Windows)
```

`.github/workflows/build-binary.yml` builds Linux/Windows/macOS binaries on
every push to `main` and on `v*` tags. A `v*` tag push additionally publishes
them as assets on a GitHub Release (this repo is public, so the release
asset URLs are fetchable with a plain `curl`, no auth needed) — that's what
Prudential's pipeline downloads from, at a stable URL that always points to
the latest release:

```
https://github.com/cx-happy-yang/cxone_ai_triage/releases/latest/download/cxone-ai-triage-linux-x64
```

## Running the binary in Prudential's GitHub Actions

[`examples/prudential-cxone-ai-triage.yaml`](examples/prudential-cxone-ai-triage.yaml)
is the full pipeline for `happy-cook/JavaVulnerableLab`'s
`.github/workflows/cxone-AI-Triage.yaml`: it keeps the existing
diagnostic-logging steps and adds downloading the released binary, running
it (reads `$GITHUB_EVENT_PATH` automatically, no flags needed), and
uploading `triage_results.json` as a workflow artifact. Needs the same
`CXONE_*`/`JIRA_*` secrets and `JIRA_FIELD_*` env vars as above, configured
on that repo (Settings → Secrets and variables → Actions).

No `-i`/`-e` flag needed — the binary reads `$GITHUB_EVENT_PATH`, which the
runner sets for every triggered event, including `workflow_dispatch` and
`repository_dispatch`.

The Jira side that fires this — the Automation rule sending just the
ticket key — is documented in
[`docs/jira-automation-setup.md`](docs/jira-automation-setup.md) (Prudential
uses `workflow_dispatch`, since their org's policy disables
`repository_dispatch`).
