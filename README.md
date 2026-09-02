# cxone-ai-triage

POC tool that turns a Prudential Jira ticket's scan/result identifiers into a
successful Checkmarx One AI Triage API call, using
[CheckmarxPythonSDK](https://pypi.org/project/CheckmarxPythonSDK/), then polls
for the finished verdict and posts it back as a comment on the ticket using
the [`jira`](https://pypi.org/project/jira/) package.

## Why this exists

Prudential dispatches this tool as a GitHub Actions `repository_dispatch`
event carrying the raw Jira ticket (`client_payload.jira_issue`). The
Automation rule that builds this payload is documented in
[`docs/jira-automation-setup.md`](docs/jira-automation-setup.md); the
identifiers `cxone_ai_triage/jira_parser.py` needs come from two places,
checked in this order:

1. **Structured fields on the payload**, when present:
   - `scanId` — a custom field holding the scan ID directly.
   - `VulnerabilityId1` .. `VulnerabilityId5` — up to five custom fields,
     each optionally holding one SAST resultHash/pathSystemId (at least one
     is populated per ticket); one triage job is created per populated
     field, all on the parent ticket key.
   - `subtasks` — for SCA, each CVE lives on a subtask's summary line (e.g.
     `"CVE-2021-44228 - log4j-core-2.14.1"`), not a VulnerabilityId field.
     One triage job per subtask that has a CVE in its summary, using the
     *subtask's own key* (not the parent's) so the AI Triage comment lands
     on the right subtask; subtasks without a CVE are skipped with a
     warning, not fatal.
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
   `CVE-\d{4}-\d+` pattern anywhere in the text. The scanner type
   (`Checkmarx (SAST)` / `Checkmarx (SCA)` marker) always comes from the
   description — there's no structured field for it yet.

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

`GET /api/results` has no `similarityId` filter, so every row for a scan is
paged through (500 at a time) and cached per scan — unavoidable, but paid
once per scan even across many ticket rows in the same batch.

### Polling the result and posting it back to Jira

`POST /api/ai-triage/triage` is async (`202 Accepted`, no verdict yet), so
after triggering, `cxone_ai_triage/pipeline.py` polls
`GET /api/ai-triage/triage/{projectId}/{groupId}` (`resolver.poll_ai_triage_result`)
until `triageStatus` leaves `NOT_TRIAGED`/`IN_PROGRESS` (or times out —
`--poll-timeout`, default 600s), then renders every field on the response
(`AiTriageResult`: verdict, reachability + reasoning, exploitability +
reasoning, attackability, confidence score + explanation, usage locations,
SCA component/version, verification steps, repository info, scanner/result/
triagedAt) into one paragraph (`comment_formatter.format_comment`) and posts
it as a comment on the originating ticket/subtask key via `jira_client.py`.

A failure at either step (timeout polling, or the Jira API call itself)
is recorded on the output row (`poll_error` / `comment_error`) but never
flips an already-successful trigger back to "failed" — see
`pipeline.run_pipeline`. Skip either step with `--no-poll` / `--no-comment`.

## Install

```bash
pip install -r requirements.txt
```

## Authentication

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

Jira comment posting is optional — read by `jira_client.py`:

```bash
export JIRA_SERVER=https://your-domain.atlassian.net
export JIRA_EMAIL=<service account email>
export JIRA_API_TOKEN=<API token, from id.atlassian.com/manage-profile/security/api-tokens>
```

If any of these are unset, the tool still resolves identifiers, triggers AI
Triage, and polls for the result — it just skips posting a comment
(`comment_posted: false` in the output, no error).

## Usage

Production mode — no arguments needed. Reads the Jira ticket from the
GitHub Actions `repository_dispatch` event at `$GITHUB_EVENT_PATH`
(every job gets this env var automatically):

```bash
python main.py -o triage_results.json
```

Or point at an event file explicitly (e.g. to replay a real dispatch payload
locally):

```bash
python main.py -e samples/github_event.sample.json -o triage_results.json
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
`samples/github_event.sample.json` (SAST) / `samples/github_event_sca.sample.json`
(SCA, with subtasks).

Output is a JSON/CSV report with the resolved `project_id`, `similarity_id`,
`alternate_id`, `group_id`, the `triage_id` returned by the trigger call,
`status` (`accepted` or `failed` with an `error` message), the polled
`ai_triage_status`/`reachability_status`/`exploitability_status`/
`attackability_status`/`ai_triage_summary` (`poll_error` if polling failed),
and `comment_posted` (`comment_error` if posting failed). The CLI exits
non-zero only if a **trigger** failed — poll/comment failures are best-effort
and reported but don't affect the exit code.

Flags: `--no-poll` (trigger only, skip polling/commenting entirely),
`--no-comment` (poll but don't post to Jira), `--poll-timeout` /
`--poll-interval` (seconds, default 600 / 15).

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
`CXONE_*`/`JIRA_*` secrets as above, configured on that repo (Settings →
Secrets and variables → Actions).

No `-i`/`-e` flag needed — the binary reads `$GITHUB_EVENT_PATH`, which the
runner sets for every triggered event, including `repository_dispatch`.

The Jira side that fires this — the Automation rule building the payload
above (including the `subtasks` array) and sending it to
`/repos/.../dispatches` — is documented in
[`docs/jira-automation-setup.md`](docs/jira-automation-setup.md).
