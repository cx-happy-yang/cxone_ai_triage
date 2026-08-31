# cxone-ai-triage

POC tool that turns a Prudential Jira ticket's scan/result identifiers into a
successful Checkmarx One AI Triage API call, using
[CheckmarxPythonSDK](https://pypi.org/project/CheckmarxPythonSDK/), then polls
for the finished verdict and posts it back as a comment on the ticket using
the [`jira`](https://pypi.org/project/jira/) package.

## Why this exists

Prudential dispatches this tool as a GitHub Actions `repository_dispatch`
event carrying the raw Jira ticket (`client_payload.jira_issue`: key,
summary, project, url, description). The scan ID and result identifier
aren't separate fields — they're embedded in the ticket's free-text
`description` (Jira wiki markup produced by the Checkmarx Jira
integration), e.g.:

```
*Checkmarx (SAST):* SQL_Injection
...
*Scan ID:* [d01d7561\-2bf5\-48b2\-bbaa\-da166c671fc3|https://.../scans?id=d01d7561-2bf5-48b2-bbaa-da166c671fc3&branch=master]
...
Review result in Checkmarx One: [SQL\_Injection|https://.../results/d01d7561-2bf5-48b2-bbaa-da166c671fc3/1b49ad6f-.../sast?result-id=XZBiE9xWT5WiRxxnpMKmKfZUJuA%3D]
```

`cxone_ai_triage/jira_parser.py` regex-extracts, per ticket: the scanner
type (`Checkmarx (SAST)` / `Checkmarx (SCA)` marker) and the scan ID (the
`scans?id=` link, chosen because it's unambiguous — the two `/results/<a>/<b>/sast`
style links elsewhere in the template don't put scan ID and project ID in a
consistent order).

For SAST, the result identifier is the `result-id=` value on the same
description (URL-decoded) — one ticket, one result, one triage job.

For SCA, Prudential's tickets carry each CVE on a **subtask**, not in the
parent ticket's description: subtask summaries look like
`"CVE-2021-44228 - log4j-core-2.14.1"`. The parent's `subtasks` array
(expected shape: Jira Automation's `{{issue.subtasks.jsonEncode}}` smart
value, i.e. `{"key": ..., "fields": {"summary": ...}}` per item) yields one
triage job per subtask that has a CVE in its summary; subtasks without one
are skipped with a warning, not fatal. **This exact subtasks field
name/shape is not yet verified against a real payload** — a ticket with no
`subtasks` field falls back to scanning the parent description directly for
a CVE ID instead.

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
every push to `main` and on `v*` tags, uploaded as workflow artifacts — that's
the artifact to hand to Prudential.

## Running the binary in Prudential's GitHub Actions

```yaml
name: CxOne AI Triage

on:
  repository_dispatch:
    types: [cxone-ai-triage]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Run CxOne AI Triage
        env:
          CXONE_SERVER: ${{ secrets.CXONE_SERVER }}
          CXONE_ACCESS_CONTROL_URL: ${{ secrets.CXONE_ACCESS_CONTROL_URL }}
          CXONE_TENANT_NAME: ${{ secrets.CXONE_TENANT_NAME }}
          CXONE_GRANT_TYPE: client_credentials
          CXONE_CLIENT_ID: ${{ secrets.CXONE_CLIENT_ID }}
          CXONE_CLIENT_SECRET: ${{ secrets.CXONE_CLIENT_SECRET }}
          JIRA_SERVER: ${{ secrets.JIRA_SERVER }}
          JIRA_EMAIL: ${{ secrets.JIRA_EMAIL }}
          JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
        run: ./cxone-ai-triage -o triage_results.json
      - name: Upload result
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: triage_results
          path: triage_results.json
```

No `-i`/`-e` flag needed — the binary reads `$GITHUB_EVENT_PATH`, which the
runner sets for every triggered event, including `repository_dispatch`.
