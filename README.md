# cxone-ai-triage

POC tool that turns a Prudential Jira ticket's scan/result identifiers into a
successful Checkmarx One AI Triage API call, using
[CheckmarxPythonSDK](https://pypi.org/project/CheckmarxPythonSDK/).

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
type (`Checkmarx (SAST)` / `Checkmarx (SCA)` marker), the scan ID (the
`scans?id=` link, chosen because it's unambiguous — the two `/results/<a>/<b>/sast`
style links elsewhere in the template don't put scan ID and project ID in a
consistent order), and either the SAST `result-id=` value (URL-decoded) or a
CVE ID (SCA — matched by pattern, not yet verified against a real SCA ticket
sample).

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
`samples/github_event.sample.json`.

Output is a JSON/CSV report with the resolved `project_id`, `similarity_id`,
`alternate_id`, `group_id`, the `triage_id` returned by the trigger call, and
`status` (`accepted` or `failed` with an `error` message). The CLI exits
non-zero if any job failed, so a GitHub Actions step can flag it.

## Tests

```bash
python -m unittest discover -s tests -v
```

Covers Jira-description parsing (including the real SAST ticket sample) and
the resolver's matching/caching/disambiguation/group-id logic against a
faked SDK — no live Checkmarx One tenant needed. Runs on every push/PR via
`.github/workflows/test.yml`.

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
