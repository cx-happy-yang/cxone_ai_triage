# Changelog

## [0.2.0]

### Fixed
- Bumped `CheckmarxPythonSDK` to `>=1.9.1`. `1.9.0` had a bug retrieving AI
  Triage results for SCA vulnerabilities (`GET /api/ai-triage/triage/{projectId}/{groupId}`),
  which surfaced during the first live test: the SAST flow worked
  end-to-end (verified in the CxOne UI and as a posted Jira comment), but
  the SCA flow failed at the poll step (`resolver.poll_ai_triage_result`).

## [0.1.0]

Initial release.

### Added
- Parse a Jira ticket delivered via a GitHub Actions `repository_dispatch`
  event into one or more triage jobs: SAST from `scanId` /
  `VulnerabilityId1`–`VulnerabilityId5` custom fields (falling back to
  regex-parsing the ticket description), SCA from subtask summaries
  (`"SCA | CVE-..."`) plus a ticket-level `packageNameVersion` field
  (falling back to a bare CVE match in the description).
- Resolve each job's `projectId`/`similarityId`/`alternateId`/`groupId` via
  `CheckmarxPythonSDK`, then trigger `POST /api/ai-triage/triage` — batching
  jobs that share the same `(scan_id, scanner_type)` into a single request.
- Poll `GET /api/ai-triage/triage/{projectId}/{groupId}` per result until
  the verdict is final, then post it as a comment on the originating
  ticket/subtask via the `jira` package.
- CLI (`main.py` / `cxone-ai-triage`), packaged as a PyInstaller binary via
  `.github/workflows/build-binary.yml`, published as GitHub Release assets
  on `v*` tags.
- `docs/jira-automation-setup.md` and `examples/prudential-cxone-ai-triage.yaml`
  documenting the Jira Automation rule and the consuming GitHub Actions
  pipeline.
