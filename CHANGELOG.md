# Changelog

## [Unreleased]

### Fixed
- `_resolve_group_id` no longer requires an exact `scanId` match against
  `GET /api/risks` results for SCA jobs. That endpoint aggregates risks at
  the *project* level (per its own docstring), not per scan, so `Risk.scanId`
  can drift to whatever scan most recently detected the risk. Live testing
  with multiple SCA CVEs on one ticket showed a CVE that was confirmed to
  already be AI-triaged come back with zero candidates and `groupId` left
  blank, because the project had been rescanned since the ticket's scan_id.
  A `scanId` match is now only a preference for disambiguating between
  several risks sharing the same CVE (falling back to `package_identifier`
  matched against `assetName`), never a hard filter that can discard the
  only real match.

## [0.2.4]

### Added
- Before posting a Jira comment, `pipeline.py` now checks the ticket's
  existing comments for the same `"*Vulnerability ID:*"`/`"*CVE ID:*"`
  marker `format_comment` leads with, and skips posting
  (`outcome.comment_skipped_reason` set) if one's already there instead of
  adding a duplicate. Covers both re-running the same ticket and multiple
  results landing on the same parent ticket within one run. A failed check
  fails open (posts as usual).

### Fixed
- `_check_existing_triage` no longer treats a prior `FAILED` `triageStatus`
  as "already exists". `FAILED` means AI Triage itself never produced a
  verdict, so treating it like a real result meant a genuinely failed
  attempt could never be retried automatically; it's now treated the same
  as blank/`NOT_TRIAGED` and gets re-triggered on the next run.

## [0.2.3]

### Changed
- `TriageResolver` now builds one shared `ApiClient` (and so one OAuth
  token) and passes it into all five `CheckmarxPythonSDK.CxOne` classes it
  uses, instead of letting each build its own via `construct_configuration()`.
  Live logs showed the latter fetching a separate token per class actually
  used in a run (up to 4–5 extra round-trips).

### Fixed
- Hardened `_check_existing_triage`'s status check (added in 0.2.2). Live
  testing showed a real tenant returning `CONFIRMED` — a SAST/SCA result
  *state* value, not one of `AiTriageResult`'s documented `triageStatus`
  values — for a vulnerability that had genuinely already been AI-triaged.
  Result states have predefined values (`TO_VERIFY`, `NOT_EXPLOITABLE`,
  `PROPOSED_NOT_EXPLOITABLE`, `CONFIRMED`, `URGENT`) plus whatever custom
  states a tenant defines, but AI Triage only ever assigns a predefined
  one — so this field's real universe of values is bounded, just broader
  than the SDK's own docstring enum. The check now normalizes for
  case/whitespace but stays deliberately permissive (anything but
  blank/`NOT_TRIAGED` counts as "already exists") rather than narrowing to
  a strict allowlist of the documented enum, which would have wrongly
  treated `CONFIRMED` as "not triaged yet" and re-triggered needlessly.

## [0.2.2]

### Added
- Before triggering, `resolver.resolve_and_trigger_all` now checks
  `GET /api/ai-triage/triage/{projectId}/{groupId}` for an existing result
  first. If one already exists (`IN_PROGRESS` or already finished), the
  trigger is skipped for that job (`outcome.trigger_skipped_reason` is set)
  instead of re-submitting an identical request — this matters most on
  re-runs/retries, where nothing gets re-triggered but polling and
  commenting still complete normally against the existing result. A failed
  check fails open (triggers as usual); a job with no `groupId` yet skips
  the check the same way it always has.

## [0.2.1]

### Fixed
- Jira comments for SCA results were being posted on the originating
  **subtask**, not the parent ticket. Comments now always go on the parent
  ticket key for both SAST and SCA — SAST already worked this way (there's
  no subtask involved), but SCA jobs resolved from a subtask now target
  `job.ticket_key` (the parent) instead of the subtask's own key. Since
  several results can now land comments on one ticket (multiple
  `VulnerabilityId`s for SAST, multiple `"SCA | CVE-..."` subtasks for SCA),
  each comment now leads with which specific vulnerability it's about —
  `*Vulnerability ID:*` for SAST (matching the ticket's `VulnerabilityIdN`
  field name) or `*CVE ID:*` for SCA — and, for SCA, `*Subtask:*` so they
  stay distinguishable. The subtask key itself is now carried in
  `jira_meta["subtask_key"]` instead of the removed `jira_meta["parent_key"]`
  (which is redundant now that `ticket_key` already is the parent).

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
