# Changelog

## [Unreleased]

## [0.3.14]

### Changed
- Polling a `TO_VERIFY` SCA target now probes `GET /api/risks` for the
  settled state on every round (the pipeline passes each SCA target's CVE
  ID to the poller via the new `sca_cve_ids` argument) and finishes the
  poll immediately once the settled state appears, instead of waiting out
  the full timeout window for the triage endpoint to settle — which for a
  live tenant's SCA results it never did (the endpoint served `TO_VERIFY`
  byte-identical every round while the UI already showed
  `PROPOSED_NOT_EXPLOITABLE`). The deadline return-as-is behavior and the
  pipeline's post-poll risk-state translation remain as backstops.

## [0.3.13]

### Fixed
- A result that is still `triageStatus=TO_VERIFY` when the poll deadline
  hits is now returned as-is instead of raising `TimeoutError`. The
  analysis itself is complete at that point (reachability/exploitability
  are populated) — only the verdict's state change hasn't settled: a live
  tenant's SCA result stayed `TO_VERIFY` for the entire window while the
  UI already showed `PROPOSED_NOT_EXPLOITABLE`. Returning it lets the run
  post the Jira comment from the available data instead of posting nothing
  (a still-`IN_PROGRESS` job at the deadline still times out as before).

### Added
- When a polled SCA result is `TO_VERIFY` (analysis complete but the
  verdict state not settled on the triage endpoint), `run_pipeline` now
  consults `GET /api/risks` for the settled state and uses it for the
  comment — a live tenant's SCA triage stayed `TO_VERIFY` on the triage
  endpoint, byte-identical every round, while the risks view (what the UI
  shows) already held `PROPOSED_NOT_EXPLOITABLE`. The lookup matches on
  the triaged `groupId` so a different risk's state is never borrowed; if
  the risks view has no matching entry (or the lookup fails), the
  `TO_VERIFY` result is kept as-is.

## [0.3.12]

### Changed
- `DEFAULT_POLL_TIMEOUT_SECONDS` (the `--poll-timeout` default) raised from
  180s to 300s. 180s proved too tight for real triage jobs: SAST verdicts
  land around the 2.5-minute mark and a live tenant's SCA run timed out
  with one CVE still `IN_PROGRESS` and another still settling on
  `TO_VERIFY` (verdict visible in the UI shortly after). 300s still bounds
  the stuck-job case; verdicts that settle later are picked up by the next
  run's existing-triage pre-check as before.

## [0.3.11]

### Fixed
- `triageStatus=TO_VERIFY` (a result *state* value the API serves briefly
  right after a triage job completes, before the verdict's state change
  lands) now counts as "still working" for the poll loop instead of being
  treated as terminal — a live tenant's run captured `TO_VERIFY` and posted
  a Jira comment with that transient state while the UI already showed the
  settled `PROPOSED_NOT_EXPLOITABLE` verdict moments later.
- The raw-body capture in `_retrieve_triage_result` now retries once when
  its follow-up GET fails — a live tenant's API flapped between 200 (the
  job-status envelope) and 404 for two identical GETs a moment apart,
  which made that poll round look "off-schema" and counted toward the
  fail-fast.

## [0.3.10]

### Fixed
- SCA `groupId` now falls back to the manually-constructed
  `similarityId#-#packageIdentifier#-#projectId` format (documented in the
  API reference, "Retrieve AI Triage Results" — "If necessary, you can
  construct the group_id manually") when `GET /api/risks` has no entry for
  the CVE. A live tenant showed the risks view lagging the results view:
  the SCA trigger was accepted (`202`, `published=True`) but both CVEs'
  `groupId`s stayed blank, so the pipeline skipped AI Triage result polling
  entirely and the run ended with `aiTriageStatus=None`. The constructed
  value uses the `packageIdentifier` from the matched `/api/results` row;
  if that's also unavailable, `groupId` remains blank (trigger still fires,
  polling skipped) as before.
- `poll_ai_triage_result` / `poll_ai_triage_results` now recognize the
  job-status envelope the AI Triage endpoint actually returns while a
  triage job is still processing — `{projectID, groupID, jobStatus:
  IN_PROGRESS}`, ~100 bytes, no `triageStatus` (the documented
  `AiTriageResult` schema simply isn't what the API serves for a running
  job; the raw-body capture added in 0.3.9 decoded this from a live
  tenant's log). `jobStatus: IN_PROGRESS` is treated exactly like
  `triageStatus: IN_PROGRESS` (keep polling until the real result or the
  timeout), instead of the 0.3.9 fail-fast wrongly giving up on a
  legitimately-running job after 2 rounds; the fail-fast now applies only
  to bodies with neither `triageStatus` nor the `IN_PROGRESS` envelope
  (e.g. an envelope with `jobStatus: FAILED`).

## [0.3.9]

### Fixed
- A `GET /api/ai-triage/triage/{projectId}/{groupId}` response whose body
  has no `triageStatus` at all (off-schema — the field is required per the
  API docs) no longer silently degrades to a 180s poll timeout with
  `ai_triage_status=None`. A live tenant showed exactly this: the trigger
  was accepted (`202`, `published=True`) but every poll for the full
  timeout window returned the same ~100-byte placeholder body, which
  `AiTriageResult.from_dict` maps to `triageStatus=None`. Now
  `_retrieve_triage_result` keeps the raw response body (one extra GET,
  only when the parsed result is off-schema), `_count_missing_status`
  logs it at `WARNING`, and both poll methods fail fast with the new
  `AiTriageMissingStatusError` (raw body included in the message, surfaced
  as `poll_error`) after 2 consecutive off-schema rounds instead of
  burning the whole timeout window. `_check_existing_triage` also logs the
  raw body when its pre-check gets an off-schema 200.

## [0.3.8]

### Fixed
- `_check_existing_triage` no longer treats a stuck `IN_PROGRESS` status as
  "already exists" either (same reasoning already applied to `FAILED`). A
  live tenant showed a multi-resultID batch trigger call where only 1 of 3
  resultIDs ended up with a real verdict; the other 2 stayed `IN_PROGRESS`
  indefinitely across multiple follow-up runs (`AiTriageResult` has no
  timestamp to tell "still actively processing" apart from "stuck
  forever"). Treating a stuck `IN_PROGRESS` as existing meant those 2
  could never be retried, ever — it's now treated the same as
  blank/`NOT_TRIAGED`/`FAILED`, safe to re-batch and re-trigger.
- `resolver.poll_ai_triage_results` (the batch method `pipeline.py`
  actually calls) now logs each target's status check the same way the
  singular `poll_ai_triage_result` already did (0.3.5) — that logging
  never actually applied to production once `pipeline.py` switched to the
  batch method, so a still-pending job's checks were happening silently,
  reported live as "it never even tries to get the other 2 vulnerability
  id triage result" when they were in fact being checked every round.
- 2+ SAST `VulnerabilityId` values that resolve to the same `similarityId`
  no longer fail the job. A live tenant hit exactly this: 2 distinct
  resultHashes genuinely sharing one `similarityId`, because Checkmarx
  groups SAST findings by vulnerability *pattern*, not by specific
  occurrence (with no `package_identifier`-style disambiguator available
  for SAST — that's SCA-only — and empty `data` on both matching
  `/api/results` rows). Since `groupId` *is* the `similarityId` for SAST
  and AI Triage only ever returns one verdict per `groupId`, this no
  longer needs to be resolved precisely: `_find_alternate_id` picks one
  matching row as the shared representative (logging every field on each
  ambiguous row for visibility), `_trigger_batch` de-duplicates the
  resultIDs it actually sends so the shared representative is only
  submitted once, the existing-triage pre-check and
  `poll_ai_triage_results` are only ever called once per shared `groupId`
  instead of once per job, and `pipeline.run_pipeline` posts one Jira
  comment naming every one of the distinct `VulnerabilityId` values
  instead of one comment per job (see `comment_formatter.
  build_vulnerability_marker_multi` / `format_comment`'s
  `vulnerability_labels` parameter).

## [0.3.7]

### Added
- `_trigger_batch` now logs the exact `POST /api/ai-triage/triage` payload
  (scanID, scannerType, resultIDs, and each result's groupId for
  reference) and response (triageID, status, published) at `INFO` level.
  Added while investigating a live report of a 3-`VulnerabilityId` SAST
  ticket where only 1 of 3 results (all with distinct, correctly-resolved
  similarity/alternate/group IDs, submitted together in one bucket sharing
  one `triageID`) ended up with a real AI Triage verdict and Jira comment
  — this makes the exact request/response visible on the next run instead
  of only being inferable from the output report.

## [0.3.6]

### Changed
- `DEFAULT_POLL_TIMEOUT_SECONDS` (the `--poll-timeout` default) lowered
  from 600s to 180s, so the 3-minute bound applies out of the box without
  needing to pass `--poll-timeout 180` explicitly — Prudential's actual
  deployed workflow file doesn't automatically pick up changes to
  `examples/prudential-cxone-ai-triage.yaml` in this repo, so a library
  default was the only way to get this without requiring a separate
  workflow-file update on their side.
  `examples/prudential-cxone-ai-triage.yaml` keeps passing `--poll-timeout
  180` explicitly anyway (now redundant with the default) so its behavior
  doesn't silently change if the default is ever tuned differently again.
  `--poll-timeout`'s help text also now clarifies it's shared across every
  pending job in a run (see 0.3.5's batch polling), not restarted per job.

## [0.3.5]

### Fixed
- `poll_ai_triage_result` now logs every status check (`INFO`), not just
  the trigger and final outcome. With the default 600s timeout and no
  progress output in between, a long-but-bounded wait (e.g. several
  sequential findings on one ticket) was reported as looking like an
  infinite loop in a live GitHub Actions log that just goes silent for
  many minutes — it's not: the loop is always bounded by `timeout_seconds`
  and raises `TimeoutError` if it's exceeded. This just makes that wait
  visible instead of silent.

### Changed
- `pipeline.run_pipeline` now polls every job's AI Triage result together
  via a new `resolver.poll_ai_triage_results` (one round of GETs across
  all still-pending jobs per `--poll-interval`), instead of fully waiting
  out each job's own `poll_ai_triage_result` loop to completion before
  even starting the next one's. AI Triage can finish every result in a
  batch trigger call around the same time server-side, so a ticket with
  several `VulnerabilityId`s/CVEs no longer waits up to
  `len(results) x --poll-timeout` in the worst case — a job drops out of
  polling as soon as its own result is ready, and the whole run stops
  waiting once every pending job's result has come back, not before.
  `poll_ai_triage_result` (singular) is unchanged and still used wherever
  only one target needs polling.
- `examples/prudential-cxone-ai-triage.yaml` now passes `--poll-timeout 180`
  explicitly, bounding the post-trigger wait for each AI Triage verdict to
  3 minutes instead of the library default (10 minutes). Polling itself
  (`resolver.poll_ai_triage_result`, called from `pipeline.run_pipeline`
  after every trigger) already existed and ran by default — this just
  tunes how long it waits per result before giving up, for this workflow
  specifically. The library-wide default (`DEFAULT_POLL_TIMEOUT_SECONDS`)
  is unchanged.

## [0.3.4]

### Fixed
- `_get_all_results` (`GET /api/results` pagination, hardened in 0.3.3)
  still failed for any scan with more than one page of results, confirmed
  live: `GET /api/results`'s `offset` parameter is a **page number**
  (0-indexed), not a row-skip count, despite the SDK's own docstring
  ("offset: Items to skip"). 0.3.3 advanced `offset` by the number of rows
  already fetched (the natural "items to skip" reading) — for a real scan
  with 564 results and `limit=500`, that meant requesting `offset=500` for
  page 2, which the API read as "page #500" and correctly-per-that-reading
  returned nothing, silently truncating the scan at 500 rows exactly as
  before. `offset` now advances by 1 (the next page number) instead,
  confirmed against that same live scan to correctly fetch all 564 rows
  across 2 pages. Also enriches the "no such similarityId" `LookupError`
  with the total row count and same-scanner-type row count actually
  fetched, to make a genuine mismatch (e.g. a stale `scan_id`) easier to
  tell apart from a fetch-coverage problem from the error message alone.

## [0.3.3]

### Fixed
- `_get_all_results` (`GET /api/results` pagination) no longer trusts the
  response's `totalCount` to decide when to stop paging. A live tenant
  returned `totalCount` matching just the first page's size (500) for a
  scan that actually had 6500 results — `offset >= totalCount` stopped the
  whole fetch after page 1, silently dropping every row past the first
  page and causing `_find_alternate_id` to report "no such similarityId"
  for results that genuinely existed (confirmed present in the CxOne UI).
  Pagination now stops on the first short page (fewer rows returned than
  requested) instead, which doesn't depend on `totalCount`'s accuracy at
  all.

## [0.3.2]

### Fixed
- `parse_jira_issue` no longer requires a `'Checkmarx (SAST)'`/`'Checkmarx
  (SCA)'` marker in the ticket description to determine scanner type when
  structured fields already say which one it is. A live ticket
  (RITSDEVSECOPS-43549) had `VulnerabilityId1` populated but no such marker
  anywhere in its description — its template doesn't include Checkmarx's
  usual description boilerplate at all — which failed before this fix,
  since the marker check ran unconditionally before any structured field
  was even looked at. `_infer_scanner_type` now checks `VulnerabilityId1..5`
  (→ SAST) and `packageNameVersion`/`subtasks` (→ SCA) first, falling back
  to the description marker only when neither structured signal is present.

## [0.3.1]

### Added
- `github_event.load_issue_key` now also reads `inputs.issue_key` (a
  `workflow_dispatch` event), not just `client_payload.issue_key`
  (`repository_dispatch`) — some orgs' policies disable
  `repository_dispatch` entirely (confirmed by Prudential against a real
  org), while `workflow_dispatch` is allowed. Both are checked
  automatically, so the same binary works with either without a rebuild;
  only the workflow file's `on:` trigger and the Jira Automation rule's
  Send Web Request URL/body need to change to switch between them.
  `examples/prudential-cxone-ai-triage.yaml` and
  `docs/jira-automation-setup.md` now document `workflow_dispatch` as the
  primary path (with `repository_dispatch` kept as a documented
  alternative). New `samples/github_event_workflow_dispatch.sample.json`;
  `samples/github_event_issue_key.sample.json` renamed to
  `samples/github_event_repository_dispatch.sample.json` for clarity.

## [0.3.0]

### Added
- `JiraCommentClient.get_issue_for_triage` now logs the fetched ticket's
  key fields (`scanId`, `VulnerabilityId1..5`, `packageNameVersion`) and
  every subtask it found (key/summary/status/assignee) — restoring the
  visibility the old `client_payload.jira_issue`-era workflow's dedicated
  diagnostic-logging steps used to provide on the GitHub Actions side,
  which had nothing to replace it once that payload shape was removed.

### Removed
- **Breaking:** `client_payload.jira_issue` (the Jira Automation rule
  building the full structured ticket itself, field-by-field) is no longer
  supported — `client_payload.issue_key` (added in 0.2.6) is now the only
  supported payload shape. `cxone_ai_triage` always fetches the ticket (and
  its subtasks) itself via the Jira REST API. `JIRA_SERVER`/`JIRA_EMAIL`/
  `JIRA_API_TOKEN` are now required (not optional) in the default
  `--github-event` mode, since without them there's no way to fetch the
  ticket at all; they remain optional with `--input` (local batch testing).
  `github_event.load_jira_issue`/`load_jira_issue_or_key` are replaced by
  `load_issue_key`. `samples/github_event.sample.json` and
  `samples/github_event_sca.sample.json` are removed;
  `samples/github_event_issue_key.sample.json` is the only sample event
  file now. `docs/jira-automation-setup.md` documents only the issue_key
  setup.

## [0.2.6]

### Added
- `client_payload.issue_key` is now a supported alternative to
  `client_payload.jira_issue`: the Jira Automation rule can send just the
  ticket key, and `cxone_ai_triage` fetches the full ticket (and its
  subtasks, via a JQL search) itself via the Jira REST API instead
  (`JiraCommentClient.get_issue_for_triage`), shaping it into the same dict
  `jira_parser.py` already expects. Which custom field is which is
  configured via new `JIRA_FIELD_SCAN_ID` / `JIRA_FIELD_VULNERABILITY_ID_1..5`
  / `JIRA_FIELD_PACKAGE_NAME_VERSION` env vars (`JiraFieldMapping`), so the
  Automation rule no longer has to maintain a field-by-field mapping (or be
  touched again when a new custom field is needed). See
  `docs/jira-automation-setup.md`'s "Alternative: send just the issue key".

## [0.2.5]

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
