# Changelog

## 02.00.01 - 2026-09-27

Classification: security/tooling fix; no application API or container-format change. Refs #15 and #13. Baseline: `8cea1fe449cff297338c8c2bd6a0e71e555382eb` (02.00.00 merged through #14).

- Replace the browser test harness's discovered debugging WebSocket with private child-process pipes. No debugging port or network fallback remains.
- Replace fixture, field and selector interpolation with fixed page functions and by-value DevTools arguments, addressing two `js/bad-code-sanitization` flows and the `js/file-access-to-http` flow without suppressing CodeQL rules.
- Add transport framing, Unicode, argument separation, timeout, failure, session-isolation and branch-retirement regressions. Preserve all ten prior real-browser workflows and add a fixture-data boundary check.
- Increment application/worker/display/SBOM versions together. Keep the reviewed lockfile and all runtime dependencies unchanged.
- Add a narrowly scoped maintenance workflow that requires exact-commit validation, deployment and zero SARIF findings, uploads recovery artifacts, then retires only integrated `release/02.00.00` and `fix/02.00.01` heads with atomic expected-SHA leases. Never delete or update `main`, `dev`, tags or unrelated branches.

See `docs/VALIDATION_02.00.01.md` for executed evidence and limitations. This patch does not resolve unrelated native-browser or independent recipient-cryptography review gates in #13.

## 02.00.00 (release candidate, 2026-09-27)

Related: #13. Baseline commit: `d9ac4217604c248e73b34edebcbdbd6e8af80b06`. Candidate/production hashes and CI evidence are recorded in the PR and tracker after publication; no hash is fabricated here.

### Additive

- Implement all nine accepted roadmap features: opaque output naming, bounded sequential batches, v3 verification without plaintext download, encrypted text, passphrase/settings/legacy re-encryption, opt-in offline installation, transactional large-file streams, Node CLI, and restricted single-recipient JWE with protected identities.
- Add direct Node-crypto interoperability, stream failure/cancellation/size tests, CLI no-overwrite and secret-input checks, offline cache-policy tests and a real Chromium workflow suite.
- Produce deterministic offline asset manifests/icons and complete static/CLI checksums; preserve validation logs in CI.

### Fixes

- Stop exposing the original filename in default encrypted outer names.
- Clear visible generated secrets after operations and preserve I/O error causes while aborting incomplete output.
- Expand SAST to all added browser modules, service worker and CLI while keeping the exact reviewed dependency lock pin.

- Validate service-worker activation message origin and client scope explicitly, with forged-origin regression coverage. Retain hidden build markers in release artifacts so the checksum manifest remains complete. Iteration evidence and remaining test-harness findings are recorded in `docs/ITERATIONS_02.00.00.md`.

### Breaking

- Optional offline behavior introduces narrowly scoped public-asset fetch/cache operations after explicit enablement; no user file or secret enters them.
- Default outer filenames change; revealing naming remains explicit.
- Recipient JWE and v3 above the old 64 MiB ceiling require a 02.00.00-capable reader. Existing buffered v3 API signatures and v1/v2 reading remain available.

No new runtime/development dependency or database migration. Independent crypto and native browser/device review are release gates, not inferred from automated tests. See `docs/ROADMAP.md`, `docs/RELEASE_02.00.00.md` and `docs/VALIDATION_02.00.00.md`.


BlindCrypt versions use `xx.xx.xx` as `<Release>.<Feature Update>.<Bug Fix>`.

## [01.01.02] - 2026-09-27

### Fixed
- Snapshot PBKDF2 salt into an ordinary owned byte buffer before the first asynchronous operation. This resolves TypeScript 7 BufferSource checking and prevents caller mutation from changing an in-flight derivation. Encryption algorithms, KDF parameters and v1/v2/v3 formats are unchanged.
- Validate pushes to `main` as well as `dev`, closing the previous post-merge CI trigger gap.

### Maintenance
- Integrate TypeScript 7.0.2 from PR #2 (`4792316950cd196960cffb170156667227e45773`), including its existing lockfile.
- Integrate deploy-pages 5.0.1 from PR #7 (`9e27a82605f443c5fe998e66785dda3458bfd90f`).
- Integrate CodeQL analyze/init 4.38.1 from PRs #10/#11 (`ceb0a32515c4cf5d3d7629b45ef05df382a04233`, `fd7fb4d51aa98aa2424349a0ce4162fd5865b89a`). Keep actions pinned to full commit SHAs.
- Replace the obsolete one-package TypeScript allowlist with the exact reviewed lockfile SHA-256, preserving fail-closed dependency validation.

### Added
- Regression tests for salt view offsets, mutation while awaiting WebCrypto, shared-buffer views and lockfile tampering.
- Source archives, a version-scoped release/cleanup workflow, release notes and branch-restoration instructions. Cleanup requires successful validation, CodeQL and Pages runs for the exact main commit and preserved rollback artifacts.

Compatibility: patch release; no intentional public API, format, database or user-configuration break. The compiler toolchain changes major version, but is development-only and must pass hosted validation before integration.

## [01.01.01] - 2026-08-13

Status: development branch candidate. Release tag reserved: `v01.01.01` after merge and successful protected validation.

References: `GHAS-PR-1`, CodeQL alert 1, PR #1.

Baseline: `b57c01dd515011273832064f0645842655196be7`.

### Security fix

- Replaced the validation HTTP server's `stat()` followed by `readFile()` sequence, which CodeQL identified as a potential filesystem check/use race.
- Replaced request-derived filesystem resolution with an exact route allowlist. Request path data is now used only as a map key and never becomes a filesystem path.
- Added explicit rejection for unlisted paths, traversal-shaped requests, and non-GET methods.

### Tests and controls

- Added regression tests that prohibit reintroduction of `stat()` checks, dynamic path decoding, and request-derived file paths in the smoke server.
- Made the public-header tamper fixture choose a guaranteed-different writer value so release version changes cannot turn the security mutation into a no-op.
- Retained the runtime smoke checks for every expected build asset and added negative requests for traversal and unlisted paths.
- Updated the application version, changelog, SBOM, security policy, release notes, validation record, release checklist, README, and commit notes.

### Classification and compatibility

- Change type: security bug fix.
- Breaking: no.
- Encryption format: unchanged at v3.
- Reader compatibility: unchanged for v1, v2, and v3.
- Runtime dependencies: unchanged at zero.
- Database, backend, environment, and configuration migration: not applicable.

## [01.01.00] - 2026-08-13

Status: superseded before release by `01.01.01`.

Reference: `SEC-AUDIT-2026-08-13`.

Baseline: `4ed8c157c6015340b363848c12527d9499fb8d69`.

### Security fixes

- Added authenticated format v3. The exact public header frame, record type, record index, and plaintext record length are bound to every AES-GCM record through additional authenticated data.
- Added a fixed-size encrypted metadata record for filename, media type, and writer version.
- Added exact container-length verification, canonical public-header parsing, record-geometry checks, and rejection of truncation or trailing data.
- Added strict upper and lower bounds for KDF iterations, public-header length, salt and IV lengths, plaintext size, record count, metadata size, and passphrase length.
- Added a 64 MiB plaintext ceiling and slice-based Blob processing to reduce memory amplification.
- Added safe filename and MIME normalization. Legacy output uses a neutral filename and media type.
- Replaced misleading custom-passphrase entropy estimates. Generated word-list phrases retain transparent word-count estimates; custom passphrases receive no entropy claim.
- Removed the four-word generator option. The minimum generated phrase is six words. Repetitive custom values are rejected.
- Added NFC normalization for v3 while preserving exact passphrase behavior for legacy v1 and v2.
- Added a restrictive Content Security Policy, a no-referrer policy, local-only executable resources, and checks that prohibit network APIs, dynamic HTML sinks, persistent storage, and console logging.

### Additive changes

- Added read compatibility for v1, v2, and v3 through a single bounded parser.
- Added unit, integration, regression, tamper, normalization, and performance tests.
- Added strict JavaScript type checking, custom linting, local SAST, configuration validation, reproducible static builds, an HTTP artifact smoke test, SHA-256 manifests, an SPDX SBOM, dependency auditing, and CodeQL.
- Classified the bundled 2,048-word list as separately validated static data so security lint does not mistake dictionary words such as `fetch` for executable network APIs.
- Added pinned GitHub Actions workflows for validation, scanning, artifact retention, and Pages deployment.
- Added version, format, architecture, API, threat-model, validation, release, rollback, repository-settings, commit-note, and security-policy documentation.

### Removed

- Removed the unused placeholder `assets/wordlist_2048.js` file.
- Removed new-file format v2 output. Version 2 remains readable.
- Removed unverified custom entropy labels and the insecure four-word generation option.

### Compatibility

- Additive reader compatibility: version `01.01.00` reads v1, v2, and v3.
- Breaking producer change: files created by `01.01.00` use v3 and cannot be opened by the unversioned baseline.
- No backend API, database schema, environment-variable, or server configuration migration exists.
