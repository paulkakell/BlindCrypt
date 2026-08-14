# Changelog

BlindCrypt versions use `xx.xx.xx` as `<Release>.<Feature Update>.<Bug Fix>`.

## [01.01.00] - 2026-08-13

Status: development branch candidate. Release tag reserved: `v01.01.00` after merge and successful protected validation.

Reference: `SEC-AUDIT-2026-08-13`

Baseline: `4ed8c157c6015340b363848c12527d9499fb8d69`

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
