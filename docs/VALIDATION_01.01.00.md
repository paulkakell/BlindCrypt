# Validation record for 01.01.00

Date: 2026-08-13

Baseline: `4ed8c157c6015340b363848c12527d9499fb8d69`

Reference: `SEC-AUDIT-2026-08-13`

## Local environment

- Node.js 22.16.0
- npm 10.9.2
- TypeScript 5.8.3
- Linux validation container

## Full validation result

Command: `npm run validate`

Result: passed.

- syntax and repository-policy lint: passed across 18 JavaScript files
- strict JavaScript type checking: passed
- unit, integration, and regression tests: 25 passed, 0 failed
- local static security analysis: passed
- workflow and configuration validation: passed
- clean static build: passed
- built-artifact HTTP smoke test: passed
- 1 MiB authenticated round-trip performance smoke test: passed

## Security regression coverage

The suite verifies:

- empty, one-byte, boundary, and multi-record v3 round trips
- NFC-equivalent v3 passphrases
- exact legacy passphrase behavior
- wrong-passphrase rejection
- public-header tamper rejection
- encrypted-metadata tamper rejection
- ciphertext-record tamper rejection
- truncation and trailing-data rejection
- excessive KDF rejection before derivation
- noncanonical header rejection
- bounded v1 and v2 compatibility
- legacy v2 trailing-data rejection
- filename and media-type normalization
- six-word minimum generation
- rejection of four-word and repetitive custom passphrases
- duplicate word-list rejection

## Performance evidence

Input: 1,048,576 bytes

Encrypted container: 1,049,908 bytes

- encryption: 471.5 ms
- decryption: 453.3 ms

These measurements describe the local host only. CI enforces a 30-second ceiling for each operation and does not treat the local values as a browser or mobile guarantee.

## Dependencies

Runtime dependencies: none.

Development dependency: TypeScript 5.8.3, exact-pinned in the lock file. Installation scripts are disabled. The GitHub validation workflow performs a fresh `npm ci --ignore-scripts` and `npm audit --audit-level=high` before rerunning the complete suite.

## Build outputs

The clean `dist/` artifact contains the application, version, license, SPDX SBOM, `.nojekyll`, and `SHA256SUMS`. The workflow retains the artifact by commit SHA.

## Hosted validation

Code commit: `01116bc7b7613980ef14a19ad082e3ecab6edca5`

- **Security validation** run `31763503108`: passed.
- Fresh `npm ci --ignore-scripts`: passed.
- `npm audit --audit-level=high`: passed with zero vulnerabilities.
- Complete `npm run validate`: passed.
- Validated artifact: `blindcrypt-01116bc7b7613980ef14a19ad082e3ecab6edca5`.
- Artifact digest: `sha256:dbd4c61f31fc539e9c62c9552df7e4b7d612837f90e0074f7ba4a4e6c9d636c3`.
- **CodeQL** run `31763503112`: passed with the extended security query suite.

Promotion remains blocked on the repository settings, protected review, production Pages deployment, and release-tag steps documented in the release checklist.
