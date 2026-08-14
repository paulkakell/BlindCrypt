# Validation record for 01.01.01

Date: 2026-08-13

Baseline: `b57c01dd515011273832064f0645842655196be7`

References: `GHAS-PR-1`, CodeQL alert 1, PR #1.

Validated head commit: `a0ca628f36b609856fd14292088007f26ebc9e97`

Pull-request merge commit used by GitHub Actions: `692edf143bc4744637bdabe5bec760423688a4c7`

## Change validated

The build-artifact smoke server now uses a fixed route allowlist. It no longer performs a filesystem metadata check followed by a separate path-based read, and request paths never become filesystem paths. The server accepts only `GET`, rejects unlisted and traversal-shaped paths, and opens each fixed target once.

The public-header tamper regression also chooses a writer value guaranteed to differ from the current release, preventing future version increments from turning the mutation into a no-op.

## Hosted validation evidence

Security validation run `31767647395`: passed.

CodeQL run `31767647419`: passed with the extended security query suite.

The GitHub Advanced Security review thread for CodeQL alert 1 was automatically resolved after analysis of the corrected code.

### Environment and dependencies

- Node.js 22.16.0
- npm 10.9.2
- fresh `npm ci --ignore-scripts`: passed
- installed packages: 2 including the root project
- `npm audit --audit-level=high`: passed with zero vulnerabilities
- runtime dependencies: zero
- development dependency: TypeScript 5.8.3, exact-pinned with lock integrity

### Full validation suite

Command: `npm run validate`

Result: passed.

- syntax and repository-policy lint: passed across 19 JavaScript files
- strict JavaScript type checking: passed
- unit, integration, compatibility, security, and regression tests: 27 passed, 0 failed
- local static security analysis: passed
- workflow and configuration validation: passed
- clean static build: passed, producing 14 release files
- allowlisted built-artifact HTTP smoke test: passed
- path traversal, unlisted route, and non-GET rejection checks: passed
- 1 MiB authenticated round-trip performance check: passed

### Performance evidence

Input: 1,048,576 bytes

Encrypted container: 1,049,908 bytes

- encryption: 154.2 ms
- decryption: 148.4 ms

These measurements describe the hosted Linux runner only. The workflow enforces a 30-second ceiling for each operation and does not treat these values as a browser or mobile guarantee.

### Build artifact

Artifact: `blindcrypt-692edf143bc4744637bdabe5bec760423688a4c7`

Artifact ID: `9206902305`

Artifact size: 29,221 bytes

Artifact digest: `sha256:d9d0c8a5c23d1cd24953460ccbd80eefa36275b9a629a171c8ef9eea37b7252b`

The artifact contains the application, version, license, SPDX SBOM, `.nojekyll`, and `SHA256SUMS` as produced by the clean build.

## Security review

The affected HTTP server is a short-lived validation utility bound to `127.0.0.1`; it is not included in the browser artifact. The fixed route map prevents request input from controlling filesystem resolution. No authentication, authorization, backend, database, secrets, environment variables, feature flags, telemetry, or application logging behavior changed.

## Compatibility and migrations

- writer format remains v3
- reader support remains v1, v2, and v3
- cryptographic framing, KDF settings, IV construction, authentication inputs, and browser file limits are unchanged
- API and user workflow compatibility is unchanged
- database migration review: not applicable
- rollback retains the format v3 reader and the previous validated artifact

## Release gate

Code and hosted security validation are complete. Promotion remains blocked until repository protection is applied, Pages uses the committed GitHub Actions deployment workflow, the pull request is merged through review, the production deployment is verified, and tag `v01.01.01` is created from the validated production commit.
