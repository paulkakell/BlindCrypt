# Release candidate 01.01.00

Date: 2026-08-13

Tag after protected merge: `v01.01.00`

Reference: `SEC-AUDIT-2026-08-13`

Baseline: `4ed8c157c6015340b363848c12527d9499fb8d69`

## Summary

This release replaces new-file format v2 with authenticated format v3, retains bounded read compatibility for v1 and v2, adds encrypted metadata, closes parser and resource-exhaustion paths, corrects passphrase guidance, and introduces a reproducible security-focused release pipeline.

## Change classification

- Breaking: old BlindCrypt builds cannot decrypt newly written v3 files.
- Additive: the new reader supports v1, v2, and v3.
- Fix: public-header integrity, encrypted metadata, exact-length validation, KDF and parser bounds, memory ceiling, neutral legacy output, passphrase assessment, CSP, and deployment validation.

## Validation evidence

Local validation environment:

- Node.js 22.16.0
- 25 unit, integration, and regression tests
- strict JavaScript type check through TypeScript 5.8.3
- syntax and policy lint
- custom static security analysis
- configuration validation
- clean `dist/` build with `SHA256SUMS`
- local HTTP smoke test of the built artifact
- 1 MiB standard-level authenticated round trip performance smoke test

Local performance smoke result: 1,048,576 input bytes, 1,049,908 encrypted bytes, 471.5 ms encryption, and 453.3 ms decryption on the recorded host.

The GitHub workflow repeats installation from `package-lock.json`, runs `npm audit --audit-level=high`, executes `npm run validate`, runs CodeQL, and retains the validated artifact. Release is blocked until those checks succeed on the final commit.

## Dependency validation

Runtime dependencies: none.

Development dependency: TypeScript 5.8.3, pinned in `package.json` and `package-lock.json`. CI installs with `npm ci --ignore-scripts` and fails on high or critical audit findings.

## Configuration and migration review

- Environment variables: none.
- Feature flags: none.
- Backend services: none.
- Database schema or migration: none.
- Runtime logging or telemetry: none.
- Pages deployment: must use the committed GitHub Actions workflow.

## Performance and resource behavior

The application processes file data in 512 KiB slices and enforces a 64 MiB plaintext ceiling. The release smoke test measures a 1 MiB encrypt/decrypt round trip and fails when either operation exceeds 30 seconds on the CI host. Performance numbers are host-specific and are not a device guarantee.

## Logging and observability

The browser application emits no console logs, network telemetry, filenames, passphrases, plaintext, or decryption details. CI records only command output, versioned source, test status, artifact metadata, and deployment status.

## Release artifacts

- validated `dist/` directory
- `dist/SHA256SUMS`
- `dist/SBOM.spdx.json`
- source commit
- tag `v01.01.00`
- this release note
- changelog
- workflow validation and CodeQL results

## Promotion checklist

1. Confirm `dev` commit and diff contain only intended files.
2. Confirm Security validation and CodeQL succeed.
3. Apply required repository rules and GitHub Pages settings.
4. Merge through a protected pull request.
5. Confirm the `main` Pages workflow deploys the validated artifact.
6. Create annotated tag `v01.01.00` on the deployed commit.
7. Attach the artifact, checksum, and release notes.
8. Preserve the previous artifact and rollback instructions.

## Commit notes

```text
security: release BlindCrypt 01.01.00 with authenticated format v3

Release: 01.01.00
Tag after protected merge: v01.01.00
Refs: SEC-AUDIT-2026-08-13
Baseline: 4ed8c157c6015340b363848c12527d9499fb8d69

- authenticate the exact v3 header and record context with AES-GCM AAD
- encrypt and validate fixed-size filename and media-type metadata
- reject truncation, trailing bytes, malformed geometry, and excessive KDF inputs
- cap plaintext at 64 MiB and process source data in bounded slices
- retain bounded v1/v2 reads with neutral legacy output and explicit warnings
- remove four-word generation and unverified custom entropy labels
- add CSP, tests, type checking, SAST, CodeQL, locked builds, and release docs

Change type: breaking producer format, additive reader support, security fixes
Rollback: preserve the v3 reader; revert deployment or interface changes separately
```
