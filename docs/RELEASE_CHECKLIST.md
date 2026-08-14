# Release checklist

This checklist is mandatory for each BlindCrypt version. Record evidence in the matching validation and release documents.

## Version and traceability

- [x] `VERSION` incremented with `xx.xx.xx` as `<Release>.<Feature Update>.<Bug Fix>`.
- [x] Application version, changelog, release notes, SBOM, security policy, and commit notes agree on `01.01.01`.
- [ ] Create tag `v01.01.01` only after the validated commit is deployed from protected `main`.

## Change record

- [x] Changelog records the CodeQL finding, reason for the fix, classification, references, and baseline commit.
- [x] Commit notes are copy-ready in `COMMIT_NOTES.md`.

## Automated validation

- [x] Unit tests pass.
- [x] Integration and legacy compatibility tests pass.
- [x] Regression tests, including the smoke-server race policy and deterministic header tampering, pass.
- [x] Performance smoke test passes.
- [x] Built-artifact HTTP smoke test passes.
- [x] Hosted Security validation passed on commit `a0ca628f36b609856fd14292088007f26ebc9e97` in run `31767647395`.
- [x] Hosted CodeQL passed in run `31767647419` and the alert 1 review thread was automatically resolved.

## Static quality and security

- [x] Syntax and policy lint pass across 19 JavaScript files.
- [x] Strict type checking passes.
- [x] Local SAST passes.
- [x] The smoke server uses fixed routes and no request-derived filesystem path.
- [x] Authentication inputs, authorization scope, input bounds, logging, secrets, and deployment permissions reviewed.
- [x] No backend authentication or authorization surface exists.
- [x] No browser telemetry, persistent storage, or network API exists.

## Dependencies and build

- [x] Runtime dependency count remains zero.
- [x] TypeScript 5.8.3 remains exact-pinned with lock integrity.
- [x] GitHub Actions remain pinned to full commit SHAs.
- [x] Hosted `npm ci --ignore-scripts` and `npm audit --audit-level=high` passed with zero vulnerabilities.
- [x] Clean `dist/` build produced 14 release files, checksums, license, and SPDX SBOM.
- [x] Artifact `blindcrypt-692edf143bc4744637bdabe5bec760423688a4c7` retained with digest `sha256:d9d0c8a5c23d1cd24953460ccbd80eefa36275b9a629a171c8ef9eea37b7252b`.

## Configuration and data

- [x] No environment variables, secrets, feature flags, backend services, or database migrations are required.
- [x] Encryption format, default security level, CSP, limits, and user behavior are unchanged.
- [x] Database migration review: not applicable.
- [x] Rollback retains the format v3 reader and previously validated artifact.

## Compatibility and documentation

- [x] Reader support remains v1, v2, and v3.
- [x] Producer output remains v3.
- [x] Change is declared a non-breaking security bug fix.
- [x] README, security policy, validation record, release notes, changelog, SBOM, checklist, and commit notes are updated.

## Production controls

- [ ] Apply the repository rules in `docs/REPOSITORY_SETTINGS.md`.
- [ ] Change Pages deployment source from legacy branch deployment to GitHub Actions.
- [ ] Preserve the previous production artifact and checksum.
- [ ] Merge through protected review, deploy, verify, tag, and publish release artifacts.
