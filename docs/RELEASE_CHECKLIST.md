# Release checklist

This checklist is mandatory for each BlindCrypt version. Record evidence in the matching validation and release documents.

## Version and traceability

- [x] `VERSION` incremented with `xx.xx.xx` as `<Release>.<Feature Update>.<Bug Fix>`.
- [x] Application version, changelog, release notes, SBOM, and commit notes agree on `01.01.00`.
- [ ] Create tag `v01.01.00` only after the validated commit is deployed from protected `main`.

## Change record

- [x] Changelog states what changed, why, classification, audit reference, and baseline commit.
- [x] Commit notes are copy-ready in `COMMIT_NOTES.md`.

## Automated validation

- [x] Unit tests pass.
- [x] Integration tests pass.
- [x] Regression and tamper tests pass.
- [x] Performance smoke test passes.
- [x] Built-artifact HTTP smoke test passes.
- [x] Hosted Security validation passed on code commit `01116bc7b7613980ef14a19ad082e3ecab6edca5` (run `31763503108`).
- [x] Hosted CodeQL passed on code commit `01116bc7b7613980ef14a19ad082e3ecab6edca5` (run `31763503112`).

## Static quality and security

- [x] Syntax and policy lint pass.
- [x] Strict type checking passes.
- [x] Local SAST passes.
- [x] Authentication inputs, authorization scope, input bounds, logging, secrets, and deployment permissions reviewed.
- [x] No backend authentication or authorization surface exists.
- [x] No browser telemetry, persistent storage, or network API exists.

## Dependencies and build

- [x] Runtime dependency count is zero.
- [x] TypeScript build dependency is exact-pinned with lock integrity.
- [x] GitHub Actions are pinned to full commit SHAs.
- [x] GitHub Advisory Database query reports no advisory affecting TypeScript 5.8.3 at review time.
- [x] Hosted `npm ci --ignore-scripts` and `npm audit --audit-level=high` passed with zero vulnerabilities on run `31763503108`.
- [x] Clean `dist/` build produces checksums, license, and SPDX SBOM.

## Configuration and data

- [x] No environment variables, secrets, feature flags, backend services, or database migrations are required.
- [x] CSP, default security level, limits, workflows, and npm policy are validated.
- [x] Database migration review: not applicable.
- [x] Rollback preserves the v3 reader and prior artifact.

## Compatibility and documentation

- [x] Reader supports v1, v2, and v3.
- [x] Producer format change to v3 is declared breaking for old clients.
- [x] README, API, format, architecture, threat model, security policy, repository settings, validation record, release notes, and rollback plan are updated.
- [x] Usage examples and all security-level options are documented.

## Production controls

- [ ] Apply the repository rules in `docs/REPOSITORY_SETTINGS.md`.
- [ ] Change Pages deployment source from legacy branch deployment to GitHub Actions.
- [ ] Preserve the previous production artifact and checksum.
- [ ] Merge through protected review, deploy, verify, tag, and publish release artifacts.
