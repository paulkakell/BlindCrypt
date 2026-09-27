# BlindCrypt 01.01.02

Maintenance patch dated 2026-09-27. No intentional public API, encryption-format, KDF-parameter, default-setting or database-schema change.

## Consolidated work

| Pull request | Branch | Preserved source commit |
|---|---|---|
| #2 | dependabot/npm_and_yarn/typescript-7.0.2 | 4792316950cd196960cffb170156667227e45773 |
| #7 | dependabot/github_actions/actions/deploy-pages-5.0.1 | 9e27a82605f443c5fe998e66785dda3458bfd90f |
| #10 | dependabot/github_actions/github/codeql-action/analyze-4.38.1 | ceb0a32515c4cf5d3d7629b45ef05df382a04233 |
| #11 | dependabot/github_actions/github/codeql-action/init-4.38.1 | fd7fb4d51aa98aa2424349a0ce4162fd5865b89a |

The pre-maintenance main commit is 0aff0635c4edd0ea4e4bde964815f5555bae7718. The retained dev branch initially pointed to 34ced24b3c1e32baf712af2121a2c525ab56d3e9 and had no commits absent from main. Preserve main and dev; retire the dependency and temporary release branches only after their exact heads are included in the validated release.

## Fixes and additions

TypeScript 7.0.2 rejected the PBKDF2 salt view because it could be backed by a buffer WebCrypto does not accept. The helper now copies exactly the supplied view into ordinary owned storage before yielding. This also prevents subsequent caller mutation from changing an in-flight derivation. Three regression tests cover offset views, asynchronous mutation and shared-memory views. Fixed nonces and reduced KDF iterations appear only in deterministic test fixtures; production cryptography settings are unchanged.

The previous SAST dependency guard explicitly permitted only TypeScript 5.8.3 and one locked package. It now pins the exact reviewed TypeScript 7 lockfile, including 20 optional native platform packages, by SHA-256. Four additional regressions demonstrate acceptance of the reviewed graph and rejection of compiler, transitive-integrity and unexpected-package changes. npm ci still verifies package SHA-512 integrity and disables install scripts; npm audit remains a separate release gate.

CodeQL init and analyze advance together to 4.38.1; deploy-pages advances to 5.0.1. Every action stays pinned to a full commit SHA. Security validation now runs after main pushes, not only on dev and pull requests. Read-only CI preserves exact source archives for traceability.

## Release and cleanup

Merge the reviewed consolidation with a merge commit, not squash, to preserve all branch ancestry. The Finalize 01.01.02 workflow waits for successful Security validation, CodeQL and Pages push runs on that exact main commit. It creates the matching v01.01.02 tag and preserves new/rollback static archives, a full Git bundle and checksums before deleting any branch. Deletion is an atomic push with exact-SHA leases; a changed or unmerged head blocks cleanup. Main and dev are never deletion targets. A retry uses the Actions workflow with main selected; a different version, stale main commit, incomplete existing release or unexpected merge shape is rejected.

Artifacts: blindcrypt-01.01.02.tar.gz, blindcrypt-01.01.01-rollback.tar.gz, blindcrypt-pre-cleanup.bundle and RELEASE-SHA256SUMS. The application archives include their own SHA256SUMS. No runtime dependencies or release credentials are packaged.

See VALIDATION_01.01.02.md, RELEASE_CHECKLIST.md and ROLLBACK.md. Hosted workflow results and the published release identify the actual validated commit; this source document does not claim an unexecuted check passed.
