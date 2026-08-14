# BlindCrypt 01.01.01 release notes

Status: development candidate on `dev`.

Target tag after protected merge and production validation: `v01.01.01`.

References: `GHAS-PR-1`, CodeQL alert 1, PR #1.

## Summary

Version 01.01.01 fixes the CodeQL finding reported against the build-artifact smoke server. The validation utility previously checked a requested file with `stat()` and then reopened the path with `readFile()`. A concurrent filesystem change between those operations could cause the second operation to act on a different object.

The smoke server now exposes only a fixed set of validation routes. Incoming request paths are map keys, not filesystem paths. The server performs one file read for the fixed route target and rejects unlisted paths, traversal-shaped requests, and non-GET methods.

## Security impact

- Eliminates the reported filesystem check/use race in `scripts/smoke.mjs`.
- Removes request-derived filesystem path construction from the validation server.
- Narrows the local server to the exact build assets required by the smoke test.
- Adds source-level regression checks and negative HTTP requests.

The affected server is a short-lived local CI and developer validation utility bound to `127.0.0.1`; it is not shipped in the browser artifact. The fix is still required because release tooling is part of the software supply chain.

## Compatibility

- No encryption-format change.
- New files remain format v3.
- Reading v1, v2, and v3 remains supported.
- No API, database, configuration, environment-variable, or user-data migration.
- No runtime dependency change.

## Validation requirements

Before promotion:

1. Run a fresh locked install with scripts disabled.
2. Run `npm audit --audit-level=high`.
3. Run `npm run validate`, including unit, integration, regression, SAST, build, smoke, and performance checks.
4. Run CodeQL with the extended security suite and confirm alert 1 is resolved.
5. Retain the build artifact and SHA-256 digest.
6. Merge through protected review, deploy from `main`, verify Pages, then create `v01.01.01`.

## Rollback

Revert the 01.01.01 commits to the previously validated 01.01.00 development candidate. Format v3 support must remain available. Do not deploy the old smoke-server implementation in release validation after the CodeQL finding is known.
