# Validation record for 01.01.01

Date: 2026-08-13

Baseline: `b57c01dd515011273832064f0645842655196be7`

References: `GHAS-PR-1`, CodeQL alert 1, PR #1.

## Change under validation

The build-artifact smoke server now uses a fixed route allowlist. It no longer performs a filesystem metadata check followed by a separate path-based read, and request paths never become filesystem paths.

## Planned validation

- fresh `npm ci --ignore-scripts`
- `npm audit --audit-level=high`
- syntax and repository-policy lint
- strict JavaScript type checking
- complete unit, integration, and regression suite
- local SAST and configuration validation
- clean reproducible build
- allowlisted HTTP artifact smoke test, including traversal and method rejection
- 1 MiB authenticated encryption/decryption performance check
- CodeQL extended security suite

## Hosted evidence

Pending the first 01.01.01 code commit. This section will be updated with commit SHA, workflow run identifiers, test totals, artifact name, and artifact digest after the hosted checks complete.

## Dependencies and configuration

Runtime dependencies remain zero. TypeScript 5.8.3 remains exact-pinned as the sole development dependency. No authentication, authorization, backend, database, environment-variable, secret, or feature-flag change is introduced.

## Release gate

Promotion remains blocked until the hosted Security validation and CodeQL workflows pass and CodeQL alert 1 is no longer present on PR #1.
