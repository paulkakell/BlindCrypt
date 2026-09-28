# BlindCrypt 02.00.01 maintenance notes

Date: September 27, 2026. Classification: security and tooling fix. Refs #15, #13.
Baseline production commit: `8cea1fe449cff297338c8c2bd6a0e71e555382eb`.

## Changes and reason

The browser harness no longer discovers a network debugging endpoint or embeds fixture JSON in executable JavaScript. Chromium communicates through private inherited pipes, while fixed page functions receive data through DevTools call arguments. These changes address the three medium scanning findings in #15 without alert dismissal, query exclusions, or sanitizer exceptions.

The transport fails closed on malformed, oversized or cross-session messages; commands have bounded pending counts and timeouts. Tests cover argument separation, Unicode, fragmented protocol reads, error cleanup and exact-SHA branch retirement. All prior real-browser feature workflows are retained.

## Compatibility and configuration

Application version, worker version, displayed fallback and SBOM move to 02.00.01. Public APIs, CLI options, passphrase semantics, v1/v2/v3 compatibility, JWE profile, limits, security defaults and cache policy are unchanged. No dependency or lockfile changes, account/backend configuration, database schema or migration is needed. No user-data logging is added. Node.js 22+ and the existing Chromium executable are still used for validation; see BROWSER_TESTS.md.

## Branch maintenance

The scoped workflow runs only for the reviewed main-branch patch. It requires successful CI, CodeQL and Pages workflows for the exact commit, then inspects the actual SARIF and refuses any remaining result. Before deletion it uploads the entire Git bundle, pre-patch source and checksum/evidence files. Only `release/02.00.00` at `73759b4649a8dd26e255770f06b6eb8caa35f03b` and the integrated `fix/02.00.01` second-parent commit are eligible. Atomic expected-SHA leases prevent removal of a concurrently advanced candidate. `main`, `dev`, tags and unrelated branches are untouched.

## Validation and release status

Observed results and workflow references belong in VALIDATION_02.00.01.md and #15. Source presence is not a passed gate. This maintenance patch does not claim the outstanding native OS/device/independent-recipient-review work in #13 is complete. No automatic release tag is created; formal release acceptance remains separate from this security patch and branch retirement.

## Rollback

Revert the maintenance merge through a reviewed follow-up, not by resetting main. Retain a 02.x reader for large and recipient files. Reverting the harness restores the old findings, so prefer a forward fix. The archived bundle and pre-patch source preserve branch recovery; see ROLLBACK.md.
