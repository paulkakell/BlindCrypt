# Validation evidence: 02.00.01

Refs #15 and #13. Baseline main: `8cea1fe449cff297338c8c2bd6a0e71e555382eb`,
source tree `85990d4faeb6edf077fa84d4b097f1dc515d1f58`. The mounted source
archive's Git tree was verified equal to the production tree before editing.

## Local evidence

The unchanged baseline passed 74 Node tests. The patch adds 14 browser-harness
regressions and seven branch-retirement tests. Focused new suites pass locally.
The full local suite passed all 95 tests. Lint, TypeScript 5.8.3 diagnostics,
custom SAST, configuration checks, deterministic build and HTTP smoke passed.
The 1 MiB performance smoke recorded 176.5 ms encryption and 163.7 ms decryption.
These runner-specific measurements are not a performance guarantee.

The exact TypeScript 7.0.2 `npm ci --ignore-scripts` could not complete locally
because registry DNS resolution returned EAI_AGAIN. The lockfile was not
modified. Any local installed TypeScript diagnostics are not locked-tool release
evidence. A fresh hosted install and current dependency audit remain required.

The replacement pipe transport reached Chromium, but Page.navigate returned
`net::ERR_BLOCKED_BY_ADMINISTRATOR`. No browser policy was bypassed. Local
browser workflows are therefore not reported as passed; the unchanged hosted
browser gate must run all prior workflows and the new fixture-data regression.

## Hosted evidence for implementation 18bf517f

Implementation commit: `18bf517ffdc058b486239c2acb749ebfb92c8c34`. Its uploaded
source tree `e350f781ca2c4f0997d272faf206ae4b733e210b` exactly matches the
locally tested implementation index. GitHub's PR merge used
`22e82f0ebceef2f577b4ac09cb21370d9e4d01c5`.

[Validation run 36365862545](https://github.com/paulkakell/BlindCrypt/actions/runs/36365862545)
passed on September 27, 2026 in America/Denver (September 28 UTC). Fresh locked
installation and dependency audit succeeded. All 95 Node tests passed with no
skips, plus 11 actual Chrome 153 workflow checks and zero console exceptions.
Lint, locked strict type checking, custom SAST, configuration, deterministic build,
HTTP smoke and performance checks passed. The hosted 1 MiB smoke measured
130.6 ms encryption and 126.9 ms decryption.

[CodeQL run 36365862525](https://github.com/paulkakell/BlindCrypt/actions/runs/36365862525)
completed successfully. The downloaded `javascript.sarif` was parsed and contains
zero results, including none of the three reported medium findings. No alert was
dismissed and no rule/query was suppressed. The SARIF ZIP SHA-256 is
`275e5b5a10f00f9dca0afb261608edbc7f924a2e57b9c436f55885e869191a82`.
The downloaded validation ZIP SHA-256 is
`8e02f86344ab11b5c3421bb1475fd7bb38b54b1fd21d8b37eb8fca0918fb2c7f`.

The eleventh browser check confirms fixture quotes, backslashes, Unicode line
separators and markup remain literal data. All ten prior application workflows
are retained. These results cover the implementation commit, not an unobserved
future merge. Final documentation and production commits must be revalidated;
immutable run references and cleanup receipts are recorded in #15 and PR #16.
The maintenance workflow independently checks exact-production-SHA CI, CodeQL,
Pages and zero SARIF results before any branch deletion.

## Review scope

No application authentication, authorization, input policy, cryptography,
dependency, database, migration, secret storage, environment-secret configuration,
API or file-format behavior changed. Only required version markers change in
browser code. The existing 1 MiB round-trip and 65 MiB streaming tests still apply.
Privileged maintenance has fixed repository/version/branch gates, complete
ancestry checks, archive-before-delete ordering and atomic expected-SHA leases.
No finding is suppressed, dismissed or excluded. All unrelated manual/security
review limitations in #13 remain in effect.
