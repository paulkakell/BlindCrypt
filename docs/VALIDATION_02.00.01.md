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

## Hosted gates

Pending at this implementation commit: exact-head locked install/audit/full
validation, actual Chromium workflows, and inspection of CodeQL SARIF results.
Workflow run IDs, source SHA and conclusions will be added to #15. Do not equate
an analysis job's success with the absence of alerts.

## Review scope

No application authentication, authorization, input policy, cryptography,
dependency, database, migration, secret storage, environment-secret configuration,
API or file-format behavior changed. Only required version markers change in
browser code. The existing 1 MiB round-trip and 65 MiB streaming tests still apply.
Privileged maintenance has fixed repository/version/branch gates, complete
ancestry checks, archive-before-delete ordering and atomic expected-SHA leases.
No finding is suppressed, dismissed or excluded. All unrelated manual/security
review limitations in #13 remain in effect.
