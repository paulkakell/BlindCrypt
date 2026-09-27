# Validation evidence: 02.00.00

Tracker: [#13](https://github.com/paulkakell/BlindCrypt/issues/13). Baseline source was recovered from GitHub Actions and its Git tree matched `b894e7909d314087a2f3cbb31ca48f8e812b3c12` for commit `d9ac4217604c248e73b34edebcbdbd6e8af80b06`.

## Evidence recorded during implementation

- Original full Node suite: 34 tests passed before changes.
- Expanded suite: 72 tests passed locally, including 38 new feature/streaming/recipient/CLI/offline tests. Rerun counts in CI are authoritative if later tests are added.
- Lint, diagnostic strict browser/worker checking, static artifact build and allowlisted HTTP smoke were executed locally. Exact final outcomes are recorded in the candidate workflow rather than inferred from these intermediate runs.
- Streaming test encrypts a file-backed 65 MiB source to disk, rejects it through the old buffered API, and decrypts it through a bounded sink with a matching SHA-256 digest. Error/cancel/tamper tests require abort rather than close.
- JWE interoperability is tested in both directions against Node's separate classic crypto interface, not only by calling the same encryption module twice.
- No new npm dependency or lockfile change. Local `npm ci --offline` could not install the uncached pinned TypeScript package. Available global TypeScript 5.8.3 was used only as a diagnostic. It is not the required TypeScript 7.0.2 release validation.
- Local Chromium navigation is blocked by the execution environment with `net::ERR_BLOCKED_BY_ADMINISTRATOR`. The restriction was not disabled. Local browser end-to-end tests therefore do not have a passing result. The same dependency-free browser test is an explicit GitHub CI gate on a normal Chrome runner.

## Required exact-commit CI evidence

`npm ci --ignore-scripts`, `npm audit --audit-level=high`, and `CHROME_BIN=/usr/bin/google-chrome npm run validate` must succeed on the exact candidate. `npm run validate` includes the actual Chromium suite; `validate:core` alone does not satisfy this requirement. CodeQL runs separately with security-extended queries. Inspect its results rather than claiming a clean audit solely because analysis executed.

CI preserves `validation-<sha>` and the full static/CLI artifact with `SHA256SUMS`. The PR and tracker must record immutable commit/run links and their actual outcomes. Pending and failed jobs remain pending/failed until observed otherwise. This document intentionally does not manufacture a run ID or commit hash before publication.

## Coverage boundaries

Node tests cover filename privacy, sequential queues, cancellation, text bounds/Unicode/strict decoding, re-encryption and legacy limits, v3 chunk/buffer compatibility, no-Blob verification, cleanup on I/O/close/authentication failures, oversize rejection, standard JWE algorithms/key bounds/wrong recipient/corruption, identity protection, independent interoperability, CLI secret parsing/no-overwrite/races/symlinks/error privacy, and asset-cache scope/digests/activation rules.

The browser suite exercises real DOM/File/WebCrypto/download flows, batch processing, plaintext-free verification downloads, text literal display, re-encryption, legacy warnings, recipient key/export/import/decrypt/verify, cancellation and offline reload with the HTTP server stopped. Its native save picker is deliberately mocked while the real cryptographic stream and adapter calls run; this is not a claim of OS-picker validation.

Still separate: native picker permissions, disk-full and overwrite behavior across operating systems; multiple browser/device/mobile/assistive-technology coverage; cache eviction/update/multiple-tab scenarios; independent cryptographic review; final deployed-origin settings; production tag/artifact publication. No database exists, so migration/rollback-migration testing is not applicable.

## Security review summary

New secret entry points share validation. Existing legacy secret semantics are preserved. Input bounds are checked before expensive work wherever possible. Public-key fingerprints must be independently verified. There are no accounts or server authorization changes. The optional worker's fixed application-asset network/storage path is explicitly documented and tested. The CLI never accepts a secret argument or outputs raw exceptions; its staged files are exclusive and mode 0600, and destination commit refuses races/overwrites. JavaScript zeroization and disk unlink are best effort, not secure-erasure claims. JWE authenticates ciphertext to the recipient, not the sender. See the updated threat model for remaining trust assumptions.
