# BlindCrypt delivery roadmap: 02.00.00

Accepted scope: all nine proposals approved on September 27, 2026. Tracker: [#13](https://github.com/paulkakell/BlindCrypt/issues/13). Baseline: `01.01.02`, commit `d9ac4217604c248e73b34edebcbdbd6e8af80b06`.

Implementation and release are separate states. This branch implements the accepted scope; production completion requires the gates below. No unfinished item is silently removed from the roadmap.

| ID | Deliverable and acceptance boundary | Dependency | Implementation | Evidence |
|---|---|---|---|---|
| BC-01 | Opaque random outer filenames by default, opt-in revealing name, authenticated original restored | Existing v3 | Implemented | `features.test.mjs`, browser filenames/download checks |
| BC-02 | Picker and drop queue, sequential bounded processing, independent encryption randomness, per-file status, cancellation | BC-01, transaction core | Implemented | `features.test.mjs`, browser batch/cancellation |
| BC-03 | Authenticate every v3 record without accumulating plaintext or offering a download; refuse legacy completeness claims | Transaction core | Implemented | `streaming.test.mjs`, browser verification |
| BC-04 | Versioned armored encrypted text, 64 KiB UTF-8 bound, literal display, clear action | Existing v3 | Implemented | `features.test.mjs`, browser text |
| BC-05 | New-passphrase/settings copy and legacy upgrade, no intermediate plaintext download, original retained and warnings preserved | BC-03 | Implemented | `features.test.mjs`, browser re-encryption/legacy |
| BC-06 | Opt-in offline assets, digest-verified complete cache, visible readiness/version, explicit update approval, install prompt, trusted local-release guidance | Deterministic build | Implemented | `offline.test.mjs`, browser offline reload; cross-device update matrix pending |
| BC-07 | 4 GiB v3 streams, bounded records, transactional sink, abort cleanup, capability check and 64 MiB fallback | Transaction core | Implemented | `streaming.test.mjs` 65 MiB disk round trip; native OS picker review pending |
| BC-08 | Node CLI encrypt/decrypt/verify, shared formats, hidden terminal or bounded stdin secret, no overwrite, private temporary output | BC-03, BC-07 | Implemented | `cli.test.mjs`, browser/API interoperability |
| BC-09 | Single-recipient JWE, public JWK/fingerprint exchange, protected private backup, key import/export, wrong-key/tamper checks | BC-01, reviewed JWE profile | Implemented, independent review pending | `recipients.test.mjs`, classic Node crypto interoperability, CLI and browser recipient flows |

## Iterations and versioning

1. Preserve the baseline, add the roadmap and branch `release/02.00.00`.
2. Refactor record I/O behind the existing v3 APIs; implement BC-01 through BC-05 with regression coverage.
3. Add transactional streaming, shared-core CLI, and an opt-in asset-only offline edition.
4. Implement the restricted standards-based recipient profile and independent-implementation interoperability tests.
5. Expand static checks, clean builds, dependency validation, browser tests, performance checks and documentation. Fix failures on the same versioned candidate branch.
6. Review exact commit evidence, merge only a validated head, revalidate the production SHA, preserve artifacts and create immutable tag `v02.00.00`.

`02.00.00` is a major release because optional offline behavior changes the browser storage/network policy and the opt-in recipient envelope is not readable by old versions. Buffered v3 APIs and legacy readers remain compatible. Small passphrase files remain v3. Old readers reject the new large-file size profile; users must retain a 02.00.00-capable reader.

No service backend, account system, cloud synchronization, database, or plaintext telemetry is introduced. Multiple recipients, sender signatures and streaming JWE are not hidden unfinished commitments: the accepted first recipient feature is single-recipient encryption, and those are later extensions.

## Release gates

- [x] Nine feature implementations and focused tests exist.
- [x] Original v1/v2/v3 regression coverage retained.
- [x] Changelog, user/API/format/architecture/security documentation, examples, commit notes and rollback plan prepared.
- [x] Locked development dependency graph unchanged; new runtime dependencies: zero.
- [ ] Exact candidate passes locked TypeScript 7.0.2, current dependency audit, full validation including Chromium, and CodeQL in GitHub Actions.
- [ ] Native save-picker cancellation/overwrite/disk-full behavior checked on supported systems; second-browser/mobile/offline-update matrix recorded.
- [ ] Recipient cryptography receives independent review before recommending it for high-value data.
- [ ] Validated production commit merged, deployment checked, tag and source/static/CLI/checksum/SBOM/validation artifacts published.

See [validation](VALIDATION_02.00.00.md), [release checklist](RELEASE_CHECKLIST.md), and [rollback](ROLLBACK.md). The tracker records immutable commit and workflow references as evidence becomes available. No issue is closed solely because an implementation checkbox is checked.

## Security maintenance follow-up: 02.00.01

After owner-authorized merge #14 at `8cea1fe449cff297338c8c2bd6a0e71e555382eb`, #15 tracks the three harness findings. Patch 02.00.01 replaces executable data interpolation and debugging network transport, adds regression tests, and retains all existing browser workflows. It prepares recovery-before-deletion cleanup for the fully integrated release and fix branches. See VALIDATION_02.00.01.md for evidence and the issue for exact current status. Native OS/device coverage and independent recipient review remain open under #13.

Implementation commit `18bf517ffdc058b486239c2acb749ebfb92c8c34` passed hosted
validation with 95 Node tests and 11 actual Chromium checks. Downloaded CodeQL
SARIF has zero results. See VALIDATION_02.00.01.md and PR #16 for immutable run
references. Production revalidation and branch retirement are separate steps;
none of the unrelated native-device or independent-review gates is closed by
these automated results.
