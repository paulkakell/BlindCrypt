# Commit notes: 02.00.00

Copy-ready implementation message. Replace no version with an informal build label; use the actual Git commit and workflow references in the PR/tracker after publication.

```text
feat(02.00.00): implement accepted local-first roadmap (#13)

- Default to opaque encrypted filenames and add bounded sequential file queues.
- Share v3 record I/O across buffered, verification-only and transactional streams.
- Add encrypted text and non-destructive passphrase/legacy migration workflows.
- Add opt-in digest-verified offline assets and explicit application update controls.
- Add a shared-core Node CLI with bounded secret input and no-overwrite output.
- Implement restricted single-recipient JWE, fingerprints and encrypted identities.
- Expand regression, interoperability, cleanup, offline and real-browser tests.
- Update security policy, architecture, API, examples, roadmap and rollback guidance.

BREAKING CHANGE: optional offline installation caches public application assets;
outer names are opaque by default; new large-profile/JWE files need a newer reader.
Buffered v3 APIs and v1/v2 reading remain available. No runtime dependencies added.
Independent recipient review and native browser/device release gates remain explicit.
```

Baseline: d9ac4217604c248e73b34edebcbdbd6e8af80b06. Related issue: #13. Do not claim a production tag, clean dependency audit, passing remote workflow or independent review until the corresponding evidence is actually recorded.
