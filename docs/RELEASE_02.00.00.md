# BlindCrypt 02.00.00 release candidate

Scope: [#13](https://github.com/paulkakell/BlindCrypt/issues/13), all nine accepted features. This file describes candidate behavior, not an assertion that the version is tagged or deployed.

## Additive

Opaque filenames with opt-in original outer names; sequential multi-file picker/drop queues and cancellation; complete v3 verification without plaintext download/Blob accumulation; bounded versioned encrypted text; passphrase/settings changes and legacy upgrade without intermediate plaintext downloads; optional digest-verified application-only offline caching and install/update controls; transactional v3 streams up to 4 GiB; a shared-core no-overwrite Node CLI; and single-recipient JWE with public fingerprint confirmation and encrypted private backups.

## Fixes and hardening

The default encrypted outer filename no longer exposes the original filename. All secret fields clear after operations, including visible generated secrets. Stream failures abort staged output and preserve I/O errors rather than misreporting them as authentication failures. Native key/header/length limits and exact algorithms are enforced in the recipient profile. Static analysis covers added modules; the lockfile pin remains enforced. Builds include deterministic icons, complete checksums, CLI files and digest-pinned offline assets. Full validation now includes real Chromium workflows rather than only HTTP retrieval.

## Breaking and compatibility notes

The optional offline edition deliberately changes the former absolute no-network/no-storage application policy: only fixed public assets are fetched/cached after user enablement. File data and secrets remain excluded. The default outer encrypted name changes; scripts expecting original filenames must opt in or specify CLI output. New recipient JWE envelopes and v3 files above 64 MiB require a 02.00.00-capable reader. The ordinary v3 format and buffered JavaScript call signatures remain compatible, and v1/v2 reading is retained. No database or schema migration is introduced.

Recipient sharing is single-recipient, capped at 16 MiB, and does not authenticate senders. Its standards-based implementation has interoperability tests but no claimed independent security audit. Do not recommend it for high-value use until independent review is recorded.

## Validation and release status

See [VALIDATION_02.00.00.md](VALIDATION_02.00.00.md) for actual local evidence and required exact-commit CI gates. Missing native browser/device checks are not marked passed. Version tag `v02.00.00` is reserved for the reviewed, validated production commit; candidate commits carry the target version but no release tag.

Before publication attach source, static/CLI archive, SHA256SUMS, SPDX SBOM, these notes and validation evidence. Retain baseline artifacts and a newer recovery reader before rollout. Use [ROLLBACK.md](ROLLBACK.md) and the [release checklist](RELEASE_CHECKLIST.md). No branch cleanup is part of this feature release.
