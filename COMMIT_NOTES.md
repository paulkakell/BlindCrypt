# Commit notes for 01.01.00

```text
security: release BlindCrypt 01.01.00 with authenticated format v3

Release: 01.01.00
Tag after protected merge: v01.01.00
Refs: SEC-AUDIT-2026-08-13
Baseline: 4ed8c157c6015340b363848c12527d9499fb8d69

- authenticate the exact v3 header and record context with AES-GCM AAD
- encrypt and validate fixed-size filename and media-type metadata
- reject truncation, trailing bytes, malformed geometry, and excessive KDF inputs
- cap plaintext at 64 MiB and process source data in bounded slices
- retain bounded v1/v2 reads with neutral legacy output and explicit warnings
- reject four-word and repetitive passphrases without assigning custom entropy claims
- add CSP, tests, type checking, SAST, CodeQL, locked builds, and release docs

Change type: breaking producer format, additive reader support, security fixes
Rollback: preserve the v3 reader; revert deployment or interface changes separately
```
