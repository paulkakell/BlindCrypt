# Security policy

## Supported versions

| Version | Status |
|---|---|
| 02.00.00 | Candidate; production status depends on exact-commit release gates |
| 01.01.02 | Retained released baseline; cannot read new large-profile/JWE data |
| 01.01.01 | Compatible rollback baseline; fixes move to 01.01.02 |
| 01.01.00 and unversioned baseline | Superseded; do not use as the production rollback reader |

## Reporting a vulnerability

Do not disclose an unpatched vulnerability in a public issue or discussion. Use GitHub private vulnerability reporting when it is enabled for this repository. If that feature is unavailable, contact the repository owner through a private channel listed on the owner's GitHub profile.

Include:

- affected commit and application version
- browser and operating system
- concise reproduction steps
- expected and observed behavior
- whether confidentiality, integrity, availability, or supply-chain controls are affected
- proof-of-concept files with non-sensitive test data only

Do not send real passphrases, plaintext, private keys, personal data, or production files.

## Security response

The maintainer will reproduce the report, assign severity, prepare a private fix, add regression coverage, run the full release checklist, and publish an advisory when disclosure is appropriate. Release tags must match the corrected `VERSION` value.

## Cryptographic scope

BlindCrypt relies on browser WebCrypto for PBKDF2-HMAC-SHA-256, AES-256-GCM, RSA-OAEP-256 and SHA-256. The CLI uses the Node WebCrypto implementation of the same primitives. It does not implement primitive algorithms. Changes to format framing, key derivation, IV construction, authentication inputs, limits, or compatibility behavior require focused security review and new known-answer, interoperability or tamper tests. The recipient implementation has not received an independent security audit; do not recommend it for high-value data before that review. Optional offline asset caching and transactional CLI/browser output are explicit new trust boundaries documented in the threat model.
