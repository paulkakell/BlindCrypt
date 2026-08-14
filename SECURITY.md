# Security policy

## Supported versions

| Version | Status |
|---|---|
| 01.01.00 development candidate | Security fixes accepted on `dev` |
| Unversioned baseline | Unsupported after 01.01.00 is released |

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

BlindCrypt relies on browser WebCrypto for PBKDF2-HMAC-SHA-256 and AES-256-GCM. It does not implement primitive algorithms. Changes to format framing, key derivation, IV construction, authentication inputs, limits, or compatibility behavior require focused security review and new known-answer or tamper tests.
