# Threat model

## Assets

- plaintext file contents
- passphrases
- authenticated filename and declared media type
- integrity and completeness of format v3 containers
- build and deployment provenance

## Trust assumptions

BlindCrypt assumes the browser, operating system, device, WebCrypto implementation, loaded application files, and hosting origin are trustworthy during use. The user must transfer the passphrase through a channel separate from the encrypted file.

## Adversaries considered

- a storage or transport provider that can read, replace, truncate, append, or reorder encrypted bytes
- an attacker who can supply a malformed local file intended to consume CPU or memory
- an attacker who changes public metadata or record geometry
- an attacker who guesses passphrases offline
- a contributor or dependency change that introduces unsafe browser APIs, dynamic code, external executable resources, or vulnerable build tooling

## Security controls

- AES-256-GCM record authentication with header and record context as additional authenticated data
- PBKDF2-HMAC-SHA-256 with bounded configurable work factors and random salts
- unique per-record IV construction under each derived key
- encrypted fixed-size metadata
- canonical parsing, exact field sets, safe integers, exact lengths, and hard resource ceilings before key derivation
- neutral legacy downloads and explicit legacy warnings
- no runtime dependencies, storage, telemetry, logs, or network APIs
- strict CSP and no-referrer policy
- locked development dependency, dependency audit, custom SAST, CodeQL, tests, type checking, and pinned Actions

## Out of scope

- malware, keyloggers, hostile extensions, compromised browsers, screen capture, clipboard monitoring, memory inspection, and physical access
- compromise of the GitHub account, repository settings, Actions platform, Pages origin, DNS, or certificate chain
- traffic analysis based on encrypted-file size or timing
- recovery of lost passphrases
- denial of service below configured local resource limits
- cryptographic guarantees for unauthenticated metadata or whole-file completeness in legacy v1 and v2 files

## Abuse and failure cases

### Offline guessing

An attacker holding a container can attempt passphrase guesses. Generated phrases are preferred. The minimum generator output is six uniformly selected words; custom passphrases are not assigned entropy estimates.

### Malformed input

The reader rejects oversized files, excessive KDF parameters, invalid encodings, noncanonical v3 headers, inconsistent record geometry, incorrect total length, and failed GCM tags. Validation occurs before expensive work whenever the format permits.

### Hosting compromise

A modified page can capture plaintext and passphrases before encryption. Users handling high-value data should verify a trusted release artifact and its checksum, then serve it from a controlled local origin.

### Rollback

After v3 files have been created, rolling back to the unversioned baseline would make those files unreadable. Rollbacks must retain the v3 reader even when reverting interface or deployment changes.
