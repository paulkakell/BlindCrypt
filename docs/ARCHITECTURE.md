# Architecture

BlindCrypt is a static single-page application with no server-side data path.

```text
User-selected File/Blob
        |
        v
assets/app.js  <----  assets/passphrase.js  <----  bundled word list
        |
        v
assets/crypto.js public facade
        |
        +--> assets/crypto-v3.js
        +--> assets/crypto-legacy.js
        +--> assets/crypto-core.js
              |  validate limits and format
              |  PBKDF2 through WebCrypto
              |  AES-GCM metadata and records
  v
Downloadable application/octet-stream Blob
```

For decryption:

```text
.blindcrypt File/Blob
        |
        v
Bounded format detector
   |                     |
   | v3                  | v1/v2 legacy
   v                     v
Canonical parser      Strict legacy parser
Exact geometry        Bounds and exact lengths
Header AAD             Neutral metadata handling
   |                     |
   +----------+----------+
              v
          WebCrypto
              |
              v
    Downloadable neutral Blob
```

## Components

### `assets/app.js`

Owns DOM interaction, accessibility state, progress reporting, user-facing validation, local downloads, generic failure messages, and legacy warnings. It contains no cryptographic primitive logic.

### `assets/passphrase.js`

Validates the 2,048-word list, generates uniformly indexed word phrases, assesses generated word-list phrases, and applies minimum rules to new custom passphrases. It does not estimate custom entropy.

### `assets/crypto-core.js`, `assets/crypto-v3.js`, `assets/crypto-legacy.js`, and the `assets/crypto.js` public facade

Owns format framing, bounds, canonical parsing, passphrase normalization for v3, PBKDF2, IV construction, AES-GCM additional authenticated data, metadata encryption, v3 encryption/decryption, and bounded legacy readers.

### Build and validation

Node scripts provide syntax checks, policy linting, strict type checking, tests, custom SAST, configuration checks, deterministic static builds, SHA-256 manifests, and a performance smoke test. GitHub Actions run the same validation in a clean environment and retain the resulting artifact.

## Data flow constraints

- No application code calls `fetch`, `XMLHttpRequest`, `WebSocket`, or `EventSource`.
- No plaintext, passphrase, metadata, or filename is placed in local storage, session storage, cookies, URL parameters, logs, or telemetry.
- Runtime executable resources are same-origin files covered by CSP.
- Output MIME type is `application/octet-stream`; authenticated original type is informational metadata only.
