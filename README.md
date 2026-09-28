# BlindCrypt

BlindCrypt `02.00.01` is a local-first file and text encryption application with a shared-core Node.js CLI. This is a release candidate until the exact commit passes the [release gates](docs/ROADMAP.md). It has no accounts, backend, uploads, analytics, or runtime package dependencies.

Ordinary passphrase files use authenticated format v3; v1/v2 remain readable with legacy warnings. Browser encryption uses WebCrypto. Optional offline installation fetches and caches only fixed application assets. User files, plaintext, passphrases and private keys are never put in application storage or network requests.

## Features

| Workflow | Example | Limits and important behavior |
|---|---|---|
| Private filenames | Encrypt `business-plan.pdf` into a random `.blindcrypt` name | Original authenticated name is restored on decryption; revealing outer names is opt-in |
| Batch files | Select or drop several documents | Up to 100 files; buffered queue approximately 64 MiB combined; sequential per-file results and cancellation |
| Verify | Check an encrypted backup without downloading plaintext | Full v3 authentication, up to 4 GiB; legacy completeness cannot be verified |
| Text | Encrypt a note and copy its `BLINDCRYPT-TEXT-1.` representation | 64 KiB UTF-8; decrypted content is literal text, never rendered as HTML |
| Re-encrypt | Change a secret, select a stronger level, or upgrade v1/v2 | Buffered 64 MiB workflow; creates a new copy without a plaintext download; old copies are not revoked |
| Offline edition | Explicitly enable cached application assets | HTTPS/localhost and a built release required; updates require approval |
| Large files | Encrypt/decrypt to a transactional local save target | v3 up to 4 GiB; capability-detected save picker, or CLI; no simple increase to the buffered limit |
| CLI | `node cli/blindcrypt.mjs verify --input backup.blindcrypt` | Node.js 22+, hidden terminal prompt or bounded stdin; never silently overwrites output |
| Recipient sharing | Encrypt for a verified public JWK | Restricted JWE RSA-OAEP-256/A256GCM, 16 MiB; encrypted private backup; no sender authentication; independent review pending |

The device, browser, operating system, WebCrypto implementation and loaded application must be trusted. BlindCrypt does not recover lost secrets, revoke copies, scan documents for malware, guarantee secure memory/disk erasure, or protect a compromised endpoint. See the [threat model](docs/THREAT_MODEL.md).

## Use

Serve the validated `dist/` directory over HTTPS or a controlled localhost server. Do not rely on `file://`. Select a workflow tab, choose local input, and provide the required secret or recipient key. Store generated secrets separately and confirm them before encryption. Share ciphertext and its passphrase through separate channels.

**Strong** remains the default. New passphrase validation is enforced in the browser workflows and CLI. Legacy secrets are interpreted as originally entered; v3 secrets use NFC normalization.

| Level | PBKDF2-HMAC-SHA-256 iterations | Generated words |
|---|---:|---:|
| Standard | 600,000 | 6 |
| Strong | 900,000 | 8 |
| High | 1,200,000 | 10 |
| Critical | 2,400,000 | 16 |

The generator selects uniformly from the bundled 2,048-word BIP39 English list with `crypto.getRandomValues`. Custom passphrases are not assigned entropy estimates. The text, large-file browser and private-backup workflows use Strong; the standard file, re-encryption and CLI passphrase-encryption workflows expose the level selector.

Detailed instructions and every option: [user guide](docs/USER_GUIDE.md), [CLI](docs/CLI.md), [offline/trusted releases](docs/OFFLINE.md).

## Development and validation

```bash
npm ci --ignore-scripts
npm audit --audit-level=high
CHROME_BIN=/usr/bin/google-chrome npm run validate
python3 -m http.server 8080 --directory dist
```

`npm run validate` runs lint, strict browser/worker type checks, all Node unit/integration/regression tests, custom SAST, configuration checks, deterministic build, HTTP smoke, performance checks, and actual Chromium workflow tests. It does not substitute an HTTP fetch for browser coverage. The browser test uses private child-process DevTools pipes and an installed Chromium/Chrome executable, not an additional npm dependency. On a local Chromium system use `CHROME_BIN=/usr/bin/chromium`.

`npm run validate:core` runs all non-browser checks for diagnostics; it is not a complete release gate. `npm run browser` runs the built-artifact browser checks separately. `npm run build` creates the site, CLI, generated icons, digest-pinned service worker and `SHA256SUMS`. The source `sw.js` intentionally cannot install before a build.

The only locked development dependency remains TypeScript 7.0.2. `npm ci` verifies the existing reviewed lock graph. The SAST check pins the complete lockfile digest; do not disable that check for dependency updates. Browser users receive no npm packages.

## Architecture and compatibility

V3 uses AES-256-GCM for encrypted fixed-size metadata and 512 KiB records. Exact header bytes, record kind, index and length are authenticated. Bounds, KDF cost, record geometry and total length are checked before expensive work wherever possible. Streaming uses the same framing, not an unauthenticated archive format.

V1/v2 metadata and whole-file completeness have historical limitations that cannot be repaired retrospectively. Their plaintext can be migrated into a new authenticated file, but migration does not certify the historical source.

Recipient envelopes are standard JWE Compact Serialization with a documented BlindCrypt inner payload, not v3 containers and not compatible with old readers. RSA-OAEP-256 wraps a fresh 256-bit content key; A256GCM encrypts the payload. The recipient fingerprint follows RFC 7638. No remote key lookup or algorithm negotiation is accepted. See [format](docs/FORMAT.md), [API](docs/API.md), and [architecture](docs/ARCHITECTURE.md).

## Roadmap, releases and rollback

All accepted work and remaining release gates are tracked in [roadmap issue #13](https://github.com/paulkakell/BlindCrypt/issues/13) and [docs/ROADMAP.md](docs/ROADMAP.md).

Version format is `<Release>.<Feature Update>.<Bug Fix>`, two digits per field. Development commits identify the target version but are not production release tags. After exact-commit validation, review and merge, create the matching immutable version tag and publish source, static/CLI artifact, checksums, SBOM, release notes and validation evidence. Retain `v01.01.02`, but do not roll back to an old reader after creating large-profile or recipient files without retaining the newer recovery reader.

See [changelog](CHANGELOG.md), [release notes](docs/RELEASE_02.00.01.md), [validation](docs/VALIDATION_02.00.01.md), [checklist](docs/RELEASE_CHECKLIST.md), [rollback](docs/ROLLBACK.md), and [commit notes](COMMIT_NOTES.md).

Report undisclosed vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue. MIT license.

## Maintenance in 02.00.01

The browser test harness uses private Chromium pipes and fixed functions with separate data arguments. See [browser testing](docs/BROWSER_TESTS.md) for configuration and examples. No browser security policy or CodeQL query is disabled. `main` and `dev` remain long-lived branches. The version-scoped maintenance workflow preserves a recovery bundle before deleting only reviewed, integrated release/fix branches. Application formats and public APIs are unchanged.
