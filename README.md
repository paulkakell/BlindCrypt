# BlindCrypt

BlindCrypt is a static browser application for authenticated client-side file encryption. Version `01.01.01` writes format v3 containers and reads format v1, v2, and v3 files.

The application has no runtime dependencies, backend, account system, telemetry, analytics, or network requests. The hosting server delivers static files. Encryption and decryption use the browser WebCrypto implementation.

## Primary use cases

- Encrypt a document before sending it through email, cloud storage, chat, or another untrusted transport.
- Decrypt a received `.blindcrypt` file without uploading its contents to a service.
- Generate a uniformly selected multiword passphrase for out-of-band exchange.
- Open older BlindCrypt v1 or v2 files while receiving an explicit warning about their legacy integrity limits.

BlindCrypt does not protect data on a compromised device, inside a hostile browser or extension, or after plaintext is downloaded.

## Use the application

1. Serve the repository through HTTPS or a local web server. Opening the page through `file://` is not recommended.
2. Select **Encrypt** and choose a file no larger than 64 MiB.
3. Select a security level. **Strong** is the default.
4. Generate a passphrase or enter a non-repetitive custom passphrase of at least 16 characters with sufficient character variety. Generated phrases require at least six bundled words.
5. Store the passphrase separately, confirm it, then select **Encrypt and download**.
6. Send the `.blindcrypt` file and passphrase through separate channels.

For decryption, select **Decrypt**, choose the encrypted file, enter the passphrase, and select **Decrypt and download**. Format v3 restores the authenticated filename. Legacy output is downloaded as `legacy-decrypted.bin` because legacy metadata is not authenticated.

## Security-level options

| Option | PBKDF2-SHA-256 iterations | Generated words | Intended use |
|---|---:|---:|---|
| Standard | 600,000 | 6 | Routine files when device speed is constrained |
| Strong | 900,000 | 8 | Default balance for ordinary sensitive files |
| High | 1,200,000 | 10 | Higher-value files on capable devices |
| Critical | 2,400,000 | 16 | Maximum configured passphrase and KDF cost |

The word generator selects from the bundled 2,048-word BIP39 English list using `crypto.getRandomValues`. Six words provide approximately 66 bits when each word is independently generated. BlindCrypt does not assign entropy estimates to custom passphrases.

## Format v3 security properties

- AES-256-GCM encrypts a fixed-size metadata record and each 512 KiB data record.
- PBKDF2-HMAC-SHA-256 derives a nonextractable key from the NFC-normalized passphrase and a random 128-bit salt.
- Each record uses a unique 96-bit IV composed of a random 64-bit prefix and a 32-bit record counter.
- The exact binary header frame, record type, record index, and plaintext record length are AES-GCM additional authenticated data.
- Filename and media type are encrypted inside a fixed-size metadata block.
- Header size, salt, IV, KDF cost, file size, record count, record geometry, metadata size, and final container length are validated before decryption proceeds.
- Truncation, appended bytes, record substitution, reordered records, public-header changes, metadata changes, and ciphertext changes cause rejection.

See [docs/FORMAT.md](docs/FORMAT.md) for the byte-level specification and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for assumptions and exclusions.

## Legacy compatibility

BlindCrypt reads v1 and v2 files so existing data remains accessible. Legacy passphrases are used exactly as entered; NFC normalization applies only to v3.

Legacy limitations cannot be repaired after encryption:

- v1 and v2 metadata is public and unauthenticated.
- v2 authenticates individual records, but the original format does not authenticate the complete file structure.
- Legacy filenames and MIME types are treated as untrusted. Downloads use a neutral filename and `application/octet-stream`.
- Strict bounds and exact-length checks reject malformed legacy files, excessive KDF settings, and trailing data, but they cannot add missing cryptographic commitments to previously created files.

## Browser and resource limits

The current browser-only implementation accepts plaintext files up to 64 MiB. Encryption and decryption process 512 KiB slices, then assemble a downloadable `Blob`. The ceiling limits memory amplification and malicious local-file resource consumption. A future large-file mode should use a reviewed writable-stream design rather than increasing this limit.

## Local development

Requirements: Node.js 22 or newer and Python 3 or another static HTTP server.

```bash
npm ci --ignore-scripts
npm audit --audit-level=high
npm run validate
python -m http.server 8080
```

Open `http://localhost:8080`.

Validation commands:

```bash
npm run lint       # syntax, HTML policy, word-list, and unsafe-API checks
npm run typecheck  # strict TypeScript checking over production JavaScript
npm test           # unit, integration, and regression tests
npm run security   # local SAST and dependency allowlist checks
npm run config     # workflow, version, default, and policy checks
npm run build      # clean static artifact plus SHA256SUMS
npm run smoke      # allowlisted local HTTP retrieval of the built artifact
npm run perf       # 1 MiB authenticated round-trip performance smoke test
```

`npm run validate` executes all commands in release order. The smoke server uses a fixed route allowlist. Request paths never become filesystem paths, preventing path traversal and filesystem check/use races in the validation utility.

## CI and deployment

- `.github/workflows/ci.yml` validates pushes to `dev` and pull requests into `main` or `dev`.
- `.github/workflows/codeql.yml` runs CodeQL with extended security queries.
- `.github/workflows/pages.yml` builds and deploys the validated `dist/` artifact after changes reach `main`.
- All referenced GitHub Actions are pinned to full commit SHAs.
- Production Pages settings must use **GitHub Actions** as the deployment source. Required repository settings are listed in [docs/REPOSITORY_SETTINGS.md](docs/REPOSITORY_SETTINGS.md).

## Versioning and releases

BlindCrypt uses `xx.xx.xx` as `<Release>.<Feature Update>.<Bug Fix>`. The repository version is stored in `VERSION` and exposed through `APP_VERSION`.

Development commits carry the next version but are not tagged. After the validated commit reaches `main`, create the matching immutable tag, such as `v01.01.01`, and attach the `dist/` artifact, `SHA256SUMS`, SPDX SBOM, release notes, and validation evidence. Do not tag a commit that did not pass the full workflow.

See [CHANGELOG.md](CHANGELOG.md), [docs/RELEASE_01.01.01.md](docs/RELEASE_01.01.01.md), [COMMIT_NOTES.md](COMMIT_NOTES.md), [docs/VALIDATION_01.01.01.md](docs/VALIDATION_01.01.01.md), [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md), and [docs/ROLLBACK.md](docs/ROLLBACK.md).

## Security reports

Do not open a public issue for an undisclosed vulnerability. Follow [SECURITY.md](SECURITY.md).

## License

MIT
