# Architecture: 02.00.00

BlindCrypt has two local user interfaces and no server-side data path:

```text
Browser selected File / text                 CLI explicit input path
          |                                           |
       app.js                                    cli/blindcrypt.mjs
          |                                           |
          +-------- features / recipients ------------+
          |                                           |
          +-------------- crypto.js ------------------+
                             |
               +-------------+-------------+
               |             |             |
          crypto-v3     crypto-legacy   crypto-core
          record I/O    bounded read    limits/KDF/AAD
               |             |             |
               +-------------+-------------+
                             |
                        WebCrypto
                             |
            buffered Blob OR transactional sink
                      |                |
               local download      private staged output
                                   close/commit OR abort
```

`app.js` owns DOM accessibility, selection/drop queues, cancellation, bounded workflow selection, literal text display and user-approved local downloads. `features.js` owns shared secret validation, opaque filenames, sequential status queues, text armor and bounded re-encryption. The existing passphrase/wordlist modules remain dependency-free.

`crypto-v3.js` separates record production/consumption from output allocation. Existing 64 MiB Blob APIs and the 4 GiB streaming APIs call the same validated framing/record functions. Verify supplies a discard consumer rather than allocating a plaintext Blob. Every decrypted record is authenticated before consumption; transaction completion requires the complete container. Plaintext buffers are wiped on a best-effort basis, not with a claim of guaranteed JavaScript zeroization.

`cli/io.mjs` implements a private exclusive temporary file and non-overwriting hard-link commit. A browser `FileSystemWritableFileStream` provides its native transaction adapter. A plain nontransactional stream does not satisfy the public sink contract.

`recipients.js` implements the fixed single-recipient JWE profile using WebCrypto RSA-OAEP-256 and A256GCM. It does not negotiate algorithms or retrieve keys. Public keys are fingerprint-confirmed outside encryption. Private backups use the existing passphrase-encrypted v3 container. JWE is bounded rather than presented as a streaming primitive. See [FORMAT.md](FORMAT.md).

## Optional offline path

```text
Explicit enable -> offline.js -> same-origin service worker registration
                                       |
                            build-pinned public asset URLs
                                       |
                          fetch + SHA-256 verification
                                       |
                      complete version/build-specific cache
                                       |
                     explicit update approval when waiting
```

The normal document keeps `connect-src 'none'`; cryptographic/UI modules have no upload/network API. The optional worker is the narrowly defined exception: it fetches only build-owned application URLs during installation. `offline.js` sends one fixed activation-control message, never file data or secrets. Selected files and decrypted bytes cannot enter the cache through this design. Unbuilt worker source refuses installation.

## Build, test and release path

```text
issue #13 -> release/02.00.00 -> focused tests and local diagnostic checks
          -> pull-request locked install/audit/full validation + CodeQL
          -> reviewed exact-head merge -> main validation + Pages
          -> v02.00.00 tag + source/static/CLI/SBOM/checksum/evidence artifacts
```

The deterministic build copies the application and CLI, generates icons, pins exact offline asset digests, and writes a complete checksum manifest. The CI source archive and validation log identify the candidate commit. Existing actions remain pinned to full SHAs. Runtime assets contain no GitHub credentials or build-tool packages.

CodeQL and custom SAST cover the browser, worker and CLI; strict JavaScript type checks cover browser and worker modules. CLI interfaces are checked through syntax, SAST, CodeQL and integration tests rather than pretending that Node ambient type definitions were added. There is no new dependency, database, backend authentication, telemetry service or secret-bearing log pipeline.
