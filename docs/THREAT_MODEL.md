# Threat model: 02.00.00

## Assets and assumptions

Protect plaintext files/text, passphrases, private recipient identities, authenticated filename/media metadata, v3/JWE ciphertext integrity, and release provenance. Trust the browser, Node runtime, operating system, device, WebCrypto implementation, destination directory and loaded application. Passphrases use a separately trusted exchange channel; recipient public keys require independently authenticated fingerprints.

No accounts, server authentication, server authorization, backend database, upload endpoint, cloud synchronization, telemetry or secret-bearing log store is introduced. Access to a passphrase/private key is the local authority to decrypt; public-key encryption does not certify the sender.

## Considered adversaries

An untrusted transport/storage provider can observe, replace, truncate, append and reorder encrypted bytes. A malicious input can attempt parser confusion, excessive KDF work, memory exhaustion, path injection or algorithm substitution. A key distributor can substitute a public key. A local destination race can try to replace an existing file during CLI output. A source/dependency/deployment change can introduce unsafe APIs, leaking logs, malicious cached assets or vulnerable tooling.

## Controls

V3 preserves exact-header and record-context AAD, AES-256-GCM tags, randomized salt/unique record IV construction, encrypted fixed-size metadata, bounded PBKDF2 work, canonical headers, safe integers, exact geometry and exact final length. New v3 data uses NFC-normalized secrets; legacy secrets retain historical semantics. New user-facing secret entry points share the existing minimum validation rules. Opaque outer filenames reduce filename leakage by default.

Buffered files stay capped at 64 MiB. Queues cap count and combined input, run sequentially and do not retain output Blobs in status arrays. Streaming v3 caps at 4 GiB and consumes at most a record at a time. Verification discards authenticated plaintext records instead of building a plaintext download. Corruption, write/close errors and cancellation abort transactional output. A sink must stage private output until full success; an arbitrary plaintext stream is not equivalent.

The CLI stages an exclusive mode-0600 file in a trusted destination directory. Final hard-link creation refuses any pre-existing destination, including a raced one; no rename-overwrite fallback exists. Paths never come from decrypted metadata. CLI input is an explicit path and a bounded hidden-terminal/stdin secret, never a passphrase argument or environment variable. Stable JSON diagnostics omit secret material, original filenames and raw errors.

The recipient profile accepts exactly RSA-OAEP-256 with RSA-3072/e=65537 and A256GCM, fresh content keys/IVs, a protected canonical JWE header, and a fixed encrypted inner payload. It rejects unsupported algorithms, key fields, malformed lengths and remote key lookups. Public fingerprints follow RFC 7638; the UI/CLI requires an independently supplied matching fingerprint before encryption. Private keys are exported only inside Strong v3 backups and imported as nonextractable decryption keys. Recipient input caps are 16 MiB plaintext, 16 KiB private backup and 2 KiB public key at file entry points.

The ordinary document retains `connect-src 'none'`, same-origin executable resources, no-referrer policy, no unsafe HTML sinks and no persistent secret storage. Optional offline installation is the narrow policy change: an explicitly registered worker fetches only fixed public application URLs, omits credentials, rejects redirects, checks build-pinned digests and caches complete version/build sets. Unknown paths, query strings and non-GET scoped requests are rejected. User files, keys, plaintext and secret strings have no worker/cache path. Updates require a fixed in-scope activation control message; no file data crosses that channel.

Development retains zero runtime dependencies, the reviewed pinned development lock graph, current dependency audit in CI, pinned GitHub Actions, strict browser/worker type checking, syntax checks, expanded custom SAST, CodeQL, negative regression tests, independent-interface JWE interoperability and real-browser workflows. These are controls and evidence, not an independent security certification.

## Failure cases and residual exposure

**Offline guesses.** Anyone holding a passphrase container or encrypted private backup can guess secrets offline. Randomly generated word phrases are preferred; no custom-secret entropy estimate is claimed. Account lockout and a password reset service do not exist.

**Legacy provenance.** V1/v2 metadata and whole-file completeness cannot be retrospectively authenticated. Neutral downloads and upgrade warnings preserve that distinction. New encryption protects the new copy, not the historical truth of its source.

**Partial output and cancellation.** WebCrypto operations already executing cannot be forcibly interrupted by the cooperative signal. Record plaintext is temporarily present in memory, and streamed decryption may stage plaintext on disk. JavaScript strings/keys cannot be reliably zeroized. Unlink, object-URL revocation and buffer clearing are not secure erasure. A process kill/power loss can leave a private partial file; a browser picker may leave an empty placeholder. Completed earlier batch outputs remain after cancellation. Keygen's two exports are not a single atomic transaction.

**Key substitution and sender identity.** A fingerprint received only with an untrusted key does not authenticate it. Valid JWE can be produced by anyone with the public key. There are no sender signatures, revocation, multi-recipient access control or key-recovery escrow. Losing a private backup/secret loses access. Re-encryption does not revoke old copies.

**Hosting and offline trust.** A malicious initially loaded page can steal data before encryption. A cached malicious build remains malicious offline. Digests from the same compromised origin do not independently prove origin authenticity. Obtain and verify known-good release artifacts through a trusted channel; use controlled local serving for sensitive recovery. Offline cache availability can be lost to browser eviction; it is not a backup service.

**Metadata and local observation.** File sizes, timing, public KDF parameters and recipient fingerprints remain observable. Optional revealing outer filenames are explicitly less private. Plaintext shown in text fields, clipboard copies, downloaded files, browser/OS histories and screenshots are outside guaranteed-erasure control. No malware/safety classification follows from successful authentication.

## Out of scope and release gates

Compromised devices, browsers/extensions, runtimes, hosting/repository accounts, DNS/certificates, keyloggers, screen/clipboard capture, privileged memory/filesystem attackers, traffic analysis and denial of service within the configured resource budgets remain out of scope.

Native save-picker permissions/overwrite/disk-full/cancellation behavior, the intended cross-browser/mobile/assistive-technology matrix, cache eviction/multiple-tab updates and independent recipient cryptographic review require separate recorded checks. In particular, the new recipient implementation must not be recommended as independently audited or for high-value use before that review.

Rollback must retain readers for every format already created, including v3 above 64 MiB and recipient JWE. There is no database migration. See [ROADMAP.md](ROADMAP.md), [VALIDATION_02.00.00.md](VALIDATION_02.00.00.md), and [ROLLBACK.md](ROLLBACK.md).
