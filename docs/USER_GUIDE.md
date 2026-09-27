# User guide: 02.00.00

Use a verified release over HTTPS or localhost. Everything below operates on files explicitly selected by you. The application does not upload their data. Optional offline installation handles only application assets.

## 1. Encrypt files and hide filenames

Select **Encrypt**, choose one or several files, or drop them on the file area. Choose Standard, Strong, High or Critical. Generate a passphrase or enter a varied custom passphrase of at least 16 characters, store it separately, and confirm it. Generated word-list secrets require at least six bundled words. The existing generator chooses 6/8/10/16 words according to the selected level. Strong is the default.

Leave **Reveal original name** unchecked for a random 128-bit outer filename such as `06fd2e5e52e4478698e3a045295712d9.blindcrypt`. The original name and media type remain in encrypted, authenticated metadata. Checking the option produces an outer name such as `report.pdf.blindcrypt`; anyone holding it can infer the original name.

For example, encrypt three project documents as three independent `.blindcrypt` files, then send them through an untrusted transport and share the passphrase through a separate channel. Every file gets fresh salt and IV prefix even when the queue shares a passphrase.

## 2. Batch processing and cancellation

A queue accepts 1 to 100 files. Buffered encryption/decryption is conservatively limited to approximately 64 MiB combined input and 64 MiB plaintext per file. This limits retained download memory. Files run sequentially. A failed file receives its own result and does not silently fail the rest of the queue. Re-selecting files replaces a dropped selection. There is no recursive directory import or archive extraction.

Use **Cancel current operation** to stop pending work. Cancellation is checked between cryptographic steps and records; a WebCrypto derivation already running cannot be forcibly interrupted. Outputs already completely downloaded remain yours. Cancellation never means those earlier outputs were revoked. Browser multi-download permission may be required; a completed processing result means a download was requested, not that the browser or operating system confirmed its final destination.

## 3. Decrypt and verify

Select **Decrypt**, choose encrypted input, enter its passphrase, and choose **Decrypt and download**. V3 filenames are restored only after authentication. Legacy downloads use `legacy-decrypted.bin` and a neutral media type because their metadata is untrusted.

Choose **Verify without downloading** to authenticate the complete v3 header, metadata and all records without creating a plaintext Blob or download. V3 verification supports up to 4 GiB per file and retains only one record's temporary plaintext. It requires the passphrase; it is not a checksum-only test. It does not scan for malware, identify the sender or establish the source's historical truth. Legacy completeness verification is rejected rather than overstated.

Example: verify a backup after copying it to another drive, then decrypt it only when needed.

## 4. Encrypted text

Open **Text**, enter a message, and supply/confirm a passphrase. This workflow uses Strong. Generate creates eight visible words so you can store them before confirmation. Choose **Encrypt text**; the plaintext field is cleared and a `BLINDCRYPT-TEXT-1.` envelope appears. **Copy encrypted text** copies only that envelope. The limit is 64 KiB of UTF-8, not 64,000 arbitrary Unicode characters.

To open a received envelope, paste it into the encrypted field, enter its passphrase, and choose **Decrypt text**. Content displays literally in a text area; HTML is not executed. **Clear text** clears both areas and the secret fields. Avoid putting secret messages in clipboard managers or screenshots. JavaScript and clipboard histories cannot be reliably erased by this application.

## 5. Change a passphrase or upgrade a legacy file

Open **Re-encrypt**, select the encrypted file, enter the existing secret, choose a new secret and confirmation, and select a new security level. An optional replacement name sets the new authenticated metadata; leaving it blank retains authenticated v3 metadata or uses a neutral legacy name.

The operation decrypts within the bounded browser workflow and immediately encrypts a new file. It never offers an intermediate plaintext download. It retains the original file. A v1/v2 upgrade warns that historical metadata/completeness were not authenticated; the new encryption cannot establish missing historical guarantees.

Example: create a Strong replacement for a legacy backup, verify the replacement with the new passphrase, and separately decide whether to retire the old copy. Changing the passphrase does not revoke older copies. Above the buffered limit, use separate CLI transactions on a trusted disk; do not claim that path avoids temporary plaintext disk storage.

## 6. Offline and installation

Choose **Enable/check offline edition** only when using a built, trusted release. Installation fetches an exact allowlist of same-origin application files and verifies their build-pinned SHA-256 digests. It never caches selected documents, output files, passphrases or private keys. Read the displayed readiness status before disconnecting. Reload once after activation to use the cached edition.

A supported browser may expose **Install app**. This adds its local application shortcut; offline readiness is a separate state. An updated worker waits while the old edition is active. **Apply downloaded update** explicitly activates it and reloads the requesting page when no operation is running. Other tabs are not deliberately reloaded mid-operation. Browser/device update behavior remains a release-review item.

Use browser site-data controls to remove the installed edition and its public asset cache. See [OFFLINE.md](OFFLINE.md) for trusted-release verification, local serving, updates and recovery.

## 7. Large files

Open **Large files** for v3 inputs up to 4 GiB. Select a file, enter the passphrase, confirm when encrypting, and choose encrypt or decrypt. Browser encryption uses Strong. Choose the output destination in the native save picker. The interface checks for that API; unsupported browsers receive instructions to use the buffered workflow or CLI rather than attempting an unsafe whole-file download.

The output sink must stage data until the operation succeeds. Successful full authentication closes and commits the destination. A wrong secret, corrupt/truncated/appended/reordered file, cancellation or write failure aborts the output. Temporary decrypted bytes may exist on disk during staging. A new empty placeholder file may remain after a browser picker creates a destination; no complete output is claimed on failure. Existing-file replacement is subject to the browser's explicit picker confirmation. The native picker needs system-specific testing for disk-full and cancellation behavior.

Old readers may reject v3 files above 64 MiB. Keep a newer reader and test recovery before relying on a large backup. This is not resumable encryption: aborted work restarts with fresh randomness.

## 8. Recipient-key sharing

Open **Recipients**, generate a strong private-backup passphrase, store it, and confirm it. **Create and download key files** produces an encrypted `.bckey` private backup and a public `.json` JWK. Save both downloads. Losing the backup or its passphrase loses access. No service stores or resets keys.

Share only the public file. Independently communicate its displayed 43-character fingerprint through a channel you already trust. A fingerprint supplied alongside an untrusted public key is not identity verification.

A sender selects that public key, enters the independently verified fingerprint, selects the document, and chooses recipient encryption. No shared file passphrase is required. The output is an opaque `.blindcrypt.jwe` file. This first release supports one recipient and 16 MiB plaintext, not multi-recipient envelopes or streaming JWE.

To open it, select the JWE file and your encrypted private backup, enter the backup passphrase, and choose decrypt or verification. Verification creates no plaintext download but this bounded JWE path necessarily authenticates/decrypts the bounded payload in memory. Neither operation authenticates the sender. A person who knows your public key can produce a valid envelope for you.

The implementation uses the restricted standards-based profile in [FORMAT.md](FORMAT.md), with automated interoperability tests. Independent cryptographic review is still required before recommending it for high-value data. Do not mistake test success for a security audit.

## 9. CLI

Use the same formats outside the browser through `node cli/blindcrypt.mjs`. Examples, every argument, exit codes, secret handling, no-overwrite behavior and partial-output recovery are in [CLI.md](CLI.md).

## Privacy and troubleshooting

Secret input fields are cleared after an operation, including temporarily visible generated secrets. Decrypted text remains visible until cleared because it is the requested output. No guaranteed secure memory erasure is possible in a browser. Output downloads and operating-system caches are outside application storage controls.

A generic decryption failure can mean the wrong secret, a wrong identity, malformed input or modified ciphertext. Never upload the private file to obtain diagnostics. Verify version, limits and the intended workflow locally. **Integrity verified** is not **safe to execute**. Do not run executable plaintext simply because its encryption was authentic.
