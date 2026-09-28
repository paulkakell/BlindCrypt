# JavaScript API: 02.00.01

All examples use ES modules and WebCrypto. `Blob` inputs are local and explicitly supplied by the caller. Production code has no runtime package dependency. Every sink and callback is trusted application code, never parsed out of a container.

## Existing facade

```js
import { encryptBlobV3, decryptBlobAny } from './assets/crypto.js';
const encrypted = await encryptBlobV3(file, secret, {
  name: file.name, type: file.type, levelKey: 'strong',
  onProgress(percent, message) { /* Update local interface state. */ },
  signal: controller.signal,
});
const opened = await decryptBlobAny(encrypted.blob, secret, undefined, controller.signal);
```

`encryptBlobV3(source, passphrase, options)` retains its original required `name`, `type`, `levelKey` and optional `onProgress`. It now accepts optional `signal`. It returns `{blob, header, metadata}`. `decryptBlobAny(source, passphrase, onProgress?, signal?)` retains its original first three arguments and returns the original `{blob, metadata, formatVersion, authenticatedMetadata, legacyWarning, publicHeader}` shape where applicable. Both buffered entry points retain 64 MiB resource limits. New user-facing encryption paths call `validateSecret`; the low-level API continues its existing derivation validation contract.

## Verification and transactional streams

```js
import { verifyV3, encryptV3ToSink, decryptV3ToSink } from './assets/crypto.js';
const verified = await verifyV3(container, secret, { signal: controller.signal });
const writable = await approvedHandle.createWritable({ keepExistingData: false });
await decryptV3ToSink(container, secret, writable, {
  signal: controller.signal,
  onProgress(percent) { /* Update local progress. */ },
});
```

`verifyV3(source, secret, {signal?, onProgress?}?)` authenticates all records and returns metadata/format/header evidence and `verified: true`, but no plaintext Blob. Legacy inputs are intentionally rejected.

`encryptV3ToSink(source, secret, {name, type, levelKey, signal?, onProgress?}, sink)` and `decryptV3ToSink(source, secret, sink, {signal?, onProgress?}?)` support v3 up to 4 GiB. Both own the transaction after receiving the sink: success closes it; any failure/cancellation attempts abort and preserves the original exception. A close failure also attempts abort.

The sink implements `write(Uint8Array)`, `close()`, and `abort()`, each synchronous or Promise-returning. `write` must finish consuming/copying bytes before it resolves. Decrypted buffers are wiped immediately afterward. The sink must keep partial plaintext private and uncommitted until close, and discard it on abort. A sink that publishes partial records violates the contract. Do not wrap an ordinary nontransactional file writer and claim equivalent guarantees. Cancellation cannot interrupt an already-running native KDF.

## Workflow helpers

`assets/features.js` exports:

- `encryptedFilename(original = 'file', reveal = false)`: random 128-bit opaque name; revealing mode sanitizes the original.
- `validateSecret(value)`: shared new-secret policy and NFC handling; throws a bounded generic validation error.
- `processQueue(items, operation, {signal?, onResult?}?)`: 1 to 100 items, sequential operations, per-item complete/failed/cancelled records. The caller owns per-file/total byte bounds and exports; no file outputs are retained by the queue helper.
- `encryptText(text, secret, levelKey = 'strong', signal?)` and `decryptText(armor, secret, signal?)`: bounded UTF-8 content and strict versioned base64url text wrapper. Display returned plaintext only through `.value` or `.textContent`.
- `reencrypt(source, oldSecret, newSecret, {levelKey?, name?, signal?}?)`: new v3 encrypted Blob plus `sourceFormat` and preserved `legacyWarning`; 64 MiB buffered workflow. Empty replacement name preserves trusted metadata or selects the neutral legacy name.

Example: call `processQueue(files, async file => { /* encrypt and complete one local export */ })`, retaining only its status results. A passphrase may be reused within that queue, but each low-level encryption generates independent salt/IV values.

## Recipient profile

```js
import { importRecipient, encryptForRecipient, unlockIdentity, decryptForRecipient } from './assets/recipients.js';
const recipient = await importRecipient(publicKeyJson);
if (recipient.fingerprint !== independentlyConfirmedFingerprint) throw new Error('Wrong recipient');
const envelope = await encryptForRecipient(file, recipient, { name: file.name, type: file.type });
const identity = await unlockIdentity(encryptedBackup, backupSecret);
const result = await decryptForRecipient(envelope, identity, { verifyOnly: true });
```

`generateIdentity(secret, signal?)` returns `{publicKey, privateBackup, fingerprint}`. `publicKey` is public-only JWK JSON and `privateBackup` is a v3-encrypted Blob. `recipientFingerprint(jwk)` implements the RFC 7638 required-member canonical RSA thumbprint. `importRecipient(text)` accepts only local RSA-3072/e=65537 public JWK members and returns a nonextractable encryption key. `unlockIdentity(backup, secret, signal?)` returns a nonextractable decryption key and fingerprint.

`encryptForRecipient(source, recipient, {name, type, signal?})` returns JWE Compact Serialization in a Blob. `decryptForRecipient(envelope, identity, {verifyOnly?, signal?}?)` returns `{metadata, blob, verified, senderAuthenticated:false}`. `blob` is null for verification. The bounded JWE payload is decrypted in memory; it is not the record-discarding v3 verification path. Maximum plaintext is 16 MiB, identity backup 16 KiB, public JWK 2 KiB. No remotely resolved key, dynamic algorithm, compression or multi-recipient parameter is accepted.

## Errors, logging and compatibility

`BlindCryptError.code` gives bounded categories such as `INVALID_FORMAT`, `INVALID_KDF`, `FILE_TOO_LARGE`, `INVALID_PASSPHRASE`, `AUTHENTICATION_FAILED`, and `CANCELLED`. Sink failures preserve their original cause for trusted local callers; the UI and CLI do not print raw exceptions or secrets. No instrumentation should include passphrases, filenames, plaintext, keys or untrusted message data.

Existing buffered callers remain source-compatible. Old readers reject the new large-profile size and recipient envelope; do not claim wire compatibility for those opt-in workflows. No database migration is required.

## 02.00.01 compatibility

This tooling/security patch changes no public API, CLI option or container format. Only version values advance. The private test-driver helpers are not application APIs; see BROWSER_TESTS.md for their contracts.
