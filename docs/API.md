# Internal module API

BlindCrypt has no network API. These browser modules are internal interfaces used by the page and tests.

## `assets/crypto.js` public facade

### `encryptBlobV3(source, passphrase, options)`

Encrypts a `Blob` into format v3.

Options:

- `name`: original filename; normalized before encrypted storage
- `type`: declared media type; normalized before encrypted storage
- `levelKey`: `standard`, `strong`, `high`, or `critical`
- `onProgress(percent, message)`: optional local progress callback

Returns `{ blob, header, metadata }`. The returned Blob uses `application/octet-stream`.

Example:

```js
const result = await encryptBlobV3(file, passphrase, {
  name: file.name,
  type: file.type,
  levelKey: "strong",
});
```

### `decryptBlobAny(source, passphrase, onProgress?)`

Detects and decrypts v1, v2, or v3.

Returns:

- `blob`: neutral downloadable plaintext Blob
- `metadata`: normalized filename, declared media type, and writer indicator
- `formatVersion`: `1`, `2`, or `3`
- `authenticatedMetadata`: true only for v3
- `legacyWarning`: null for v3; warning text for legacy files
- `publicHeader`: parsed public header for diagnostic display or tests

### `sanitizeFilename(value)`

Removes controls, bidirectional overrides, separators, reserved filename characters, unsafe trailing characters, and excessive length.

### `sanitizeMimeType(value)`

Accepts a restricted lowercase `type/subtype` form. Invalid values become `application/octet-stream`.

### Constants

- `APP_VERSION`
- `FORMAT_VERSION`
- `CHUNK_SIZE`
- `METADATA_BLOCK_SIZE`
- `MAX_PLAINTEXT_SIZE`
- `MAX_PASSPHRASE_BYTES`
- `LEVELS`
- `LIMITS`

## `assets/passphrase.js`

### `buildWordSet(words)`

Requires exactly 2,048 unique lowercase words.

### `generatePassphrase(words, count)`

Generates 6 through 16 independently selected words through `crypto.getRandomValues`.

### `assessPassphrase(passphrase, wordSet)`

Returns transparent word-count information for bundled-word phrases. Custom passphrases return no entropy estimate.

### `validateNewPassphrase(passphrase, wordSet)`

Accepts at least six bundled words or a non-repetitive custom passphrase meeting the configured length rules. Returns the NFC-normalized value used by format v3.
