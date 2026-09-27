# BlindCrypt format v3

## Overview

All integers are unsigned big-endian. Text is UTF-8. JSON is canonical for this implementation: `JSON.stringify(JSON.parse(text))` must equal the original text byte-for-byte.

```text
+--------------------------+
| Magic "BC03"      4 B    |
+--------------------------+
| Header length     4 B    |
+--------------------------+
| Public header     N B    |
+--------------------------+
| Metadata cipher 1040 B   |  1024 plaintext + 16-byte GCM tag
+--------------------------+
| Data record 0      ...   |
+--------------------------+
| Data record 1      ...   |
+--------------------------+
| ...                      |
+--------------------------+
```

The complete container length must equal the length derived from the public header. Missing bytes and trailing bytes are invalid.

## Public header

The header contains exactly these keys in this insertion order:

```json
{"v":3,"mode":"chunked-aesgcm-aad","kdf":"PBKDF2","hash":"SHA-256","iter":900000,"alg":"AES-256-GCM","salt":"...","iv":"...","size":1234,"chunk":524288,"chunks":1,"last":1234,"meta":1024,"norm":"NFC","writer":"01.01.00"}
```

Fields:

- `v`: integer `3`
- `mode`: `chunked-aesgcm-aad`
- `kdf`: `PBKDF2`
- `hash`: `SHA-256`
- `iter`: integer from 600,000 through 2,400,000
- `alg`: `AES-256-GCM`
- `salt`: canonical unpadded base64url encoding of 16 random bytes
- `iv`: canonical unpadded base64url encoding of an 8-byte random IV prefix
- `size`: plaintext size from 0 through 67,108,864 bytes
- `chunk`: integer `524288`
- `chunks`: `0` for an empty file; otherwise `ceil(size / chunk)`
- `last`: `0` for an empty file; otherwise `size - ((chunks - 1) * chunk)`
- `meta`: integer `1024`
- `norm`: `NFC`
- `writer`: application version in `xx.xx.xx` form

The header frame used for authentication is the exact concatenation of the 4-byte magic, 4-byte header length, and raw header bytes. Readers do not reserialize the header when constructing authenticated data.

## Key derivation

1. Normalize the passphrase to Unicode NFC.
2. Encode it as UTF-8. The encoded length must be 1 through 1,024 bytes.
3. Import it as PBKDF2 key material.
4. Derive a nonextractable 256-bit AES-GCM key using SHA-256, the public 16-byte salt, and the validated iteration count.

Legacy v1 and v2 passphrases are not normalized.

## Record IVs

Every AES-GCM IV is 12 bytes:

```text
[random 8-byte prefix][32-bit record counter]
```

- metadata record counter: `0`
- data record `i` counter: `i + 1`

The file-size ceiling keeps the counter far below exhaustion.

## Additional authenticated data

Every record authenticates:

```text
"BlindCrypt-v3\0" || headerFrame || recordType || recordIndex || plaintextLength
```

- domain string: UTF-8 bytes shown above
- `recordType`: one byte, `0` for metadata and `1` for file data
- `recordIndex`: 4-byte unsigned integer; metadata uses `0`
- `plaintextLength`: 4-byte unsigned integer

This binding prevents valid records from being transplanted, reordered, reinterpreted, or accepted under a changed header.

## Encrypted metadata

Metadata plaintext is always 1,024 bytes:

```text
[JSON length 4 B][canonical JSON][random padding]
```

The JSON contains exactly:

```json
{"name":"safe-file.txt","type":"text/plain","writer":"01.01.00"}
```

Filename and media type must already satisfy the reader's safety normalization. The fixed block limits metadata-length disclosure.

## Data records

Each plaintext record is at most 524,288 bytes. AES-GCM appends a 16-byte authentication tag. The last record length is taken from the authenticated public header. Empty files have no data records but still contain the authenticated encrypted metadata record.

## Reader validation order

1. Enforce the overall encrypted-file ceiling.
2. Read and validate magic and public-header length.
3. Decode canonical UTF-8 JSON and exact fields.
4. Validate constants, numeric types, bounds, salt, IV, record geometry, and exact total length.
5. Derive the key.
6. Authenticate and parse metadata.
7. Authenticate each data record in order.
8. Require the final offset to equal the file length.

## Legacy formats

Version 1 and version 2 remain read-only. Their public metadata is untrusted. Version 2 record tags do not cryptographically commit to the complete original file. The application applies strict resource bounds and neutral output handling but cannot retrofit missing authentication.


## 02.00.00 v3 resource profiles

The binary format above remains v3. Buffered APIs retain the 64 MiB plaintext limit. Explicit streaming APIs and record-discarding verification allow up to 4 GiB, with the same 512 KiB records, 1,024-byte metadata, 16-byte tags, salt/nonce construction and canonical header/AAD rules. Readers validate exact header geometry and total length before KDF work. The 32-bit record counter is not approached by the 8,192-record stream ceiling. Old readers intentionally reject files above their own bound; retaining format number 3 does not imply old resource-limit compatibility.

## Encrypted text wrapper

`BLINDCRYPT-TEXT-1.` followed immediately by canonical unpadded base64url of one v3 container. No whitespace, alternate alphabets or appended data. Authenticated metadata is `message.txt` and `text/plain`; plaintext is at most 65,536 UTF-8 bytes and decoded with fatal UTF-8 validation. This wrapper is copyable text, not HTML and not a URL. A normal file container with unrelated metadata is not silently interpreted as a note.

## Restricted single-recipient JWE profile

Normative external constructions: RFC 7516 (JWE Compact Serialization), RFC 7518 (RSA-OAEP-256 and A256GCM), RFC 7638 (JWK thumbprint). BlindCrypt restricts the accepted algorithms and payload. Standards-based primitives do not replace review of this implementation.

The envelope has exactly five canonical unpadded base64url segments separated by four dots: protected header, encrypted content key, IV, ciphertext, authentication tag. The protected header is UTF-8 JSON with exactly these fields in this order:

```json
{"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"application/vnd.blindcrypt.recipient-v1","kid":"PUBLIC_RFC7638_FINGERPRINT"}
```

Canonical re-encoding is required. Duplicate/unknown headers, unprotected headers, `jku`/remote key lookup, compression, algorithm negotiation, RSA1_5, RSA-OAEP/SHA-1, and `none` are not supported. The public `kid` can correlate files addressed to the same key; it is not confidential recipient metadata.

The RSA modulus is exactly 3,072 bits (384 canonical decoded bytes), exponent 65,537 (`AQAB`). Public JWK accepts exactly `e`, `kty`, `n`; import is bounded to 2,048 text bytes at UI/CLI file boundaries. The fingerprint is SHA-256 of RFC 7638 canonical UTF-8 `{"e":...,"kty":"RSA","n":...}`, encoded as unpadded base64url (43 characters). The user must independently authenticate that fingerprint.

Each envelope generates a fresh random 32-byte content-encryption key and 12-byte IV. RSA-OAEP with SHA-256/MGF1-SHA-256 and the empty default label wraps the content key; the encrypted key must be 384 bytes. AES-256-GCM uses a 128-bit tag. Its additional authenticated data is the ASCII bytes of the protected-header base64url segment, as specified by JWE. The ciphertext segment excludes the final 16-byte tag, which occupies the fifth segment.

The encrypted payload is `BCR1` (four ASCII bytes), followed by the existing 1,024-byte metadata block, followed by exactly the original plaintext file bytes. Metadata fields remain name, type and writer under the existing metadata block parser. The original file is limited to 16 MiB; the armored input is bounded before parsing/decoding. An authenticated payload with the wrong magic, metadata geometry or unsupported version is rejected. Empty file payloads are valid.

Private identity export uses a normal v3 container named `blindcrypt-identity.json` with media type `application/json`, encrypted with a Strong passphrase. The inner JSON has exactly RSA members `e`, `kty`, `n`, `d`, `p`, `q`, `dp`, `dq`, `qi`; it is never downloaded unencrypted. Private backup input is capped at 16 KiB and inner key text at 8 KiB. The imported private CryptoKey is nonextractable. JavaScript-exported strings during generation cannot be guaranteed erased; this limitation is documented.

No sender signature is present. Anyone possessing the public key can create an authentic-to-that-recipient envelope. There is no multi-recipient wrapping, revocation, key escrow, or recovery service. Recipient verification creates no plaintext download but authenticates a bounded in-memory payload, unlike record-discarding v3 verification. Independent implementation tests cover encryption/decryption in both directions using Node's classic crypto API.
