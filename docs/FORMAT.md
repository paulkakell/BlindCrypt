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
