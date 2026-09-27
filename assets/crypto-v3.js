// @ts-check

import {
  APP_VERSION,
  FORMAT_VERSION,
  CHUNK_SIZE,
  METADATA_BLOCK_SIZE,
  MAX_PLAINTEXT_SIZE,
  MAX_HEADER_SIZE,
  GCM_TAG_BYTES,
  MIN_V3_ITERATIONS,
  MAX_KDF_ITERATIONS,
  MAX_STREAM_PLAINTEXT_SIZE,
  MAGIC,
  LEVELS,
  BlindCryptError,
  hasExactKeys,
  assertSafeInteger,
  requireWebCrypto,
  randomBytes,
  u32be,
  readU32be,
  concatBytes,
  base64urlEncode,
  base64urlDecodeStrict,
  readBlobSlice,
  parseCanonicalJson,
  textEncoder,
  deriveKey,
  makeRecordIv,
  makeRecordAad,
  createMetadataBlock,
  parseMetadataBlock,
} from "./crypto-core.js";

/**
 * @typedef {object} EncryptOptions
 * @property {string} name
 * @property {string} type
 * @property {keyof typeof LEVELS} levelKey
 * @property {(percent: number, message: string) => void} [onProgress]
 * @property {AbortSignal} [signal]
 */

/**
 * Encrypt a Blob into the authenticated v3 container format.
 * @param {Blob} source
 * @param {string} passphrase
 * @param {EncryptOptions} options
 * @param {(bytes: Uint8Array) => Promise<void> | void} write
 * @param {number} maxSize
 */
async function encryptRecords(source, passphrase, options, write, maxSize) {
  checkCancelled(options.signal);
  requireWebCrypto();
  if (!(source instanceof Blob)) {
    throw new BlindCryptError("INVALID_INPUT", "Source must be a Blob");
  }
  if (!Number.isSafeInteger(source.size) || source.size < 0 || source.size > maxSize) {
    throw new BlindCryptError("FILE_TOO_LARGE", "File exceeds the selected safety limit");
  }
  const level = LEVELS[options.levelKey];
  if (!level) {
    throw new BlindCryptError("INVALID_KDF", "Unknown security level");
  }

  const chunks = source.size === 0 ? 0 : Math.ceil(source.size / CHUNK_SIZE);
  const last = source.size === 0 ? 0 : source.size - (chunks - 1) * CHUNK_SIZE;
  if (chunks > Math.ceil(maxSize / CHUNK_SIZE)) {
    throw new BlindCryptError("FILE_TOO_LARGE", "File has too many records");
  }

  const salt = randomBytes(16);
  const ivPrefix = randomBytes(8);
  const header = {
    v: FORMAT_VERSION,
    mode: "chunked-aesgcm-aad",
    kdf: "PBKDF2",
    hash: "SHA-256",
    iter: level.iterations,
    alg: "AES-256-GCM",
    salt: base64urlEncode(salt),
    iv: base64urlEncode(ivPrefix),
    size: source.size,
    chunk: CHUNK_SIZE,
    chunks,
    last,
    meta: METADATA_BLOCK_SIZE,
    norm: "NFC",
    writer: APP_VERSION,
  };
  const headerBytes = textEncoder.encode(JSON.stringify(header));
  if (headerBytes.length > MAX_HEADER_SIZE) {
    throw new BlindCryptError("INVALID_FORMAT", "Generated header is too large");
  }
  const headerFrame = concatBytes(MAGIC, u32be(headerBytes.length), headerBytes);

  options.onProgress?.(1, "Deriving key");
  const key = await deriveKey(passphrase, salt, level.iterations, true);
  checkCancelled(options.signal);
  const { block: metadataBlock, metadata } = createMetadataBlock(options.name, options.type);

  try {
    const metadataCipher = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: makeRecordIv(ivPrefix, 0),
          additionalData: makeRecordAad(headerFrame, 0, 0, METADATA_BLOCK_SIZE),
          tagLength: 128,
        },
        key,
        metadataBlock,
      ),
    );
    await write(headerFrame);
    await write(metadataCipher);
    options.onProgress?.(7, "Encrypting file");

    for (let index = 0; index < chunks; index += 1) {
      checkCancelled(options.signal);
      const start = index * CHUNK_SIZE;
      const end = Math.min(source.size, start + CHUNK_SIZE);
      const plain = await readBlobSlice(source, start, end);
      try {
        const cipher = new Uint8Array(
          await globalThis.crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: makeRecordIv(ivPrefix, index + 1),
              additionalData: makeRecordAad(headerFrame, 1, index, plain.length),
              tagLength: 128,
            },
            key,
            plain,
          ),
        );
        checkCancelled(options.signal);
        await write(cipher);
      } finally {
        plain.fill(0);
      }
      const percent = 7 + ((index + 1) / Math.max(1, chunks)) * 93;
      options.onProgress?.(percent, `${percent.toFixed(1)}%`);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  } finally {
    metadataBlock.fill(0);
  }

  options.onProgress?.(100, "100.0%");
  return {
    header,
    metadata,
  };
}

/** @param {Record<string, unknown>} header @param {number} maxSize */
function validateV3Header(header, maxSize) {
  const keys = [
    "v",
    "mode",
    "kdf",
    "hash",
    "iter",
    "alg",
    "salt",
    "iv",
    "size",
    "chunk",
    "chunks",
    "last",
    "meta",
    "norm",
    "writer",
  ];
  if (!hasExactKeys(header, keys)) {
    throw new BlindCryptError("INVALID_FORMAT", "Public header fields are invalid");
  }
  if (
    header.v !== FORMAT_VERSION ||
    header.mode !== "chunked-aesgcm-aad" ||
    header.kdf !== "PBKDF2" ||
    header.hash !== "SHA-256" ||
    header.alg !== "AES-256-GCM" ||
    header.chunk !== CHUNK_SIZE ||
    header.meta !== METADATA_BLOCK_SIZE ||
    header.norm !== "NFC" ||
    typeof header.writer !== "string" ||
    !/^\d{2}\.\d{2}\.\d{2}$/u.test(header.writer)
  ) {
    throw new BlindCryptError("INVALID_FORMAT", "Public header constants are invalid");
  }

  const iterations = assertSafeInteger(header.iter, "KDF iterations");
  const size = assertSafeInteger(header.size, "Plaintext size");
  const chunks = assertSafeInteger(header.chunks, "Record count");
  const last = assertSafeInteger(header.last, "Final record size");

  if (iterations < MIN_V3_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
    throw new BlindCryptError("INVALID_KDF", "KDF iteration count is outside the supported range");
  }
  if (size < 0 || size > maxSize) {
    throw new BlindCryptError("FILE_TOO_LARGE", "Declared plaintext size exceeds the safety limit");
  }
  const expectedChunks = size === 0 ? 0 : Math.ceil(size / CHUNK_SIZE);
  const expectedLast = size === 0 ? 0 : size - (expectedChunks - 1) * CHUNK_SIZE;
  if (chunks !== expectedChunks || last !== expectedLast || chunks > Math.ceil(maxSize / CHUNK_SIZE)) {
    throw new BlindCryptError("INVALID_FORMAT", "Record geometry is inconsistent");
  }

  const salt = base64urlDecodeStrict(header.salt, 16, "Salt");
  const ivPrefix = base64urlDecodeStrict(header.iv, 8, "IV prefix");
  return { iterations, size, chunks, last, salt, ivPrefix };
}

/**
 * @param {Blob} source
 * @param {string} passphrase
 * @param {((percent: number, message: string) => void) | undefined} onProgress
 * @param {(bytes: Uint8Array) => Promise<void> | void} write
 * @param {number} maxSize
 * @param {AbortSignal} [signal]
 */
async function decryptRecords(source, passphrase, onProgress, write, maxSize, signal) {
  requireWebCrypto();
  checkCancelled(signal);
  if (!(source instanceof Blob)) throw new BlindCryptError("INVALID_INPUT", "Source must be a Blob");
  if (source.size < 8 + METADATA_BLOCK_SIZE + GCM_TAG_BYTES) {
    throw new BlindCryptError("INVALID_FORMAT", "File is too small for format v3");
  }
  const prefix = await readBlobSlice(source, 0, 8);
  if (!MAGIC.every((value, index) => prefix[index] === value)) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid format v3 magic");
  }
  const headerLength = readU32be(prefix, 4);
  if (headerLength < 2 || headerLength > MAX_HEADER_SIZE || 8 + headerLength > source.size) {
    throw new BlindCryptError("INVALID_FORMAT", "Public header length is invalid");
  }
  const headerBytes = await readBlobSlice(source, 8, 8 + headerLength);
  const header = parseCanonicalJson(headerBytes, "Public header");
  const geometry = validateV3Header(header, maxSize);
  const headerFrame = concatBytes(prefix, headerBytes);

  const expectedSize =
    headerFrame.length +
    METADATA_BLOCK_SIZE +
    GCM_TAG_BYTES +
    geometry.size +
    geometry.chunks * GCM_TAG_BYTES;
  if (!Number.isSafeInteger(expectedSize) || source.size !== expectedSize) {
    throw new BlindCryptError("INVALID_FORMAT", "Container length does not match its authenticated geometry");
  }

  onProgress?.(1, "Deriving key");
  const key = await deriveKey(passphrase, geometry.salt, geometry.iterations, true);
  checkCancelled(signal);
  let offset = headerFrame.length;
  const metadataCipherLength = METADATA_BLOCK_SIZE + GCM_TAG_BYTES;
  const metadataCipher = await readBlobSlice(source, offset, offset + metadataCipherLength);
  offset += metadataCipherLength;

  let metadataPlain;
  try {
    metadataPlain = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: makeRecordIv(geometry.ivPrefix, 0),
          additionalData: makeRecordAad(headerFrame, 0, 0, METADATA_BLOCK_SIZE),
          tagLength: 128,
        },
        key,
        metadataCipher,
      ),
    );
  } catch {
    throw new BlindCryptError("AUTHENTICATION_FAILED", "Passphrase is wrong or the file was modified");
  }

  let metadata;
  try {
    metadata = parseMetadataBlock(metadataPlain);
  } finally {
    metadataPlain.fill(0);
  }
  onProgress?.(7, "Decrypting file");

  for (let index = 0; index < geometry.chunks; index += 1) {
    checkCancelled(signal);
    const plainLength = index === geometry.chunks - 1 ? geometry.last : CHUNK_SIZE;
    const cipherLength = plainLength + GCM_TAG_BYTES;
    const cipher = await readBlobSlice(source, offset, offset + cipherLength);
    offset += cipherLength;
    let plain;
    try {
      plain = new Uint8Array(await globalThis.crypto.subtle.decrypt({
        name: "AES-GCM", iv: makeRecordIv(geometry.ivPrefix, index + 1),
        additionalData: makeRecordAad(headerFrame, 1, index, plainLength), tagLength: 128,
      }, key, cipher));
    } catch {
      throw new BlindCryptError("AUTHENTICATION_FAILED", "Passphrase is wrong or the file was modified");
    }
    try {
      if (plain.length !== plainLength) throw new BlindCryptError("INVALID_FORMAT", "Decrypted record length is invalid");
      checkCancelled(signal);
      await write(plain);
    } finally { plain.fill(0); }
    const percent = 7 + ((index + 1) / Math.max(1, geometry.chunks)) * 93;
    onProgress?.(percent, `${percent.toFixed(1)}%`);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  if (offset !== source.size) {
    throw new BlindCryptError("INVALID_FORMAT", "Container has trailing or missing data");
  }
  onProgress?.(100, "100.0%");
  return {
    metadata,
    formatVersion: FORMAT_VERSION,
    authenticatedMetadata: true,
    legacyWarning: null,
    publicHeader: header,
  };
}


/** @param {AbortSignal} [signal] */
export function checkCancelled(signal) {
  if (signal?.aborted) throw new BlindCryptError("CANCELLED", "Operation cancelled");
}

/**
 * The sink must stage output privately until close(), and discard it on abort().
 * write() must finish consuming bytes before resolving; its input is then wiped.
 * @typedef {{write: (bytes: Uint8Array) => Promise<void> | void,
 * close: () => Promise<void> | void, abort: () => Promise<void> | void}} TransactionalSink
 */

/** @template T
 * @param {TransactionalSink} sink @param {() => Promise<T>} operation @param {AbortSignal} [signal] */
async function transaction(sink, operation, signal) {
  if (!sink || typeof sink.write !== "function" || typeof sink.close !== "function" || typeof sink.abort !== "function") {
    throw new BlindCryptError("INVALID_INPUT", "A transactional output sink is required");
  }
  try {
    const result = await operation();
    checkCancelled(signal);
    await sink.close();
    return result;
  } catch (error) {
    try { await sink.abort(); } catch { /* Preserve the original failure. */ }
    throw error;
  }
}

/** Buffered compatibility API: never accepts more than 64 MiB.
 * @param {Blob} source @param {string} passphrase @param {EncryptOptions} options
 */
export async function encryptBlobV3(source, passphrase, options) {
  /** @type {Blob[]} */
  const parts = [];
  const result = await encryptRecords(source, passphrase, options,
    (bytes) => { parts.push(new Blob([bytes])); }, MAX_PLAINTEXT_SIZE);
  checkCancelled(options.signal);
  return { ...result, blob: new Blob(parts, { type: "application/octet-stream" }) };
}

/** @param {Blob} source @param {string} passphrase
 * @param {(percent: number, message: string) => void} [onProgress]
 * @param {AbortSignal} [signal]
 */
export async function decryptV3(source, passphrase, onProgress, signal) {
  /** @type {Blob[]} */
  const parts = [];
  const result = await decryptRecords(source, passphrase, onProgress,
    (bytes) => { parts.push(new Blob([bytes])); }, MAX_PLAINTEXT_SIZE, signal);
  checkCancelled(signal);
  return { ...result, blob: new Blob(parts, { type: "application/octet-stream" }) };
}

/** All v3 records are authenticated and discarded; no plaintext Blob or output sink.
 * Legacy formats are intentionally rejected: their completeness cannot be verified.
 * @param {Blob} source @param {string} passphrase
 * @param {{onProgress?: (percent: number, message: string) => void, signal?: AbortSignal}} [options]
 */
export async function verifyV3(source, passphrase, options = {}) {
  const result = await decryptRecords(source, passphrase, options.onProgress,
    () => {}, MAX_STREAM_PLAINTEXT_SIZE, options.signal);
  checkCancelled(options.signal);
  return { ...result, verified: true };
}

/** @param {Blob} source @param {string} passphrase @param {EncryptOptions} options @param {TransactionalSink} sink */
export async function encryptV3ToSink(source, passphrase, options, sink) {
  return transaction(sink, () => encryptRecords(source, passphrase, options,
    (bytes) => sink.write(bytes), MAX_STREAM_PLAINTEXT_SIZE), options.signal);
}

/** @param {Blob} source @param {string} passphrase @param {TransactionalSink} sink
 * @param {{onProgress?: (percent: number, message: string) => void, signal?: AbortSignal}} [options]
 */
export async function decryptV3ToSink(source, passphrase, sink, options = {}) {
  return transaction(sink, () => decryptRecords(source, passphrase, options.onProgress,
    (bytes) => sink.write(bytes), MAX_STREAM_PLAINTEXT_SIZE, options.signal), options.signal);
}
