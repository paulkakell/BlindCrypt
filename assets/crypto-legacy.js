// @ts-check

import {
  CHUNK_SIZE,
  MAX_PLAINTEXT_SIZE,
  MAX_HEADER_SIZE,
  GCM_TAG_BYTES,
  MIN_LEGACY_ITERATIONS,
  MAX_KDF_ITERATIONS,
  MAX_CONTAINER_SIZE,
  BlindCryptError,
  isPlainObject,
  assertSafeInteger,
  base64urlDecodeStrict,
  readBlobSlice,
  readU32be,
  decodeUtf8Strict,
  deriveKey,
  sanitizeFilename,
  sanitizeMimeType,
  u32be,
} from "./crypto-core.js";

/** @param {Record<string, unknown>} header */
function validateLegacyCommon(header) {
  if (header.v !== 1 && header.v !== 2) {
    throw new BlindCryptError("UNSUPPORTED_VERSION", "Unsupported BlindCrypt format version");
  }
  const iterations = assertSafeInteger(header.iter, "KDF iterations");
  if (iterations < MIN_LEGACY_ITERATIONS || iterations > MAX_KDF_ITERATIONS) {
    throw new BlindCryptError("INVALID_KDF", "Legacy KDF iteration count is outside the supported range");
  }
  if (header.kdf !== undefined && header.kdf !== "PBKDF2") {
    throw new BlindCryptError("INVALID_FORMAT", "Unsupported legacy KDF");
  }
  if (header.hash !== undefined && header.hash !== "SHA-256") {
    throw new BlindCryptError("INVALID_FORMAT", "Unsupported legacy hash");
  }
  if (header.alg !== undefined && header.alg !== "AES-256-GCM") {
    throw new BlindCryptError("INVALID_FORMAT", "Unsupported legacy cipher");
  }
  const salt = base64urlDecodeStrict(header.salt, 16, "Legacy salt");
  const iv = base64urlDecodeStrict(header.iv, 12, "Legacy IV");
  return { iterations, salt, iv };
}

/** @param {Record<string, unknown>} header */
function legacyMetadata(header) {
  return {
    name: sanitizeFilename(typeof header.name === "string" ? header.name : "legacy-decrypted.bin"),
    type: sanitizeMimeType(typeof header.type === "string" ? header.type : "application/octet-stream"),
    writer: "legacy",
  };
}

/**
 * @param {Blob} source
 * @param {string} passphrase
 * @param {(percent: number, message: string) => void} [onProgress]
 */
export async function decryptLegacy(source, passphrase, onProgress) {
  if (source.size < 5 || source.size > MAX_CONTAINER_SIZE) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy file size is invalid");
  }
  const prefix = await readBlobSlice(source, 0, 4);
  const headerLength = readU32be(prefix, 0);
  if (headerLength < 2 || headerLength > MAX_HEADER_SIZE || 4 + headerLength > source.size) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy header length is invalid");
  }
  const headerBytes = await readBlobSlice(source, 4, 4 + headerLength);
  let header;
  try {
    header = JSON.parse(decodeUtf8Strict(headerBytes, "Legacy header"));
  } catch (error) {
    if (error instanceof BlindCryptError) throw error;
    throw new BlindCryptError("INVALID_FORMAT", "Legacy header is not valid JSON");
  }
  if (!isPlainObject(header)) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy header is invalid");
  }
  const legacy = validateLegacyCommon(/** @type {Record<string, unknown>} */ (header));
  const headerEnd = 4 + headerLength;

  if (header.v === 1) {
    const cipherLength = source.size - headerEnd;
    if (cipherLength < GCM_TAG_BYTES || cipherLength > MAX_PLAINTEXT_SIZE + GCM_TAG_BYTES) {
      throw new BlindCryptError("INVALID_FORMAT", "Legacy v1 ciphertext length is invalid");
    }
    onProgress?.(1, "Deriving legacy key");
    const key = await deriveKey(passphrase, legacy.salt, legacy.iterations, false);
    const cipher = await readBlobSlice(source, headerEnd, source.size);
    try {
      const plain = new Uint8Array(
        await globalThis.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: legacy.iv, tagLength: 128 },
          key,
          cipher,
        ),
      );
      if (plain.length > MAX_PLAINTEXT_SIZE) {
        throw new BlindCryptError("FILE_TOO_LARGE", "Legacy plaintext exceeds the safety limit");
      }
      onProgress?.(100, "100.0%");
      return {
        blob: new Blob([plain], { type: "application/octet-stream" }),
        metadata: legacyMetadata(/** @type {Record<string, unknown>} */ (header)),
        formatVersion: 1,
        authenticatedMetadata: false,
        legacyWarning:
          "Legacy v1 metadata and whole-file structure are not authenticated. The download uses a neutral filename and MIME type.",
        publicHeader: header,
      };
    } catch (error) {
      if (error instanceof BlindCryptError) throw error;
      throw new BlindCryptError("AUTHENTICATION_FAILED", "Passphrase is wrong or the legacy file was modified");
    }
  }

  const size = assertSafeInteger(header.size, "Legacy plaintext size");
  const chunkSize = assertSafeInteger(header.chunk, "Legacy chunk size");
  const chunks = assertSafeInteger(header.chunks, "Legacy chunk count");
  const last = assertSafeInteger(header.last, "Legacy final chunk size");
  if (size < 0 || size > MAX_PLAINTEXT_SIZE || chunkSize !== CHUNK_SIZE) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy v2 geometry is outside supported bounds");
  }
  const expectedChunks = Math.max(1, Math.ceil(size / chunkSize));
  const expectedLast = size - (expectedChunks - 1) * chunkSize;
  if (chunks !== expectedChunks || last !== expectedLast || last < 0 || last > chunkSize) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy v2 record geometry is inconsistent");
  }
  const expectedCipherLength = size + chunks * GCM_TAG_BYTES;
  if (source.size - headerEnd !== expectedCipherLength) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy v2 has trailing, missing, or inconsistent data");
  }

  onProgress?.(1, "Deriving legacy key");
  const key = await deriveKey(passphrase, legacy.salt, legacy.iterations, false);
  /** @type {BlobPart[]} */
  const plainParts = [];
  let offset = headerEnd;

  for (let index = 0; index < chunks; index += 1) {
    const plainLength = index === chunks - 1 ? last : chunkSize;
    const cipherLength = plainLength + GCM_TAG_BYTES;
    const cipher = await readBlobSlice(source, offset, offset + cipherLength);
    offset += cipherLength;
    const iv = new Uint8Array(12);
    iv.set(legacy.iv.subarray(0, 8), 0);
    iv.set(u32be(index), 8);
    try {
      const plain = new Uint8Array(
        await globalThis.crypto.subtle.decrypt(
          { name: "AES-GCM", iv, tagLength: 128 },
          key,
          cipher,
        ),
      );
      if (plain.length !== plainLength) {
        throw new BlindCryptError("INVALID_FORMAT", "Legacy decrypted record length is invalid");
      }
      plainParts.push(plain);
    } catch (error) {
      if (error instanceof BlindCryptError) throw error;
      throw new BlindCryptError("AUTHENTICATION_FAILED", "Passphrase is wrong or the legacy file was modified");
    }
    const percent = 5 + ((index + 1) / chunks) * 95;
    onProgress?.(percent, `${percent.toFixed(1)}%`);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  if (offset !== source.size) {
    throw new BlindCryptError("INVALID_FORMAT", "Legacy v2 has trailing data");
  }
  onProgress?.(100, "100.0%");
  return {
    blob: new Blob(plainParts, { type: "application/octet-stream" }),
    metadata: legacyMetadata(/** @type {Record<string, unknown>} */ (header)),
    formatVersion: 2,
    authenticatedMetadata: false,
    legacyWarning:
      "Legacy v2 authenticates records separately but not its metadata or whole-file completeness. The download uses a neutral filename and MIME type.",
    publicHeader: header,
  };
}

