// @ts-check

/** BlindCrypt application version. */
export const APP_VERSION = "01.01.01";

/** New files are written with format v3. */
export const FORMAT_VERSION = 3;

/** 512 KiB plaintext records. */
export const CHUNK_SIZE = 512 * 1024;

/** Fixed encrypted metadata plaintext length. */
export const METADATA_BLOCK_SIZE = 1024;

/** Browser-only safety ceiling. */
export const MAX_PLAINTEXT_SIZE = 64 * 1024 * 1024;

/** Maximum accepted public header length. */
export const MAX_HEADER_SIZE = 4096;

/** Maximum passphrase size after UTF-8 encoding. */
export const MAX_PASSPHRASE_BYTES = 1024;

export const GCM_TAG_BYTES = 16;
export const MIN_V3_ITERATIONS = 600_000;
export const MAX_KDF_ITERATIONS = 2_400_000;
export const MIN_LEGACY_ITERATIONS = 10_000;
export const MAX_METADATA_JSON_BYTES = METADATA_BLOCK_SIZE - 4;
export const MAX_CHUNKS = Math.ceil(MAX_PLAINTEXT_SIZE / CHUNK_SIZE);
export const MAX_CONTAINER_SIZE =
  8 +
  MAX_HEADER_SIZE +
  METADATA_BLOCK_SIZE +
  GCM_TAG_BYTES +
  MAX_PLAINTEXT_SIZE +
  MAX_CHUNKS * GCM_TAG_BYTES;

export const MAGIC = Uint8Array.of(0x42, 0x43, 0x30, 0x33); // BC03
const RECORD_DOMAIN = new TextEncoder().encode("BlindCrypt-v3\0");
export const textEncoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export const LEVELS = Object.freeze({
  standard: Object.freeze({ iterations: 600_000, words: 6 }),
  strong: Object.freeze({ iterations: 900_000, words: 8 }),
  high: Object.freeze({ iterations: 1_200_000, words: 10 }),
  critical: Object.freeze({ iterations: 2_400_000, words: 16 }),
});

export class BlindCryptError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = "BlindCryptError";
    this.code = code;
  }
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
export function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * @param {unknown} value
 * @param {string[]} expected
 */
export function hasExactKeys(value, expected) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

/** @param {unknown} value @param {string} label */
export function assertSafeInteger(value, label) {
  if (!Number.isSafeInteger(value)) {
    throw new BlindCryptError("INVALID_FORMAT", `${label} must be a safe integer`);
  }
  return /** @type {number} */ (value);
}

export function requireWebCrypto() {
  if (!globalThis.crypto?.subtle || typeof globalThis.crypto.getRandomValues !== "function") {
    throw new BlindCryptError("CRYPTO_UNAVAILABLE", "WebCrypto is unavailable");
  }
}

/** @param {number} length */
export function randomBytes(length) {
  requireWebCrypto();
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** @param {number} value */
export function u32be(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new BlindCryptError("INVALID_FORMAT", "Unsigned 32-bit value out of range");
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** @param {Uint8Array} bytes @param {number} offset */
export function readU32be(bytes, offset) {
  if (!Number.isInteger(offset) || offset < 0 || offset + 4 > bytes.length) {
    throw new BlindCryptError("INVALID_FORMAT", "Unable to read unsigned 32-bit value");
  }
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

/** @param {...Uint8Array} parts */
export function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/** @param {Uint8Array} bytes */
export function base64urlEncode(bytes) {
  let binary = "";
  const stride = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += stride) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + stride));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** @param {unknown} value @param {number} expectedLength @param {string} label */
export function base64urlDecodeStrict(value, expectedLength, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) {
    throw new BlindCryptError("INVALID_FORMAT", `${label} is not canonical base64url`);
  }
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  let binary;
  try {
    binary = atob(normalized + padding);
  } catch {
    throw new BlindCryptError("INVALID_FORMAT", `${label} is invalid base64url`);
  }
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    out[index] = binary.charCodeAt(index);
  }
  if (out.length !== expectedLength || base64urlEncode(out) !== value) {
    throw new BlindCryptError("INVALID_FORMAT", `${label} has an invalid length or encoding`);
  }
  return out;
}

/** @param {Blob} blob @param {number} start @param {number} end */
export async function readBlobSlice(blob, start, end) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > blob.size) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid file slice");
  }
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

/** @param {Uint8Array} bytes @param {string} label */
export function decodeUtf8Strict(bytes, label) {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    throw new BlindCryptError("INVALID_FORMAT", `${label} is not valid UTF-8`);
  }
}

/** @param {Uint8Array} bytes @param {string} label */
export function parseCanonicalJson(bytes, label) {
  const text = decodeUtf8Strict(bytes, label);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new BlindCryptError("INVALID_FORMAT", `${label} is not valid JSON`);
  }
  if (!isPlainObject(value) || JSON.stringify(value) !== text) {
    throw new BlindCryptError("INVALID_FORMAT", `${label} is not canonical JSON`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/** @param {string} value */
export function sanitizeFilename(value) {
  let name = String(value || "file").normalize("NFC");
  name = name
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu, "")
    .replace(/[<>:"/\\|?*]/gu, "_")
    .replace(/\.{2,}/gu, "_")
    .replace(/_+/gu, "_")
    .replace(/\s+/gu, " ")
    .trim()
    .replace(/^[. ]+/u, "")
    .replace(/[. ]+$/u, "");

  if (!name || name === "." || name === "..") name = "file";

  const reserved = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
  if (reserved.test(name)) name = `_${name}`;

  const codePoints = [...name];
  if (codePoints.length > 180) name = codePoints.slice(0, 180).join("");
  return name || "file";
}

/** @param {string} value */
export function sanitizeMimeType(value) {
  const type = String(value || "").trim().toLowerCase();
  if (
    type.length <= 129 &&
    /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/u.test(type)
  ) {
    return type;
  }
  return "application/octet-stream";
}

/** @param {string} passphrase @param {boolean} normalize */
export function encodePassphrase(passphrase, normalize) {
  if (typeof passphrase !== "string") {
    throw new BlindCryptError("INVALID_PASSPHRASE", "Passphrase must be text");
  }
  const value = normalize ? passphrase.normalize("NFC") : passphrase;
  const bytes = textEncoder.encode(value);
  if (bytes.length < 1 || bytes.length > MAX_PASSPHRASE_BYTES) {
    throw new BlindCryptError("INVALID_PASSPHRASE", "Passphrase length is outside the supported range");
  }
  return bytes;
}

/**
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {boolean} normalize
 */
export async function deriveKey(passphrase, salt, iterations, normalize) {
  requireWebCrypto();
  const passphraseBytes = encodePassphrase(passphrase, normalize);
  try {
    const baseKey = await globalThis.crypto.subtle.importKey(
      "raw",
      passphraseBytes,
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return await globalThis.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    passphraseBytes.fill(0);
  }
}

/** @param {Uint8Array} ivPrefix @param {number} counter */
export function makeRecordIv(ivPrefix, counter) {
  if (ivPrefix.length !== 8 || !Number.isInteger(counter) || counter < 0 || counter > 0xffff_ffff) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid record IV parameters");
  }
  return concatBytes(ivPrefix, u32be(counter));
}

/**
 * @param {Uint8Array} headerFrame
 * @param {number} recordType
 * @param {number} index
 * @param {number} plainLength
 */
export function makeRecordAad(headerFrame, recordType, index, plainLength) {
  if (recordType !== 0 && recordType !== 1) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid record type");
  }
  return concatBytes(
    RECORD_DOMAIN,
    headerFrame,
    Uint8Array.of(recordType),
    u32be(index),
    u32be(plainLength),
  );
}

/** @param {string} name @param {string} type */
export function createMetadataBlock(name, type) {
  const metadata = {
    name: sanitizeFilename(name),
    type: sanitizeMimeType(type),
    writer: APP_VERSION,
  };
  const json = textEncoder.encode(JSON.stringify(metadata));
  if (json.length > MAX_METADATA_JSON_BYTES) {
    throw new BlindCryptError("INVALID_METADATA", "Encrypted metadata is too large");
  }
  const block = randomBytes(METADATA_BLOCK_SIZE);
  block.set(u32be(json.length), 0);
  block.set(json, 4);
  return { block, metadata };
}

/** @param {Uint8Array} block */
export function parseMetadataBlock(block) {
  if (block.length !== METADATA_BLOCK_SIZE) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid encrypted metadata length");
  }
  const jsonLength = readU32be(block, 0);
  if (jsonLength < 2 || jsonLength > MAX_METADATA_JSON_BYTES) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid encrypted metadata JSON length");
  }
  const metadata = parseCanonicalJson(block.subarray(4, 4 + jsonLength), "Encrypted metadata");
  if (!hasExactKeys(metadata, ["name", "type", "writer"])) {
    throw new BlindCryptError("INVALID_FORMAT", "Encrypted metadata fields are invalid");
  }
  const name = metadata.name;
  const type = metadata.type;
  const writer = metadata.writer;
  if (
    typeof name !== "string" ||
    typeof type !== "string" ||
    typeof writer !== "string" ||
    !/^\d{2}\.\d{2}\.\d{2}$/u.test(writer) ||
    sanitizeFilename(name) !== name ||
    sanitizeMimeType(type) !== type
  ) {
    throw new BlindCryptError("INVALID_FORMAT", "Encrypted metadata values are invalid");
  }
  return { name, type, writer };
}

export const LIMITS = Object.freeze({
  maxPlaintextSize: MAX_PLAINTEXT_SIZE,
  maxContainerSize: MAX_CONTAINER_SIZE,
  maxHeaderSize: MAX_HEADER_SIZE,
  maxPassphraseBytes: MAX_PASSPHRASE_BYTES,
  minV3Iterations: MIN_V3_ITERATIONS,
  maxKdfIterations: MAX_KDF_ITERATIONS,
});
