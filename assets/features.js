// @ts-check
import "./wordlist.js";
import {
  BlindCryptError, LEVELS, MAGIC, MAX_CONTAINER_SIZE, randomBytes, sanitizeFilename,
  base64urlEncode, base64urlDecodeStrict, encryptBlobV3, decryptBlobAny, textEncoder,
} from "./crypto.js";
import { checkCancelled } from "./crypto-v3.js";
import { buildWordSet, validateNewPassphrase } from "./passphrase.js";

export const MAX_BATCH_FILES = 100;
export const MAX_TEXT_BYTES = 64 * 1024;
export const TEXT_PREFIX = "BLINDCRYPT-TEXT-1.";
const MAX_TEXT_CONTAINER = MAX_TEXT_BYTES + 8192;
export const MAX_TEXT_ARMOR = TEXT_PREFIX.length + Math.ceil(MAX_TEXT_CONTAINER * 4 / 3);
const words = /** @type {string[]} */ (Reflect.get(globalThis, "WORDS"));
const wordSet = buildWordSet(words);

/** Validate new secrets at every user-facing encryption entry point.
 * Existing decryption continues accepting the exact legacy passphrase rules.
 * @param {string} value
 */
export function validateSecret(value) {
  try { return validateNewPassphrase(value, wordSet); }
  catch { throw new BlindCryptError("INVALID_PASSPHRASE", "Use a generated phrase or a varied passphrase of at least 16 characters"); }
}

/** @param {string} [original] @param {boolean} [reveal] */
export function encryptedFilename(original = "file", reveal = false) {
  if (reveal) return `${sanitizeFilename(original)}.blindcrypt`;
  return `${Array.from(randomBytes(16), (byte) => byte.toString(16).padStart(2, "0")).join("")}.blindcrypt`;
}

/**
 * Sequential queue deliberately retains no outputs, only per-item status.
 * @template T
 * @param {readonly T[]} items
 * @param {(item: T, index: number) => Promise<void>} operation
 * @param {{signal?: AbortSignal, onResult?: (result: {index: number, state: string, code: string | null}) => void}} [options]
 */
export async function processQueue(items, operation, options = {}) {
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_BATCH_FILES) {
    throw new BlindCryptError("INVALID_INPUT", "Choose between 1 and 100 files");
  }
  const snapshot = [...items];
  const results = [];
  let stopped = false;
  for (let index = 0; index < snapshot.length; index += 1) {
    let state = "complete";
    /** @type {string | null} */
    let code = null;
    try {
      if (stopped) throw new BlindCryptError("CANCELLED", "Queue cancelled");
      checkCancelled(options.signal);
      await operation(snapshot[index], index);
    } catch (error) {
      code = error instanceof BlindCryptError ? error.code : "OPERATION_FAILED";
      stopped = code === "CANCELLED" || !!options.signal?.aborted;
      state = stopped ? "cancelled" : "failed";
    }
    const result = { index, state, code };
    results.push(result);
    options.onResult?.(result);
  }
  return results;
}

/** @param {string} text @param {string} secret
 * @param {keyof typeof LEVELS} [levelKey] @param {AbortSignal} [signal]
 */
export async function encryptText(text, secret, levelKey = "strong", signal) {
  if (typeof text !== "string" || text.length > MAX_TEXT_BYTES) {
    throw new BlindCryptError("FILE_TOO_LARGE", "Text is limited to 64 KiB of UTF-8");
  }
  const bytes = textEncoder.encode(text);
  try {
    if (bytes.length > MAX_TEXT_BYTES) throw new BlindCryptError("FILE_TOO_LARGE", "Text is limited to 64 KiB of UTF-8");
    const result = await encryptBlobV3(new Blob([bytes]), validateSecret(secret), {
      name: "message.txt", type: "text/plain", levelKey, signal,
    });
    return TEXT_PREFIX + base64urlEncode(new Uint8Array(await result.blob.arrayBuffer()));
  } finally { bytes.fill(0); }
}

/** @param {string} armor @param {string} secret @param {AbortSignal} [signal] */
export async function decryptText(armor, secret, signal) {
  if (typeof armor !== "string" || armor.length > MAX_TEXT_ARMOR || !armor.startsWith(TEXT_PREFIX)) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid encrypted-text envelope");
  }
  const encoded = armor.slice(TEXT_PREFIX.length);
  const bytes = base64urlDecodeStrict(encoded, Math.floor(encoded.length * 3 / 4), "Encrypted text");
  if (!MAGIC.every((value, index) => bytes[index] === value)) {
    throw new BlindCryptError("INVALID_FORMAT", "Encrypted text requires format v3");
  }
  const result = await decryptBlobAny(new Blob([bytes]), secret, undefined, signal);
  if (result.blob.size > MAX_TEXT_BYTES || result.metadata.name !== "message.txt" || result.metadata.type !== "text/plain") {
    throw new BlindCryptError("INVALID_FORMAT", "Not a supported text message");
  }
  const plain = new Uint8Array(await result.blob.arrayBuffer());
  try { return new TextDecoder("utf-8", { fatal: true }).decode(plain); }
  finally { plain.fill(0); }
}

/** Creates a new copy; never revokes or overwrites the original.
 * @param {Blob} source @param {string} oldSecret @param {string} newSecret
 * @param {{levelKey?: keyof typeof LEVELS, name?: string, signal?: AbortSignal}} [options]
 */
export async function reencrypt(source, oldSecret, newSecret, options = {}) {
  const accepted = validateSecret(newSecret);
  if (!(source instanceof Blob) || source.size > MAX_CONTAINER_SIZE) {
    throw new BlindCryptError("FILE_TOO_LARGE", "Re-encryption is limited to buffered files up to 64 MiB");
  }
  const original = await decryptBlobAny(source, oldSecret, undefined, options.signal);
  checkCancelled(options.signal);
  const result = await encryptBlobV3(original.blob, accepted, {
    name: options.name || (original.authenticatedMetadata ? original.metadata.name : "legacy-decrypted.bin"),
    type: original.authenticatedMetadata ? original.metadata.type : "application/octet-stream",
    levelKey: options.levelKey || "strong", signal: options.signal,
  });
  return { ...result, sourceFormat: original.formatVersion, legacyWarning: original.legacyWarning };
}
