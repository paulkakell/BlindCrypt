// @ts-check

import {
  BlindCryptError,
  MAGIC,
  MAX_CONTAINER_SIZE,
  requireWebCrypto,
  readBlobSlice,
} from "./crypto-core.js";
import { decryptLegacy } from "./crypto-legacy.js";
import { decryptV3 } from "./crypto-v3.js";

export * from "./crypto-core.js";
export { encryptBlobV3 } from "./crypto-v3.js";

/**
 * Decrypt v3 or read-compatible legacy v1/v2 containers.
 * @param {Blob} source
 * @param {string} passphrase
 * @param {(percent: number, message: string) => void} [onProgress]
 */
export async function decryptBlobAny(source, passphrase, onProgress) {
  requireWebCrypto();
  if (!(source instanceof Blob)) {
    throw new BlindCryptError("INVALID_INPUT", "Source must be a Blob");
  }
  if (!Number.isSafeInteger(source.size) || source.size < 5 || source.size > MAX_CONTAINER_SIZE) {
    throw new BlindCryptError("FILE_TOO_LARGE", "Encrypted file is outside the supported safety limit");
  }
  const firstFour = await readBlobSlice(source, 0, 4);
  const isV3 = MAGIC.every((value, index) => firstFour[index] === value);
  return isV3
    ? decryptV3(source, passphrase, onProgress)
    : decryptLegacy(source, passphrase, onProgress);
}
