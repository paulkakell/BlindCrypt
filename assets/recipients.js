// @ts-check
// Restricted JWE Compact profile: RFC 7516 + RFC 7518, RSA-OAEP-256/A256GCM.
// Only one RSA-3072 recipient; no algorithm negotiation, URLs, compression, or signatures.
import {
  BlindCryptError, METADATA_BLOCK_SIZE, MAGIC, randomBytes, textEncoder,
  base64urlEncode, base64urlDecodeStrict, concatBytes, hasExactKeys,
  createMetadataBlock, parseMetadataBlock, encryptBlobV3, decryptBlobAny,
} from "./crypto.js";
import { validateSecret } from "./features.js";
import { checkCancelled } from "./crypto-v3.js";

export const MAX_RECIPIENT_BYTES = 16 * 1024 * 1024;
export const MAX_RECIPIENT_ENVELOPE = Math.ceil((MAX_RECIPIENT_BYTES + 2048) * 4 / 3) + 2048;
export const MAX_IDENTITY_BYTES = 16 * 1024;
const CONTENT_TYPE = "application/vnd.blindcrypt.recipient-v1";
const PAYLOAD_MAGIC = Uint8Array.of(0x42, 0x43, 0x52, 0x31);
const PRIVATE_FIELDS = ["d", "p", "q", "dp", "dq", "qi"];
const decoder = new TextDecoder("utf-8", { fatal: true });

/** @param {string} value @param {number} length @param {string} label */
function decode(value, length, label) { return base64urlDecodeStrict(value, length, label); }

/** @param {unknown} value @param {boolean} [privateKey] @returns {JsonWebKey} */
function validateJwk(value, privateKey = false) {
  const fields = ["e", "kty", "n", ...(privateKey ? PRIVATE_FIELDS : [])];
  if (!hasExactKeys(value, fields)) throw new BlindCryptError("INVALID_KEY", "Unsupported key fields");
  const jwk = /** @type {JsonWebKey} */ (value);
  if (jwk.kty !== "RSA" || jwk.e !== "AQAB" || typeof jwk.n !== "string") {
    throw new BlindCryptError("INVALID_KEY", "Only RSA-3072 with exponent 65537 is supported");
  }
  const modulus = decode(jwk.n, 384, "RSA modulus");
  if (!(modulus[0] & 0x80) || !(modulus[383] & 1)) throw new BlindCryptError("INVALID_KEY", "Invalid RSA modulus");
  if (privateKey) {
    for (const field of PRIVATE_FIELDS) {
      const data = Reflect.get(jwk, field);
      if (typeof data !== "string" || data.length > 512 || data.length < 1) {
        throw new BlindCryptError("INVALID_KEY", "Invalid private key field");
      }
      decode(data, Math.floor(data.length * 3 / 4), "Private key field").fill(0);
    }
  }
  return jwk;
}

/** RFC 7638 canonical required RSA members, hashed with SHA-256.
 * @param {JsonWebKey} jwk
 */
export async function recipientFingerprint(jwk) {
  const publicJwk = validateJwk({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  return base64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256",
    textEncoder.encode(JSON.stringify({ e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n })))));
}

/** Import only locally supplied public material; never resolve a key URL.
 * @param {string} text
 */
export async function importRecipient(text) {
  if (typeof text !== "string" || text.length > 2048) throw new BlindCryptError("INVALID_KEY", "Public key is too large");
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw new BlindCryptError("INVALID_KEY", "Invalid public key JSON"); }
  const jwk = validateJwk(parsed);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  return { key, jwk, fingerprint: await recipientFingerprint(jwk) };
}

/** Generate an identity; only its passphrase-encrypted private backup is returned.
 * @param {string} secret @param {AbortSignal} [signal]
 */
export async function generateIdentity(secret, signal) {
  const accepted = validateSecret(secret);
  checkCancelled(signal);
  const pair = await crypto.subtle.generateKey({
    name: "RSA-OAEP", modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
  }, true, ["encrypt", "decrypt"]);
  checkCancelled(signal);
  const exported = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicJwk = { e: exported.e, kty: exported.kty, n: exported.n };
  const privateJwk = Object.fromEntries(["e", "kty", "n", ...PRIVATE_FIELDS].map((field) => [field, Reflect.get(exported, field)]));
  const bytes = textEncoder.encode(JSON.stringify(privateJwk));
  try {
    const backup = await encryptBlobV3(new Blob([bytes]), accepted, {
      name: "blindcrypt-identity.json", type: "application/json", levelKey: "strong", signal,
    });
    return { publicKey: JSON.stringify(publicJwk), privateBackup: backup.blob,
      fingerprint: await recipientFingerprint(publicJwk) };
  } finally {
    bytes.fill(0);
    // JavaScript strings/CryptoKeys cannot be reliably zeroized; drop references.
    for (const field of PRIVATE_FIELDS) { Reflect.deleteProperty(privateJwk, field); Reflect.deleteProperty(exported, field); }
  }
}

/** @param {Blob} backup @param {string} secret @param {AbortSignal} [signal] */
export async function unlockIdentity(backup, secret, signal) {
  if (!(backup instanceof Blob) || backup.size > MAX_IDENTITY_BYTES) throw new BlindCryptError("INVALID_KEY", "Invalid identity backup size");
  const magic = new Uint8Array(await backup.slice(0, 4).arrayBuffer());
  if (!MAGIC.every((value, index) => value === magic[index])) throw new BlindCryptError("INVALID_KEY", "Identity backups require authenticated format v3");
  const result = await decryptBlobAny(backup, secret, undefined, signal);
  if (result.metadata.name !== "blindcrypt-identity.json" || result.metadata.type !== "application/json" || result.blob.size > 8192) {
    throw new BlindCryptError("INVALID_KEY", "Not a supported identity backup");
  }
  const bytes = new Uint8Array(await result.blob.arrayBuffer());
  try {
    const jwk = validateJwk(JSON.parse(decoder.decode(bytes)), true);
    try {
      const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
      return { key, fingerprint: await recipientFingerprint(jwk) };
    } finally { for (const field of PRIVATE_FIELDS) Reflect.deleteProperty(jwk, field); }
  } finally { bytes.fill(0); }
}

/** @param {Blob} source @param {Awaited<ReturnType<typeof importRecipient>>} recipient
 * @param {{name: string, type: string, signal?: AbortSignal}} options
 */
export async function encryptForRecipient(source, recipient, options) {
  if (!(source instanceof Blob) || source.size > MAX_RECIPIENT_BYTES) throw new BlindCryptError("FILE_TOO_LARGE", "Recipient encryption is limited to 16 MiB");
  checkCancelled(options.signal);
  const protectedHeader = base64urlEncode(textEncoder.encode(JSON.stringify({
    alg: "RSA-OAEP-256", enc: "A256GCM", cty: CONTENT_TYPE, kid: recipient.fingerprint,
  })));
  const cek = randomBytes(32);
  const iv = randomBytes(12);
  const { block } = createMetadataBlock(options.name, options.type);
  let file;
  let payload;
  try {
    file = new Uint8Array(await source.arrayBuffer());
    checkCancelled(options.signal);
    payload = concatBytes(PAYLOAD_MAGIC, block, file);
    file.fill(0); block.fill(0);
    const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipient.key, cek));
    const cipher = new Uint8Array(await crypto.subtle.encrypt({
      name: "AES-GCM", iv, additionalData: textEncoder.encode(protectedHeader), tagLength: 128,
    }, key, payload));
    checkCancelled(options.signal);
    const compact = [protectedHeader, base64urlEncode(wrapped), base64urlEncode(iv),
      base64urlEncode(cipher.subarray(0, -16)), base64urlEncode(cipher.subarray(-16))].join(".");
    return new Blob([compact], { type: "application/jose" });
  } finally { cek.fill(0); block.fill(0); file?.fill(0); payload?.fill(0); }
}

/** @param {Blob} envelope @param {Awaited<ReturnType<typeof unlockIdentity>>} identity
 * @param {{verifyOnly?: boolean, signal?: AbortSignal}} [options]
 */
export async function decryptForRecipient(envelope, identity, options = {}) {
  if (!(envelope instanceof Blob) || envelope.size > MAX_RECIPIENT_ENVELOPE) throw new BlindCryptError("FILE_TOO_LARGE", "Recipient envelope exceeds the safety limit");
  checkCancelled(options.signal);
  const parts = (await envelope.text()).split(".");
  if (parts.length !== 5 || parts[0].length > 1024) throw new BlindCryptError("INVALID_FORMAT", "Invalid JWE compact envelope");
  const header = JSON.parse(decoder.decode(decode(parts[0], Math.floor(parts[0].length * 3 / 4), "Protected header")));
  if (!hasExactKeys(header, ["alg", "enc", "cty", "kid"]) || header.alg !== "RSA-OAEP-256" || header.enc !== "A256GCM" || header.cty !== CONTENT_TYPE || header.kid !== identity.fingerprint) {
    throw new BlindCryptError("AUTHENTICATION_FAILED", "Unsupported envelope or wrong recipient");
  }
  // Canonical protected header also rejects duplicate members and ambiguous parsing.
  if (parts[0] !== base64urlEncode(textEncoder.encode(JSON.stringify({alg: header.alg, enc: header.enc, cty: header.cty, kid: header.kid})))) {
    throw new BlindCryptError("INVALID_FORMAT", "Noncanonical protected header");
  }
  const wrapped = decode(parts[1], 384, "Wrapped key");
  const iv = decode(parts[2], 12, "JWE IV");
  const cipher = decode(parts[3], Math.floor(parts[3].length * 3 / 4), "JWE ciphertext");
  const tag = decode(parts[4], 16, "JWE tag");
  if (cipher.length < 4 + METADATA_BLOCK_SIZE || cipher.length > MAX_RECIPIENT_BYTES + 4 + METADATA_BLOCK_SIZE) {
    throw new BlindCryptError("INVALID_FORMAT", "Invalid recipient payload length");
  }
  let cek;
  let plain;
  try {
    cek = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, identity.key, wrapped));
    if (cek.length !== 32) throw new Error("Invalid content key");
    const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv,
      additionalData: textEncoder.encode(parts[0]), tagLength: 128,
    }, key, concatBytes(cipher, tag)));
  } catch { throw new BlindCryptError("AUTHENTICATION_FAILED", "Wrong recipient or modified envelope"); }
  finally { cek?.fill(0); }
  try {
    checkCancelled(options.signal);
    if (!PAYLOAD_MAGIC.every((value, index) => value === plain[index])) throw new BlindCryptError("INVALID_FORMAT", "Unsupported recipient payload");
    const metadata = parseMetadataBlock(plain.subarray(4, 4 + METADATA_BLOCK_SIZE));
    const blob = options.verifyOnly ? null : new Blob([plain.subarray(4 + METADATA_BLOCK_SIZE)], { type: "application/octet-stream" });
    return { metadata, blob, verified: true, senderAuthenticated: false };
  } finally { plain.fill(0); }
}
