import { base64urlEncode, readU32be, u32be } from "../assets/crypto.js";

const encoder = new TextEncoder();

export function makeWordList() {
  const words = [];
  for (let index = 0; index < 2048; index += 1) {
    let value = index;
    let suffix = "";
    for (let place = 0; place < 4; place += 1) {
      suffix = String.fromCharCode(97 + (value % 26)) + suffix;
      value = Math.floor(value / 26);
    }
    words.push(`w${suffix}`);
  }
  return words;
}

export async function blobBytes(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

export function assertBytesEqual(assert, actual, expected) {
  assert.equal(actual.length, expected.length);
  for (let index = 0; index < actual.length; index += 1) {
    assert.equal(actual[index], expected[index], `byte ${index}`);
  }
}

async function deriveLegacyKey(passphrase, salt, iterations) {
  const base = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function createLegacyV1(plain, passphrase, metadata = {}) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 10_000;
  const key = await deriveLegacyKey(passphrase, salt, iterations);
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, plain),
  );
  const header = {
    v: 1,
    kdf: "PBKDF2",
    hash: "SHA-256",
    iter: iterations,
    alg: "AES-256-GCM",
    salt: base64urlEncode(salt),
    iv: base64urlEncode(iv),
    name: metadata.name || "legacy-v1.txt",
    type: metadata.type || "text/plain",
  };
  const headerBytes = encoder.encode(JSON.stringify(header));
  return new Blob([u32be(headerBytes.length), headerBytes, cipher]);
}

export async function createLegacyV2(plain, passphrase, metadata = {}) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ivBase = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 10_000;
  const chunkSize = 512 * 1024;
  const chunks = Math.max(1, Math.ceil(plain.length / chunkSize));
  const last = plain.length - (chunks - 1) * chunkSize;
  const key = await deriveLegacyKey(passphrase, salt, iterations);
  const cipherParts = [];

  for (let index = 0; index < chunks; index += 1) {
    const start = index * chunkSize;
    const end = Math.min(plain.length, start + chunkSize);
    const iv = new Uint8Array(12);
    iv.set(ivBase.subarray(0, 8), 0);
    iv.set(u32be(index), 8);
    cipherParts.push(
      new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv, tagLength: 128 },
          key,
          plain.subarray(start, end),
        ),
      ),
    );
  }

  const header = {
    v: 2,
    mode: "chunked-aesgcm",
    kdf: "PBKDF2",
    hash: "SHA-256",
    iter: iterations,
    alg: "AES-256-GCM",
    salt: base64urlEncode(salt),
    iv: base64urlEncode(ivBase),
    size: plain.length,
    chunk: chunkSize,
    chunks,
    last,
    name: metadata.name || "legacy-v2.txt",
    type: metadata.type || "text/plain",
  };
  const headerBytes = encoder.encode(JSON.stringify(header));
  return new Blob([u32be(headerBytes.length), headerBytes, ...cipherParts]);
}

export async function mutateV3Header(blob, mutator) {
  const bytes = await blobBytes(blob);
  const headerLength = readU32be(bytes, 4);
  const headerStart = 8;
  const headerEnd = headerStart + headerLength;
  const header = JSON.parse(new TextDecoder().decode(bytes.subarray(headerStart, headerEnd)));
  mutator(header);
  const headerBytes = encoder.encode(JSON.stringify(header));
  return new Blob([
    bytes.subarray(0, 4),
    u32be(headerBytes.length),
    headerBytes,
    bytes.subarray(headerEnd),
  ]);
}

export function concatBytes(...parts) {
  return concat(...parts);
}
