import test, { before } from "node:test";
import assert from "node:assert/strict";
import {
  BlindCryptError,
  CHUNK_SIZE,
  decryptBlobAny,
  encryptBlobV3,
  readU32be,
} from "../assets/crypto.js";
import { blobBytes, mutateV3Header } from "./helpers.mjs";

const passphrase = "abandon ability able about above absent";
let encrypted;
let encryptedBytes;

before(async () => {
  const plain = new Uint8Array(CHUNK_SIZE + 37);
  for (let index = 0; index < plain.length; index += 1) plain[index] = (index * 17) % 251;
  encrypted = await encryptBlobV3(new Blob([plain]), passphrase, {
    name: "integrity.bin",
    type: "application/octet-stream",
    levelKey: "standard",
  });
  encryptedBytes = await blobBytes(encrypted.blob);
});

test("v3 rejects authenticated public-header tampering", async () => {
  const tampered = await mutateV3Header(encrypted.blob, (header) => {
    header.writer = header.writer === "99.99.99" ? "98.98.98" : "99.99.99";
  });
  await assert.rejects(
    decryptBlobAny(tampered, passphrase),
    (error) => error instanceof BlindCryptError && error.code === "AUTHENTICATION_FAILED",
  );
});

test("v3 rejects encrypted metadata tampering", async () => {
  const bytes = encryptedBytes.slice();
  const headerLength = readU32be(bytes, 4);
  bytes[8 + headerLength + 10] ^= 0x80;
  await assert.rejects(
    decryptBlobAny(new Blob([bytes]), passphrase),
    (error) => error instanceof BlindCryptError && error.code === "AUTHENTICATION_FAILED",
  );
});

test("v3 rejects ciphertext record tampering", async () => {
  const bytes = encryptedBytes.slice();
  const headerLength = readU32be(bytes, 4);
  const firstDataOffset = 8 + headerLength + 1024 + 16;
  bytes[firstDataOffset + 20] ^= 0x01;
  await assert.rejects(
    decryptBlobAny(new Blob([bytes]), passphrase),
    (error) => error instanceof BlindCryptError && error.code === "AUTHENTICATION_FAILED",
  );
});

test("v3 rejects trailing data", async () => {
  const withTrailing = new Blob([encrypted.blob, Uint8Array.of(1, 2, 3, 4)]);
  await assert.rejects(
    decryptBlobAny(withTrailing, passphrase),
    (error) => error instanceof BlindCryptError && error.code === "INVALID_FORMAT",
  );
});

test("v3 rejects truncation", async () => {
  const truncated = encrypted.blob.slice(0, encrypted.blob.size - 16);
  await assert.rejects(
    decryptBlobAny(truncated, passphrase),
    (error) => error instanceof BlindCryptError && error.code === "INVALID_FORMAT",
  );
});

test("v3 rejects excessive KDF settings before key derivation", async () => {
  const tampered = await mutateV3Header(encrypted.blob, (header) => {
    header.iter = 2_400_001;
  });
  await assert.rejects(
    decryptBlobAny(tampered, passphrase),
    (error) => error instanceof BlindCryptError && error.code === "INVALID_KDF",
  );
});

test("v3 rejects noncanonical header JSON", async () => {
  const bytes = encryptedBytes;
  const headerLength = readU32be(bytes, 4);
  const headerText = new TextDecoder().decode(bytes.subarray(8, 8 + headerLength));
  const spaced = new TextEncoder().encode(` ${headerText}`);
  const changed = new Blob([
    bytes.subarray(0, 4),
    new Uint8Array([0, 0, spaced.length >>> 8, spaced.length & 0xff]),
    spaced,
    bytes.subarray(8 + headerLength),
  ]);
  await assert.rejects(
    decryptBlobAny(changed, passphrase),
    (error) => error instanceof BlindCryptError && error.code === "INVALID_FORMAT",
  );
});
