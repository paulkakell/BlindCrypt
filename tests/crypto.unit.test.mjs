import test from "node:test";
import assert from "node:assert/strict";
import {
  BlindCryptError,
  CHUNK_SIZE,
  decryptBlobAny,
  encryptBlobV3,
  sanitizeFilename,
  sanitizeMimeType,
} from "../assets/crypto.js";
import { assertBytesEqual, blobBytes } from "./helpers.mjs";

const passphrase = "abandon ability able about above absent";

for (const size of [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1]) {
  test(`v3 round trip for ${size} bytes`, async () => {
    const plain = new Uint8Array(size);
    for (let index = 0; index < plain.length; index += 1) plain[index] = index % 251;
    const encrypted = await encryptBlobV3(new Blob([plain]), passphrase, {
      name: "sample.txt",
      type: "text/plain",
      levelKey: "standard",
    });
    const decrypted = await decryptBlobAny(encrypted.blob, passphrase);
    assert.equal(decrypted.formatVersion, 3);
    assert.equal(decrypted.authenticatedMetadata, true);
    assert.equal(decrypted.metadata.name, "sample.txt");
    assert.equal(decrypted.metadata.type, "text/plain");
    assert.equal(decrypted.legacyWarning, null);
    assertBytesEqual(assert, await blobBytes(decrypted.blob), plain);
  });
}

test("v3 normalizes passphrases with NFC", async () => {
  const composed = "caf\u00e9 passphrase with enough length";
  const decomposed = "cafe\u0301 passphrase with enough length";
  const encrypted = await encryptBlobV3(new Blob(["normalized"]), decomposed, {
    name: "unicode.txt",
    type: "text/plain",
    levelKey: "standard",
  });
  const decrypted = await decryptBlobAny(encrypted.blob, composed);
  assert.equal(await decrypted.blob.text(), "normalized");
});

test("wrong v3 passphrase fails authentication", async () => {
  const encrypted = await encryptBlobV3(new Blob(["secret"]), passphrase, {
    name: "secret.txt",
    type: "text/plain",
    levelKey: "standard",
  });
  await assert.rejects(
    decryptBlobAny(encrypted.blob, "wrong passphrase that is long enough"),
    (error) => error instanceof BlindCryptError && error.code === "AUTHENTICATION_FAILED",
  );
});

test("filename and MIME sanitization remove dangerous values", () => {
  assert.equal(sanitizeFilename("../CON\u202e.txt"), "_CON.txt");
  assert.equal(sanitizeFilename("  report / final?.pdf  "), "report _ final_.pdf");
  assert.equal(sanitizeMimeType("Text/Plain"), "text/plain");
  assert.equal(sanitizeMimeType("text/html; charset=utf-8"), "application/octet-stream");
});
