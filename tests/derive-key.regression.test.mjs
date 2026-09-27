import test from "node:test";
import assert from "node:assert/strict";
import { deriveKey } from "../assets/crypto-core.js";

const phrase = "test-only derivation fixture";
const saltBytes = Uint8Array.from({ length: 16 }, (_, index) => index + 1);

async function fingerprint(key) {
  assert.equal(key.extractable, false);
  assert.deepEqual(key.usages, ["encrypt", "decrypt"]);
  // This fixed nonce is used only with deterministic test keys and test plaintext.
  return new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(12) },
    key,
    new TextEncoder().encode("test fixture"),
  ));
}

async function expectedFingerprint() {
  return fingerprint(await deriveKey(phrase, saltBytes.slice(), 10_000, true));
}

test("deriveKey preserves the exact bytes of an offset salt view", async () => {
  const backing = new Uint8Array(32).fill(255);
  backing.set(saltBytes, 8);
  const before = backing.slice();
  const actual = await deriveKey(phrase, backing.subarray(8, 24), 10_000, true);
  assert.deepEqual(await fingerprint(actual), await expectedFingerprint());
  assert.deepEqual(backing, before);
});

test("deriveKey snapshots the salt before yielding to WebCrypto", async () => {
  const salt = saltBytes.slice();
  const pending = deriveKey(phrase, salt, 10_000, true);
  salt.fill(0);
  assert.deepEqual(await fingerprint(await pending), await expectedFingerprint());
});

test("deriveKey supplies an ordinary buffer for shared-memory salt views", async () => {
  const salt = new Uint8Array(new SharedArrayBuffer(32), 8, 16);
  salt.set(saltBytes);
  const actual = await deriveKey(phrase, salt, 10_000, true);
  assert.deepEqual(await fingerprint(actual), await expectedFingerprint());
  assert.deepEqual(salt, saltBytes);
});
