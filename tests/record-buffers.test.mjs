import test from "node:test";
import assert from "node:assert/strict";
import { encryptV3ToSink, decryptV3ToSink } from "../assets/crypto.js";
const secret = "abandon ability able about above absent absorb abstract";
test("v3 record producers provide ordinary owned buffers to every consumer", async () => {
  const encrypted = [];
  const sink = (parts) => ({
    write(bytes) {
      assert.ok(bytes.buffer instanceof ArrayBuffer);
      assert.equal(bytes.byteOffset, 0);
      assert.equal(bytes.byteLength, bytes.buffer.byteLength);
      parts.push(new Uint8Array(bytes));
    },
    close() {}, abort() { assert.fail("Unexpected abort"); },
  });
  await encryptV3ToSink(new Blob(["buffer boundary"]), secret,
    { name: "example.txt", type: "text/plain", levelKey: "standard" }, sink(encrypted));
  const plaintext = [];
  await decryptV3ToSink(new Blob(encrypted), secret, sink(plaintext));
  assert.equal(await new Blob(plaintext).text(), "buffer boundary");
});
