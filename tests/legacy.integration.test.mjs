import test from "node:test";
import assert from "node:assert/strict";
import { BlindCryptError, decryptBlobAny } from "../assets/crypto.js";
import {
  assertBytesEqual,
  blobBytes,
  createLegacyV1,
  createLegacyV2,
} from "./helpers.mjs";

const passphrase = "legacy exact passphrase";

for (const version of [1, 2]) {
  test(`legacy v${version} remains readable with neutral output handling`, async () => {
    const plain = new TextEncoder().encode(`legacy format ${version}`);
    const container = version === 1
      ? await createLegacyV1(plain, passphrase, { name: "../../report.html", type: "text/html" })
      : await createLegacyV2(plain, passphrase, { name: "../../report.html", type: "text/html" });
    const result = await decryptBlobAny(container, passphrase);
    assert.equal(result.formatVersion, version);
    assert.equal(result.authenticatedMetadata, false);
    assert.match(result.legacyWarning, /Legacy/u);
    assert.equal(result.blob.type, "application/octet-stream");
    assert.equal(result.metadata.name, "_report.html");
    assertBytesEqual(assert, await blobBytes(result.blob), plain);
  });
}

test("legacy v2 rejects trailing data", async () => {
  const plain = new TextEncoder().encode("legacy trailing test");
  const container = await createLegacyV2(plain, passphrase);
  await assert.rejects(
    decryptBlobAny(new Blob([container, Uint8Array.of(9)]), passphrase),
    (error) => error instanceof BlindCryptError && error.code === "INVALID_FORMAT",
  );
});

test("legacy decryption keeps exact passphrase semantics", async () => {
  const decomposed = "cafe\u0301 legacy phrase";
  const composed = "caf\u00e9 legacy phrase";
  const plain = new TextEncoder().encode("legacy normalization");
  const container = await createLegacyV1(plain, decomposed);
  await assert.rejects(
    decryptBlobAny(container, composed),
    (error) => error instanceof BlindCryptError && error.code === "AUTHENTICATION_FAILED",
  );
  assert.equal(await (await decryptBlobAny(container, decomposed)).blob.text(), "legacy normalization");
});
