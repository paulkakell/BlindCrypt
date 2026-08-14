import { performance } from "node:perf_hooks";
import { decryptBlobAny, encryptBlobV3 } from "../assets/crypto.js";

const size = 1024 * 1024;
const plain = new Uint8Array(size);
for (let index = 0; index < plain.length; index += 1) plain[index] = (index * 31) % 251;
const passphrase = "abandon ability able about above absent";

const encryptStart = performance.now();
const encrypted = await encryptBlobV3(new Blob([plain]), passphrase, {
  name: "performance.bin",
  type: "application/octet-stream",
  levelKey: "standard",
});
const encryptMs = performance.now() - encryptStart;

const decryptStart = performance.now();
const decrypted = await decryptBlobAny(encrypted.blob, passphrase);
const decryptMs = performance.now() - decryptStart;
const result = new Uint8Array(await decrypted.blob.arrayBuffer());

if (result.length !== plain.length || result.some((value, index) => value !== plain[index])) {
  throw new Error("Performance smoke test round trip failed");
}
if (encryptMs > 30_000 || decryptMs > 30_000) {
  throw new Error(`Performance smoke test exceeded 30 seconds: encrypt=${encryptMs.toFixed(1)}ms decrypt=${decryptMs.toFixed(1)}ms`);
}
console.log(JSON.stringify({
  bytes: size,
  encryptedBytes: encrypted.blob.size,
  encryptMs: Number(encryptMs.toFixed(1)),
  decryptMs: Number(decryptMs.toFixed(1)),
}));
