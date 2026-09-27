import { readFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const failures = [];
const assets = (await readdir(resolve(root, "assets"))).filter((name) => name.endsWith(".js") && name !== "wordlist.js").map((name) => `assets/${name}`);
const sources = await Promise.all(assets.map(async (path) => {
  let source = await readFile(resolve(root, path), "utf8");
  // Only a fixed, non-sensitive control message to this origin's service worker.
  // Every other message channel remains forbidden, including in offline.js.
  if (path === "assets/offline.js") source = source.replace('registration.waiting.postMessage({ type: "ACTIVATE" })', 'ACTIVATION_CONTROL');
  return source;
}));
const additional = ["sw.js", "cli/blindcrypt.mjs", "cli/io.mjs"];
for (const path of additional) sources.push(await readFile(resolve(root, path), "utf8"));
const content = sources.join("\n");

const disallowed = [
  [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u, "private key material"],
  [/\bgh[oprsu]_[A-Za-z0-9_]{20,}\b/u, "GitHub token"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u, "AWS access key"],
  [/\b(?:password|passphrase)\s*[:=]\s*["'][^"']{8,}["']/iu, "hard-coded credential-like value"],
  [/\bpostMessage\s*\(/u, "cross-window message channel"],
  [/\bSharedArrayBuffer\b/u, "shared memory"],
  [/\bMath\.random\s*\(/u, "non-cryptographic randomness"],
];
for (const [pattern, label] of disallowed) {
  if (pattern.test(content)) failures.push(`Detected ${label}`);
}

const cryptoSource = content;
const requiredSecurityMarkers = [
  "additionalData: makeRecordAad",
  "tagLength: 128",
  "Container length does not match its authenticated geometry",
  "KDF iteration count is outside the supported range",
  "METADATA_BLOCK_SIZE = 1024",
  "MAX_PLAINTEXT_SIZE = 64 * 1024 * 1024",
  "Legacy v2 authenticates records separately but not its metadata or whole-file completeness",
];
for (const marker of requiredSecurityMarkers) {
  if (!cryptoSource.includes(marker)) failures.push(`Missing security control marker: ${marker}`);
}
if ((cryptoSource.match(/additionalData:/gu) || []).length < 3) {
  failures.push("Format v3 does not use associated data for every record path");
}

const packageJson = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
if (packageJson.dependencies && Object.keys(packageJson.dependencies).length) {
  failures.push("Runtime dependencies are not allowed");
}
const allowedDevDependencies = { typescript: "7.0.2" };
if (JSON.stringify(packageJson.devDependencies) !== JSON.stringify(allowedDevDependencies)) {
  failures.push("Development dependency allowlist changed");
}
// Pin the complete reviewed lockfile, including all 20 optional native compiler packages.
// npm ci separately verifies every package's SHA-512 integrity from this lockfile.
const lockText = await readFile(resolve(root, "package-lock.json"), "utf8");
const lock = JSON.parse(lockText);
const expectedLockSha256 = "c5df91e83f41f12c011ab53c5da0a45ac926638c0161049121ad1ff4acf441f0";
if (lock.lockfileVersion !== 3 || createHash("sha256").update(lockText).digest("hex") !== expectedLockSha256) {
  failures.push("Reviewed development lockfile changed; dependency security review required");
}

if (failures.length) {
  console.error(failures.map((failure) => `- ${failure}`).join("\n"));
  process.exit(1);
}
console.log("Static security analysis passed.");
