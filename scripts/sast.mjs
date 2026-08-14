import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const failures = [];
const assets = [
  "assets/crypto-core.js",
  "assets/crypto-v3.js",
  "assets/crypto-legacy.js",
  "assets/crypto.js",
  "assets/passphrase.js",
  "assets/app.js",
];
const content = (await Promise.all(assets.map((path) => readFile(resolve(root, path), "utf8")))).join("\n");

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
const allowedDevDependencies = { typescript: "5.8.3" };
if (JSON.stringify(packageJson.devDependencies) !== JSON.stringify(allowedDevDependencies)) {
  failures.push("Development dependency allowlist changed");
}
const lock = JSON.parse(await readFile(resolve(root, "package-lock.json"), "utf8"));
if (lock.lockfileVersion !== 3 || lock.packages?.["node_modules/typescript"]?.integrity !== "sha512-p1diW6TqL9L07nNxvRMM7hMMw4c5XOo/1ibL4aAIGmSAt9slTE1Xgw5KWuof2uTOvCg9BY7ZRi+GaF+7sfgPeQ==") {
  failures.push("TypeScript lock integrity changed");
}
const lockedPackages = Object.keys(lock.packages).filter(Boolean);
if (lockedPackages.length !== 1 || lockedPackages[0] !== "node_modules/typescript") {
  failures.push("Unexpected package appears in package-lock.json");
}

if (failures.length) {
  console.error(failures.map((failure) => `- ${failure}`).join("\n"));
  process.exit(1);
}
console.log("Static security analysis passed.");
