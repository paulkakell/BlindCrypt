import { createHash } from "node:crypto";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const dist = resolve(root, "dist");
const files = [
  "index.html",
  "VERSION",
  "LICENSE",
  "SBOM.spdx.json",
  "assets/app.css",
  "assets/app.js",
  "assets/crypto-core.js",
  "assets/crypto-v3.js",
  "assets/crypto-legacy.js",
  "assets/crypto.js",
  "assets/passphrase.js",
  "assets/wordlist.js",
];

await rm(dist, { recursive: true, force: true });
for (const file of files) {
  const source = resolve(root, file);
  const destination = resolve(dist, file);
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination);
}
await writeFile(resolve(dist, ".nojekyll"), "", "utf8");

const manifest = [];
for (const file of [...files, ".nojekyll"].sort()) {
  const bytes = await readFile(resolve(dist, file));
  const digest = createHash("sha256").update(bytes).digest("hex");
  manifest.push(`${digest}  ${file}`);
}
await writeFile(resolve(dist, "SHA256SUMS"), `${manifest.join("\n")}\n`, "utf8");
console.log(`Built ${files.length + 2} release files in dist/.`);
