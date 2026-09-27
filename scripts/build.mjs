import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const root = fileURLToPath(new URL("..", import.meta.url));
const dist = resolve(root, "dist");
const version = (await readFile(resolve(root, "VERSION"), "utf8")).trim();
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const assets = (await readdir(resolve(root, "assets"))).filter((name) => /\.(?:js|css)$/u.test(name)).sort().map((name) => `assets/${name}`);
const files = ["index.html", "manifest.webmanifest", "VERSION", "LICENSE", "SBOM.spdx.json", ...assets,
  "cli/blindcrypt.mjs", "cli/io.mjs"];
await rm(dist, { recursive: true, force: true });
for (const file of files) {
  const destination = resolve(dist, file);
  await mkdir(dirname(destination), { recursive: true });
  await cp(resolve(root, file), destination);
}
// A minimal package marker lets Node load the shared production modules as ESM.
await writeFile(resolve(dist, "package.json"), `${JSON.stringify({ name: "blindcrypt-release", private: true, type: "module", version: version.split(".").map(Number).join("."), engines: { node: ">=22" } }, null, 2)}\n`);
files.push("package.json");

// Deterministic, dependency-free PNG icons. No font files or external artwork.
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const name = Buffer.from(type);
  const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, crc]);
}
function icon(size) {
  const rows = ["11110  01111", "10001  10000", "10001  10000", "11110  10000", "10001  10000", "10001  10000", "11110  01111"];
  const pixels = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y += 1) for (let x = 0; x < size; x += 1) {
    const gx = Math.floor((x / size - 0.12) / 0.065);
    const gy = Math.floor((y / size - 0.27) / 0.065);
    const white = rows[gy]?.[gx] === "1";
    const i = y * (size * 4 + 1) + 1 + x * 4;
    pixels.set(white ? [240, 245, 250, 255] : [20, 33, 51, 255], i);
  }
  const header = Buffer.alloc(13); header.writeUInt32BE(size); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6;
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), pngChunk("IHDR", header), pngChunk("IDAT", deflateSync(pixels, { level: 9 })), pngChunk("IEND", Buffer.alloc(0))]);
}
for (const size of [192, 512]) {
  const file = `assets/icon-${size}.png`;
  await writeFile(resolve(dist, file), icon(size)); files.push(file);
}

// Only public browser application assets enter the worker manifest. No CLI,
// documents, user files, secrets, query-string URLs, or arbitrary runtime URLs.
const cached = ["index.html", "manifest.webmanifest", "VERSION", ...assets, "assets/icon-192.png", "assets/icon-512.png"].sort();
const assetManifest = Object.fromEntries(await Promise.all(cached.map(async (file) => [file, digest(await readFile(resolve(dist, file)))])));
const buildId = digest(JSON.stringify(assetManifest));
let worker = await readFile(resolve(root, "sw.js"), "utf8");
if (!worker.includes(`const VERSION = "${version}";`)) throw new Error("Worker version mismatch");
worker = worker.replace('/* BUILD_ID */ "unbuilt"', JSON.stringify(buildId)).replace("/* ASSET_MANIFEST */ {}", JSON.stringify(assetManifest, null, 2));
await writeFile(resolve(dist, "sw.js"), worker);
files.push("sw.js");
await writeFile(resolve(dist, ".nojekyll"), ""); files.push(".nojekyll");
const checksums = [];
for (const file of [...files].sort()) checksums.push(`${digest(await readFile(resolve(dist, file)))}  ${file}`);
await writeFile(resolve(dist, "SHA256SUMS"), `${checksums.join("\n")}\n`);
console.log(`Built BlindCrypt ${version}: ${files.length + 1} files; offline build ${buildId}.`);
