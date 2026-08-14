import { readdir, readFile, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve, relative } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const failures = [];

async function walk(directory) {
  const entries = await readdir(directory);
  const files = [];
  for (const entry of entries) {
    if (["node_modules", "dist", ".git"].includes(entry)) continue;
    const path = resolve(directory, entry);
    const info = await stat(path);
    if (info.isDirectory()) files.push(...await walk(path));
    else files.push(path);
  }
  return files;
}

function fail(message) {
  failures.push(message);
}

const files = await walk(root);
const scripts = files.filter((file) => /\.(?:js|mjs)$/u.test(file));
for (const file of scripts) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (result.status !== 0) fail(`${relative(root, file)}: ${result.stderr.trim()}`);
}

const productionScripts = scripts.filter((file) => relative(root, file).startsWith("assets/"));
const forbiddenPatterns = [
  [/(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b/u, "unsafe DOM HTML sink"],
  [/\beval\s*\(|\bnew\s+Function\b/u, "dynamic code execution"],
  [/\b(?:localStorage|sessionStorage)\b/u, "persistent browser storage"],
  [/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b/u, "network API"],
  [/\bconsole\./u, "console logging"],
];
for (const file of productionScripts) {
  const content = await readFile(file, "utf8");
  for (const [pattern, label] of forbiddenPatterns) {
    if (pattern.test(content)) fail(`${relative(root, file)} contains ${label}`);
  }
}

const html = await readFile(resolve(root, "index.html"), "utf8");
if (/\sstyle\s*=/iu.test(html)) fail("index.html contains an inline style attribute");
if (/\son[a-z]+\s*=/iu.test(html)) fail("index.html contains an inline event handler");
if (/unsafe-inline|unsafe-eval/iu.test(html)) fail("index.html weakens CSP with an unsafe source");
const requiredCsp = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
];
for (const directive of requiredCsp) {
  if (!html.includes(directive)) fail(`index.html CSP is missing: ${directive}`);
}
if (!/<meta\s+name="referrer"\s+content="no-referrer">/iu.test(html)) {
  fail("index.html is missing the no-referrer policy");
}
for (const match of html.matchAll(/<(?:script|link)\b[^>]*(?:src|href)="([^"]+)"/giu)) {
  if (/^(?:https?:)?\/\//iu.test(match[1])) fail(`remote executable resource: ${match[1]}`);
}

const version = (await readFile(resolve(root, "VERSION"), "utf8")).trim();
if (!/^\d{2}\.\d{2}\.\d{2}$/u.test(version)) fail("VERSION does not use xx.xx.xx");
const cryptoSource = await readFile(resolve(root, "assets/crypto-core.js"), "utf8");
if (!cryptoSource.includes(`APP_VERSION = "${version}"`)) fail("VERSION and APP_VERSION differ");
if (!html.includes(`data-app-version>${version}<`)) fail("index.html fallback version differs");

const placeholderPath = resolve(root, "assets/wordlist_2048.js");
if (files.includes(placeholderPath)) fail("unused placeholder assets/wordlist_2048.js is present");
const wordlistSource = await readFile(resolve(root, "assets/wordlist.js"), "utf8");
const wordMatch = wordlistSource.match(/const\s+WORDS_TEXT\s*=\s*`([\s\S]*?)`;/u);
if (!wordMatch) {
  fail("assets/wordlist.js does not expose WORDS_TEXT");
} else {
  const words = wordMatch[1].trim().split(/\s+/u);
  if (words.length !== 2048) fail(`word list contains ${words.length} words instead of 2048`);
  if (new Set(words).size !== words.length) fail("word list contains duplicate words");
  if (!words.every((word) => /^[a-z]+$/u.test(word))) fail("word list contains a non-lowercase word");
}

if (failures.length) {
  console.error(failures.map((failure) => `- ${failure}`).join("\n"));
  process.exit(1);
}
console.log(`Lint passed for ${scripts.length} JavaScript files.`);
