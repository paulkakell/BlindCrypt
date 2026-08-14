import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const source = await readFile(resolve(root, "scripts/smoke.mjs"), "utf8");

test("smoke server avoids filesystem check-use races", () => {
  assert.doesNotMatch(source, /\bstat\s*\(/u);
  assert.doesNotMatch(source, /decodeURIComponent/u);
  assert.match(source, /const routes = new Map\(/u);
  assert.match(source, /routes\.get\(url\.pathname\)/u);
});

test("smoke server rejects paths outside its fixed route allowlist", () => {
  assert.match(source, /if \(!relativePath\)/u);
  assert.match(source, /\/\.\.%2Fpackage\.json/u);
  assert.match(source, /\/not-allowlisted\.txt/u);
  assert.match(source, /request\.method !== "GET"/u);
});
