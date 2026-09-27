import test from "node:test";
import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = fileURLToPath(new URL("..", import.meta.url));
async function checkPolicy(mutate) {
  const temporary = await mkdtemp(join(tmpdir(), "blindcrypt-policy-"));
  try {
    await mkdir(join(temporary, "scripts"));
    await cp(join(root, "assets"), join(temporary, "assets"), { recursive: true });
    await cp(join(root, "cli"), join(temporary, "cli"), { recursive: true });
    await cp(join(root, "sw.js"), join(temporary, "sw.js"));
    for (const file of ["package.json", "package-lock.json", "scripts/sast.mjs"]) {
      await cp(join(root, file), join(temporary, file));
    }
    if (mutate) {
      const path = join(temporary, "package-lock.json");
      const lock = JSON.parse(await readFile(path, "utf8"));
      mutate(lock);
      await writeFile(path, `${JSON.stringify(lock, null, 2)}\n`);
    }
    return spawnSync(process.execPath, [join(temporary, "scripts/sast.mjs")], {
      encoding: "utf8", timeout: 10_000,
    });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

test("dependency policy accepts the exact reviewed TypeScript 7 lock", async () => {
  const result = await checkPolicy();
  assert.equal(result.status, 0, result.stderr);
});

for (const [name, mutate] of [
  ["compiler version", (lock) => { lock.packages["node_modules/typescript"].version = "0.0.0"; }],
  ["native compiler integrity", (lock) => {
    lock.packages["node_modules/@typescript/typescript-linux-x64"].integrity = "sha512-unreviewed";
  }],
  ["extra package", (lock) => { lock.packages["node_modules/unreviewed"] = { version: "1.0.0" }; }],
]) {
  test(`dependency policy rejects changed ${name}`, async () => {
    const result = await checkPolicy(mutate);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Reviewed development lockfile changed/u);
  });
}
