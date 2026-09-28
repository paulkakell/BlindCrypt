// Version-scoped retirement of reviewed, merged heads. Never updates main or dev.
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const BASELINE = "8cea1fe449cff297338c8c2bd6a0e71e555382eb";
const OLD_RELEASE = "73759b4649a8dd26e255770f06b6eb8caa35f03b";
const SHA = /^[a-f0-9]{40}$/u;

export function parseHeads(text) {
  const heads = new Map();
  for (const line of text.trim().split("\n")) {
    if (!line) continue;
    const fields = line.trim().split(/\s+/u);
    const [sha, ref] = fields;
    if (fields.length !== 2 || !SHA.test(sha) || !ref.startsWith("refs/heads/") || heads.has(ref)) {
      throw new Error("Invalid remote branch listing");
    }
    heads.set(ref, sha);
  }
  return heads;
}

export function retirementPlan(mainSha, parents, heads, isAncestor) {
  if (!SHA.test(mainSha) || parents.length !== 2 || !parents.every(sha => SHA.test(sha)) || parents[0] !== BASELINE) {
    throw new Error("Expected the reviewed 02.00.01 two-parent maintenance merge");
  }
  if (heads.get("refs/heads/main") !== mainSha) throw new Error("main advanced; no branches deleted");
  const candidates = [["release/02.00.00", OLD_RELEASE], ["fix/02.00.01", parents[1]]];
  const plan = [];
  for (const [branch, expected] of candidates) {
    const ref = `refs/heads/${branch}`;
    if (!heads.has(ref)) continue;
    if (heads.get(ref) !== expected) throw new Error(`${branch} advanced; preserve it for review`);
    if (!isAncestor(expected, mainSha)) throw new Error(`${branch} is not integrated; preserve it`);
    plan.push({ branch, ref, sha: expected });
  }
  return plan;
}

export function deletionArguments(plan) {
  const allowed = new Set(["refs/heads/release/02.00.00", "refs/heads/fix/02.00.01"]);
  if (plan.some(item => !allowed.has(item.ref) || !SHA.test(item.sha)) ||
      new Set(plan.map(item => item.ref)).size !== plan.length) throw new Error("Unsafe retirement target");
  if (!plan.length) return [];
  return ["push", "--atomic", ...plan.map(item => `--force-with-lease=${item.ref}:${item.sha}`),
    "origin", ...plan.map(item => `:${item.ref}`)];
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--apply") throw new Error("Use --apply in the scoped maintenance workflow");
  if (process.env.GITHUB_REPOSITORY !== "paulkakell/BlindCrypt" || process.env.GITHUB_REF !== "refs/heads/main" ||
      process.env.GITHUB_EVENT_NAME !== "push" || (await readFile("VERSION", "utf8")).trim() !== "02.00.01") {
    throw new Error("Retirement is restricted to this repository's 02.00.01 main push");
  }
  const sha = process.env.GITHUB_SHA;
  const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
  if (!SHA.test(sha || "") || git("rev-parse", "HEAD") !== sha) throw new Error("Unexpected checkout");
  const evidence = JSON.parse(await readFile("maintenance-evidence.json", "utf8"));
  if (evidence.sha !== sha || evidence.sarifResults !== 0 || evidence.gatesPassed !== true ||
      !/^[0-9]+$/u.test(process.env.BACKUP_ARTIFACT_ID || "")) throw new Error("Validated backup evidence is required");
  const parents = git("show", "-s", "--format=%P", sha).split(" ");
  const heads = parseHeads(git("ls-remote", "--heads", "origin"));
  const plan = retirementPlan(sha, parents, heads, (ancestor, head) => {
    try { git("merge-base", "--is-ancestor", ancestor, head); return true; } catch { return false; }
  });
  const args = deletionArguments(plan);
  if (args.length) {
    if (!process.env.GH_TOKEN) throw new Error("Missing workflow credential");
    // The token stays in the child's environment, not command arguments or logs.
    const env = { ...process.env, GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
      GIT_CONFIG_VALUE_0: "AUTHORIZATION: basic " + Buffer.from(`x-access-token:${process.env.GH_TOKEN}`).toString("base64") };
    execFileSync("git", args, { env, stdio: ["ignore", "pipe", "pipe"] });
  }
  console.log(JSON.stringify({ event: "merged_branches_retired", sha, backupArtifactId: process.env.BACKUP_ARTIFACT_ID, branches: plan }));
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch(() => { console.error("Branch retirement refused or failed; inspect the preserved evidence. No unsafe fallback was attempted."); process.exitCode = 1; });
}
