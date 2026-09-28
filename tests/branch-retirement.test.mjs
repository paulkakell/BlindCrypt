import test from "node:test";
import assert from "node:assert/strict";
import { parseHeads, retirementPlan, deletionArguments } from "../scripts/retire-branches.mjs";

const base = "8cea1fe449cff297338c8c2bd6a0e71e555382eb", old = "73759b4649a8dd26e255770f06b6eb8caa35f03b";
const head = "a".repeat(40), fix = "b".repeat(40);
function heads() { return new Map([["refs/heads/main", head], ["refs/heads/dev", base],
  ["refs/heads/release/02.00.00", old], ["refs/heads/fix/02.00.01", fix], ["refs/heads/unrelated", fix]]); }

test("retirement includes only the two integrated maintenance heads", () => {
  const visited = [], remote = heads();
  const plan = retirementPlan(head, [base, fix], remote, (a, b) => { visited.push([a, b]); return true; });
  assert.deepEqual(plan.map(item => item.branch), ["release/02.00.00", "fix/02.00.01"]);
  assert.deepEqual(visited, [[old, head], [fix, head]]);
  assert.equal(remote.size, 5);
  assert.deepEqual(deletionArguments(plan), ["push", "--atomic", `--force-with-lease=refs/heads/release/02.00.00:${old}`,
    `--force-with-lease=refs/heads/fix/02.00.01:${fix}`, "origin", ":refs/heads/release/02.00.00", ":refs/heads/fix/02.00.01"]);
});

test("retirement is idempotent when reviewed heads are already absent", () => {
  const remote = new Map([["refs/heads/main", head], ["refs/heads/dev", base]]);
  assert.deepEqual(retirementPlan(head, [base, fix], remote, () => true), []);
  assert.deepEqual(deletionArguments([]), []);
});

test("retirement refuses an advanced production branch", () => {
  const remote = heads(); remote.set("refs/heads/main", fix);
  assert.throws(() => retirementPlan(head, [base, fix], remote, () => true), /main advanced/u);
});

test("retirement refuses either candidate if its head changes", () => {
  for (const ref of ["refs/heads/release/02.00.00", "refs/heads/fix/02.00.01"]) {
    const remote = heads(); remote.set(ref, head);
    assert.throws(() => retirementPlan(head, [base, fix], remote, () => true), /advanced/u);
  }
});

test("retirement refuses unmerged commits and unexpected merge parents", () => {
  assert.throws(() => retirementPlan(head, [base, fix], heads(), () => false), /not integrated/u);
  for (const parents of [[base], [fix, base], [base, fix, old], [base, "bad"]]) {
    assert.throws(() => retirementPlan(head, parents, heads(), () => true), /maintenance merge/u);
  }
});

test("deletion arguments reject main, dev, tags, unrelated refs and duplicates", () => {
  for (const ref of ["refs/heads/main", "refs/heads/dev", "refs/tags/v02.00.00", "refs/heads/unrelated"]) {
    assert.throws(() => deletionArguments([{ ref, sha: fix }]), /Unsafe/u);
  }
  const item = { ref: "refs/heads/fix/02.00.01", sha: fix };
  assert.throws(() => deletionArguments([item, item]), /Unsafe/u);
  assert.throws(() => deletionArguments([{ ...item, sha: "invalid" }]), /Unsafe/u);
});

test("remote head parsing rejects malformed and duplicate records", () => {
  assert.equal(parseHeads(`${head}\trefs/heads/main\n`).get("refs/heads/main"), head);
  assert.equal(parseHeads("").size, 0);
  for (const text of ["bad refs/heads/main", `${head} refs/tags/test`, `${head} refs/heads/main extra`,
    `${head} refs/heads/main\n${head} refs/heads/main`]) {
    assert.throws(() => parseHeads(text), /Invalid/u);
  }
});
