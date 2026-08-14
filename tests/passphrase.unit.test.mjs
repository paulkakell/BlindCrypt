import test from "node:test";
import assert from "node:assert/strict";
import {
  assessPassphrase,
  buildWordSet,
  generatePassphrase,
  validateNewPassphrase,
} from "../assets/passphrase.js";
import { makeWordList } from "./helpers.mjs";

const words = makeWordList();
const wordSet = buildWordSet(words);

test("generated passphrases contain the requested secure word count", () => {
  const generated = generatePassphrase(words, 6);
  const parts = generated.split(" ");
  assert.equal(parts.length, 6);
  assert.ok(parts.every((word) => wordSet.has(word)));
  const assessment = assessPassphrase(generated, wordSet);
  assert.equal(assessment.accepted, true);
  assert.equal(assessment.bits, 66);
  assert.equal(assessment.label, "Standard");
});

test("four-word phrases are rejected", () => {
  const phrase = words.slice(0, 4).join(" ");
  assert.equal(assessPassphrase(phrase, wordSet).accepted, false);
  assert.throws(() => validateNewPassphrase(phrase, wordSet), /At least 6/u);
  assert.throws(() => generatePassphrase(words, 4), /6-16/u);
});

test("custom passphrases are not assigned estimated entropy", () => {
  const assessment = assessPassphrase("Correct horse? Battery 47!", wordSet);
  assert.equal(assessment.kind, "custom");
  assert.equal(assessment.accepted, true);
  assert.equal(assessment.bits, null);
  assert.equal(assessment.label, "Custom");
  assert.match(assessment.text, /Strength is not estimated/u);
});

test("repetitive custom passphrases are rejected", () => {
  for (const repeated of ["1".repeat(32), "password".repeat(4), "ab".repeat(16)]) {
    const assessment = assessPassphrase(repeated, wordSet);
    assert.equal(assessment.kind, "custom");
    assert.equal(assessment.accepted, false);
    assert.equal(assessment.bits, null);
    assert.match(assessment.text, /too repetitive/u);
    assert.throws(() => validateNewPassphrase(repeated, wordSet), /too repetitive/u);
  }
});

test("custom passphrases reject outer whitespace and short values", () => {
  assert.equal(assessPassphrase(" short passphrase ", wordSet).accepted, false);
  assert.equal(assessPassphrase("short", wordSet).accepted, false);
});

test("word list validation rejects duplicates", () => {
  const duplicate = [...words];
  duplicate[2047] = duplicate[0];
  assert.throws(() => buildWordSet(duplicate), /duplicates/u);
});
