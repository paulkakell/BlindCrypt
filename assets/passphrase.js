// @ts-check

import { MAX_PASSPHRASE_BYTES } from "./crypto.js";

export const MIN_GENERATED_WORDS = 6;
export const MAX_GENERATED_WORDS = 16;
export const MIN_CUSTOM_CODEPOINTS = 16;
export const MIN_CUSTOM_UNIQUE_CODEPOINTS = 6;

/** @param {unknown} words */
export function buildWordSet(words) {
  if (!Array.isArray(words) || words.length !== 2048) {
    throw new Error("The bundled passphrase word list must contain exactly 2048 words");
  }
  const normalized = words.map((word) => {
    if (typeof word !== "string" || !/^[a-z]+$/u.test(word)) {
      throw new Error("The bundled passphrase word list contains an invalid word");
    }
    return word;
  });
  const unique = new Set(normalized);
  if (unique.size !== 2048) {
    throw new Error("The bundled passphrase word list contains duplicates");
  }
  return unique;
}

/**
 * @param {string[]} words
 * @param {number} count
 */
export function generatePassphrase(words, count) {
  const wordSet = buildWordSet(words);
  if (
    wordSet.size !== 2048 ||
    !Number.isInteger(count) ||
    count < MIN_GENERATED_WORDS ||
    count > MAX_GENERATED_WORDS
  ) {
    throw new Error(`Generated passphrases must contain ${MIN_GENERATED_WORDS}-${MAX_GENERATED_WORDS} words`);
  }
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== "function") {
    throw new Error("Secure randomness is unavailable");
  }

  const random = new Uint32Array(count);
  globalThis.crypto.getRandomValues(random);
  const selected = [];
  for (let index = 0; index < count; index += 1) {
    // 2048 divides 2^32, so this mapping has no modulo bias.
    selected.push(words[random[index] & 2047]);
  }
  return selected.join(" ");
}

/** @param {string[]} codePoints */
function isRepeatedSequence(codePoints) {
  const length = codePoints.length;
  for (let period = 1; period <= Math.floor(length / 2); period += 1) {
    if (length % period !== 0) continue;
    let repeated = true;
    for (let index = period; index < length; index += 1) {
      if (codePoints[index] !== codePoints[index % period]) {
        repeated = false;
        break;
      }
    }
    if (repeated) return true;
  }
  return false;
}

/**
 * @typedef {object} PassphraseAssessment
 * @property {"empty" | "word-list" | "custom"} kind
 * @property {boolean} accepted
 * @property {number | null} bits
 * @property {number} progress
 * @property {string} label
 * @property {string} text
 * @property {string} normalized
 */

/**
 * @param {string} passphrase
 * @param {Set<string>} wordSet
 * @returns {PassphraseAssessment}
 */
export function assessPassphrase(passphrase, wordSet) {
  const normalized = String(passphrase || "").normalize("NFC");
  if (!normalized) {
    return {
      kind: "empty",
      accepted: false,
      bits: null,
      progress: 0,
      label: "Empty",
      text: "Enter a passphrase or generate one.",
      normalized,
    };
  }

  const trimmed = normalized.trim();
  const parts = trimmed.split(/\s+/u).filter(Boolean);
  const isWordListPhrase =
    trimmed === normalized &&
    parts.length >= 2 &&
    parts.every((word) => wordSet.has(word.toLowerCase()));

  if (isWordListPhrase) {
    const bits = 11 * parts.length;
    const accepted = parts.length >= MIN_GENERATED_WORDS;
    let label = "Below minimum";
    if (parts.length >= 16) label = "Critical";
    else if (parts.length >= 10) label = "High";
    else if (parts.length >= 8) label = "Strong";
    else if (parts.length >= 6) label = "Standard";

    return {
      kind: "word-list",
      accepted,
      bits,
      progress: Math.min(100, (parts.length / MAX_GENERATED_WORDS) * 100),
      label,
      text: accepted
        ? `${label}: ${parts.length} independently selected words, approximately ${bits} bits.`
        : `${parts.length} word-list words. At least ${MIN_GENERATED_WORDS} are required.`,
      normalized,
    };
  }

  const codePointValues = [...normalized];
  const codePoints = codePointValues.length;
  const noOuterWhitespace = normalized === normalized.trim();
  const sufficientlyVaried = new Set(codePointValues).size >= MIN_CUSTOM_UNIQUE_CODEPOINTS;
  const repeatedSequence = isRepeatedSequence(codePointValues);
  const accepted =
    codePoints >= MIN_CUSTOM_CODEPOINTS &&
    noOuterWhitespace &&
    sufficientlyVaried &&
    !repeatedSequence;

  let text;
  if (!noOuterWhitespace) {
    text = "Leading or trailing whitespace is not allowed in new passphrases.";
  } else if (codePoints < MIN_CUSTOM_CODEPOINTS) {
    text = `Custom passphrases require at least ${MIN_CUSTOM_CODEPOINTS} characters. Generated word phrases are preferred.`;
  } else if (!sufficientlyVaried || repeatedSequence) {
    text = "Custom passphrase is too repetitive. Use a generated word phrase or a less predictable custom value.";
  } else {
    text = `Custom passphrase accepted at ${codePoints} characters. Strength is not estimated; generated word phrases are preferred.`;
  }

  return {
    kind: "custom",
    accepted,
    bits: null,
    progress: 0,
    label: "Custom",
    text,
    normalized,
  };
}

/**
 * @param {string} passphrase
 * @param {Set<string>} wordSet
 */
export function validateNewPassphrase(passphrase, wordSet) {
  const assessment = assessPassphrase(passphrase, wordSet);
  if (!assessment.accepted) {
    throw new Error(assessment.text);
  }
  const encodedLength = new TextEncoder().encode(assessment.normalized).length;
  if (encodedLength > MAX_PASSPHRASE_BYTES) {
    throw new Error("Passphrase is too long");
  }
  return assessment.normalized;
}
