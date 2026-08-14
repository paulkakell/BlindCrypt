// @ts-check

import {
  APP_VERSION,
  BlindCryptError,
  LEVELS,
  LIMITS,
  decryptBlobAny,
  encryptBlobV3,
  sanitizeFilename,
} from "./crypto.js";
import {
  assessPassphrase,
  buildWordSet,
  generatePassphrase,
  validateNewPassphrase,
} from "./passphrase.js";

/** @param {string} id */
function element(id) {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing required element: ${id}`);
  return found;
}

/** @param {string} id */
function input(id) {
  return /** @type {HTMLInputElement} */ (element(id));
}

/** @param {string} id */
function select(id) {
  return /** @type {HTMLSelectElement} */ (element(id));
}

/** @param {string} id */
function button(id) {
  return /** @type {HTMLButtonElement} */ (element(id));
}

/** @param {string} id */
function progress(id) {
  return /** @type {HTMLProgressElement} */ (element(id));
}

const bundledWords = /** @type {unknown} */ (Reflect.get(globalThis, "WORDS"));
if (!Array.isArray(bundledWords)) throw new Error("Bundled word list is unavailable");
const words = /** @type {string[]} */ (bundledWords);
const wordSet = buildWordSet(words);

/**
 * @param {HTMLElement} target
 * @param {string} message
 * @param {"info" | "good" | "bad" | "warn"} [kind]
 */
function setStatus(target, message, kind = "info") {
  target.textContent = message;
  target.dataset.kind = kind;
}

/**
 * @param {HTMLProgressElement} bar
 * @param {HTMLElement} text
 * @param {number} percent
 * @param {string} message
 */
function setProgress(bar, text, percent, message) {
  const bounded = Math.max(0, Math.min(100, Number(percent) || 0));
  bar.value = bounded;
  text.textContent = message || (bounded > 0 ? `${bounded.toFixed(1)}%` : "");
}

/** @param {Blob} blob @param {string} filename */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = sanitizeFilename(filename);
  anchor.rel = "noopener noreferrer";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

/** @param {unknown} error */
function encryptionErrorMessage(error) {
  if (error instanceof BlindCryptError) {
    if (["FILE_TOO_LARGE", "INVALID_INPUT", "INVALID_KDF", "INVALID_PASSPHRASE"].includes(error.code)) {
      return error.message;
    }
  }
  return "Encryption failed. No output was created.";
}

/** @param {unknown} error */
function decryptionErrorMessage(error) {
  if (error instanceof BlindCryptError && error.code === "FILE_TOO_LARGE") return error.message;
  return "Decryption failed. The passphrase is wrong, the file is invalid, or the file was modified.";
}

function updateLevelLabel() {
  const levelKey = select("encLevel").value;
  const level = LEVELS[/** @type {keyof typeof LEVELS} */ (levelKey)] || LEVELS.strong;
  element("encIterLabel").textContent = level.iterations.toLocaleString("en-US");
  element("encWordLabel").textContent = String(level.words);
}

function updatePassphraseAssessment() {
  const assessment = assessPassphrase(input("encPass").value, wordSet);
  const bar = progress("passStrengthBar");
  const text = element("passStrengthText");
  const hint = element("passStrengthHint");

  text.textContent = assessment.label;
  hint.textContent = assessment.text;
  if (assessment.kind === "word-list") {
    bar.hidden = false;
    bar.value = assessment.progress;
  } else {
    bar.hidden = true;
    bar.value = 0;
  }
}

/** @param {string} name */
function setTab(name) {
  for (const tab of document.querySelectorAll("[role='tab']")) {
    const active = tab instanceof HTMLElement && tab.dataset.tab === name;
    tab.setAttribute("aria-selected", active ? "true" : "false");
    tab.setAttribute("tabindex", active ? "0" : "-1");
    tab.classList.toggle("active", active);
  }
  for (const panel of document.querySelectorAll("[role='tabpanel']")) {
    if (panel instanceof HTMLElement) panel.hidden = panel.id !== `panel-${name}`;
  }
}

function bindTabs() {
  const tabs = [...document.querySelectorAll("[role='tab']")];
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => {
      if (tab instanceof HTMLElement && tab.dataset.tab) setTab(tab.dataset.tab);
    });
    tab.addEventListener("keydown", (event) => {
      if (!(event instanceof KeyboardEvent) || !["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      event.preventDefault();
      const delta = event.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(index + delta + tabs.length) % tabs.length];
      if (next instanceof HTMLElement && next.dataset.tab) {
        setTab(next.dataset.tab);
        next.focus();
      }
    });
  });
}

function bindPasswordVisibility() {
  button("encShow").addEventListener("click", () => {
    const field = input("encPass");
    field.type = field.type === "password" ? "text" : "password";
    button("encShow").textContent = field.type === "password" ? "Show" : "Hide";
  });
  button("decShow").addEventListener("click", () => {
    const field = input("decPass");
    field.type = field.type === "password" ? "text" : "password";
    button("decShow").textContent = field.type === "password" ? "Show" : "Hide";
  });
}

function bindPassphraseControls() {
  select("encLevel").addEventListener("change", updateLevelLabel);
  input("encPass").addEventListener("input", updatePassphraseAssessment);

  button("genPass").addEventListener("click", () => {
    const levelKey = /** @type {keyof typeof LEVELS} */ (select("encLevel").value);
    const level = LEVELS[levelKey] || LEVELS.strong;
    try {
      const generated = generatePassphrase(words, level.words);
      input("encPass").value = generated;
      input("encConfirm").value = "";
      updatePassphraseAssessment();
      setStatus(
        element("encStatus"),
        "Passphrase generated. Store it separately before encrypting; lost passphrases cannot be recovered.",
        "warn",
      );
    } catch {
      setStatus(element("encStatus"), "Secure passphrase generation is unavailable.", "bad");
    }
  });

  button("copyPass").addEventListener("click", async () => {
    const passphrase = input("encPass").value;
    if (!passphrase) {
      setStatus(element("encStatus"), "There is no passphrase to copy.", "bad");
      return;
    }
    try {
      await navigator.clipboard.writeText(passphrase);
      setStatus(
        element("encStatus"),
        "Passphrase copied. Clipboard contents may be visible to other applications; clear it after use.",
        "warn",
      );
    } catch {
      setStatus(element("encStatus"), "Clipboard access was blocked. Select and copy the passphrase manually.", "bad");
    }
  });
}

function bindEncryption() {
  button("doEncrypt").addEventListener("click", async () => {
    const action = button("doEncrypt");
    const status = element("encStatus");
    const progressBar = progress("encProgress");
    const progressText = element("encProgressText");
    setProgress(progressBar, progressText, 0, "");

    const file = input("encFile").files?.[0];
    if (!file) {
      setStatus(status, "Choose a file first.", "bad");
      return;
    }
    if (file.size > LIMITS.maxPlaintextSize) {
      setStatus(status, "The selected file exceeds the 64 MiB browser safety limit.", "bad");
      return;
    }

    let passphrase;
    try {
      passphrase = validateNewPassphrase(input("encPass").value, wordSet);
    } catch (error) {
      setStatus(status, error instanceof Error ? error.message : "Passphrase is invalid.", "bad");
      return;
    }
    const confirmation = input("encConfirm").value.normalize("NFC");
    if (passphrase !== confirmation) {
      setStatus(status, "Passphrase confirmation does not match.", "bad");
      return;
    }

    const levelKey = /** @type {keyof typeof LEVELS} */ (select("encLevel").value);
    try {
      action.disabled = true;
      setStatus(status, "Encrypting locally. The file and passphrase are not transmitted.", "info");
      const result = await encryptBlobV3(file, passphrase, {
        name: file.name,
        type: file.type,
        levelKey,
        onProgress: (percent, message) => setProgress(progressBar, progressText, percent, message),
      });
      downloadBlob(result.blob, `${result.metadata.name}.blindcrypt`);
      input("encConfirm").value = "";
      setProgress(progressBar, progressText, 100, "100.0%");
      setStatus(
        status,
        "Authenticated format v3 file created. Share the passphrase through a separate channel.",
        "good",
      );
    } catch (error) {
      setProgress(progressBar, progressText, 0, "");
      setStatus(status, encryptionErrorMessage(error), "bad");
    } finally {
      action.disabled = false;
    }
  });
}

function resetDecryptionMetadata() {
  element("metaFormat").textContent = "-";
  element("metaName").textContent = "-";
  element("metaType").textContent = "-";
  element("metaIntegrity").textContent = "-";
}

function bindDecryption() {
  button("doDecrypt").addEventListener("click", async () => {
    const action = button("doDecrypt");
    const status = element("decStatus");
    const progressBar = progress("decProgress");
    const progressText = element("decProgressText");
    resetDecryptionMetadata();
    setProgress(progressBar, progressText, 0, "");

    const file = input("decFile").files?.[0];
    if (!file) {
      setStatus(status, "Choose an encrypted file first.", "bad");
      return;
    }
    if (file.size > LIMITS.maxContainerSize) {
      setStatus(status, "The encrypted file exceeds the supported browser safety limit.", "bad");
      return;
    }
    const passphrase = input("decPass").value;
    if (!passphrase) {
      setStatus(status, "Enter the passphrase.", "bad");
      return;
    }

    try {
      action.disabled = true;
      setStatus(status, "Decrypting locally. No file data is transmitted.", "info");
      const result = await decryptBlobAny(
        file,
        passphrase,
        (percent, message) => setProgress(progressBar, progressText, percent, message),
      );
      element("metaFormat").textContent = `v${result.formatVersion}`;
      element("metaName").textContent = result.metadata.name;
      element("metaType").textContent = result.metadata.type;
      element("metaIntegrity").textContent = result.authenticatedMetadata
        ? "Header, metadata, and every record authenticated"
        : "Legacy limitations apply";

      const outputName = result.authenticatedMetadata ? result.metadata.name : "legacy-decrypted.bin";
      downloadBlob(result.blob, outputName);
      input("decPass").value = "";
      input("decPass").type = "password";
      button("decShow").textContent = "Show";
      setProgress(progressBar, progressText, 100, "100.0%");
      setStatus(
        status,
        result.legacyWarning || "Decryption complete. Authenticated output download started.",
        result.legacyWarning ? "warn" : "good",
      );
    } catch (error) {
      setProgress(progressBar, progressText, 0, "");
      setStatus(status, decryptionErrorMessage(error), "bad");
    } finally {
      action.disabled = false;
    }
  });
}

function initialize() {
  document.documentElement.dataset.version = APP_VERSION;
  for (const versionElement of document.querySelectorAll("[data-app-version]")) {
    versionElement.textContent = APP_VERSION;
  }
  element("maxFileSize").textContent = `${LIMITS.maxPlaintextSize / (1024 * 1024)} MiB`;
  bindTabs();
  bindPasswordVisibility();
  bindPassphraseControls();
  bindEncryption();
  bindDecryption();
  updateLevelLabel();
  updatePassphraseAssessment();
  resetDecryptionMetadata();
  setTab("encrypt");
}

initialize();
