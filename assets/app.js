// @ts-check
import {
  APP_VERSION, BlindCryptError, LEVELS, LIMITS, MAX_CONTAINER_SIZE, MAX_STREAM_CONTAINER_SIZE,
  MAX_STREAM_PLAINTEXT_SIZE, encryptBlobV3, decryptBlobAny, verifyV3, encryptV3ToSink,
  decryptV3ToSink, sanitizeFilename,
} from "./crypto.js";
import { assessPassphrase, buildWordSet, generatePassphrase } from "./passphrase.js";
import { encryptedFilename, processQueue, encryptText, decryptText, reencrypt, validateSecret } from "./features.js";
import { generateIdentity, importRecipient, unlockIdentity, encryptForRecipient, decryptForRecipient,
  MAX_RECIPIENT_BYTES, MAX_RECIPIENT_ENVELOPE, MAX_IDENTITY_BYTES } from "./recipients.js";
import { initializeOffline } from "./offline.js";

/** @param {string} id */
function element(id) {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing required element: ${id}`);
  return found;
}
/** @param {string} id */
function input(id) { return /** @type {HTMLInputElement} */ (element(id)); }
/** @param {string} id */
function text(id) { return /** @type {HTMLTextAreaElement} */ (element(id)); }
/** @param {string} id */
function button(id) { return /** @type {HTMLButtonElement} */ (element(id)); }
/** @param {string} id */
function level(id) { return /** @type {keyof typeof LEVELS} */ (/** @type {HTMLSelectElement} */ (element(id)).value); }
const words = /** @type {string[]} */ (Reflect.get(globalThis, "WORDS"));
const wordSet = buildWordSet(words);
let busy = false;
/** @type {AbortController | null} */
let controller = null;
/** @type {Map<string, File[]>} */
const dropped = new Map();

/** @param {string} id @param {string} message @param {string} [kind] */
function status(id, message, kind = "info") {
  element(id).textContent = message;
  element(id).dataset.kind = kind;
}
/** @param {string} id @param {number} percent */
function progress(id, percent) {
  /** @type {HTMLProgressElement} */ (element(id)).value = Math.max(0, Math.min(100, percent));
}
/** @param {string} id @param {number} max */
function selected(id, max) {
  const file = input(id).files?.[0];
  if (!file) throw new BlindCryptError("INVALID_INPUT", "Choose the required file first");
  if (file.size > max) throw new BlindCryptError("FILE_TOO_LARGE", "File exceeds this workflow's safety limit");
  return file;
}
/** @param {string} field @param {string} confirmation */
function confirmed(field, confirmation) {
  const value = validateSecret(input(field).value);
  if (value !== input(confirmation).value.normalize("NFC")) throw new BlindCryptError("INVALID_INPUT", "Passphrase confirmation does not match");
  return value;
}
/** Downloads stay local. Release each URL before processing the next queue item.
 * @param {Blob} blob @param {string} filename
 */
async function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = sanitizeFilename(filename);
  anchor.rel = "noopener noreferrer";
  document.body.appendChild(anchor);
  try {
    anchor.click();
    await new Promise((resolve) => setTimeout(resolve, 1000));
  } finally { anchor.remove(); URL.revokeObjectURL(url); }
}

/** @param {string} target @param {(signal: AbortSignal) => Promise<string>} operation */
async function run(target, operation) {
  if (busy) return;
  busy = true;
  controller = new AbortController();
  const controls = [...document.querySelectorAll("button,input,select,textarea")].filter(
    (item) => item instanceof HTMLButtonElement || item instanceof HTMLInputElement || item instanceof HTMLSelectElement || item instanceof HTMLTextAreaElement);
  const states = controls.map((item) => item.disabled);
  controls.forEach((item) => { item.disabled = true; });
  button("cancelOperation").disabled = false;
  status(target, "Processing locally. No file data is transmitted.");
  try {
    const message = await operation(controller.signal);
    status(target, message, controller.signal.aborted ? "warn" : "good");
  } catch (error) {
    const known = error instanceof BlindCryptError;
    const display = known && ["INVALID_INPUT", "INVALID_PASSPHRASE", "FILE_TOO_LARGE", "CANCELLED", "UNSUPPORTED_BROWSER"].includes(error.code);
    const cancelled = controller.signal.aborted || (error instanceof DOMException && error.name === "AbortError");
    status(target, cancelled ? "Cancelled. No completed output is claimed." : display ? error.message :
      "Operation failed. Check the secret, file format, recipient, and file integrity.", cancelled ? "warn" : "bad");
  } finally {
    for (const field of document.querySelectorAll("input[type=password]")) {
      if (field instanceof HTMLInputElement) field.value = "";
    }
    for (const id of ["encPass", "decPass", "textPass", "upgradeOld", "upgradeNew", "largePass", "identityPass", "identityUnlock"]) {
      input(id).value = ""; input(id).type = "password";
    }
    button("encShow").textContent = "Show";
    button("decShow").textContent = "Show";
    controls.forEach((item, index) => { item.disabled = states[index]; });
    button("cancelOperation").disabled = true;
    controller = null;
    busy = false;
    updateAssessment();
  }
}

function updateAssessment() {
  const assessment = assessPassphrase(input("encPass").value, wordSet);
  const bar = /** @type {HTMLProgressElement} */ (element("passStrengthBar"));
  bar.hidden = assessment.kind !== "word-list";
  bar.value = assessment.progress;
  element("passStrengthText").textContent = assessment.label;
  element("passStrengthHint").textContent = assessment.text;
}
function updateLevel() {
  const settings = LEVELS[level("encLevel")] || LEVELS.strong;
  element("encIterLabel").textContent = settings.iterations.toLocaleString("en-US");
  element("encWordLabel").textContent = String(settings.words);
}
/** @param {string} name */
function setTab(name) {
  for (const tab of document.querySelectorAll("[role=tab]")) {
    const active = tab instanceof HTMLElement && tab.dataset.tab === name;
    tab.setAttribute("aria-selected", String(active));
    tab.setAttribute("tabindex", active ? "0" : "-1");
    tab.classList.toggle("active", active);
  }
  for (const panel of document.querySelectorAll("[role=tabpanel]")) {
    if (panel instanceof HTMLElement) panel.hidden = panel.id !== `panel-${name}`;
  }
}

/** @param {"enc" | "dec"} kind @param {boolean} [verify] */
function queueFiles(kind, verify = false) {
  const files = dropped.get(kind) || [...(input(`${kind}File`).files || [])];
  if (!files.length || files.length > 100) throw new BlindCryptError("INVALID_INPUT", "Choose between 1 and 100 files");
  if (!verify && files.reduce((total, file) => total + file.size, 0) > MAX_CONTAINER_SIZE) {
    throw new BlindCryptError("FILE_TOO_LARGE", "Buffered queues are limited to 64 MiB combined; use Large files or smaller batches");
  }
  if (verify && files.some((file) => file.size > MAX_STREAM_CONTAINER_SIZE)) throw new BlindCryptError("FILE_TOO_LARGE", "Verification is limited to 4 GiB per file");
  element(`${kind}Results`).replaceChildren();
  return files;
}
/** @param {"enc" | "dec"} kind @param {File[]} files @param {{index: number, state: string, code: string | null}} result */
function queueResult(kind, files, result) {
  const item = document.createElement("li");
  item.textContent = `${files[result.index].name}: ${result.state}${result.code ? ` (${result.code})` : ""}`;
  element(`${kind}Results`).appendChild(item);
}
/** @param {{state: string}[]} results */
function queueSummary(results) {
  return ["complete", "failed", "cancelled"].map((state) => `${results.filter((result) => result.state === state).length} ${state}`).join("; ") + ". Downloads may require browser permission.";
}
/** @param {{name: string, type: string}} metadata @param {string} format @param {boolean} authenticated */
function showMetadata(metadata, format, authenticated) {
  element("metaFormat").textContent = format;
  element("metaName").textContent = metadata.name;
  element("metaType").textContent = metadata.type;
  element("metaIntegrity").textContent = authenticated ? "Complete container integrity verified; not a malware or sender check" : "Legacy limitations apply";
}

function bindFiles() {
  for (const kind of /** @type {const} */ (["enc", "dec"])) {
    input(`${kind}File`).addEventListener("change", () => { dropped.delete(kind); });
    element(`${kind}Drop`).addEventListener("dragover", (event) => { event.preventDefault(); });
    element(`${kind}Drop`).addEventListener("drop", (event) => {
      event.preventDefault();
      if (busy || !(event instanceof DragEvent) || !event.dataTransfer) return;
      const files = [...event.dataTransfer.files];
      if (!files.length || files.length > 100) { status(`${kind}Status`, "Choose between 1 and 100 files", "bad"); return; }
      dropped.set(kind, files);
      input(`${kind}File`).value = "";
      status(`${kind}Status`, `${files.length} files queued locally.`);
    });
  }
  document.addEventListener("dragover", (event) => { event.preventDefault(); });
  document.addEventListener("drop", (event) => { event.preventDefault(); });
  button("doEncrypt").addEventListener("click", () => run("encStatus", async (signal) => {
    const files = queueFiles("enc");
    const secret = confirmed("encPass", "encConfirm");
    const results = await processQueue(files, async (file) => {
      const result = await encryptBlobV3(file, secret, { name: file.name, type: file.type,
        levelKey: level("encLevel"), signal, onProgress: (p) => progress("encProgress", p) });
      await download(result.blob, encryptedFilename(file.name, input("revealName").checked));
    }, { signal, onResult: (result) => queueResult("enc", files, result) });
    return queueSummary(results);
  }));
  for (const verify of [false, true]) {
    button(verify ? "doVerify" : "doDecrypt").addEventListener("click", () => run("decStatus", async (signal) => {
      const files = queueFiles("dec", verify);
      const secret = input("decPass").value;
      if (!secret) throw new BlindCryptError("INVALID_INPUT", "Enter the passphrase");
      for (const id of ["metaFormat", "metaName", "metaType", "metaIntegrity"]) element(id).textContent = "-";
      let legacy = false;
      const results = await processQueue(files, async (file) => {
        const onProgress = /** @param {number} p */ (p) => progress("decProgress", p);
        if (verify) {
          const result = await verifyV3(file, secret, { signal, onProgress });
          showMetadata(result.metadata, "v3", true);
        } else {
          const result = await decryptBlobAny(file, secret, onProgress, signal);
          showMetadata(result.metadata, `v${result.formatVersion}`, result.authenticatedMetadata);
          legacy ||= !result.authenticatedMetadata;
          await download(result.blob, result.authenticatedMetadata ? result.metadata.name : "legacy-decrypted.bin");
        }
      }, { signal, onResult: (result) => queueResult("dec", files, result) });
      return (verify ? "Verification creates no plaintext downloads. Legacy completeness is not supported. " : "") +
        (legacy ? "Warning: legacy metadata and completeness are not authenticated. " : "") + queueSummary(results);
    }));
  }
}

function bindAdditionalWorkflows() {
  button("encryptText").addEventListener("click", () => run("textStatus", async (signal) => {
    text("textCipher").value = await encryptText(text("textPlain").value, confirmed("textPass", "textConfirm"), "strong", signal);
    text("textPlain").value = "";
    return "Encrypted text ready. Share the passphrase separately.";
  }));
  button("decryptText").addEventListener("click", () => run("textStatus", async (signal) => {
    text("textPlain").value = "";
    text("textPlain").value = await decryptText(text("textCipher").value, input("textPass").value, signal);
    return "Text decrypted and authenticated. Clear it after use.";
  }));
  button("copyText").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text("textCipher").value); status("textStatus", "Encrypted text copied."); }
    catch { status("textStatus", "Clipboard unavailable. Select and copy the encrypted text manually.", "warn"); }
  });
  button("clearText").addEventListener("click", () => { text("textPlain").value = ""; text("textCipher").value = ""; input("textPass").value = ""; input("textConfirm").value = ""; });
  button("doUpgrade").addEventListener("click", () => run("upgradeStatus", async (signal) => {
    const result = await reencrypt(selected("upgradeFile", MAX_CONTAINER_SIZE), input("upgradeOld").value,
      confirmed("upgradeNew", "upgradeConfirm"), { name: input("upgradeName").value, levelKey: level("upgradeLevel"), signal });
    await download(result.blob, encryptedFilename());
    return "New encrypted copy created. Old copies are not revoked. " + (result.legacyWarning || "Verify the replacement before retiring the original.");
  }));
  for (const encrypt of [true, false]) {
    button(encrypt ? "largeEncrypt" : "largeDecrypt").addEventListener("click", () => run("largeStatus", async (signal) => {
      const picker = Reflect.get(globalThis, "showSaveFilePicker");
      if (typeof picker !== "function") throw new BlindCryptError("UNSUPPORTED_BROWSER", "This browser lacks a transactional save picker. Use the 64 MiB workflow or CLI.");
      const source = selected("largeFile", encrypt ? MAX_STREAM_PLAINTEXT_SIZE : MAX_STREAM_CONTAINER_SIZE);
      const secret = encrypt ? confirmed("largePass", "largeConfirm") : input("largePass").value;
      if (!secret) throw new BlindCryptError("INVALID_INPUT", "Enter the passphrase");
      // Invoke the picker before any await, while the click still has user activation.
      const handle = await picker({ suggestedName: encrypt ? encryptedFilename() : "decrypted.bin" });
      const sink = /** @type {import("./crypto-v3.js").TransactionalSink} */ (await handle.createWritable({ keepExistingData: false }));
      const onProgress = /** @param {number} p */ (p) => progress("largeProgress", p);
      if (encrypt) await encryptV3ToSink(source, secret, { name: source.name, type: source.type, levelKey: "strong", signal, onProgress }, sink);
      else await decryptV3ToSink(source, secret, sink, { signal, onProgress });
      return "Complete output committed to the selected file.";
    }));
  }
  button("createIdentity").addEventListener("click", () => run("recipientStatus", async (signal) => {
    const identity = await generateIdentity(confirmed("identityPass", "identityConfirm"), signal);
    element("identityFingerprint").textContent = identity.fingerprint;
    await download(identity.privateBackup, "blindcrypt-private.bckey");
    await download(new Blob([identity.publicKey], { type: "application/json" }), "blindcrypt-public.json");
    return "Save both files. Share only the public key and independently verify its fingerprint.";
  }));
  button("recipientEncrypt").addEventListener("click", () => run("recipientStatus", async (signal) => {
    const recipient = await importRecipient(await selected("recipientPublic", 2048).text());
    if (input("expectedFingerprint").value !== recipient.fingerprint) throw new BlindCryptError("INVALID_INPUT", "Recipient fingerprint does not match the independently received value");
    const file = selected("recipientFile", MAX_RECIPIENT_BYTES);
    await download(await encryptForRecipient(file, recipient, { name: file.name, type: file.type, signal }), `${encryptedFilename()}.jwe`);
    return "Recipient envelope created. It does not authenticate the sender.";
  }));
  for (const verifyOnly of [false, true]) {
    button(verifyOnly ? "recipientVerify" : "recipientDecrypt").addEventListener("click", () => run("recipientStatus", async (signal) => {
      const identity = await unlockIdentity(selected("identityBackup", MAX_IDENTITY_BYTES), input("identityUnlock").value, signal);
      const result = await decryptForRecipient(selected("recipientEnvelope", MAX_RECIPIENT_ENVELOPE), identity, { signal, verifyOnly });
      if (result.blob) await download(result.blob, result.metadata.name);
      return "Recipient envelope integrity verified. Sender identity is not authenticated.";
    }));
  }
}

function initialize() {
  for (const item of document.querySelectorAll("[data-app-version]")) item.textContent = APP_VERSION;
  document.documentElement.dataset.version = APP_VERSION;
  element("maxFileSize").textContent = `${LIMITS.maxPlaintextSize / (1024 * 1024)} MiB`;
  const tabs = [...document.querySelectorAll("[role=tab]")];
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => { if (tab instanceof HTMLElement && tab.dataset.tab) setTab(tab.dataset.tab); });
    tab.addEventListener("keydown", (event) => {
      if (!(event instanceof KeyboardEvent) || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const nextIndex = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      const next = tabs[nextIndex];
      if (next instanceof HTMLElement && next.dataset.tab) { setTab(next.dataset.tab); next.focus(); }
    });
  });
  for (const kind of ["enc", "dec"]) button(`${kind}Show`).addEventListener("click", () => {
    input(`${kind}Pass`).type = input(`${kind}Pass`).type === "password" ? "text" : "password";
    button(`${kind}Show`).textContent = input(`${kind}Pass`).type === "password" ? "Show" : "Hide";
  });
  button("genPass").addEventListener("click", () => {
    input("encPass").value = generatePassphrase(words, LEVELS[level("encLevel")].words);
    input("encConfirm").value = "";
    updateAssessment();
    status("encStatus", "Store this passphrase separately, then confirm it. Lost passphrases cannot be recovered.", "warn");
  });
  for (const item of document.querySelectorAll("[data-generate-for]")) item.addEventListener("click", () => {
    if (item instanceof HTMLElement && item.dataset.generateFor) {
      const field = input(item.dataset.generateFor);
      field.value = generatePassphrase(words, 8);
      field.type = "text";
      field.focus();
      field.select();
    }
  });
  button("copyPass").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(input("encPass").value); status("encStatus", "Passphrase copied. Other applications may read the clipboard; clear it after use.", "warn"); }
    catch { status("encStatus", "Clipboard unavailable. Copy the passphrase manually.", "warn"); }
  });
  input("encPass").addEventListener("input", updateAssessment);
  element("encLevel").addEventListener("change", updateLevel);
  button("cancelOperation").addEventListener("click", () => controller?.abort());
  bindFiles(); bindAdditionalWorkflows(); updateLevel(); updateAssessment(); setTab("encrypt");
  initializeOffline(() => busy);
}
initialize();
