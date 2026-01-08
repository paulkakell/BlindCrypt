/* BlindCrypt
   Client-side encrypt/decrypt using WebCrypto.
   Format: [4 bytes big-endian headerLength][header JSON utf8][ciphertext bytes]
*/

const $ = (id) => document.getElementById(id);

const LEVELS = {
  standard: { iterations: 310000, words: 4 },
  strong:   { iterations: 600000, words: 6 },
  high:     { iterations: 1200000, words: 8 },
};

function setStatus(el, msg, kind = "info") {
  el.textContent = msg;
  el.dataset.kind = kind;
}

function b64uEncode(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}

function b64uDecode(str) {
  const s = str.replaceAll("-","+").replaceAll("_","/");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function utf8Encode(s) {
  return new TextEncoder().encode(s);
}
function utf8Decode(b) {
  return new TextDecoder().decode(b);
}

function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}
function readU32be(b, off) {
  return ((b[off] << 24) | (b[off+1] << 16) | (b[off+2] << 8) | (b[off+3])) >>> 0;
}

function concatBytes(...parts) {
  const total = parts.reduce((n,p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function downloadBytes(bytes, filename) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function sampleWords(count) {
  if (!Array.isArray(window.WORDS) || window.WORDS.length < 2048) {
    throw new Error("Word list is missing or incomplete");
  }
  const r = new Uint32Array(count);
  crypto.getRandomValues(r);
  const out = [];
  for (let i = 0; i < count; i++) out.push(window.WORDS[r[i] % window.WORDS.length]);
  return out.join(" ");
}

async function deriveKeyPBKDF2(passphrase, saltBytes, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    utf8Encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptFile(file, passphrase, levelKey) {
  const level = LEVELS[levelKey] || LEVELS.strong;

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const key = await deriveKeyPBKDF2(passphrase, salt, level.iterations);

  const plain = new Uint8Array(await file.arrayBuffer());
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plain
  );
  const cipher = new Uint8Array(cipherBuf);

  const header = {
    v: 1,
    kdf: "PBKDF2",
    hash: "SHA-256",
    iter: level.iterations,
    alg: "AES-256-GCM",
    salt: b64uEncode(salt),
    iv: b64uEncode(iv),
    name: file.name || "file",
    type: file.type || "application/octet-stream"
  };

  const headerBytes = utf8Encode(JSON.stringify(header));
  const out = concatBytes(u32be(headerBytes.length), headerBytes, cipher);
  return { bytes: out, header };
}

async function decryptFile(fileBytes, passphrase) {
  if (fileBytes.length < 5) throw new Error("File too small");

  const headerLen = readU32be(fileBytes, 0);
  const headerStart = 4;
  const headerEnd = headerStart + headerLen;

  if (headerEnd > fileBytes.length) throw new Error("Invalid header length");

  const headerJson = utf8Decode(fileBytes.slice(headerStart, headerEnd));
  let header;
  try { header = JSON.parse(headerJson); }
  catch { throw new Error("Invalid header JSON"); }

  if (!header || header.v !== 1) throw new Error("Unsupported format version");

  const salt = b64uDecode(header.salt);
  const iv = b64uDecode(header.iv);

  const iter = Number(header.iter);
  if (!Number.isFinite(iter) || iter < 10000) throw new Error("Invalid KDF settings");

  const key = await deriveKeyPBKDF2(passphrase, salt, iter);
  const cipher = fileBytes.slice(headerEnd);

  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipher
  );

  return { plain: new Uint8Array(plainBuf), header };
}

function setTab(name) {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");

  tabs.forEach(t => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", active ? "true" : "false");
  });

  panels.forEach(p => p.classList.toggle("show", p.id === name));
}

function updateIterLabel() {
  const levelKey = $("encLevel").value;
  const level = LEVELS[levelKey] || LEVELS.strong;
  $("encIterLabel").textContent = String(level.iterations);
}

function bindUI() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => setTab(btn.dataset.tab));
  });

  $("encLevel").addEventListener("change", updateIterLabel);
  updateIterLabel();

  $("encShow").addEventListener("click", () => {
    const i = $("encPass");
    i.type = (i.type === "password") ? "text" : "password";
    $("encShow").textContent = (i.type === "password") ? "Show" : "Hide";
  });

  $("decShow").addEventListener("click", () => {
    const i = $("decPass");
    i.type = (i.type === "password") ? "text" : "password";
    $("decShow").textContent = (i.type === "password") ? "Show" : "Hide";
  });

  $("genPass").addEventListener("click", () => {
    const levelKey = $("encLevel").value;
    const level = LEVELS[levelKey] || LEVELS.strong;
    try {
      const pass = sampleWords(level.words);
      $("encPass").value = pass;
      $("encConfirm").value = "";
      setStatus($("encStatus"), "Passphrase generated. Copy it and store it safely.", "info");
    } catch (e) {
      setStatus($("encStatus"), `Passphrase generation failed: ${e?.message || String(e)}`, "bad");
    }
  });

  $("copyPass").addEventListener("click", async () => {
    const pass = $("encPass").value;
    if (!pass) { setStatus($("encStatus"), "Nothing to copy.", "bad"); return; }
    try {
      await navigator.clipboard.writeText(pass);
      setStatus($("encStatus"), "Copied passphrase to clipboard.", "good");
    } catch {
      setStatus($("encStatus"), "Clipboard blocked by browser. Select and copy manually.", "bad");
    }
  });

  $("doEncrypt").addEventListener("click", async () => {
    const st = $("encStatus");
    setStatus(st, "", "info");

    const f = $("encFile").files?.[0];
    if (!f) { setStatus(st, "Choose a file first.", "bad"); return; }

    const pass = $("encPass").value;
    const conf = $("encConfirm").value;
    if (!pass) { setStatus(st, "Enter a passphrase or generate one.", "bad"); return; }
    if (pass !== conf) { setStatus(st, "Passphrase confirmation does not match.", "bad"); return; }

    const levelKey = $("encLevel").value;

    try {
      setStatus(st, "Encrypting locally...", "info");
      const { bytes } = await encryptFile(f, pass, levelKey);

      const safeName = (f.name && f.name.trim().length) ? f.name.trim() : "file";
      downloadBytes(bytes, `${safeName}.blindcrypt`);

      setStatus(st, "Encrypted file downloaded. Share it and share the passphrase out of band.", "good");
    } catch (e) {
      setStatus(st, `Encryption failed: ${e?.message || String(e)}`, "bad");
    }
  });

  $("doDecrypt").addEventListener("click", async () => {
    const st = $("decStatus");
    setStatus(st, "", "info");

    $("metaName").textContent = "-";
    $("metaType").textContent = "-";
    $("metaIter").textContent = "-";

    const f = $("decFile").files?.[0];
    if (!f) { setStatus(st, "Choose an encrypted file first.", "bad"); return; }

    const pass = $("decPass").value;
    if (!pass) { setStatus(st, "Enter the passphrase.", "bad"); return; }

    try {
      setStatus(st, "Decrypting locally...", "info");

      const bytes = new Uint8Array(await f.arrayBuffer());
      const { plain, header } = await decryptFile(bytes, pass);

      $("metaName").textContent = header.name || "file";
      $("metaType").textContent = header.type || "application/octet-stream";
      $("metaIter").textContent = String(header.iter || "-");

      const outName = header.name || "decrypted.bin";
      const blob = new Blob([plain], { type: header.type || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = outName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);

      setStatus(st, "Decryption complete. Download started.", "good");
    } catch (e) {
      setStatus(st, "Decryption failed. Wrong passphrase or file was modified.", "bad");
    }
  });
}

bindUI();
