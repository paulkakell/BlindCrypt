import { DICEWARE_2048 } from './wordlist_2048.js';

const $ = (id) => document.getElementById(id);

function setStatus(el, msg) { el.textContent = msg || ''; }

function switchTab(name) {
  for (const btn of document.querySelectorAll('.tab')) {
    btn.classList.toggle('active', btn.dataset.tab === name);
  }
  for (const panel of document.querySelectorAll('.panel')) {
    panel.classList.toggle('active', panel.id === `tab-${name}`);
  }
}

for (const btn of document.querySelectorAll('.tab')) {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
}

/* Passphrase strength (approximate entropy in bits) */
function estimateEntropyBits(pass) {
  if (!pass) return 0;

  // Diceware words separated by spaces
  const words = pass.trim().split(/\s+/).filter(Boolean);
  const looksLikeDiceware = words.length >= 2 && words.every(w => DICEWARE_2048.includes(w));
  if (looksLikeDiceware) {
    // Each word ~ log2(2048) = 11 bits
    return Math.round(words.length * 11);
  }

  let charset = 0;
  if (/[a-z]/.test(pass)) charset += 26;
  if (/[A-Z]/.test(pass)) charset += 26;
  if (/[0-9]/.test(pass)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(pass)) charset += 33; // rough printable symbols
  if (charset === 0) charset = 1;

  const len = pass.length;
  const bits = Math.log2(charset) * len;
  return Math.round(bits);
}

function strengthLabel(bits) {
  if (bits < 40) return 'Weak';
  if (bits < 60) return 'Fair';
  if (bits < 80) return 'Strong';
  if (bits < 100) return 'Very strong';
  return 'Excellent';
}

function bindStrength(inputId, barId, labelId) {
  const inp = $(inputId);
  const bar = $(barId);
  const lab = $(labelId);
  const onChange = () => {
    const bits = estimateEntropyBits(inp.value);
    bar.value = Math.min(bits, 120);
    lab.textContent = `${bits} bits (${strengthLabel(bits)})`;
  };
  inp.addEventListener('input', onChange);
  onChange();
}

bindStrength('encPass', 'encStrengthBar', 'encStrengthLabel');
bindStrength('decPass', 'decStrengthBar', 'decStrengthLabel');

/* Diceware generation */
function secureRandomInt(max) {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return a[0] % max;
}

function wordsForLevel(level) {
  // Forward-thinking defaults: more words rather than fewer.
  if (level === 'standard') return 6;
  if (level === 'high') return 8;
  return 10; // critical
}

function generatePassphrase(level) {
  const count = wordsForLevel(level);
  const out = [];
  for (let i = 0; i < count; i++) out.push(DICEWARE_2048[secureRandomInt(DICEWARE_2048.length)]);
  return out.join(' ');
}

$('genBtn').addEventListener('click', () => {
  const level = $('genLevel').value;
  $('genOut').value = generatePassphrase(level);
  $('encPass').value = $('genOut').value;
  $('encPass').dispatchEvent(new Event('input'));
});

/* gzip helpers (CompressionStream/DecompressionStream) */
async function gzipCompress(uint8) {
  if (!('CompressionStream' in window)) return { data: uint8, compressed: false, note: 'CompressionStream not supported' };

  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  await writer.write(uint8);
  await writer.close();

  const ab = await new Response(cs.readable).arrayBuffer();
  return { data: new Uint8Array(ab), compressed: true, note: '' };
}

async function gzipDecompress(uint8) {
  if (!('DecompressionStream' in window)) throw new Error('DecompressionStream not supported by this browser');

  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  await writer.write(uint8);
  await writer.close();

  const ab = await new Response(ds.readable).arrayBuffer();
  return new Uint8Array(ab);
}

/* Crypto helpers */
function b64encode(uint8) {
  let s = '';
  for (let i = 0; i < uint8.length; i++) s += String.fromCharCode(uint8[i]);
  return btoa(s);
}
function b64decode(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function levelParams(level) {
  if (level === 'standard') {
    return { pbkdf2Iterations: 310000, argon2Time: 3, argon2MemKB: 65536, argon2Parallelism: 1 };
  }
  if (level === 'high') {
    return { pbkdf2Iterations: 600000, argon2Time: 4, argon2MemKB: 131072, argon2Parallelism: 1 };
  }
  // critical
  return { pbkdf2Iterations: 1000000, argon2Time: 6, argon2MemKB: 262144, argon2Parallelism: 1 };
}

async function deriveKey(passphrase, kdf, level, saltUint8) {
  const params = levelParams(level);
  const passBytes = new TextEncoder().encode(passphrase);

  if (kdf === 'pbkdf2') {
    const baseKey = await crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltUint8, iterations: params.pbkdf2Iterations },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // argon2id via argon2-browser (loaded from CDN)
  if (!window.argon2 || !window.argon2.hash) {
    throw new Error('Argon2 library not loaded. Check network access to jsDelivr or switch to PBKDF2.');
  }

  const hash = await window.argon2.hash({
    pass: passBytes,
    salt: saltUint8,
    time: params.argon2Time,
    mem: params.argon2MemKB,
    parallelism: params.argon2Parallelism,
    hashLen: 32,
    type: window.argon2.ArgonType.Argon2id
  });

  const rawKey = hash.hash; // Uint8Array
  return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptBytes(plainUint8, key, ivUint8) {
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivUint8 }, key, plainUint8);
  return new Uint8Array(ct);
}

async function decryptBytes(cipherUint8, key, ivUint8) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivUint8 }, key, cipherUint8);
  return new Uint8Array(pt);
}

function downloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* Encrypt flow */
$('encryptBtn').addEventListener('click', async () => {
  const file = $('encFile').files?.[0];
  const level = $('encLevel').value;
  const kdf = $('encKdf').value;
  const pass = $('encPass').value;

  const status = $('encStatus');
  try {
    if (!file) throw new Error('Choose a file first.');
    if (!pass) throw new Error('Enter a passphrase.');

    setStatus(status, 'Reading file...');
    const originalBuf = new Uint8Array(await file.arrayBuffer());

    setStatus(status, 'Compressing (default)...');
    const comp = await gzipCompress(originalBuf);
    if (comp.note) setStatus(status, `Compressing skipped: ${comp.note}`);

    const salt = new Uint8Array(16);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(salt);
    crypto.getRandomValues(iv);

    setStatus(status, `Deriving key (${kdf}, ${level})...`);
    const key = await deriveKey(pass, kdf, level, salt);

    setStatus(status, 'Encrypting...');
    const cipher = await encryptBytes(comp.data, key, iv);

    const header = {
      magic: 'BLINDCRYPT',
      version: 2,
      createdAt: new Date().toISOString(),
      filename: file.name,
      mime: file.type || 'application/octet-stream',
      originalSize: originalBuf.length,
      compressed: comp.compressed,
      kdf,
      level,
      salt_b64: b64encode(salt),
      iv_b64: b64encode(iv),
      cipher_b64: b64encode(cipher)
    };

    const out = JSON.stringify(header);
    downloadBlob(new Blob([out], { type: 'application/json' }), `${file.name}.blindcrypt`);
    setStatus(status, 'Done. Encrypted file downloaded.');
  } catch (e) {
    setStatus(status, `Error: ${e.message || e}`);
  }
});

/* Decrypt flow */
$('decryptBtn').addEventListener('click', async () => {
  const file = $('decFile').files?.[0];
  const pass = $('decPass').value;
  const status = $('decStatus');

  try {
    if (!file) throw new Error('Choose an encrypted file first.');
    if (!pass) throw new Error('Enter the passphrase.');

    setStatus(status, 'Reading encrypted file...');
    const txt = await file.text();
    const header = JSON.parse(txt);

    if (header.magic !== 'BLINDCRYPT') throw new Error('Not a BlindCrypt file.');
    const kdf = header.kdf || 'pbkdf2';
    const level = header.level || 'standard';

    const salt = b64decode(header.salt_b64);
    const iv = b64decode(header.iv_b64);
    const cipher = b64decode(header.cipher_b64);

    setStatus(status, `Deriving key (${kdf}, ${level})...`);
    const key = await deriveKey(pass, kdf, level, salt);

    setStatus(status, 'Decrypting...');
    let plain = await decryptBytes(cipher, key, iv);

    if (header.compressed) {
      setStatus(status, 'Decompressing (default)...');
      plain = await gzipDecompress(plain);
    }

    const outName = header.filename || 'decrypted.bin';
    const mime = header.mime || 'application/octet-stream';
    downloadBlob(new Blob([plain], { type: mime }), outName);
    setStatus(status, 'Done. Decrypted file downloaded.');
  } catch (e) {
    setStatus(status, `Error: ${e.message || e}`);
  }
});
