#!/usr/bin/env node
import { openAsBlob } from "node:fs";
import { resolve, basename, join } from "node:path";
import { pathToFileURL } from "node:url";
import { APP_VERSION, LEVELS, MAGIC, MAX_STREAM_CONTAINER_SIZE, decryptBlobAny,
  encryptV3ToSink, decryptV3ToSink, verifyV3, BlindCryptError } from "../assets/crypto.js";
import { checkCancelled } from "../assets/crypto-v3.js";
import { encryptedFilename, validateSecret } from "../assets/features.js";
import { importRecipient, unlockIdentity, generateIdentity, encryptForRecipient,
  decryptForRecipient, MAX_RECIPIENT_ENVELOPE, MAX_IDENTITY_BYTES } from "../assets/recipients.js";
import { atomicSink, saveBlob } from "./io.mjs";

export const HELP = `BlindCrypt ${APP_VERSION}
Usage: node cli/blindcrypt.mjs COMMAND [OPTIONS]
Commands: encrypt, decrypt, verify, keygen
Options:
  --input PATH               Input file (required except keygen)
  --output PATH              New output; required for decrypt and keygen
  --level LEVEL              standard, strong (default), high, critical; encrypt only
  --passphrase-stdin         Read exactly one UTF-8 line from stdin, then EOF
  --recipient PATH          Public JWK for recipient encryption
  --fingerprint VALUE       Independently verified recipient fingerprint
  --identity PATH           Encrypted private backup for recipient decrypt/verify
  --public-output PATH      Public JWK destination for keygen
  --reveal-name              Use the original outer filename for encrypt
  --version                 Print version
  --help                    Print this help
Without --passphrase-stdin, the passphrase is read from a hidden terminal prompt.
No passphrase argument, environment variable, overwrite, upload, or telemetry.
Verify supports v3 and recipient envelopes, not legacy completeness claims.
Limits: v3 streams 4 GiB; legacy buffered 64 MiB; recipient files 16 MiB.
Recipient encryption does not authenticate the sender. Keep private backups safe.
Temporary decrypted data can exist on disk until commit/abort; deletion is not secure erasure.
`;

/** Parse a deliberately small, closed set of arguments. */
export function parseArgs(args) {
  if (args.length === 1 && ["--help", "--version"].includes(args[0])) return { command: args[0] };
  const [command, ...rest] = args;
  if (!["encrypt", "decrypt", "verify", "keygen"].includes(command)) throw new BlindCryptError("USAGE", "Unknown command");
  const boolean = new Set(["passphrase-stdin", "reveal-name"]);
  const values = new Set(["input", "output", "level", "recipient", "fingerprint", "identity", "public-output"]);
  const result = { command };
  for (let i = 0; i < rest.length; i += 1) {
    const flag = rest[i].startsWith("--") ? rest[i].slice(2) : "";
    if ((!boolean.has(flag) && !values.has(flag)) || Object.hasOwn(result, flag)) throw new BlindCryptError("USAGE", "Unknown or duplicate option");
    if (boolean.has(flag)) result[flag] = true;
    else {
      const value = rest[++i];
      if (!value || value.startsWith("--")) throw new BlindCryptError("USAGE", "Option value is missing");
      result[flag] = value;
    }
  }
  if (command !== "keygen" && !result.input) throw new BlindCryptError("USAGE", "Input is required");
  if (["decrypt", "keygen"].includes(command) && !result.output) throw new BlindCryptError("USAGE", "Output is required");
  if (command === "keygen" && !result["public-output"]) throw new BlindCryptError("USAGE", "Public output is required");
  if (command === "verify" && result.output) throw new BlindCryptError("USAGE", "Verify creates no output");
  if (result.level && (command !== "encrypt" || !Object.hasOwn(LEVELS, result.level))) throw new BlindCryptError("USAGE", "Invalid level");
  if (result.recipient && (command !== "encrypt" || !result.fingerprint || result.identity || result.level || result["passphrase-stdin"])) throw new BlindCryptError("USAGE", "Invalid recipient options");
  if (result.fingerprint && !result.recipient) throw new BlindCryptError("USAGE", "Recipient is required");
  if (result.identity && !["decrypt", "verify"].includes(command)) throw new BlindCryptError("USAGE", "Identity is only for decrypt or verify");
  if (result["reveal-name"] && command !== "encrypt") throw new BlindCryptError("USAGE", "Filename option is only for encrypt");
  if (command !== "keygen" && result["public-output"]) throw new BlindCryptError("USAGE", "Public output is only for keygen");
  if (command === "keygen" && (result.input || result.identity || result.recipient || result["reveal-name"] || result.level)) throw new BlindCryptError("USAGE", "Invalid keygen options");
  return result;
}

/** Stdin has a hard bound, exactly one line, and no trimming of the secret. */
export async function secretFromStream(stream, signal) {
  const chunks = [];
  let length = 0;
  const cancel = () => stream.destroy(new BlindCryptError("CANCELLED", "Cancelled"));
  signal?.addEventListener("abort", cancel, { once: true });
  if (signal?.aborted) cancel();
  try {
    for await (const chunk of stream) {
      checkCancelled(signal);
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > 1026) { bytes.fill(0); throw new BlindCryptError("INVALID_PASSPHRASE", "Secret input exceeds the limit"); }
      chunks.push(bytes);
    }
    const all = Buffer.concat(chunks);
    try {
      const value = new TextDecoder("utf-8", { fatal: true }).decode(all).replace(/\r?\n$/u, "");
      if (!value || /[\r\n\0]/u.test(value) || Buffer.byteLength(value) > 1024) throw new BlindCryptError("INVALID_PASSPHRASE", "Expected one nonempty secret line");
      return value;
    } finally { all.fill(0); }
  } finally { signal?.removeEventListener("abort", cancel); for (const bytes of chunks) bytes.fill(0); }
}

async function hiddenPrompt(signal, label = "Enter secret: ") {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) throw new BlindCryptError("USAGE", "Use --passphrase-stdin for noninteractive input");
  process.stderr.write(label);
  const bytes = [];
  const wasRaw = process.stdin.isRaw;
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolveSecret, reject) => {
    const cleanup = () => {
      process.stdin.removeListener("data", onData);
      process.stdin.removeListener("end", onEnd);
      signal.removeEventListener("abort", onAbort);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stderr.write("\n");
      bytes.fill(0);
    };
    const finish = (error, value) => { cleanup(); error ? reject(error) : resolveSecret(value); };
    const onAbort = () => finish(new BlindCryptError("CANCELLED", "Cancelled"));
    const onEnd = () => finish(new BlindCryptError("INVALID_PASSPHRASE", "Secret input ended"));
    const onData = (data) => {
      for (const byte of data) {
        if (byte === 3) { onAbort(); return; }
        if (byte === 13 || byte === 10) {
          const buffer = Buffer.from(bytes);
          try {
            const value = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
            finish(value ? null : new BlindCryptError("INVALID_PASSPHRASE", "Empty secret"), value);
          } catch { finish(new BlindCryptError("INVALID_PASSPHRASE", "Invalid UTF-8")); }
          finally { buffer.fill(0); }
          return;
        }
        if (byte === 127 || byte === 8) {
          if (bytes.length) {
            while (bytes.length && (bytes[bytes.length - 1] & 0xc0) === 0x80) bytes.pop();
            bytes.pop();
          }
        } else if (byte >= 32) bytes.push(byte);
        else { finish(new BlindCryptError("INVALID_PASSPHRASE", "Control character rejected")); return; }
        if (bytes.length > 1024) { finish(new BlindCryptError("INVALID_PASSPHRASE", "Secret input exceeds the limit")); return; }
      }
    };
    process.stdin.on("data", onData);
    process.stdin.once("end", onEnd);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

async function smallFile(path, maximum) {
  const blob = await openAsBlob(resolve(path));
  if (blob.size > maximum) throw new BlindCryptError("FILE_TOO_LARGE", "Input exceeds the limit");
  return blob;
}

export async function execute(options, secret, signal) {
  checkCancelled(signal);
  if (options.command === "keygen") {
    if (resolve(options.output) === resolve(options["public-output"])) throw new BlindCryptError("USAGE", "Identity output paths must differ");
    const identity = await generateIdentity(secret, signal);
    await saveBlob(identity.privateBackup, options.output, signal);
    // Private backup is committed first and retained if public export fails.
    await saveBlob(new Blob([identity.publicKey]), options["public-output"], signal);
    return { status: "created", fingerprint: identity.fingerprint };
  }
  const source = await smallFile(options.input, Math.max(MAX_STREAM_CONTAINER_SIZE, MAX_RECIPIENT_ENVELOPE));
  const output = options.output || join(process.cwd(), encryptedFilename(basename(options.input), Boolean(options["reveal-name"])) + (options.recipient ? ".jwe" : ""));
  if (options.command !== "verify" && resolve(options.input) === resolve(output)) throw new BlindCryptError("OUTPUT_EXISTS", "Input and output must differ");
  if (options.recipient) {
    const recipient = await importRecipient(await (await smallFile(options.recipient, 2048)).text());
    if (recipient.fingerprint !== options.fingerprint) throw new BlindCryptError("INVALID_KEY", "Recipient fingerprint does not match");
    const blob = await encryptForRecipient(source, recipient, { name: basename(options.input), type: "application/octet-stream", signal });
    await saveBlob(blob, output, signal);
    return { status: "encrypted", format: "JWE" };
  }
  if (options.identity) {
    const identity = await unlockIdentity(await smallFile(options.identity, MAX_IDENTITY_BYTES), secret, signal);
    const result = await decryptForRecipient(source, identity, { verifyOnly: options.command === "verify", signal });
    if (result.blob) await saveBlob(result.blob, output, signal);
    return { status: options.command === "verify" ? "integrity-verified" : "decrypted", format: "JWE", senderAuthenticated: false };
  }
  if (options.command === "encrypt") {
    const accepted = validateSecret(secret);
    const sink = await atomicSink(output, signal);
    await encryptV3ToSink(source, accepted, { name: basename(options.input), type: "application/octet-stream", levelKey: options.level || "strong", signal }, sink);
    return { status: "encrypted", format: 3 };
  }
  if (options.command === "verify") {
    await verifyV3(source, secret, { signal });
    return { status: "integrity-verified", format: 3 };
  }
  const magic = new Uint8Array(await source.slice(0, 4).arrayBuffer());
  if (MAGIC.every((value, i) => value === magic[i])) {
    await decryptV3ToSink(source, secret, await atomicSink(output, signal), { signal });
    return { status: "decrypted", format: 3 };
  }
  const result = await decryptBlobAny(source, secret, undefined, signal);
  await saveBlob(result.blob, output, signal);
  return { status: "decrypted", format: result.formatVersion, warning: "LEGACY_INTEGRITY_LIMITATIONS" };
}

async function main() {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.on("SIGINT", cancel);
  process.on("SIGTERM", cancel);
  let secret = "";
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.command === "--help") { process.stdout.write(HELP); return; }
    if (options.command === "--version") { process.stdout.write(`${APP_VERSION}\n`); return; }
    if (!options.recipient) {
      secret = options["passphrase-stdin"] ? await secretFromStream(process.stdin, controller.signal) : await hiddenPrompt(controller.signal);
      if (!options["passphrase-stdin"] && ["encrypt", "keygen"].includes(options.command)) {
        const confirmation = await hiddenPrompt(controller.signal, "Confirm secret: ");
        if (secret.normalize("NFC") !== confirmation.normalize("NFC")) throw new BlindCryptError("INVALID_PASSPHRASE", "Confirmation differs");
      }
    }
    const result = await execute(options, secret, controller.signal);
    process.stdout.write(`${JSON.stringify({ version: APP_VERSION, ...result })}\n`);
  } catch (error) {
    const codes = new Set(["USAGE", "CANCELLED", "INVALID_KEY", "INVALID_FORMAT", "INVALID_PASSPHRASE", "FILE_TOO_LARGE", "AUTHENTICATION_FAILED", "OUTPUT_EXISTS", "IO_FAILED", "EEXIST"]);
    const code = codes.has(error?.code) ? error.code : "OPERATION_FAILED";
    // Never echo argv, paths, private material, raw exceptions, or stack traces.
    process.stderr.write(`${JSON.stringify({ version: APP_VERSION, error: code })}\n`);
    process.exitCode = code === "CANCELLED" ? 130 : code === "USAGE" ? 2 : 1;
  } finally {
    secret = "";
    process.removeListener("SIGINT", cancel);
    process.removeListener("SIGTERM", cancel);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
