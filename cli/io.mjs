import { open, link, unlink, lstat } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { BlindCryptError } from "../assets/crypto.js";
import { checkCancelled } from "../assets/crypto-v3.js";

/** A private, same-directory temporary file. link() never overwrites a destination.
 * The destination directory must be trusted. Abort removes only this operation's
 * temporary file, never the input or a pre-existing destination.
 * @param {string} destination @param {AbortSignal} [signal]
 */
export async function atomicSink(destination, signal) {
  const output = resolve(destination);
  try {
    await lstat(output);
    throw new BlindCryptError("OUTPUT_EXISTS", "Output already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  checkCancelled(signal);
  const temporary = join(dirname(output), `.blindcrypt-${randomBytes(16).toString("hex")}.partial`);
  const handle = await open(temporary, "wx", 0o600);
  let closed = false;
  let committed = false;
  let position = 0;
  return {
    async write(bytes) {
      checkCancelled(signal);
      if (closed || !(bytes instanceof Uint8Array)) throw new BlindCryptError("IO_FAILED", "Invalid output state");
      let offset = 0;
      while (offset < bytes.length) {
        checkCancelled(signal);
        const result = await handle.write(bytes, offset, bytes.length - offset, position);
        if (!result.bytesWritten) throw new BlindCryptError("IO_FAILED", "Incomplete output write");
        offset += result.bytesWritten;
        position += result.bytesWritten;
      }
    },
    async close() {
      if (closed) throw new BlindCryptError("IO_FAILED", "Output is already closed");
      await handle.sync();
      await handle.close();
      closed = true;
      checkCancelled(signal);
      // Do not replace this with rename(): rename can silently replace a file.
      await link(temporary, output);
      committed = true;
      await unlink(temporary);
    },
    async abort() {
      if (!closed) { await handle.close(); closed = true; }
      try { await unlink(temporary); } catch (error) { if (error?.code !== "ENOENT") throw error; }
      // A completed output is retained even if cleanup was interrupted.
      return committed;
    },
  };
}

/** Write a bounded Blob transactionally; used for legacy and recipient output. */
export async function saveBlob(blob, output, signal) {
  const sink = await atomicSink(output, signal);
  try {
    for (let offset = 0; offset < blob.size; offset += 512 * 1024) {
      const bytes = new Uint8Array(await blob.slice(offset, offset + 512 * 1024).arrayBuffer());
      try { await sink.write(bytes); } finally { bytes.fill(0); }
    }
    checkCancelled(signal);
    await sink.close();
  } catch (error) { await sink.abort(); throw error; }
}
