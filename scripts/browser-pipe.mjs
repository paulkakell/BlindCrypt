// Private Chromium DevTools transport. No TCP port, endpoint discovery, or socket.
// Chrome reads null-terminated JSON on descriptor 3 and writes it on descriptor 4.
export function createPipeTransport(writer, reader, {
  onEvent = () => {}, timeoutMs = 20_000, maxMessageBytes = 8 * 1024 * 1024,
} = {}) {
  if (!writer?.write || !reader?.on) throw new TypeError("Two child-process pipes are required");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 ||
      !Number.isSafeInteger(maxMessageBytes) || maxMessageBytes < 1) {
    throw new RangeError("Invalid DevTools transport limits");
  }
  const pending = new Map();
  let sequence = 0;
  let buffered = Buffer.alloc(0);
  let failure;

  function close(error = new Error("DevTools pipe closed")) {
    if (failure) return;
    failure = error;
    buffered = Buffer.alloc(0);
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
    pending.clear();
    // Keep error listeners attached until the child exits to consume late EPIPEs.
  }

  function receive(chunk) {
    if (failure) return;
    try {
      // Split first, so several individually bounded frames can share a read.
      let offset = 0;
      while (offset < chunk.length) {
        const delimiter = chunk.indexOf(0, offset);
        const end = delimiter === -1 ? chunk.length : delimiter;
        if (buffered.length + end - offset > maxMessageBytes) {
          throw new Error("DevTools response exceeds its size limit");
        }
        buffered = Buffer.concat([buffered, chunk.subarray(offset, end)]);
        if (delimiter === -1) break;
        const frame = buffered;
        buffered = Buffer.alloc(0);
        offset = delimiter + 1;
        const message = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(frame));
        if (!message || typeof message !== "object" || Array.isArray(message)) {
          throw new Error("Invalid DevTools response");
        }
        if (Object.hasOwn(message, "id")) {
          const entry = pending.get(message.id);
          if (!entry) continue; // Late response to a timed-out command.
          if (entry.sessionId !== message.sessionId) {
            throw new Error("DevTools response session mismatch");
          }
          pending.delete(message.id);
          clearTimeout(entry.timer);
          if (message.error) entry.reject(new Error(`DevTools command failed (${message.error.code})`));
          else entry.resolve(message.result);
        } else if (typeof message.method === "string") {
          onEvent(message);
        } else {
          throw new Error("Invalid DevTools event");
        }
      }
    } catch (error) {
      close(error instanceof Error ? error : new Error("DevTools protocol failure"));
    }
  }
  reader.on("data", receive);
  reader.on("end", () => close(new Error("DevTools pipe ended")));
  reader.on("close", () => close());
  reader.on("error", close);
  writer.on("error", close);
  writer.on("close", () => close());

  function send(method, params = {}, sessionId) {
    if (failure) return Promise.reject(failure);
    if (pending.size >= 32) return Promise.reject(new Error("Too many pending DevTools commands"));
    if (typeof method !== "string" || !/^[A-Za-z]+\.[A-Za-z]+$/u.test(method)) {
      return Promise.reject(new TypeError("Invalid DevTools method"));
    }
    const id = ++sequence;
    let frame;
    try {
      frame = Buffer.from(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
      if (frame.length > maxMessageBytes) throw new Error("DevTools command exceeds its size limit");
    } catch (error) {
      return Promise.reject(error);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`DevTools command timed out: ${method}`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timer, sessionId });
      try {
        writer.write(frame, (error) => { if (error) close(error); });
      } catch (error) {
        close(error instanceof Error ? error : new Error("DevTools pipe write failed"));
      }
    });
  }
  return { send, close };
}
