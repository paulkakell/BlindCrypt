import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import { readFile } from "node:fs/promises";
import { createPipeTransport } from "../scripts/browser-pipe.mjs";
import { createPageActions, pageCallParameters } from "../scripts/browser-actions.mjs";

function fixture(options = {}) {
  const writer = new PassThrough(), reader = new PassThrough(), frames = [], events = [];
  writer.on("data", frame => frames.push(JSON.parse(frame.subarray(0, -1).toString())));
  const transport = createPipeTransport(writer, reader, { onEvent: event => events.push(event), ...options });
  return { writer, reader, frames, events, ...transport };
}
const reply = value => Buffer.from(JSON.stringify(value) + "\0");

test("pipe routes fragmented and coalesced replies by id and preserves Unicode", async () => {
  const f = fixture();
  try {
    const first = f.send("Runtime.enable", {}, "page"), second = f.send("Browser.getVersion");
    const bytes = Buffer.concat([reply({ id: 2, result: { text: "😀" } }), reply({ id: 1, sessionId: "page", result: {} })]);
    const split = bytes.indexOf(Buffer.from("😀")) + 1;
    f.reader.write(bytes.subarray(0, split));
    f.reader.write(bytes.subarray(split));
    assert.deepEqual(await second, { text: "😀" }); assert.deepEqual(await first, {});
    assert.deepEqual(f.frames.map(frame => frame.id), [1, 2]);
    assert.equal(f.frames[0].sessionId, "page");
  } finally { f.close(); }
});

test("pipe forwards events separately from replies", async () => {
  const f = fixture();
  const promise = f.send("Browser.getVersion");
  f.reader.write(Buffer.concat([reply({ method: "Browser.downloadWillBegin", params: { guid: "test" } }), reply({ id: 1, result: {} })]));
  await promise;
  assert.equal(f.events[0].params.guid, "test"); f.close();
});

test("pipe rejects protocol errors without echoing payloads", async () => {
  const f = fixture(), promise = f.send("Browser.getVersion");
  f.reader.write(reply({ id: 1, error: { code: -1, message: "sensitive fixture data" } }));
  await assert.rejects(promise, error => error.message === "DevTools command failed (-1)"); f.close();
});

test("pipe rejects cross-session replies and subsequent sends", async () => {
  const f = fixture(), promise = f.send("Runtime.enable", {}, "correct");
  f.reader.write(reply({ id: 1, sessionId: "wrong", result: {} }));
  await assert.rejects(promise, /session mismatch/u);
  await assert.rejects(f.send("Browser.getVersion"), /session mismatch/u);
});

test("pipe fails closed on malformed JSON and invalid UTF-8", async () => {
  for (const bytes of [Buffer.from("{broken}\0"), Buffer.from([0xff, 0]), reply(null), reply([]), reply({})]) {
    const f = fixture(), promise = f.send("Browser.getVersion");
    f.reader.write(bytes); await assert.rejects(promise);
    await assert.rejects(f.send("Browser.getVersion"));
  }
});

test("pipe bounds incoming partial frames and outgoing messages", async () => {
  const f = fixture({ maxMessageBytes: 128 }), promise = f.send("Browser.getVersion");
  f.reader.write(Buffer.alloc(129, 65)); await assert.rejects(promise, /size limit/u);
  const g = fixture({ maxMessageBytes: 128 });
  await assert.rejects(g.send("Runtime.enable", { text: "x".repeat(256) }), /size limit/u);
  assert.equal(g.frames.length, 0); g.close();
});

test("pipe timeouts reject callers and late replies are ignored", async () => {
  const f = fixture({ timeoutMs: 10 });
  await assert.rejects(f.send("Browser.getVersion"), /timed out/u);
  f.reader.write(reply({ id: 1, result: {} }));
  const next = f.send("Browser.getVersion");
  f.reader.write(reply({ id: 2, result: { ok: true } }));
  assert.deepEqual(await next, { ok: true }); f.close();
});

test("pipe close rejects all pending calls and write errors do not hang", async () => {
  const f = fixture(), first = f.send("Browser.getVersion"), second = f.send("Runtime.enable");
  const checks = [assert.rejects(first, /closed/u), assert.rejects(second, /closed/u)];
  f.close(); await Promise.all(checks);
  const writer = new Writable({ write(_chunk, _encoding, callback) { callback(new Error("write failed")); } });
  const reader = new PassThrough(), g = createPipeTransport(writer, reader);
  await assert.rejects(g.send("Browser.getVersion"), /write failed/u);
});

test("pipe peer EOF rejects pending work", async () => {
  const f = fixture(), promise = f.send("Browser.getVersion");
  f.reader.end(); await assert.rejects(promise, /ended|closed/u);
});

test("pipe limits outstanding commands and validates its configuration", async () => {
  assert.throws(() => createPipeTransport(null, null), /pipes/u);
  assert.throws(() => fixture({ timeoutMs: 0 }), /limits/u);
  const f = fixture(), pending = Array.from({ length: 32 }, () => f.send("Runtime.enable").catch(error => error));
  await assert.rejects(f.send("Runtime.enable"), /Too many/u);
  f.close(); assert.equal((await Promise.all(pending)).length, 32);
});

test("page action arguments never become executable source", () => {
  const text = `quotes " ' \\ line\u2028paragraph\u2029 <script>literal</script> 😀`;
  for (const action of ["fill", "click", "tab", "upload", "state", "ready"]) {
    const clean = pageCallParameters(action, "context", ["ordinary"]);
    const untrusted = pageCallParameters(action, "context", [text, [{ name: text, data: Buffer.from(text).toString("base64") }]]);
    assert.equal(untrusted.functionDeclaration, clean.functionDeclaration);
    assert.ok(!untrusted.functionDeclaration.includes(text));
    assert.equal(untrusted.arguments[0].value, text);
    assert.deepEqual(JSON.parse(JSON.stringify(untrusted)), untrusted);
  }
  for (const invalid of ["constructor", "__proto__", "toString", "unknown"]) {
    assert.throws(() => pageCallParameters(invalid, "context"), /Unknown/u);
  }
  assert.throws(() => pageCallParameters("fill", ""), /context/u);
});

test("page actions use structured parameters and release context handles", async () => {
  const calls = [];
  const callPage = createPageActions(async (method, params) => {
    calls.push({ method, params });
    if (method === "Runtime.evaluate") return { result: { objectId: "global" } };
    if (method === "Runtime.callFunctionOn") return { result: { value: "ok" } };
    return {};
  });
  assert.equal(await callPage("fill", "textPlain", "'\\\u2028"), "ok");
  assert.equal(calls[0].params.expression, "globalThis");
  assert.equal(calls[1].method, "Runtime.callFunctionOn");
  assert.deepEqual(calls[1].params.arguments, [{ value: "textPlain" }, { value: "'\\\u2028" }]);
  assert.equal(calls[2].method, "Runtime.releaseObject");
});

test("failed page actions release handles without exposing fixture errors", async () => {
  const calls = [];
  const callPage = createPageActions(async (method) => {
    calls.push(method);
    if (method === "Runtime.evaluate") return { result: { objectId: "global" } };
    if (method === "Runtime.callFunctionOn") return { exceptionDetails: { text: "fixture secret" } };
    throw new Error("context already destroyed");
  });
  await assert.rejects(callPage("click", "button"), error => error.message === "Browser test action failed");
  assert.equal(calls.at(-1), "Runtime.releaseObject");
});

test("browser launcher has only pipe debugging and no data-built evaluations", async () => {
  const source = await readFile(new URL("../scripts/browser.mjs", import.meta.url), "utf8");
  assert.ok(source.includes('"--remote-debugging-pipe"'));
  assert.ok(source.includes('stdio:["ignore","ignore","ignore","pipe","pipe"]'));
  assert.doesNotMatch(source, /WebSocket|remote-debugging-port|DevTools listening/u);
  assert.doesNotMatch(source, /evaluate\s*\(\s*`/u);
  assert.ok(source.includes("createPageActions(command)"));
});
