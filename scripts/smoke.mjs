import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";

const root = resolve(new URL("../dist", import.meta.url).pathname);
const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", "http://127.0.0.1");
    const relativePath = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname.slice(1));
    const filePath = resolve(root, relativePath);
    if (filePath !== root && !filePath.startsWith(`${root}${sep}`)) {
      response.writeHead(400).end("Bad request");
      return;
    }
    const info = await stat(filePath);
    if (!info.isFile()) throw new Error("Not a file");
    const body = await readFile(filePath);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": contentTypes[extname(filePath)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(body);
  } catch {
    response.writeHead(404).end("Not found");
  }
});

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});

try {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Unable to determine smoke-test port");
  const base = `http://127.0.0.1:${address.port}`;
  for (const path of ["/", "/VERSION", "/assets/app.js", "/assets/crypto.js", "/assets/passphrase.js", "/assets/wordlist.js", "/SHA256SUMS"]) {
    const response = await fetch(`${base}${path}`, { redirect: "error" });
    if (!response.ok) throw new Error(`${path} returned ${response.status}`);
    const body = await response.arrayBuffer();
    if (body.byteLength === 0 && path !== "/.nojekyll") throw new Error(`${path} is empty`);
  }
  const traversal = await fetch(`${base}/..%2Fpackage.json`, { redirect: "error" });
  if (traversal.status !== 400 && traversal.status !== 404) {
    throw new Error(`Traversal request returned ${traversal.status}`);
  }
  console.log("Built artifact HTTP smoke test passed.");
} finally {
  await new Promise((resolveClose, rejectClose) => {
    server.close((error) => error ? rejectClose(error) : resolveClose());
  });
}
