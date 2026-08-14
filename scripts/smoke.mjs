import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";

const root = resolve(new URL("../dist", import.meta.url).pathname);
const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

// The smoke server exposes only the exact files exercised by validation.
// Request data is used solely as a map key and never becomes a filesystem path.
const routes = new Map([
  ["/", "index.html"],
  ["/VERSION", "VERSION"],
  ["/assets/app.js", "assets/app.js"],
  ["/assets/crypto.js", "assets/crypto.js"],
  ["/assets/passphrase.js", "assets/passphrase.js"],
  ["/assets/wordlist.js", "assets/wordlist.js"],
  ["/SHA256SUMS", "SHA256SUMS"],
]);

const server = createServer(async (request, response) => {
  try {
    if (request.method !== "GET") {
      response.writeHead(405, { Allow: "GET" }).end("Method not allowed");
      return;
    }

    const url = new URL(request.url || "/", "http://127.0.0.1");
    const relativePath = routes.get(url.pathname);
    if (!relativePath) {
      response.writeHead(404).end("Not found");
      return;
    }

    const filePath = resolve(root, relativePath);
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
  for (const path of routes.keys()) {
    const response = await fetch(`${base}${path}`, { redirect: "error" });
    if (!response.ok) throw new Error(`${path} returned ${response.status}`);
    const body = await response.arrayBuffer();
    if (body.byteLength === 0) throw new Error(`${path} is empty`);
  }

  for (const path of ["/..%2Fpackage.json", "/assets%2F..%2FVERSION", "/not-allowlisted.txt"]) {
    const response = await fetch(`${base}${path}`, { redirect: "error" });
    if (response.status !== 404) throw new Error(`${path} returned ${response.status}`);
  }

  const post = await fetch(`${base}/`, { method: "POST", redirect: "error" });
  if (post.status !== 405) throw new Error(`POST request returned ${post.status}`);

  console.log("Built artifact HTTP smoke test passed.");
} finally {
  await new Promise((resolveClose, rejectClose) => {
    server.close((error) => error ? rejectClose(error) : resolveClose());
  });
}
