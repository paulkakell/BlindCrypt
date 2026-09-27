// @ts-check
// Build injects an exact immutable asset manifest. This unbuilt source cannot install.
const worker = /** @type {ServiceWorkerGlobalScope} */ (/** @type {unknown} */ (self));
const VERSION = "02.00.00";
const BUILD_ID = /* BUILD_ID */ "unbuilt";
/** @type {Record<string, string>} */
const ASSETS = /* ASSET_MANIFEST */ {};
const PREFIX = `blindcrypt:${worker.registration.scope}:`;
const CACHE = `${PREFIX}${VERSION}:${BUILD_ID}`;
const base = new URL(worker.registration.scope);
const allowed = new Map(Object.entries(ASSETS).map(([path, digest]) => [new URL(path, base).href, digest]));

worker.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    if (allowed.size < 5) throw new Error("A verified build is required for offline installation");
    const cache = await caches.open(CACHE);
    try {
      for (const [url, digest] of allowed) {
        const response = await fetch(url, { cache: "reload", credentials: "omit", redirect: "error" });
        if (!response.ok) throw new Error("Application asset unavailable");
        const bytes = await response.clone().arrayBuffer();
        const actual = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (byte) => byte.toString(16).padStart(2, "0")).join("");
        if (actual !== digest) throw new Error("Application asset integrity mismatch");
        await cache.put(url, response);
      }
    } catch (error) {
      await caches.delete(CACHE);
      throw error;
    }
  })());
});
worker.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key.startsWith(PREFIX) && key !== CACHE) await caches.delete(key);
    await worker.clients.claim();
  })());
});
worker.addEventListener("message", (event) => {
  // Check the browser-supplied message origin before interpreting the payload.
  if (event.origin !== base.origin) return;
  const source = event.source;
  if (!source || !("url" in source)) return;
  let clientUrl;
  try { clientUrl = new URL(source.url); } catch { return; }
  if (clientUrl.origin !== base.origin || !clientUrl.pathname.startsWith(base.pathname)) return;
  if (event.data?.type === "ACTIVATE") event.waitUntil(worker.skipWaiting());
});
worker.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== base.origin || !url.pathname.startsWith(base.pathname)) return;
  const key = url.href === base.href ? new URL("index.html", base).href : url.href;
  if (request.method !== "GET" || url.search || !allowed.has(key)) {
    event.respondWith(Promise.resolve(new Response("Not an application asset", { status: 404 })));
    return;
  }
  // No runtime network fallback: the installed edition always serves one complete build.
  event.respondWith((async () => (await (await caches.open(CACHE)).match(key)) ||
    new Response("Offline asset unavailable; reinstall the verified release", { status: 503 }))());
});
