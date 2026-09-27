// @ts-check
/** Explicit application-asset installation; never sends file data or secrets. */
export function initializeOffline(/** @type {() => boolean} */ isBusy) {
  const enable = /** @type {HTMLButtonElement} */ (document.getElementById("enableOffline"));
  const update = /** @type {HTMLButtonElement} */ (document.getElementById("applyUpdate"));
  const install = /** @type {HTMLButtonElement} */ (document.getElementById("installApp"));
  const status = /** @type {HTMLElement} */ (document.getElementById("offlineStatus"));
  const scope = new URL("../", import.meta.url);
  /** @type {ServiceWorkerRegistration | null} */
  let registration = null;
  let approvedReload = false;
  /** @type {(Event & {prompt: () => Promise<void>}) | null} */
  let installPrompt = null;
  if (!("serviceWorker" in navigator)) {
    enable.disabled = true;
    status.textContent = "Offline installation is unavailable in this browser. Use a verified local release instead.";
    return;
  }
  /** @param {ServiceWorkerRegistration} value */
  function watch(value) {
    registration = value;
    const refresh = () => {
      update.disabled = !value.waiting || isBusy();
      if (value.waiting) status.textContent = "An application update is downloaded. Apply it only after finishing your work.";
      else if (value.active) status.textContent = "Application assets cached for offline use. No documents or secrets are cached. Reload to use the cached edition.";
    };
    value.addEventListener("updatefound", () => value.installing?.addEventListener("statechange", refresh));
    refresh();
  }
  navigator.serviceWorker.getRegistration(scope.href).then((value) => {
    if (value && value.scope === scope.href) watch(value);
  }).catch(() => { status.textContent = "Offline status unavailable."; });
  enable.addEventListener("click", async () => {
    if (isBusy()) return;
    enable.disabled = true;
    try {
      const value = await navigator.serviceWorker.register(new URL("../sw.js", import.meta.url), {
        scope: scope.href, updateViaCache: "none",
      });
      watch(value);
      await value.update();
      status.textContent = "Installing or checking application assets. Offline readiness is reported after activation.";
    } catch {
      status.textContent = "Offline installation failed. Serve the verified dist/ build over HTTPS or localhost, then retry.";
    } finally { enable.disabled = false; }
  });
  update.addEventListener("click", () => {
    if (isBusy() || !registration?.waiting) return;
    approvedReload = true;
    // Fixed control message to our same-origin service worker, never window messaging.
    registration.waiting.postMessage({ type: "ACTIVATE" });
  });
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (approvedReload && !isBusy()) location.reload();
    else status.textContent = "Offline edition active. Only versioned application assets are cached.";
  });
  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    installPrompt = /** @type {Event & {prompt: () => Promise<void>}} */ (event);
    install.hidden = false;
  });
  install.addEventListener("click", async () => {
    if (isBusy() || !installPrompt) return;
    await installPrompt.prompt();
    installPrompt = null;
    install.hidden = true;
  });
}
