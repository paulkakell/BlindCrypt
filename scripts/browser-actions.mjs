// Fixed page functions and separate, by-value protocol arguments. Input values
// are never interpolated into function declarations, expressions, or selectors.
const DECLARATIONS = Object.freeze({
  fill: "function(id, value) { document.getElementById(id).value = value; }",
  click: "function(id) { document.getElementById(id).click(); }",
  tab: `function(name) {
    const tab = Array.from(document.querySelectorAll('[data-tab]')).find(item => item.dataset.tab === name);
    if (!tab) throw new Error('Missing tab');
    tab.click();
  }`,
  upload: `function(id, files) {
    const transfer = new DataTransfer();
    for (const file of files) {
      const bytes = Uint8Array.from(atob(file.data), c => c.charCodeAt(0));
      transfer.items.add(new File([bytes], file.name, { type: file.type || 'application/octet-stream' }));
    }
    const input = document.getElementById(id);
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }`,
  state: `function(id) {
    const item = document.getElementById(id);
    return { disabled: item.disabled, kind: item.dataset.kind, text: item.textContent };
  }`,
  ready: `function(version, afterReload) {
    return document.documentElement.dataset.version === version &&
      !!document.getElementById('doEncrypt') && (!afterReload || typeof reloadMarker === 'undefined');
  }`,
});

export function pageCallParameters(action, objectId, values = []) {
  if (!Object.hasOwn(DECLARATIONS, action)) throw new Error("Unknown browser test action");
  if (typeof objectId !== "string" || !objectId) throw new TypeError("Missing page context");
  if (!Array.isArray(values)) throw new TypeError("Action arguments must be an array");
  return {
    functionDeclaration: DECLARATIONS[action], objectId,
    arguments: values.map(value => ({ value })), awaitPromise: true, returnByValue: true,
  };
}

export function createPageActions(command) {
  return async function callPage(action, ...values) {
    // Resolve the current page each time; a reload invalidates previous handles.
    const context = await command("Runtime.evaluate", { expression: "globalThis", returnByValue: false });
    const objectId = context.result?.objectId;
    try {
      const result = await command("Runtime.callFunctionOn", pageCallParameters(action, objectId, values));
      if (result.exceptionDetails) throw new Error("Browser test action failed");
      return result.result?.value;
    } finally {
      if (objectId) {
        // Navigation may already have discarded the handle.
        await command("Runtime.releaseObject", { objectId }).catch(() => {});
      }
    }
  };
}
