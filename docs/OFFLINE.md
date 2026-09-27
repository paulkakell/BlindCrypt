# Offline installation and trusted local releases

## Trust boundary

Offline caching avoids needing the network for subsequent application loads. It does not make an initially compromised origin trustworthy. A changed page can read a secret before encryption. Application digests detect incomplete or inconsistent installations; digests supplied by the same compromised origin do not independently authenticate that origin.

Obtain the release artifact and its `SHA256SUMS` through a trusted release channel. Confirm the version/tag/commit and validation evidence independently where your risk warrants it. Keep a known-good recovery copy outside the live hosting origin. A GitHub release tag alone is not a cryptographic signature by a trusted publisher.

## Local release example

Extract the full static/CLI artifact into a private directory and verify the manifest before use:

```bash
sha256sum -c SHA256SUMS
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://127.0.0.1:8080/`. This standard server is an example for a trusted local directory, not an internet-facing hardened service. Bind only to loopback and keep unrelated private files out of the served directory. The CLI can be used directly without running a web server. Windows users can use a SHA-256 verification tool that checks every listed artifact; do not treat checking just one JavaScript file as verification of the complete release.

From a source checkout, install the locked tooling, run full validation, and serve `dist/` rather than the repository root:

```bash
npm ci --ignore-scripts
npm audit --audit-level=high
CHROME_BIN=/usr/bin/google-chrome npm run validate
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

`file://` is not supported for installation. HTTPS or a browser-recognized localhost secure context is required. Build-generated PNG icons and the digest manifest are part of the release. Unbuilt `sw.js` deliberately rejects installation.

## Installation, readiness and updates

Offline registration happens only after **Enable/check offline edition** is selected. The worker requests exactly the fixed same-origin application assets in its build manifest, with credentials omitted and redirects rejected. Each body must match the pinned SHA-256 digest. A failure deletes the incomplete new cache, not an existing older cache. Activation retains only the active build's cache within this application scope. It does not remove caches from other applications.

Once active, the worker serves the fixed cached application and has no runtime network fallback. Unknown paths, query strings and non-GET requests within its scope are rejected. No user input becomes a fetch URL or cache key. Documents, downloads, passphrases, private keys and CLI files are excluded from the cache.

The interface reports active/waiting/failed status and the displayed application version. Reload after first activation, then disconnect and reopen to confirm readiness on your device. Cache eviction or browser site-data deletion can remove offline availability; the application does not promise permanent storage. Browser installation prompts vary; **Install app** is offered only when a supported prompt is available.

Updates are checked by registration and the explicit check button. A new worker with a complete asset set waits until **Apply downloaded update** is selected while idle. That requests activation and reloads the requesting tab. There is no forced mid-operation reload of other tabs. Old live tabs may finish loaded operations, but close/reopen idle tabs after an update to avoid mixing user expectations about versions.

Use browser settings to uninstall/remove site data. This removes public application cache entries, not your separately downloaded files. No automatic rollback to an unreviewed internet copy is attempted. Restore a known-good release with readers for every format already used; see [ROLLBACK.md](ROLLBACK.md).

## Acceptance evidence and remaining device checks

The unit suite tests asset allowlisting, digest rejection, install rollback, scope isolation, rejected document/query/POST requests and explicit activation messages. The Chromium suite checks real installation and reload after stopping the HTTP server. That is distinct from native desktop installation prompts, Safari/Firefox/mobile behavior, cache pressure, multiple-tab update races and native save-picker failures; record those separately before broad production claims.
