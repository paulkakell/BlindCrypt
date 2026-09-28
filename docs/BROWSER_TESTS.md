# Browser test harness

## Run

Use Node.js 22 or newer and an installed Chrome/Chromium executable:

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm run validate:core
CHROME_BIN=/usr/bin/google-chrome npm run browser
```

`npm run validate` includes both core and browser validation. Without CHROME_BIN,
the local browser path is `/usr/bin/chromium`. It is an executable path, not a
command with extra arguments. Use only a trusted browser binary. The temporary
profile and downloads are removed at the end. Administrator navigation or browser
security restrictions cause failure; the harness does not bypass those policies.

## Security boundaries in 02.00.01

The child uses `--remote-debugging-pipe`, not a TCP debugging listener. Chromium
reads NUL-framed JSON from descriptor 3 and writes it to descriptor 4. No endpoint
is parsed from logs and no WebSocket or network fallback exists. A loopback HTTP
server serves only the built application's allowlisted paths for the tests; it
is not the DevTools transport.

Dynamic fields, filenames, fixture bytes and version values go in
`Runtime.callFunctionOn.arguments[].value`. Function declarations come from a
fixed action table, not from input strings. Remaining Runtime.evaluate calls use
literal expressions only. Page handles are released after each action.

Examples: the `fill` action takes a field ID and value; `upload` takes an ID and
an array of `{name, data, type}` test records; `tab` compares a name to existing
data attributes rather than constructing a selector. `state` reads status, and
`ready` checks the expected version and reload condition. Unknown actions fail.
This is internal test tooling, not a public application interface.

Transport defaults are a 20-second command timeout, 32 outstanding requests and
8 MiB per protocol frame. Fragmentation, Unicode and multiple frames in one read
are supported. Malformed JSON/UTF-8, session mismatches, oversized frames, pipe
closure and write errors reject callers rather than hanging the run.

## Coverage

The ten existing application workflows remain: batch/private names, verification,
restoration, text, re-encryption, stream adapter, recipients, cancellation, legacy
handling, and offline reload with HTTP stopped. A new browser check confirms that
quotes, backslashes, Unicode line separators and markup remain literal fixture
data. Unit regressions cover the transport and structured argument contracts.
The native OS picker is still mocked; device and independent cryptographic reviews
are not replaced by these checks.

References: Chrome DevTools Protocol Runtime.callFunctionOn and CallArgument;
Chromium DevTools pipe descriptors; CodeQL js/bad-code-sanitization and
js/file-access-to-http query documentation.
