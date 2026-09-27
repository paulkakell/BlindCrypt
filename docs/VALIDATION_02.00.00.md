# Validation evidence: 02.00.00

Roadmap: #13. Implementation PR: #14. Remaining browser-harness security findings: #15. Full iteration history is in [ITERATIONS_02.00.00.md](ITERATIONS_02.00.00.md).

## Exact implementation and hosted evidence

Implementation head: `7e20d421501c7e0d5601c7bb41a0e56b1fd718cb`. Source tree: `80fcc795a7e37cb86c2a1386cd8cab0d537368e7`. The locally tested and uploaded source trees match exactly. GitHub's synthetic PR merge `b1d8e014b6363fc1ace79e5073c2bbe5bc3df6ba` uses the same tree, so the hosted workflow tested identical source content. Later documentation-only commits do not establish a new production release.

[Security validation run 36343333793](https://github.com/paulkakell/BlindCrypt/actions/runs/36343333793) succeeded on September 27, 2026:

- Fresh Node.js 22.16.0 installation using the unchanged reviewed TypeScript 7.0.2 lockfile.
- Dependency audit: zero known vulnerabilities reported for the installed graph. This is a dated scan, not a guarantee of absence of unknown vulnerabilities.
- Lint, strict browser/worker type checking, all 74 unit/integration/regression tests, custom SAST, configuration validation, deterministic build, allowlisted HTTP smoke and performance checks passed.
- Ten actual Chrome 153 workflow checks passed with zero console exceptions, including file downloads, text, recipient workflows, cancellation, legacy handling and offline reload after stopping the HTTP server.
- The 1 MiB performance smoke recorded 166.8 ms encryption and 161.5 ms decryption on that runner. These are smoke-test observations, not cross-device performance guarantees.
- Every downloaded static/CLI artifact entry matched its SHA256SUMS, including the generated hidden `.nojekyll` marker. Source, validation log and SARIF artifacts are retained by the workflows.

The original 34-test suite passed before implementation. The candidate adds 40 tests. Browser/worker types are strictly checked; the CLI has syntax, integration and static-analysis coverage rather than newly introduced Node ambient type dependencies. No runtime or development dependency was added.

## Security scan: not clean

[CodeQL run 36343333761](https://github.com/paulkakell/BlindCrypt/actions/runs/36343333761) produced inspectable SARIF. The service-worker origin-check finding from the previous iteration is absent after explicit message-origin/client-scope validation and forged-origin regression coverage.

Three findings remain in `scripts/browser.mjs`: two `js/bad-code-sanitization` results at line 50 and one `js/file-access-to-http` result at line 38. These concern fixture content embedded in DevTools code and its debugging transport, not a demonstrated application upload of user documents. They remain release blockers in #15. A proposed harness revision was blocked by tool safety checks and was not committed. No query or security rule was disabled, and no finding was suppressed or dismissed. A successful analysis job does not mean code-scanning acceptance passed.

## Coverage and limitations

Tests cover opaque names, sequential queues, independent randomness, cancellation, text UTF-8/size/encoding bounds, re-encryption/legacy warnings, buffer/stream compatibility, no-Blob verification, tampering, write/close failures, owned-buffer contracts, protected identities, wrong recipients, two-way interoperability with Node's separate classic crypto interface, CLI no-overwrite/races/symlinks/secret parsing, and offline asset allowlists/digests/rollback/origin checks.

The streaming suite performed a real file-backed 65 MiB encrypted round trip with a matching SHA-256 digest and a maximum 512 KiB plaintext sink write. The configured 4 GiB ceiling is not a claim that a full 4 GiB native-browser workload was tested. The browser suite mocks the OS save picker while exercising the actual cryptographic stream and adapter calls.

Local Chromium navigation was blocked by administrator policy and that restriction was not bypassed. Local offline installation of the uncached pinned compiler also failed. Local TypeScript 5.8.3 diagnostics were not treated as release evidence; the hosted locked-tool and real-browser results above supply that evidence.

## Outstanding release gates

Resolve #15 and obtain a clean scan on the exact candidate. Record native save-picker permission/overwrite/disk-full/cancellation, the intended additional browser/device/assistive-technology matrix, offline cache eviction and multiple-tab updates. Obtain independent recipient-cryptography review before high-value recommendations. Automated interoperability is not an independent audit.

Review and merge only an accepted head, rerun production-SHA validation, verify deployment, and publish immutable `v02.00.00` with source/static/CLI/checksum/SBOM/release-note/evidence artifacts. No production merge, deployment or release tag is claimed here. Preserve prior artifacts and newer readers for large-profile/JWE files during rollback.

No accounts, server authorization, database, schema migration or new environment-secret configuration exist. New secret entry points share validation; legacy passphrase semantics remain intact. CLI diagnostics omit raw exceptions/secrets, partial files use exclusive mode-0600 output, and commit refuses overwrites. JavaScript buffer clearing and filesystem unlink do not guarantee secure erasure. Optional offline storage contains public application assets only. See the threat model and rollback guide for the complete boundaries.
