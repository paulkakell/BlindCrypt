# Release checklist: 02.00.00

Use exact commit evidence, not inherited success from 01.01.02.

1. Confirm VERSION, APP_VERSION, UI fallback, worker, SBOM, documentation and notes agree on `02.00.00`; classify additions, fixes and breaking behavior in the changelog. Link #13 and actual implementation commits.
2. Confirm every roadmap feature has code, user examples, positive/negative tests and explicit limits. Record unfinished release gates separately from implemented features.
3. In a fresh Node 22 runner, run `npm ci --ignore-scripts`, current dependency audit, and full `npm run validate` with a configured Chromium executable. The reviewed lockfile must remain pinned; do not bypass failed checks.
4. Inspect CodeQL security-extended results and custom SAST. Review keys, public fingerprints, input/CPU/memory bounds, transactional cleanup, CLI output privacy, optional asset-only network/cache paths and update handling.
5. Verify native OS save-picker behavior, disk-full/cancellation, at least the intended browser/device matrix, and independent recipient-crypto review before high-value claims. Mark missing checks honestly.
6. Confirm default Strong settings, opaque names, 64 MiB buffered/4 GiB streamed/16 MiB recipient/64 KiB text limits and legacy warnings. No backend accounts, environment secrets, database or migrations are introduced.
7. Verify deterministic build/checksums, source/static/CLI artifacts, exact version and tested recovery readers. Preserve v01.01.02 artifacts and candidate readers for newly created formats.
8. Merge only the reviewed PR head with its expected SHA; do not bypass protections or erase unrelated work. Rerun Security validation, CodeQL and Pages on the exact production SHA.
9. Create immutable `v02.00.00` on that validated production commit. Attach release notes, source, static/CLI archive, SHA256SUMS, SBOM and validation evidence. Do not label a branch artifact as a published release.
10. Test the deployed origin, installation and update paths. Record native-browser limitations, operational rollback instructions, tag/commit/run references and rollout decision in #13.

There is no automatic deletion of branches or old ciphertext. No asynchronous agent is implied by this roadmap; each iteration must be actually executed and recorded.
