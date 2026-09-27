# Commit notes for 01.01.02

```text
fix(release): consolidate validated dependency branches for 01.01.02

Release: 01.01.02
Tag: v01.01.02 on the validated main merge commit only

Integrate PRs #2, #7, #10 and #11 while preserving merge ancestry.
Copy PBKDF2 salt before asynchronous WebCrypto calls for TypeScript 7
compatibility and deterministic caller-buffer handling.
Pin the complete reviewed dependency lockfile with SHA-256.
Add salt and lockfile-tampering regression coverage.
Validate main pushes, retain dev, and preserve rollback artifacts before
expected-SHA deletion of integrated dependency and release branches.
Update release, API, architecture, security and rollback documentation.

No public API, container format or database migration change.
Hosted validation, CodeQL and Pages must pass before final release cleanup.
```
