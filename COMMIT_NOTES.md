# Commit notes: 02.00.01

```text
fix(02.00.01): remediate browser-harness scans and retire merged branches

Replace discovered DevTools WebSocket connections with private pipes.
Pass fixture data through structured arguments to fixed page functions.
Preserve real-browser coverage and add security/cleanup regressions.
Require zero SARIF findings and exact-commit validation before cleanup.
Archive branch history before atomic, expected-SHA branch deletion.
Retain main, dev, existing tags, and compatible readers.
Update version, changelog, maintenance documentation and rollback notes.

Refs #15, #13
```

Classification: security/tooling fix, not a new file format. Baseline commit:
`8cea1fe449cff297338c8c2bd6a0e71e555382eb`. No runtime or development package
was added or updated. Native browser and independent cryptography reviews
remain separate acceptance work. See the validation document for observed
results; a completed CodeQL analysis job alone is not proof of a clean scan.
