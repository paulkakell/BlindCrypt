# Commit notes for 01.01.01

```text
security: fix smoke-server filesystem race for 01.01.01

Release: 01.01.01
Tag after protected merge: v01.01.01
Refs: GHAS-PR-1, CodeQL alert 1, PR #1
Baseline: b57c01dd515011273832064f0645842655196be7

- replace stat-then-read validation with a fixed route allowlist
- prevent request paths from becoming filesystem paths
- reject traversal-shaped, unlisted, and non-GET requests
- add regression coverage for the CodeQL finding
- make authenticated-header tamper coverage deterministic across version increments
- update version, changelog, SBOM, security policy, release notes, validation, and rollback evidence

Change type: non-breaking security bug fix
Compatibility: format v3 writer and v1/v2/v3 reader behavior unchanged
Rollback: revert the 01.01.01 commits to the validated 01.01.00 candidate; retain format v3 support
```
