# Rollback plan

## Before production release

The `dev` branch can be reset or deleted without affecting deployed Pages because production remains on `main`. Preserve the failed commit SHA for investigation.

## After format v3 is released

Do not restore the unversioned baseline as the only production reader. It cannot open v3 files.

Preferred rollback sequence:

1. Stop further deployment from the faulty commit.
2. Restore the most recent validated static artifact that still contains the v3 reader.
3. Revert interface, styling, workflow, or non-format changes independently.
4. Keep v1, v2, and v3 decryption support available.
5. If the v3 writer itself is defective, disable new encryption while retaining decryption and publish a security notice.
6. Issue a corrected `xx.xx.xx` version and tag after full validation.

## Git operations

- identify the deployed tag and commit SHA
- create a rollback branch from the last validated compatible tag
- revert the faulty commit without force-pushing protected branches
- run the complete validation suite
- merge through the protected process
- redeploy the validated artifact

## Verification

After rollback, confirm:

- the visible application version and artifact checksum match the intended rollback version
- v1, v2, and representative v3 fixtures decrypt
- new encryption is either verified or intentionally disabled
- CSP, no-network behavior, file limits, and neutral legacy output remain intact
- Pages reports the expected deployment commit
