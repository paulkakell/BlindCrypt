# Rollback plan

## Before production release

Keep `dev` and its history. Before production promotion, revert failed changes on the release branch or create a corrective commit; do not force-reset or delete the retained development branch.

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

## 01.01.02 recovery

Pre-consolidation `main`: `0aff0635c4edd0ea4e4bde964815f5555bae7718` (01.01.01). The release preserves `blindcrypt-01.01.01-rollback.tar.gz`, `blindcrypt-01.01.02.tar.gz`, `blindcrypt-pre-cleanup.bundle` and `RELEASE-SHA256SUMS` before deleting any branch. Verify checksums before using the artifacts. Both versions retain the v3 reader.

To restore an individual retired branch, use its exact SHA from `docs/RELEASE_01.01.02.md`: `git branch <original-name> <recorded-sha>` then `git push origin <original-name>`. Do not overwrite an existing branch. The recorded commits also remain ancestors of `main`; the Git bundle provides an independent history backup (`git bundle verify blindcrypt-pre-cleanup.bundle`).

For application rollback, redeploy the preserved 01.01.01 static artifact, or create a rollback pull request reverting the consolidation merge with `git revert -m 1 <merge-sha>`, then rerun validation. Do not reset `main`, rewrite the published tag, or return to the unversioned reader. A failed finalization retains branches until artifact and ancestry checks pass; a partial draft release must be inspected before retry.
