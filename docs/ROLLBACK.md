# Rollback and recovery: 02.00.00

Baseline: `v01.01.02`, commit `d9ac4217604c248e73b34edebcbdbd6e8af80b06`. Preserve its released source/artifacts. Also preserve the validated 02.00.00 reader, static/CLI artifact and checksums before any rollout. Existing rollback instructions for the historical release are retained in Git history.

## Before a candidate reaches production

Close or revert the candidate PR without moving protected branches or changing immutable tags. `main` remains unchanged. Keep issue #13 open with actual implementation/validation status. Delete no encrypted user files, identities or prior artifacts.

## After users create new files

Do not blindly redeploy an older reader as the only recovery path. V1/v2 and buffered v3 remain accessible in old compatible releases, but v3 above 64 MiB and recipient JWE need the newer reader. A UI/worker regression can be reverted while retaining the new reader modules. If the hosted edition is unhealthy, use the retained verified local CLI/browser artifact on a trusted device.

To undo a passphrase migration, retain and use the original encrypted copy until its replacement is verified. There is no revocation or destructive in-place conversion. For recipient data retain the encrypted private backup and its passphrase; generating a new identity does not restore access to an old one.

## Offline recovery

Installed application assets can outlive a server rollback. Publish a newly versioned corrective worker/build with explicit approval, or instruct users to remove the site's public cache/registration through browser controls and load a verified local release. Do not falsely label an older reader with the newer version or reuse an immutable release tag for different bytes. Existing sensitive files are not in the service-worker cache and must not be deleted as part of cache recovery.

A broken worker might prevent an in-app repair flow. Keep out-of-band local-use instructions and recovery artifacts available. Independent verification of the trusted source matters because a checksum fetched from the same compromised origin is not sufficient origin authentication.

## Transactional failures

The browser/CLI aborts incomplete staged output on recoverable cancellation, write error and authentication failure. The browser may leave an empty placeholder chosen in its save picker. CLI hard-link commit refuses an existing destination; it removes only its own `.blindcrypt-*.partial` temporary path. Unexpected kill, power loss, or unlink failure can leave such a path; inspect it in the trusted destination directory and remove it deliberately after confirming which complete output exists. Temporary plaintext deletion is not secure erasure.

Keygen's two downloads/outputs are not one atomic filesystem transaction. Preserve the encrypted private backup even if public export fails. Do not delete a valid backup merely to rerun key generation.

## Verification after rollback

Run legacy and v3 fixtures, a large-profile round trip, recipient decryption with the preserved identity, malformed/tampered rejection, CLI no-overwrite/cleanup, and offline cache-version tests against the retained reader. Verify checksums, display version and exact commit evidence. There is no database migration or schema rollback. Record which versions remain needed for recovery and never announce rollback success based only on a page returning HTTP 200.
