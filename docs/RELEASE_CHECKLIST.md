# Release checklist for 01.01.02

Version format: `<Release>.<Feature Update>.<Bug Fix>`, two digits per field. This maintenance patch increments 01.01.01 to 01.01.02.

The definitive evidence is the workflow result for the exact candidate/main SHA, not inherited checkboxes from a previous release.

1. Confirm VERSION, application/UI version, README, SBOM, security policy and release notes agree.
2. Review PRs #2, #7, #10 and #11 and preserve all four source heads as merge ancestors.
3. Install the locked development graph in a fresh Node 22.16.0 runner with scripts disabled; run the current npm vulnerability audit.
4. Run lint, strict type checking, all unit/integration/regression tests, custom SAST, configuration validation, deterministic static build, HTTP smoke checks and the performance suite.
5. Require the security-extended CodeQL workflow and inspect findings. A successful scanner run is not an independent security certification.
6. Review credential handling, authorization, input bounds, logging and browser no-network controls. There is no server-side authentication or database migration in this release.
7. Confirm existing v1/v2/v3 readers, v3 writer, defaults and public API remain compatible.
8. Merge only the reviewed head with the checked expected SHA. Do not bypass any active protection or review requirement.
9. Confirm Security validation, CodeQL and Pages succeed on the exact production SHA.
10. Preserve release and rollback artifacts with checksums, and create v01.01.02 on that SHA before expected-SHA branch cleanup.
11. Retain main and dev; synchronize dev by fast-forward only after successful release.
12. Check the final branch list, PR states, release assets and tag, and record any unresolved operational limitation.

Native graphical-browser testing and enforcement of the documented repository-protection settings require separate verification; do not describe an HTTP smoke test as browser interaction coverage.
