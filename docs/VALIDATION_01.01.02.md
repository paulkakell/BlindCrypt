# Validation record for 01.01.02

## Reproducible checks

Use Node 22.16.0, npm 10.9.2 and the locked TypeScript 7.0.2 toolchain:

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm run validate
```

The validate command runs syntax/security lint, strict JavaScript type checking, all unit/integration/regression tests, custom SAST, configuration checks, a fresh static build, the HTTP smoke suite and the performance test. The committed CodeQL workflow runs security-extended analysis separately. Exact hosted results are attached to the consolidation PR and the corresponding main commit; publication waits for those main checks and Pages to succeed.

## Locally observed evidence

The 27 pre-existing tests passed before changes. Of the three new salt tests, offset handling already passed; mutation-after-call and shared-buffer handling failed before the fix. All three passed after the fix. The expanded suite passed 34 tests with no skips or failures; syntax lint, custom SAST, configuration, build, HTTP smoke and the 1 MiB performance round trip also passed. The local compiler was the preinstalled TypeScript 5.8.3, so that result is not a substitute for the required hosted 7.0.2 run or current npm audit.

The exact dependency-lock SHA-256 is c5df91e83f41f12c011ab53c5da0a45ac926638c0161049121ad1ff4acf441f0. Native tooling is development-only and omitted from dist. No install scripts are enabled. New dependency-policy tests mutate copies in isolated temporary directories and require the guard to fail closed.

## Security and compatibility review

Reviewed the salt/KDF boundary, authenticated v3 header/record checks, strict file-size and iteration bounds, legacy neutral output handling, browser no-network/CSP lint rules, action pins, dependency controls and release token scope. No cryptographic algorithm, IV construction, authentication-tag size or KDF iteration change is made. Existing v1/v2/v3 compatibility and tamper cases remain in the suite. There are no server authentication/authorization flows or database migrations in this static application. No migration or rollback SQL is applicable.

Release credentials exist only in GitHub Actions environment steps, never in browser assets. Ordinary CI remains read-only. The version-scoped finalizer can publish artifacts and retire only listed, fully merged branch heads after successful gates, with exact-SHA leases and an independent history backup. It does not bypass branch rules or overwrite main/dev. Logs record workflow outcomes, release SHAs and retired branch SHAs; browser code still forbids console logging and network APIs. No application metrics or alert configuration is changed.

## Scope limitations

This is a code/CI review, not independent cryptographic certification. A CodeQL success indicates the scan ran; findings still require inspection. HTTP smoke checks are not interactive browser coverage. Cross-platform native compiler packages are locked but only the hosted runner's platform is executed. A 1 MiB round trip is not maximum-size or sustained-load benchmarking.

At the initial repository inspection main and dev were unprotected and no rulesets were returned. The documented protection/review controls need separate administrative enforcement; no claim is made that a source-file change enables them. Branch retirement and tagging are complete only when the finalization workflow and final repository state confirm them.
