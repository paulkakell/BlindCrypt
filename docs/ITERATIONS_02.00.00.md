# Implementation iterations: 02.00.00

Related roadmap: #13; implementation PR: #14. All entries retain the target release version and immutable commit evidence. This journal supplements CHANGELOG.md and the validation document; no production tag is implied.

## Iteration 1: complete feature candidate

Commit `8ef6242f29e845a1114217d87994de4786d4a035`, tree `36976f6fc09f7304e02547539b9f67c2334f41e0`, contains all nine features. Uploaded and local source trees were identical. The 72-test Node suite and diagnostic non-browser validation passed locally.

Hosted validation [36342602272](https://github.com/paulkakell/BlindCrypt/actions/runs/36342602272) installed the unchanged locked TypeScript 7.0.2 graph and reported zero known dependency vulnerabilities. Strict type checking correctly failed at two internal record-consumer callback types that unnecessarily admitted SharedArrayBuffer-backed views. CodeQL analysis run [36342602282](https://github.com/paulkakell/BlindCrypt/actions/runs/36342602282) completed, but its security result reported four medium alerts. Workflow completion was not mistaken for a clean security result.

## Iteration 2: compiler contract fix and inspectable findings

Fix: narrow the two private record callback parameters to ArrayBuffer-backed Uint8Array, matching every actual WebCrypto/record producer. Add an ordinary-owned-buffer regression test for both encryption and decryption. No cast, downgrade, extra plaintext copy or disabled check is introduced; wire compatibility is unchanged.

Additive: retain CodeQL SARIF as a commit-specific artifact so every reported finding can be inspected and resolved. The security scan still uploads to code scanning with security-extended queries, unchanged permissions and pinned actions. All reported alerts remain unresolved until evidence confirms otherwise. No runtime dependency or schema change.

Rerun the entire suite on this candidate before drawing a release conclusion. Native browser/device and independent recipient review remain separate gates.

## Iteration 3: offline origin fix and remaining harness review

Hosted iteration-2 validation [36342919380](https://github.com/paulkakell/BlindCrypt/actions/runs/36342919380) passed the locked compiler, zero-vulnerability dependency audit, all 73 Node tests, lint/SAST/config/build/smoke/performance, and 10 actual Chrome workflow checks with zero console exceptions. The native picker was mocked, not independently validated.

Inspected SARIF from [36342919330](https://github.com/paulkakell/BlindCrypt/actions/runs/36342919330) identified four findings: two fixture-to-dynamic-JavaScript flows (`js/bad-code-sanitization`), browser fixture bytes reaching a dynamically discovered DevTools WebSocket (`js/file-access-to-http`), and missing explicit message-origin verification in the service worker (`js/missing-origin-check`).

Fix: validate both browser-supplied message origin and parsed in-scope client URL before interpreting activation messages. Add a regression for forged, missing, foreign and lookalike origins. Retain the generated `.nojekyll` marker in the published CI artifact so its complete checksum manifest can be verified.

A separate attempted test-harness revision was blocked by a tool safety check and was not committed. The existing harness remains unchanged; its three reported security findings require further remediation and review. No finding was suppressed, no query was disabled, and a successful test workflow is not a clean CodeQL result. Do not merge or publish this candidate while those findings or other release gates remain unresolved.

## Recorded outcome after iteration 3

[Validation 36343333793](https://github.com/paulkakell/BlindCrypt/actions/runs/36343333793) passed all 74 Node tests and 10 real Chrome checks on `7e20d421501c7e0d5601c7bb41a0e56b1fd718cb`. The workflow's synthetic merge commit `b1d8e014b6363fc1ace79e5073c2bbe5bc3df6ba` has the same source tree `80fcc795a7e37cb86c2a1386cd8cab0d537368e7` as the candidate. Every downloaded static/CLI artifact entry matched SHA256SUMS, including `.nojekyll`.

[CodeQL 36343333761](https://github.com/paulkakell/BlindCrypt/actions/runs/36343333761) confirms the missing-origin-check finding is absent. Three findings remain: two `js/bad-code-sanitization` results at `scripts/browser.mjs:50` and one `js/file-access-to-http` result at `scripts/browser.mjs:38`. They are tracked in #15. The analysis workflow succeeds but code-scanning acceptance does not; this is not a clean security scan. Production remains unchanged and the release is not tagged.
