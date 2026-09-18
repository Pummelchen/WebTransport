# AUDIT — report

Generated from `AUDIT/ledger.json` by `AUDIT/render-report.py`. The counts, the
breakdowns and the finding table are read from the ledger; the prose is not, because a
report that recomputed its own conclusions could not contradict them.

Branch `audit/2026-09-18`. Primary host `Mac14,3` (macOS 27.0, Xcode 27.0, Swift 6.4).
Baseline commit `397b047`, which `main` still points at.

## What was done

A pre-production audit of both libraries in this repository — the Swift package and the
independent C99 CMake library — against the supplied standard: the pinned toolchain
recorded per language (`environment.md`), tool coverage and language-standard enforcement
proved with deliberate violations (`tool-coverage.md`), the ledger kept as the single
source of truth, both projects baselined on the primary host (`baseline.md`), the L0-L7
passes run at tier-appropriate depth plus the standard's own §5 façade hunt and §6 unused-
code pass (`passes.md`), every finding fixed in severity order with `run-sweep.sh` as the
gate, and discovery repeated until a full sweep added no new task (`convergence.md`).

The Tier A review is recorded in `tier-a-review.md`, which names what was read, what it
found, and — for the refusals it could not reach — the proof that they are unreachable.
Phase E has not run: it needs an independent host, and the standard says to ask first
(`phase-e.md`, `AUD-0002`).

## Findings

38 tasks were filed. BLOCKED 1, DONE 37.

| severity | count |
| --- | --- |
| S1 | 6 |
| S2 | 18 |
| S3 | 14 |

| tier | count |
| --- | --- |
| A | 25 |
| B | 4 |
| C | 9 |

| id | sev | status | finding |
| --- | --- | --- | --- |
| AUD-0001 | S3 | DONE | Record the pinned toolchain per language on the primary host |
| AUD-0002 | S1 | BLOCKED | Phase E needs one independent host; none is provisioned |
| AUD-0003 | S3 | DONE | Inventory, dependency graph, trust boundaries and tier table |
| AUD-0004 | S3 | DONE | Baseline both projects on the primary host |
| AUD-0005 | S2 | DONE | Tool-coverage and language-standard proofs for every delegated check |
| AUD-0006 | S1 | DONE | SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force |
| AUD-0007 | S1 | DONE | Ruff has no config, so B, E722, S101 and PT are not enabled |
| AUD-0008 | S2 | DONE | -require-explicit-sendable is enforced only per-invocation in CI, not in the build config |
| AUD-0009 | S2 | DONE | No C99 coverage measurement exists, so one baseline metric is missing |
| AUD-0010 | S3 | DONE | No committed .clang-format and the tree is not clang-format clean |
| AUD-0011 | S3 | DONE | Repository convention says audit ledgers are not kept in the tree; this audit mandates committing one |
| AUD-0012 | S2 | DONE | SwiftLint inclusive_language conflicts with RFC 8446 terminology |
| AUD-0013 | S1 | DONE | SwiftLint trailing_comma and swift-format rewrote each other, breaking a green gate |
| AUD-0014 | S1 | DONE | SwiftLint opening_brace conflicts with the committed formatter's multi-line condition style |
| AUD-0015 | S3 | DONE | identifier_name: rename what is internal, exclude only RFC-registry and public-API names |
| AUD-0016 | S1 | DONE | SwiftLint redundant_void_return's fix does not compile |
| AUD-0017 | S2 | DONE | The API-compatibility check consumes the package by path, so it cannot catch unsafe-flags breakage |
| AUD-0018 | S3 | DONE | The connection-churn soak exists but no workflow runs it, so the resource property it verifies is unchecked |
| AUD-0019 | S2 | DONE | The portability check claimed more than its hand-maintained list could verify, and the inventory had drifted |
| AUD-0020 | S2 | DONE | The Swift address-sanitizer job ran three tests, not the suite, so the standard's 'sanitizers run the suite' was only partly true |
| AUD-0021 | S3 | DONE | Dead local variables were hidden from the compiler by (void) casts, so the earlier unused-code pass could not see them |
| AUD-0022 | S3 | DONE | NEW_TOKEN stored the wire's unvalidated length in a public field that nothing reads, before knowing the token was taken |
| AUD-0023 | S2 | DONE | wt_quic_initial_token read a Version Negotiation packet as an Initial with a token, and reported no version the caller could check |
| AUD-0024 | S2 | DONE | The ACK-range validator's refusal paths were never executed by the suite, and two of its guards are load-bearing |
| AUD-0025 | S2 | DONE | The flow-control capsule rules the header states outright were unexecuted: trailing bytes, a partial varint, and an over-long close reason |
| AUD-0026 | S2 | DONE | Four of RFC 9204 section 4.5.1's decoding error exits and its wrap branch were never executed |
| AUD-0027 | S2 | DONE | A public API accepted a QPACK decoder capacity this build cannot honour, because nothing parses the encoder stream |
| AUD-0028 | S2 | DONE | The ClientHello cipher-suite vector rule was never executed, and the obvious test for it passes with the check deleted |
| AUD-0029 | S3 | DONE | wt_quic_initial_token's two leading guards -- the header form and the packet type -- were never executed |
| AUD-0030 | S2 | DONE | Neither trusting mode's 'these bytes are not a certificate' refusal had ever executed |
| AUD-0031 | S3 | DONE | Three uncovered peer-input refusals are unreachable, each with a proof, and one tried to be tested twice over |
| AUD-0032 | S2 | DONE | Two WebTransport capsule refusals a previous audit added had no test, and both are honest regressions |
| AUD-0033 | S2 | DONE | RFC 9000 section 7.3's client half -- the check that stops an injected connection ID -- had all three refusals unexecuted |
| AUD-0034 | S3 | DONE | The Huffman decoder's bound is unreachable because its table is a complete prefix code, and the empty :method rule had no test |
| AUD-0035 | S3 | DONE | The quarter-ID overflow guard added for a past audit finding cannot fire from the wire, and the helper it protects still wraps silently |
| AUD-0036 | S2 | DONE | The test for RFC 9114's no-pseudo-headers-in-trailers rule passed with the rule deleted, because the refusal came from the message decoder |
| AUD-0037 | S3 | DONE | Both static-table index refusals were unexecuted, because every index the tests used was valid |
| AUD-0038 | S2 | DONE | The C99 sanitizer configuration could not be built with gcc, and CI excluded the one leg that would have said so |

## Verification yardstick

Every claim above rests on gates, not on reading. `AUDIT/run-sweep.sh` runs the same
commands the CI workflows do, so the two cannot drift; the final sweep ran 28 gates and **0 failed**:

- toolchain pinned (Swift 6.4 / Xcode 27)
- manifests agree on shared targets
- no unsafe build flags
- the two libraries report the same version
- target imports declared as dependencies
- swift-format lint --strict
- swiftlint lint --strict
- swift build with safety diagnostics
- public API compatibility sample
- package tests
- PKCS#12 resolution is keychain-free
- nested manifest test target
- library smoke pair
- build, warnings-as-errors, ctest
- RFC vectors match the documents
- installed package consumer
- compliance matrix against the tree
- portability inventory against the tree
- no dead locals hidden by a (void) cast
- tree matches .clang-format
- cppcheck
- Clang Static Analyzer
- workflow files parse
- ledger satisfies the standard's field rules
- ledger.md matches the ledger
- report.md matches the ledger
- gitleaks over full history
- trivy filesystem scan

The heavy gates are serialised on the primary host and run before Phase E:

- client and server CLI conformance (`--scenario all`, 40 each)
- the suite under AddressSanitizer (379 tested, 0 failed)
- the peer-input fuzz run under AddressSanitizer
- the suite under Thread Sanitizer
- the C99 suite under ASan and UBSan (97/97)
- the reproducible arm64 release build
- the connection-churn soak (400/400 sessions, no sustained growth)

The regression yardstick, unchanged from the baseline: both projects build with 0
warnings, Swift tests 401, C99 tests 97/97, C99 line coverage **91.97%** (from 91.64% when
first measured, having dipped to 91.49% under the audit's own added branches), SwiftLint 0
findings from 556, `swift format lint --strict` clean, gitleaks and trivy clean.

## Convergence

`AUDIT/convergence.md` records the sweeps in order. The last one added no task, which is
the standard's convergence condition; three of the later sweeps were re-run after the
Tier A review found work the sweep itself could not, which is recorded there rather than
folded into the first convergence claim.

## Not done, and why

| id | sev | status | finding | blocked on |
| --- | --- | --- | --- | --- |
| AUD-0002 | S1 | BLOCKED | Phase E needs one independent host; none is provisioned | owner: repository owner. No second host is available and provisioning one (VPS) requires explicit approval per the standard. Tried: nothing (not attempted, by rule). The procedure for the host is written down in `AUDIT/phase-e.md` (independence criteria, the exact commands, what counts as passing, and what a new-host failure means), so provisioning is the only step left. Options for the human: (1) approve a VPS/CI runner and provide access, (2) nominate an existing independent machine and provide access, (3) accept a documented waiver that Phase E ran on the primary host only. |

**Phase E has not run.** §12 makes the audit complete when the open count is exactly 0
(it is) *and* Phase E has passed on an independent host (it has not — there is no host).
Calling this audit complete would be the kind of claim the audit exists to prevent.
`AUDIT/phase-e.md` is the runbook: what makes a host independent, what to install, the
exact commands, what counts as passing, and what a failure there means.

`AUD-0008` is the second open decision: the standard asks for
`-require-explicit-sendable` in the build configuration, the only SwiftPM mechanism for
that breaks published consumers, and the three options for the repository owner are
recorded on the task.
