# AUDIT — the L0–L7 passes

§4 of the standard names eight passes. This file records, for each one, what was actually run
or read, at what depth, and what it found. The depth is stated per pass and per tier, because
"reviewed" without a tier is a claim nobody can check: Tier A is deep manual reading, Tier B is
tool-first, Tier C is scanner-only, and the tier table is in `AUDIT/inventory.md` §2.4.

Findings are named by their ledger id; the ledger is the source of truth for their state.

## L0 — build, toolchain and baseline

**Question:** does the tree build, on which tools, and what is the starting point?

Run on the primary host before any fix: both builds (0 warnings, `-Werror` on both sides), the
full suites (400 Swift / 97 C99 at baseline), both formatters, both linters, the CVE scanner and
the secret scanner. Recorded in `AUDIT/baseline.md`, with the pinned toolchain in
`AUDIT/environment.md` and the regression yardstick at the foot of the baseline.

**Found:** `AUD-0006` (SwiftLint had no committed config and ran nowhere), `AUD-0007` (Ruff
installed but the standard's rule set not enabled), `AUD-0009` (C99 coverage not measurable),
`AUD-0010` (no `.clang-format`). All four closed.

## L1 — architecture

**Question:** are the layers real, and is anything depending on something it should not?

The dependency graph was derived from `swift package dump-package` and from the C99 tree's
includes, with the depth cap at 2 (the C99 layering `core <- quic <- tls,http3 <- webtransport
<- runtime <- api <- cli`). Both are in `AUDIT/inventory.md` §2.2, with the trust boundaries in
§2.3 and the two cross-project contracts (the wire protocol, the version lockstep) named as
contracts rather than assumptions.

**Found: no findings.** What would have counted, and is checked continuously rather than once:
a dependency cycle, a leaf target importing upward (`Swift/check-target-imports.sh`), or a
vendored third-party tree (`C99/third_party/` carries no sources). The one architectural
observation that mattered operationally — `WebTransportNetworkRuntime` is the fan-in node and
the only target that touches the OS — is what put it in Tier A.

## L2 — module

**Question:** does each module do what it says, at the depth its tier requires?

Depth was applied by tier. Tier A (every parsing, crypto, native-memory and network-facing
module in both projects) was read manually and in full; that reading is what produced the
structural findings, and the refactors that closed them are the proof it happened — the frame
codec, the QPACK field-line decoder, the flow-control capsule parser, the packet-range merge,
the STREAM receive path, the two handshake paths and the UDP receive path were each taken apart
and put back with the suite green. Tier B (`WebTransportCLIConformance`) was tool-first: it is
exercised by the CLI suites rather than read line by line. Tier C (tests, scripts, docs,
workflows) was scanner-only, and this is disclosed rather than implied.

**Found:** `AUD-0006` (mostly structural, in Tier A modules), `AUD-0017` (the API-compatibility
check consumes the package by path, so it cannot catch unsafe-flags breakage). Both closed.

## L3 — line

**Question:** does every line survive the compilers and linters the standard names?

Both builds run warnings-as-errors, with the language's strictness settings on (Swift 6 language
mode, complete concurrency, strict memory safety; C99 `-std=c99 -pedantic-errors` plus the
hardening flag set). `swift-format lint --strict` and `swiftlint lint --strict` are gates,
`clang-format` is one now, and `cppcheck` and the Clang Static Analyzer cover the C side.

**Found:** `AUD-0006` (556 SwiftLint findings → 0, none suppressed), `AUD-0010` (the C tree had
never been machine-formatted). Both closed; both gates are wired and green.

## L4 — security

**Question:** secrets, known CVEs, memory safety, and the trust decisions the code makes.

`gitleaks` over the full history and `trivy` over the tree are clean. Memory safety is enforced
rather than asserted: strict memory safety on the Swift side (every native call carries an
`unsafe` marker and a SAFETY note), the C99 hardening flags, and both sanitizer suites. Force
unwrapping is a SwiftLint error, so it cannot reappear. The trust decisions were reviewed at
Tier A depth — certificate verification, the pinned-certificate policy, and the PKCS#12 import
that `check-pkcs12-keychain-free.sh` pins to a memory-only import while the default keychain is
locked.

**Found:** `AUD-0008` (the standard asks for `-require-explicit-sendable` in build config; the
only SwiftPM mechanism breaks published consumers — BLOCKED with three options for the owner),
`AUD-0017` (closed: a gate now refuses unsafe flags, which the consumer check could not see).

## L5 — performance

**Question:** does the implementation behave under load, and are the hot paths sane?

Two kinds of evidence, and it is worth being precise about which is which.

*Measured:* `Swift/run-soak.sh` drives sustained connection churn and watches resident memory
and thread count for sustained growth rather than for absolute size. Run on the primary host:
400/400 connections completed, **400 established and 400 released**, threads settled from a peak
of 10 back to 2, and the harness's own verdict was `SOAK PASSED: no sustained growth`. The
growth during churn (+82.6% first-half to second-half average) is the behaviour that script
documents as expected while abandoned work holds sessions for its wait window; the session
counts are what decide, and they balance.

*Read:* the Tier A pass included the hot paths as they were refactored — the O(1) in-order fast
path in the received-packet-range merge, the QPACK Huffman decoder, the frame codec's dispatch,
the UDP receive path's single `recvmsg` and reused buffer. Nothing there is a measurement, and
none is presented as one.

**Found:** `AUD-0018` — the soak harness exists but **no workflow runs it**, so the resource
property it verifies is checked only when someone remembers. Filed by this pass, and fixed.

## L6 — tests

**Question:** is the suite real, and does it cover what it claims?

Both coverage numbers are measured rather than estimated: Swift 90.74% lines over the union of
the test bundles, C99 **91.64% lines** (15677 lines, 1310 missed) over the instrumented library,
by `C99/scripts/measure-coverage.sh`. The suites are 401 Swift tests and 97 C99 tests, all
passing on the reformatted and refactored tree. The generated RFC vectors are re-derived and
byte-compared by `check-vectors.sh`, the parsers are fuzzed under AddressSanitizer, and the
`QUICFrame` round trip now covers **all nineteen frame types** rather than the 11 it covered
before — added because grouping that dispatch would otherwise have traded a compile-time
guarantee for nothing.

**Found:** `AUD-0009` (coverage was not measurable; closed with the script and a CI job),
`AUD-0017` (the blind spot in the API-compatibility check; closed).

## L7 — operations

**Question:** can this be built, verified, released and diagnosed by someone who is not the
author?

Four CI workflows cover the two projects plus security scanning; every gate named in this audit
is wired into one of them, and `AUDIT/run-sweep.sh` runs the same commands locally so the two
cannot drift. The release path is `release-macos-arm64.sh` with `RELEASE.md` as its standard,
the version lockstep is a gate on both sides, and the installed C99 package is verified by
building and *running* a consumer against it.

**Found:** `AUD-0002` (the Phase E independent host does not exist — BLOCKED, owner named,
options recorded), `AUD-0018` (the soak is not wired), plus the gate wiring delivered by
`AUD-0006`, `AUD-0009`, `AUD-0010` and `AUD-0017`.
