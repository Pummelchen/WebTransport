# AUDIT — ledger

Generated from `AUDIT/ledger.json` by `AUDIT/render-ledger.sh`. Do not edit by hand.

Branch `audit/2026-09-18` | primary host Mac14,3 (macOS 27.0, Xcode 27.0, Swift 6.4) | baseline `397b047`

## Status counts

| status | count |
| --- | --- |
| BLOCKED | 2 |
| DONE | 25 |

Non-terminal (open): 0
Terminal: 27

## Tasks

| id | severity | tier | project | status | title | file:line |
| --- | --- | --- | --- | --- | --- | --- |
| AUD-0001 | S3 | C | both | DONE | Record the pinned toolchain per language on the primary host | AUDIT/environment.md |
| AUD-0002 | S1 | C | both | BLOCKED | Phase E needs one independent host; none is provisioned | AUDIT/environment.md |
| AUD-0003 | S3 | C | both | DONE | Inventory, dependency graph, trust boundaries and tier table | AUDIT/inventory.md |
| AUD-0004 | S3 | C | both | DONE | Baseline both projects on the primary host | AUDIT/baseline.md |
| AUD-0005 | S2 | C | both | DONE | Tool-coverage and language-standard proofs for every delegated check | AUDIT/tool-coverage.md |
| AUD-0006 | S1 | A | P1 | DONE | SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force | Package.swift |
| AUD-0007 | S1 | A | both | DONE | Ruff has no config, so B, E722, S101 and PT are not enabled | AUDIT/environment.md |
| AUD-0008 | S2 | A | P1 | BLOCKED | -require-explicit-sendable is enforced only per-invocation in CI, not in the build config | Package.swift:12-17 |
| AUD-0009 | S2 | B | P2 | DONE | No C99 coverage measurement exists, so one baseline metric is missing | C99/scripts/measure-coverage.sh |
| AUD-0010 | S3 | B | P2 | DONE | No committed .clang-format and the tree is not clang-format clean | C99/ |
| AUD-0011 | S3 | C | both | DONE | Repository convention says audit ledgers are not kept in the tree; this audit mandates committing one | AUDIT/ledger.json |
| AUD-0012 | S2 | A | P1 | DONE | SwiftLint inclusive_language conflicts with RFC 8446 terminology | .swiftlint.yml |
| AUD-0013 | S1 | A | P1 | DONE | SwiftLint trailing_comma and swift-format rewrote each other, breaking a green gate | .swiftlint.yml |
| AUD-0014 | S1 | A | P1 | DONE | SwiftLint opening_brace conflicts with the committed formatter's multi-line condition style | .swiftlint.yml |
| AUD-0015 | S3 | A | P1 | DONE | identifier_name: rename what is internal, exclude only RFC-registry and public-API names | .swiftlint.yml |
| AUD-0016 | S1 | A | P1 | DONE | SwiftLint redundant_void_return's fix does not compile | .swiftlint.yml |
| AUD-0017 | S2 | B | P1 | DONE | The API-compatibility check consumes the package by path, so it cannot catch unsafe-flags breakage | Swift/check-api-compatibility.sh |
| AUD-0018 | S3 | C | P1 | DONE | The connection-churn soak exists but no workflow runs it, so the resource property it verifies is unchecked | Swift/run-soak.sh |
| AUD-0019 | S2 | C | P2 | DONE | The portability check claimed more than its hand-maintained list could verify, and the inventory had drifted | C99/scripts/check-portability.sh |
| AUD-0020 | S2 | C | P1 | DONE | The Swift address-sanitizer job ran three tests, not the suite, so the standard's 'sanitizers run the suite' was only partly true | .github/workflows/swift-ci.yml |
| AUD-0021 | S3 | A | P2 | DONE | Dead local variables were hidden from the compiler by (void) casts, so the earlier unused-code pass could not see them | C99/src/quic/transport_parameters.c:151 |
| AUD-0022 | S3 | A | P2 | DONE | NEW_TOKEN stored the wire's unvalidated length in a public field that nothing reads, before knowing the token was taken | C99/src/quic/frame.c:259 |
| AUD-0023 | S2 | A | P2 | DONE | wt_quic_initial_token read a Version Negotiation packet as an Initial with a token, and reported no version the caller could check | C99/src/quic/packet.c:113 |
| AUD-0024 | S2 | A | P2 | DONE | The ACK-range validator's refusal paths were never executed by the suite, and two of its guards are load-bearing | C99/src/quic/connection_loss.c:85 |
| AUD-0025 | S2 | A | P2 | DONE | The flow-control capsule rules the header states outright were unexecuted: trailing bytes, a partial varint, and an over-long close reason | C99/src/webtransport/capsule.c:194 |
| AUD-0026 | S2 | A | P2 | DONE | Four of RFC 9204 section 4.5.1's decoding error exits and its wrap branch were never executed | C99/src/http3/qpack_header_prefix.c:90 |
| AUD-0027 | S2 | A | P2 | DONE | A public API accepted a QPACK decoder capacity this build cannot honour, because nothing parses the encoder stream | C99/src/http3/endpoint.c:118 |

## Detail

### AUD-0001 — Record the pinned toolchain per language on the primary host

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/environment.md
- evidence before: No AUDIT/environment.md existed; Xcode 27.0 / Swift 6.4 / clang / SwiftLint 0.65.1 / swift-format 603.0.0 / Ruff 0.16.7 / gitleaks 8.30.1 / trivy 0.74.0 / cppcheck 2.21.0 / llvm 23.1.1 all present but unrecorded
- fix: Wrote AUDIT/environment.md with name, version, install method and host per tool, plus the exact build-config mapping from the mandated Xcode settings to this SwiftPM-only repository
- evidence after: AUDIT/environment.md committed
- commit: 5265558

### AUD-0002 — Phase E needs one independent host; none is provisioned

- severity: S1 | tier: C | project: both | status: BLOCKED | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/environment.md
- evidence before: Only Mac14,3 exists in this session; Phase E requires a fresh clone on one independent host, and a fresh clone on the same host is not independent
- fix: 
- evidence after: 
- commit: 
- BLOCKED: owner: repository owner. No second host is available and provisioning one (VPS) requires explicit approval per the standard. Tried: nothing (not attempted, by rule). The procedure for the host is written down in `AUDIT/phase-e.md` (independence criteria, the exact commands, what counts as passing, and what a new-host failure means), so provisioning is the only step left. Options for the human: (1) approve a VPS/CI runner and provide access, (2) nominate an existing independent machine and provide access, (3) accept a documented waiver that Phase E ran on the primary host only.

### AUD-0003 — Inventory, dependency graph, trust boundaries and tier table

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/inventory.md
- evidence before: No committed inventory; tiers had never been assigned
- fix: AUDIT/inventory.md: two projects, Swift target graph from dump-package, C99 layering, five cross-project contracts, seven trust boundaries, per-module tiers
- evidence after: AUDIT/inventory.md committed
- commit: 5265558

### AUD-0004 — Baseline both projects on the primary host

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/baseline.md
- evidence before: No committed baseline; the repository's own claims were the only numbers
- fix: AUDIT/baseline.md: Swift 0 warnings / 400 tests / 90.74% line coverage; C99 0 warnings / 97 tests; gitleaks 713 commits clean; trivy clean
- evidence after: AUDIT/baseline.md committed
- commit: 5265558

### AUD-0005 — Tool-coverage and language-standard proofs for every delegated check

- severity: S2 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/tool-coverage.md
- evidence before: No proof that any delegated check is actually enforced; SwiftLint and Ruff are not even configured
- fix: Proved every delegated check against a deliberate violation and recorded the tool's own output in AUDIT/tool-coverage.md: Swift 6 strict concurrency (escaping @Sendable capture -> #SendableClosureCaptures, build exit 1), C99 (implicit declaration and a GNU nested function both rejected under the project's real flags), swift-format (Indentation/Spacing errors), Ruff (B006/E722/S101/PT011), gitleaks (leaks found: 1), SwiftLint (force_unwrapping and the rest), cppcheck (arrayIndexOutOfBounds + memleak), clang --analyze (core.NullDereference) and trivy (1 secret).
- evidence after: AUDIT/tool-coverage.md carries each violation, the exact command and the tool output. One honest correction is recorded there: the first Swift concurrency violation COMPILED, because Swift 6's region-based isolation legitimately permits transferring a uniquely referenced value into a task; the proof was replaced with a genuinely illegal escaping-capture form. A proof that passes for the wrong reason is not a proof.
- commit: 514a41e

### AUD-0006 — SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-a
- where: Package.swift
- evidence before: git ls-files shows no .swiftlint.yml; no workflow step invokes swiftlint; `swiftlint lint Swift/Sources` reports 317 findings (292 warning, 25 error) that nothing consumes
- fix: Committed `.swiftlint.yml` and brought the tree to zero findings rather than raising a threshold: 556 findings -> 0. 11 type_body_length fixed by splitting oversized types into same-file extensions; 18 cyclomatic_complexity and 40 function_body_length fixed by extracting named helpers along seams the code already had -- including `QUICFrame`'s two 19-way switches, split while keeping the outer switch exhaustive so a new frame type still fails to compile. Wired the gate into `swift-ci.yml` as `swiftlint lint --strict`, with SwiftLint itself installed from a digest-pinned 0.65.1 release so the step cannot silently skip.
- evidence after: `swiftlint lint --strict --quiet Swift/Sources Swift/Tests` exits 0 with **zero** findings (from 556). `swift test`: 401 passed. `swift format lint --strict`: clean. `./Swift/run-library-smoke.sh`: passes. The gate is wired and green at the commit that adds it. Four rules are disabled in the config, each with its own numbered DONE task (AUD-0012..0016) recording the evidence: `inclusive_language`, `trailing_comma`, `opening_brace` and `redundant_void_return` -- the first two because `swift-format` owns that formatting and `swiftlint --fix` removed commas the formatter requires, the last because its suggested fix does not compile. No threshold was raised, no file excluded, and no rule silenced without a recorded reason.
- commit: eba03c5

### AUD-0007 — Ruff has no config, so B, E722, S101 and PT are not enabled

- severity: S1 | tier: A | project: both | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-a
- where: AUDIT/environment.md
- evidence before: No ruff.toml/pyproject.toml; `ruff check` over the 16 tracked Python files reports 22 findings from the default rule set only, which does not include the bare-except, assert or pytest-style rules the standard names
- fix: Added ruff.toml: one pinned interpreter, line-length 120, and an explicit select of E/F/W plus the standard's B, E722, S101, PT, plus EXE (a tool-default rule that flags a shebang without an exec bit). Fixed the 5 findings the configured set reports (1 F401 unused import, 1 E401 multiple imports, 3 F841 dead variables - two of which were dead duplicates of the real render_vectors output, not missing output), ran ruff format over the tree (12 files), and set 7 exec bits. Added a python-lint job to c99-ci.yml running ruff check . and ruff format --check . so the config is in force rather than decorative.
- evidence after: ruff check . -> 'All checks passed!'; ruff format --check . -> '48 files already formatted'; C99/scripts/check-vectors.sh -> all 5 vectors still reproduce after the reformat; rule proofs (B006/E722/S101/PT011) in AUDIT/tool-coverage.md; workflows parse (C99/scripts/check-workflows.py)
- commit: d992ff0

### AUD-0008 — -require-explicit-sendable is enforced only per-invocation in CI, not in the build config

- severity: S2 | tier: A | project: P1 | status: BLOCKED | host: Mac14,3
- category: standards | discovered by: phase-a
- where: Package.swift:12-17
- evidence before: swift-ci.yml passes -Xswiftc -require-explicit-sendable; Package.swift carries strictMemorySafety and treatAllWarnings but not the flag, so a local `swift build`/`swift test` accepts a public type that omits Sendable
- fix: 
- evidence after: Manifests restored and `./Swift/check-api-compatibility.sh` passes. The experiment also found a second, independent gap, recorded in this reason rather than lost: the API-compatibility check uses a path dependency, so it structurally cannot catch unsafe-flags breakage -- a new task will be filed for it.
- commit: 
- BLOCKED: owner: repository owner. The standard says to enforce -require-explicit-sendable in build config, not per invocation. The only SwiftPM mechanism is `.unsafeFlags(["-require-explicit-sendable"])`, and it breaks the package for the consumers this repository publishes it to. Tried, not assumed: the flag was added to both manifests and `./Swift/check-api-compatibility.sh` PASSED, because that check consumes the package by PATH; SwiftPM refuses unsafe build flags only for VERSION-BASED dependencies ('The package product ... cannot be used as a dependency of this target because it uses unsafe build flags', and SwiftPM's own tests note the error is expected 'in the version-based dependency'). A published consumer reaching the package by URL would therefore be refused, and the in-repo check cannot see it. Options for the human: (1) accept unsafeFlags and drop the package's usability as a versioned dependency -- rejected as worse than the deviation; (2) keep the CI-invocation enforcement and record the deviation from the standard (current state); (3) make the API-compatibility check consume a versioned dependency first, so it can catch this whole class, and revisit the trade-off then.

### AUD-0009 — No C99 coverage measurement exists, so one baseline metric is missing

- severity: S2 | tier: B | project: P2 | status: DONE | host: Mac14,3
- category: tests | discovered by: phase-a
- where: C99/scripts/measure-coverage.sh
- evidence before: No gcovr/lcov installed and no coverage configuration in the CMake tree; `C99/scripts/build-and-test.sh` runs 97 tests without instrumentation
- fix: Added C99/scripts/measure-coverage.sh: it configures an instrumented tree in its own directory (C99/out/coverage) with the mandated clang's source-based coverage flags, runs the 97-test suite, merges the profiles and reports the library's line coverage. Wired into c99-ci.yml as a `coverage` job. No new tool is installed to make the metric appear, and no threshold gate is invented: the standard asks for a baseline metric, not a policy the repository has not set.
- evidence after: Baseline: 91.64% lines (15677 lines, 1310 missed; 87.20% regions, 99.79% functions) of libwebtransport, tests/ and third_party/ excluded. Recorded in AUDIT/baseline.md. Two measurement traps are written into the script because they produce a plausible wrong answer: `llvm-cov report` does not aggregate across several executables (it reported a 94-region total for 89 test binaries), so the report comes from the shared library, and the script asserts the dylib exists rather than reporting a clean zero.
- commit: 45674c0

### AUD-0010 — No committed .clang-format and the tree is not clang-format clean

- severity: S3 | tier: B | project: P2 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-a
- where: C99/
- evidence before: clang-format 23.1.1 is installed; git ls-files shows no .clang-format; the tree's style is hand-maintained and has never been machine-checked
- fix: Committed `.clang-format` at the repository root describing the style the tree already had (2-space indents, column limit 100, indented case labels, the one-line `if (x == NULL) return ...;` guard idiom, case bodies kept on their own lines, comments not reflowed), then applied it to the 314 tracked C sources the tree owns. Added `C99/scripts/check-format.sh` and a dedicated `format` CI job that installs the pinned `clang-format==23.1.1` from PyPI -- one version, not a matrix, because formatter output differs between releases.
- evidence after: 261 of 314 sources reformatted (6331 insertions, 7284 deletions -- net shorter, from unwrapping). Safety evidence on the reformatted tree, all on the primary host: `C99/scripts/build-and-test.sh` -> 0 warnings and 0 errors under `-Werror` plus the hardening flag set, **97/97 tests passed**; `check-cppcheck.sh` clean; `check-static-analysis.sh` -> 106 sources analyzed, no findings; `check-portability.sh` clean. CORRECTION, found by the convergence sweep after this task was marked done: the first version of this evidence said the generated vectors were untouched, which was true only of `tests/vectors/`. The reformat also rewrote `C99/src/http3/qpack_huffman_table.h`, a generated file the extractors render into the library, and `check-vectors.sh` caught the mismatch. The file was restored to the generator's bytes (verified by `check-vectors.sh` passing) and `check-format.sh` now excludes both `src/http3/qpack_*.h` paths with the reason recorded. `check-format.sh` reports 312 sources matching; shellcheck and `shfmt -i 2` clean. See AUDIT/convergence.md sweeps 1 and 2.
- commit: 10a4cae

### AUD-0011 — Repository convention says audit ledgers are not kept in the tree; this audit mandates committing one

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/ledger.json
- evidence before: The wiki's Project Tracker states the audits' working material (ledgers, per-area findings, reports) is deliberately not kept in the tree, because a later audit should read the code rather than a finished pass
- fix: Followed the audit instruction, which is the more specific and more recent authority, and recorded the conflict here and in the final report instead of silently diverging. AUDIT/ is additive and on the audit branch only
- evidence after: This entry
- commit: 5265558

### AUD-0012 — SwiftLint inclusive_language conflicts with RFC 8446 terminology

- severity: S2 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 8 findings, all `masterSecret` / `exporterMasterSecret` in WebTransportTLSCore
- fix: Rule disabled in the committed config with the reason: RFC 8446 section 7.1 defines the master secret, and renaming a reference implementation's symbols away from the document it implements makes it harder to read against the spec.
- evidence after: `swiftlint lint` reports no inclusive_language findings; the reason is in .swiftlint.yml and here
- commit: bd00d51

### AUD-0013 — SwiftLint trailing_comma and swift-format rewrote each other, breaking a green gate

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 43 trailing_comma findings; `swiftlint --fix` removed the trailing commas the committed .swift-format requires
- fix: Rule disabled: the formatter owns comma placement. Proven rather than asserted -- after `swiftlint --fix`, `swift format lint --strict` failed with `[TrailingComma] add trailing comma to the last element`, and `swift format --in-place` restored it.
- evidence after: `swift format lint --strict` exits 0; `swiftlint lint` reports no trailing_comma findings; 400 Swift tests pass
- commit: bd00d51

### AUD-0014 — SwiftLint opening_brace conflicts with the committed formatter's multi-line condition style

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 13 opening_brace findings that survive `swift format --in-place`
- fix: Rule disabled: after the formatter ran in place over the tree, `swiftlint lint` still reported 13 opening_brace violations, so the two cannot both be satisfied; the formatter is the CI-enforced owner.
- evidence after: `swift format lint --strict` exits 0 and no opening_brace findings remain
- commit: bd00d51

### AUD-0015 — identifier_name: rename what is internal, exclude only RFC-registry and public-API names

- severity: S3 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 13 findings: `iv` x5, `aes128GCM_SHA256`, `fd`, `ok`, `i`/`z` x3, and two over-length names
- fix: Renamed the internal identifiers for real (InteroperableQUIC* -> *, the long producer/request-stream names, fd -> descriptor, i -> index, z -> hash, ok -> accepted, the long test suite type). Excluded only `iv` (RFC 9001's own term), `aes128GCM_SHA256` and `webTransportPyWebTransportStreamInteropDefaults` (public API; renaming would break consumers and the api-compat gate), and restored SwiftLint's DEFAULT exclusion (`id`), which setting `excluded` had silently replaced -- caught because the finding count went UP, 13 -> 43.
- evidence after: `swiftlint lint` reports zero identifier_name findings; 400 Swift tests pass; a rename that also hit the POSIX `pollfd(fd:)` label was caught by the compiler and corrected
- commit: bd00d51

### AUD-0016 — SwiftLint redundant_void_return's fix does not compile

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: `swiftlint --fix` removed an explicit `-> Void` from a closure in WebTransportLoopbackTestLockTests; `swift build --build-tests` then failed with `result of call to 'withLockAsync(label:maximumWait:filePath:_:)' is unused`
- fix: Rule disabled with the reproduction: the closure's signature participates in generic inference, so dropping `-> Void` makes `withLockAsync` return a non-Void whose result is unused under strict memory safety. The `-> Void` is restored and commented as load-bearing.
- evidence after: `swift build --build-tests` succeeds; `swift test` 400 passed; `swift format lint --strict` accepts the restored signature
- commit: bd00d51

### AUD-0017 — The API-compatibility check consumes the package by path, so it cannot catch unsafe-flags breakage

- severity: S2 | tier: B | project: P1 | status: DONE | host: Mac14,3
- category: tests | discovered by: AUD-0008
- where: Swift/check-api-compatibility.sh
- evidence before: Found while testing AUD-0008: adding `.unsafeFlags(["-require-explicit-sendable"])` to the library targets still let `./Swift/check-api-compatibility.sh` pass. SwiftPM refuses unsafe build flags only for VERSION-BASED dependencies, and the check builds a consumer with `.package(path: ...)`, so the one gate whose job is to prove a consumer still builds is structurally unable to catch a change that stops consumers building.
- fix: Added `Swift/check-unsafe-flags.sh`, wired into `swift-ci.yml` next to the manifest-sync gate. It reads `swift package dump-package` for both manifests and fails naming every target whose settings carry `unsafeFlags`, so the class of change the path-based consumer check cannot see is now caught by a gate that reads what SwiftPM actually resolved.
- evidence after: Proven both ways on the primary host: exit 0 with the tree as it stands, and exit 1 with `.unsafeFlags(["-require-explicit-sendable"])` added to `Swift/Package.swift`, listing all 22 affected targets (`WebTransport: -require-explicit-sendable`, ...). The deliberate violation was reverted and the gate re-run green. `shellcheck` clean; `check-workflows.py` parses the edited workflow.
- commit: ad210da

### AUD-0018 — The connection-churn soak exists but no workflow runs it, so the resource property it verifies is unchecked

- severity: S3 | tier: C | project: P1 | status: DONE | host: Mac14,3
- category: ops | discovered by: the L5 pass (AUDIT/passes.md)
- where: Swift/run-soak.sh
- evidence before: `Swift/run-soak.sh` drives 400 connections and watches resident memory and thread count for sustained growth, and its own header states the justification: a leak per connection is invisible at 200 connections and fatal at 200,000. `grep -rn run-soak .github/workflows/*.yml` returned nothing, so the property was verified only when someone remembered to run it, and nothing recorded the result.
- fix: Added `.github/workflows/soak.yml`: scheduled nightly at 04:17 UTC with `workflow_dispatch` for a release to run it on demand, on the same `xcode-27` image as `swift-ci.yml`, with the toolchain asserted and the products built before the soak starts. Scheduled rather than per-pull-request because the check is timing- and memory-sensitive and a loaded shared runner can move the numbers without anything being wrong. The soak is also in the heavy set of `AUDIT/run-sweep.sh`, so a local sweep can cover it.
- evidence after: The soak was run on the primary host as the L5 pass: 400/400 connections completed, **400 established and 400 released**, threads settled from a peak of 10 back to 2, and the harness's own verdict `SOAK PASSED: no sustained growth in resident memory or thread count` (exit 0). `check-workflows.py` parses all four workflow files with no duplicate keys, and the new workflow's triggers, job and steps were read back from the parsed YAML.
- commit: 14cf6da

### AUD-0019 — The portability check claimed more than its hand-maintained list could verify, and the inventory had drifted

- severity: S2 | tier: C | project: P2 | status: DONE | host: Mac14,3
- category: docs | discovered by: the §5 facade hunt (AUDIT/passes.md)
- where: C99/scripts/check-portability.sh
- evidence before: `check-portability.sh` ended with "every POSIX-only name the library uses is in the inventory", but it can only check the names on its own hard-coded list. Proven, not assumed: injecting `getpid()` -- a POSIX call MSVC does not have -- into `src/core/time.c` left the check green and printing that sentence. Widening the list to cover the whole platform seam then found two calls the library really does use and the inventory did not name: `htons` and `clock_gettime`. `docs/PORTABILITY.md` had drifted too: its section describing the check was titled "The two symbols this document is checked for" while its body listed nine and the script checked nineteen.
- fix: Widened the list with `htons ntohs clock_gettime` -- which immediately failed on the two genuinely missing inventory entries -- added both to `docs/PORTABILITY.md` with the adaptation each needs (Winsock supplies `htons`/`ntohs` with the same names, so the adaptation is the include; Windows uses `QueryPerformanceCounter`, which `core/time.c` already branches to), replaced the stale section with a pointer to the script as the source of truth rather than a list copied into prose, and rewrote the success message to state what was actually verified. The mechanism's limit is now written down in both the script and the document, with the real enforcement named and checked: `msvc`, `clang-cl` and `windows-native` in c99-ci.yml each configure, build and ctest the library, so a call Windows does not have fails there.
- evidence after: Deliberate violation, both directions: with `getpid()` injected the check still passes -- recorded as the documented limit rather than hidden; with the widened list and before the document was updated the check FAILED with `htons is used in the library but is not in the inventory` and `clock_gettime ...`, exit 1. After adding both rows the check passes and prints the corrected message. `docs/PORTABILITY.md` names both calls; the stale section is gone. The Windows jobs' steps were read back from the parsed workflow to confirm they build the library rather than only configure it.
- commit: bc0e51f

### AUD-0020 — The Swift address-sanitizer job ran three tests, not the suite, so the standard's 'sanitizers run the suite' was only partly true

- severity: S2 | tier: C | project: P1 | status: DONE | host: Mac14,3
- category: tests | discovered by: the §1 tool-coverage review
- where: .github/workflows/swift-ci.yml
- evidence before: The standard asks sanitizers to run the suite. C99 did (`--sanitize` → 97/97 under ASan+UBSan) and the Swift thread-sanitizer job did (everything but `CLIProcess`/`ReleaseArtifacts`), but the Swift address-sanitizer job ran `swift test --sanitize=address --filter 'peerFacingParsers|huffmanDecoder'` -- three tests. A memory error anywhere else in the package was outside the run. `AUDIT/tool-coverage.md`, the document the standard names for tool-coverage proofs, had no sanitizer section at all, so the gap was not written down either.
- fix: Ran the whole suite under AddressSanitizer on the primary host first: `swift test --sanitize=address --skip CLIProcess --skip ReleaseArtifacts` → 379 passed, 0 failed, no sanitizer reports, exit 0. Then added an `address-sanitizer` job to swift-ci.yml running exactly that, with the two skipped suites and the reason (they spawn non-instrumented binaries a sanitizer runtime cannot observe) in the job's own comment, and added the same run to `AUDIT/run-sweep.sh`'s heavy set. AGENTS.md's gate list now names the job. `AUDIT/tool-coverage.md` gained a sanitizer section stating what each of the four runs covers, so the distinction between running the suite and running part of it is written down rather than assumed.
- evidence after: `swift test --sanitize=address --skip CLIProcess --skip ReleaseArtifacts`: `passed: 379 failed: 0`, 0 AddressSanitizer reports, exit 0. `check-workflows.py` parses all four workflow files with no duplicate keys; the new job's name, runner and steps were read back from the parsed YAML. The peer-input fuzz run (the 20000-iteration ASan job) is left as it is, because it exists for adversarial input rather than coverage, and the new section says so.
- commit: 94530c9

### AUD-0021 — Dead local variables were hidden from the compiler by (void) casts, so the earlier unused-code pass could not see them

- severity: S3 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: unused | discovered by: the Tier A deep review (AUDIT/tier-a-review.md)
- where: C99/src/quic/transport_parameters.c:151
- evidence before: The §6 unused-code pass reported none, because it relied on `-Wall -Wextra -Werror`: `(void)name;` counts as a use, so a local that is assigned and never read raises no warning at all. Four such locals existed: `start` and `start_offset` in `transport_parameters.c` (computed from the cursor and dropped, with `(void)` casts three lines later), `unused` in `qpack_encoder_stream.c`, and `w` in `scenario_refusals.c`, whose bytes are written by hand while a `wt_writer_t` was initialised and never used. Adding `-Wunused-but-set-variable` does NOT catch them: recompiling `transport_parameters.c` with it and `-Werror` exits 0, which was tested rather than assumed.
- fix: Removed all four dead locals and the casts that hid them, so the compiler is no longer silenced: if any of the code is revived it will be warned about again. Added `C99/scripts/check-unused-locals.py`, which separates the two cases `(void)` is used for -- a name appearing in a function parameter list is a deliberate unused-parameter suppression and is skipped, anything else is a local and is reported when nothing but its declaration, its assignments and the cast mention it. Wired into `c99-ci.yml` and into `AUDIT/run-sweep.sh`.
- evidence after: `python3 C99/scripts/check-unused-locals.py` reports the four before the fix and `no dead locals hidden by a (void) cast` after; re-injecting one into `qpack_encoder_stream.c` makes it fail with `C99/src/http3/qpack_encoder_stream.c:70: (void)unused; -- local, set but never read`, and restoring leaves it clean. The parameter suppressions it must NOT flag are in `apps/support/session_loop.c` (`stream_id`, `unidirectional`, `quarter_stream_id`) and it correctly skips them. `./C99/scripts/build-and-test.sh` after the removals: `100% tests passed out of 97`, no warnings. ruff and ruff-format clean on the new script; check-workflows.py parses all four workflows.
- commit: c522caf

### AUD-0022 — NEW_TOKEN stored the wire's unvalidated length in a public field that nothing reads, before knowing the token was taken

- severity: S3 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: unused | discovered by: the Tier A deep review (AUDIT/tier-a-review.md)
- where: C99/src/quic/frame.c:259
- evidence before: `out->as.new_token.token_length = length;` was assigned from the wire's 64-bit length immediately after `wt_quic_take`, before the status said whether the token had actually been taken. Every other field in that decoder is assigned only after its value is validated. A scan of `new_token.` across src, include, apps and tests found exactly one write (this line) and no reader: the round-trip test sets `token` and `length`, and the encoder writes `length`. So the field is write-only, and on a refused frame it held an unvalidated 64-bit length beside a NULL token and a zero `length`.
- fix: Assign it only when the take succeeded, so a refused frame is left zeroed like every other field, and documented the field in `frame.h`: read `length` (the narrowed size that bounds `token` and that the encoder writes), nothing reads `token_length`, and it is kept because removing a field from a public structure is an ABI change under `WT_ABI_VERSION`'s own rule -- a maintainer's decision, not an audit cleanup. Added a regression test to `test_quic_frame.c` beside the existing truncation cases: a NEW_TOKEN whose body is missing must be refused AND must leave no length behind.
- evidence after: The new check fails against the unfixed code -- `wt_quic_frame: 1 of 1334 checks FAILED`, 1 of 97 tests failing, exit 8 -- and passes with the fix restored: `100% tests passed out of 97`. That is the deliberate-violation proof for the test itself, not just for the code. `check-format.sh` reports all 312 C sources match .clang-format.
- commit: 52bb353

### AUD-0023 — wt_quic_initial_token read a Version Negotiation packet as an Initial with a token, and reported no version the caller could check

- severity: S2 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: parsing | discovered by: the Tier A deep review (AUDIT/tier-a-review.md)
- where: C99/src/quic/packet.c:113
- evidence before: RFC 9000 section 17.2.1 makes the low bits of a Version Negotiation packet's first byte ARBITRARY, so its type bits can read as Initial. `wt_quic_initial_token` checked the header form, the fixed bit and the type bits but skipped the version field unread, so the version list parsed as its Token Length field and token. Proven with a probe program linked against the built library: `wt_quic_packet_kind` classified the bytes as VERSION_NEGOTIATION (kind=2) while `wt_quic_initial_token` returned WT_OK with `token_length = 1`. Unlike `wt_quic_long_header_decode`, which reports the version to its caller, this function reports none -- so `read_initial` in server_retry.c had no way to tell, treated the datagram as an Initial, and a crafted version-0 packet with a non-zero 'token' suppressed the server's Retry. `wt_quic_protected_pn_offset` already refuses version zero for exactly this reason, with a comment saying so; this function and `wt_quic_long_header_connection_ids` were the two that did not.
- fix: Read the version in `wt_quic_initial_token` and refuse version zero with WT_ERR_PROTOCOL, mirroring the guard and the comment `wt_quic_protected_pn_offset` already had. Added a regression test to `test_quic_packet.c` with a full Version Negotiation packet -- connection IDs and a version list, unlike the existing five-byte fixture which is too short to reach the token -- asserting that the packet is classified as version negotiation AND refused as an Initial, with no token and no token length.
- evidence after: The probe, before: `initial_token -> 0 (WT_OK)`, `token_length accepted -> 1`. After: `initial_token -> 4` (WT_ERR_PROTOCOL), `token_length accepted -> 0`, with `packet_kind` still reporting VERSION_NEGOTIATION. The regression test was proved by deliberate violation: against the unfixed code it fails with `FAIL a version negotiation is not an Initial: want protocol, got ok` (3 of 210 checks, 1 of 97 tests, exit 8), and with the fix `100% tests passed out of 97`. `check-format.sh`: all 312 C sources match.
- commit: 80f5b1c

### AUD-0024 — The ACK-range validator's refusal paths were never executed by the suite, and two of its guards are load-bearing

- severity: S2 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: tests | discovered by: Tier A review, using line coverage as a reviewer (AUDIT/tier-a-review.md)
- where: C99/src/quic/connection_loss.c:85
- evidence before: Line coverage was used to ask WHICH lines are unexecuted rather than how many: `llvm-cov show` over the instrumented library listed 295 uncovered guard-like lines, and `validate_ack` in `connection_loss.c` -- RFC 9000 section 19.3.1's range chain, reached from `handle_ack` on every ACK a peer sends -- had its whole refusal block (lines 85-94) unexecuted. Every ACK in the suite was a well-formed one, so the three checks could have been deleted with CI green.
- fix: Added `test_a_malformed_ack_range_is_refused` to `test_quic_connection_loss.c`, which encodes three malformed ACK frames, sends each in a real packet over the socket pair and asserts the client closes with FRAME_ENCODING_ERROR -- which is what a failed `validate_ack` produces, and deliberately NOT the PROTOCOL_VIOLATION an acknowledgement of an unsent packet gets, so the test cannot pass by reaching the wrong check. The three cases target the zero-length range, a gap past the smallest acknowledged packet, and a range longer than the acknowledgement.
- evidence after: Coverage before the test: `connection_loss.c` had 64 uncovered lines; after: 55, and the total moved 91.49% to 91.54% lines. `llvm-cov show` confirms lines 89, 90 and 92 now execute. Deliberate violation, and it produced a finding rather than a confirmation: removing the `range.length - 1U > largest` check fails with `FAIL with a frame encoding error: want 7, got 10`, so that guard is genuinely pinned -- but removing the `range.length == 0U` check changes NOTHING, because `length - 1U` underflows to UINT64_MAX and the next guard refuses the same input. **Line 89 is therefore redundant with line 92**, and the underflow in line 92 is load-bearing: a future reader who 'fixes' it to `range.length > largest + 1U` would let a zero-length range through with a wrapped `smallest`. Both lines are kept -- an explicit RFC rule beside the arithmetic that enforces it is defence in depth -- but the redundancy is written down here because the suite cannot detect its removal.
- commit: 913fa5e

### AUD-0025 — The flow-control capsule rules the header states outright were unexecuted: trailing bytes, a partial varint, and an over-long close reason

- severity: S2 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: tests | discovered by: Tier A review, coverage-as-reviewer worklist (AUDIT/tier-a-review.md)
- where: C99/src/webtransport/capsule.c:194
- evidence before: `include/webtransport/webtransport/capsule.h` states the contract in prose -- "Parse the one-varint capsules. Anything but exactly one varint is H3_MESSAGE_ERROR: a flow-control value that is not a number is not a limit" -- and line coverage showed none of it executed: `parse_one`'s and `parse_two`'s refusals (trailing bytes, a partial varint, a missing second varint) and the over-long close reason were all at zero. Every capsule in the suite was a well-formed one, so those refusals could have been deleted with CI green. Capsules are peer input on WebTransport's own protocol layer.
- fix: Added `test_flow_control_values_must_be_exactly_one_varint` to `test_webtransport_capsule.c`: a value with trailing bytes, a value that is not a whole varint, a two-varint capsule carrying one, one carrying three, and a close reason past WT_CAPSULE_CLOSE_MAX_REASON -- each asserting WT_ERR_PROTOCOL and the message-error code the header promises. The close case uses zero bytes on purpose, which are valid UTF-8, so the length check is what refuses it and not the well-formedness check after it.
- evidence after: ["Coverage: `capsule.c` 19 uncovered lines -> 10, and the total 91.54% -> **91.60%** lines; no file lost coverage. Deliberate violation: removing `parse_one`'s `!wt_cursor_at_end` refusal fails the new test with `FAIL a flow-control value with trailing bytes is refused: want protocol, got ok` and `FAIL as a message error: want 270, got 256` (2 of 66 checks, exit 8); restoring it leaves `100% tests passed out of 97`. The guard-like uncovered-line worklist is now 285 lines in 53 files, down from 295 in 53, which is the figure the next Tier A round starts from."]
- commit: e2414e0

### AUD-0026 — Four of RFC 9204 section 4.5.1's decoding error exits and its wrap branch were never executed

- severity: S2 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: tests | discovered by: Tier A review, coverage-as-reviewer worklist (AUDIT/tier-a-review.md)
- where: C99/src/http3/qpack_header_prefix.c:90
- evidence before: The field-section prefix decoder implements RFC 9204 section 4.5.1's algorithm faithfully -- the code and the RFC's pseudocode match line for line, including the `full_range < max_entries` wrap guard -- but line coverage showed four of its six error exits and its wrap branch unexecuted: the integer decode failures for the encoded count and for the delta, the `required == 0` exit, the positive-delta overflow exit, and the `required -= full_range` subtraction. The existing tests covered the three most obvious exits, so the rest could have been lost quietly. This is peer input: the prefix is the first thing decoded in a field section.
- fix: Added `test_the_algorithm_s_refusals_are_all_reachable` to `test_qpack_header_prefix.c`, with each case aimed at one line of the algorithm rather than at "something malformed": a MaxEntries whose doubled full range wraps, an encoded count whose continuation runs past the 62-bit bound, the same for the delta after a valid count, a wrap that lands on zero, the wrap itself (six inserts known and a two-entry window, so an encoded two names nine and subtracts to five), and a positive delta that would carry the base past UINT64_MAX.
- evidence after: Coverage: `qpack_header_prefix.c` 18 uncovered lines -> 4, and the total 91.60% -> **91.69%** lines -- above the 91.64% recorded at AUD-0009, which the audit's own added branches had pushed down. No file lost coverage. The guard-like worklist is now **277 lines in 53 files**, from 295 when the worklist started, then 285 after AUD-0025. Deliberate violation: removing the `required == 0` exit fails the new test with `FAIL a wrap that lands on zero is refused: want protocol, got ok` and `FAIL as a decompression failure: want 512, got 0` (2 of 71 checks, exit 8); restoring leaves `100% tests passed out of 97`.
- commit: e339fdf

### AUD-0027 — A public API accepted a QPACK decoder capacity this build cannot honour, because nothing parses the encoder stream

- severity: S2 | tier: A | project: P2 | status: DONE | host: Mac14,3
- category: api | discovered by: Tier A review, following the coverage worklist into unreachable code (AUDIT/tier-a-review.md)
- where: C99/src/http3/endpoint.c:118
- evidence before: The coverage worklist showed 28 uncovered refusals in `qpack_encoder_stream.c`, and the reason turned out to be structural: `wt_qpack_encoder_stream_apply`, the decoder for the peer's encoder-stream instructions, has **no production caller** -- `wt_qpack_encoder_stream_init` is called only from tests. Verified end to end rather than assumed: the only caller of `wt_qpack_dynamic_insert` outside the tests is inside that unreachable path, and `decoder_insert_count` is only ever SET TO ZERO (endpoint.c:34, :126) and read, never incremented. So the endpoint's decoder table can never hold an entry. Meanwhile `wt_http3_endpoint_set_decoder_capacity` -- public API -- accepted any capacity, and its only caller anywhere was a test passing 0. A caller passing 4096 would put the endpoint into a mode it cannot honour: `max_entries` becomes non-zero, so every field-section prefix is read against a window that can never be populated, and every dynamic reference in it fails with a decompression error that BLAMES THE PEER. The build also advertises no QPACK capacity (the SETTINGS identifier is defined and never sent), so the two halves disagreed.
- fix: `wt_http3_endpoint_set_decoder_capacity` refuses a non-zero capacity with `WT_ERR_UNSUPPORTED` -- the status the library defines for exactly this, "something is not implemented or not compiled in ... so a caller can degrade deliberately". The comment and the header both state what is missing (the encoder stream is never parsed) and that the tested encoder-stream decoder is what would make the call meaningful, so the gap is visible to the next reader instead of silently accepted. Capacity 0 still succeeds and still makes `max_entries` zero, which is the correct state for an endpoint that advertises no dynamic table. A test asserts the refusal AND that the endpoint keeps the capacity it had.
- evidence after: `100% tests passed out of 97`, `check-format.sh`: all 312 C sources match. Deliberate violation: removing the refusal fails with `FAIL a capacity this build cannot fill is unsupported: want unsupported, got ok` and `FAIL and the endpoint keeps the capacity it had: want 0, got 4096` (2 of 181 checks, exit 8); restoring leaves the suite green. Not fixed by implementing the dynamic table -- that is a feature, not an audit repair, and the 247 tested lines of encoder-stream decoder are left in the tree with the wiring recorded as the remaining work rather than deleted.
- commit: PENDING

