# AUDIT — ledger

Generated from `AUDIT/ledger.json` by `AUDIT/render-ledger.sh`. Do not edit by hand.

Branch `audit/2026-09-18` | primary host Mac14,3 (macOS 27.0, Xcode 27.0, Swift 6.4) | baseline `397b047`

## Status counts

| status | count |
| --- | --- |
| BLOCKED | 2 |
| DONE | 12 |
| OPEN | 3 |

Non-terminal (open): 3
Terminal: 14

## Tasks

| id | severity | tier | project | status | title | file:line |
| --- | --- | --- | --- | --- | --- | --- |
| AUD-0001 | S3 | C | both | DONE | Record the pinned toolchain per language on the primary host | AUDIT/environment.md |
| AUD-0002 | S1 | C | both | BLOCKED | Phase E needs one independent host; none is provisioned | AUDIT/environment.md |
| AUD-0003 | S3 | C | both | DONE | Inventory, dependency graph, trust boundaries and tier table | AUDIT/inventory.md |
| AUD-0004 | S3 | C | both | DONE | Baseline both projects on the primary host | AUDIT/baseline.md |
| AUD-0005 | S2 | C | both | DONE | Tool-coverage and language-standard proofs for every delegated check | AUDIT/tool-coverage.md |
| AUD-0006 | S1 | A | P1 | OPEN | SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force | Package.swift |
| AUD-0007 | S1 | A | both | DONE | Ruff has no config, so B, E722, S101 and PT are not enabled | AUDIT/environment.md |
| AUD-0008 | S2 | A | P1 | BLOCKED | -require-explicit-sendable is enforced only per-invocation in CI, not in the build config | Package.swift:12-17 |
| AUD-0009 | S2 | B | P2 | DONE | No C99 coverage measurement exists, so one baseline metric is missing | C99/scripts/measure-coverage.sh |
| AUD-0010 | S3 | B | P2 | OPEN | No committed .clang-format and the tree is not clang-format clean | C99/ |
| AUD-0011 | S3 | C | both | DONE | Repository convention says audit ledgers are not kept in the tree; this audit mandates committing one | AUDIT/ledger.json |
| AUD-0012 | S2 | A | P1 | DONE | SwiftLint inclusive_language conflicts with RFC 8446 terminology | .swiftlint.yml |
| AUD-0013 | S1 | A | P1 | DONE | SwiftLint trailing_comma and swift-format rewrote each other, breaking a green gate | .swiftlint.yml |
| AUD-0014 | S1 | A | P1 | DONE | SwiftLint opening_brace conflicts with the committed formatter's multi-line condition style | .swiftlint.yml |
| AUD-0015 | S3 | A | P1 | DONE | identifier_name: rename what is internal, exclude only RFC-registry and public-API names | .swiftlint.yml |
| AUD-0016 | S1 | A | P1 | DONE | SwiftLint redundant_void_return's fix does not compile | .swiftlint.yml |
| AUD-0017 | S2 | B | P1 | OPEN | The API-compatibility check consumes the package by path, so it cannot catch unsafe-flags breakage | Swift/check-api-compatibility.sh |

## Detail

### AUD-0001 — Record the pinned toolchain per language on the primary host

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/environment.md
- evidence before: No AUDIT/environment.md existed; Xcode 27.0 / Swift 6.4 / clang / SwiftLint 0.65.1 / swift-format 603.0.0 / Ruff 0.16.7 / gitleaks 8.30.1 / trivy 0.74.0 / cppcheck 2.21.0 / llvm 23.1.1 all present but unrecorded
- fix: Wrote AUDIT/environment.md with name, version, install method and host per tool, plus the exact build-config mapping from the mandated Xcode settings to this SwiftPM-only repository
- evidence after: AUDIT/environment.md committed
- commit: 

### AUD-0002 — Phase E needs one independent host; none is provisioned

- severity: S1 | tier: C | project: both | status: BLOCKED | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/environment.md
- evidence before: Only Mac14,3 exists in this session; Phase E requires a fresh clone on one independent host, and a fresh clone on the same host is not independent
- fix: 
- evidence after: 
- commit: 
- BLOCKED: owner: repository owner. No second host is available and provisioning one (VPS) requires explicit approval per the standard. Tried: nothing (not attempted, by rule). Options for the human: (1) approve a VPS/CI runner and provide access, (2) nominate an existing independent machine and provide access, (3) accept a documented waiver that Phase E ran on the primary host only.

### AUD-0003 — Inventory, dependency graph, trust boundaries and tier table

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/inventory.md
- evidence before: No committed inventory; tiers had never been assigned
- fix: AUDIT/inventory.md: two projects, Swift target graph from dump-package, C99 layering, five cross-project contracts, seven trust boundaries, per-module tiers
- evidence after: AUDIT/inventory.md committed
- commit: 

### AUD-0004 — Baseline both projects on the primary host

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/baseline.md
- evidence before: No committed baseline; the repository's own claims were the only numbers
- fix: AUDIT/baseline.md: Swift 0 warnings / 400 tests / 90.74% line coverage; C99 0 warnings / 97 tests; gitleaks 713 commits clean; trivy clean
- evidence after: AUDIT/baseline.md committed
- commit: 

### AUD-0005 — Tool-coverage and language-standard proofs for every delegated check

- severity: S2 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/tool-coverage.md
- evidence before: No proof that any delegated check is actually enforced; SwiftLint and Ruff are not even configured
- fix: Proved every delegated check against a deliberate violation and recorded the tool's own output in AUDIT/tool-coverage.md: Swift 6 strict concurrency (escaping @Sendable capture -> #SendableClosureCaptures, build exit 1), C99 (implicit declaration and a GNU nested function both rejected under the project's real flags), swift-format (Indentation/Spacing errors), Ruff (B006/E722/S101/PT011), gitleaks (leaks found: 1), SwiftLint (force_unwrapping and the rest), cppcheck (arrayIndexOutOfBounds + memleak), clang --analyze (core.NullDereference) and trivy (1 secret).
- evidence after: AUDIT/tool-coverage.md carries each violation, the exact command and the tool output. One honest correction is recorded there: the first Swift concurrency violation COMPILED, because Swift 6's region-based isolation legitimately permits transferring a uniquely referenced value into a task; the proof was replaced with a genuinely illegal escaping-capture form. A proof that passes for the wrong reason is not a proof.
- commit: 

### AUD-0006 — SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force

- severity: S1 | tier: A | project: P1 | status: OPEN | host: Mac14,3
- category: standards | discovered by: phase-a
- where: Package.swift
- evidence before: git ls-files shows no .swiftlint.yml; no workflow step invokes swiftlint; `swiftlint lint Swift/Sources` reports 317 findings (292 warning, 25 error) that nothing consumes
- fix: In progress. Added the committed .swiftlint.yml the standard requires: SwiftLint's default rules plus opt_in force_unwrapping, line_length aligned to the committed .swift-format 160 and file_length to the repository's documented 1000-line ceiling, with five justified rule deviations each carrying its own task (AUD-0012..AUD-0016). Fixed every non-structural finding: 10 force_unwraps and 1 force-try (production and tests), 3 lossy String(decoding:), 4 orphaned doc comments, 18 naming findings, and the mechanical correctables.
- evidence after: Configured `swiftlint --strict`: 556 findings -> 54, all function-level (38 function_body_length, 16 cyclomatic_complexity). Every type_body_length finding is fixed by splitting the eleven oversized types into extensions; the difference classifier, the 453-line scenario catalogue and the conformance orchestrator (complexity 41) are split into named helpers. `swift test`: 400 passed. `swift format lint --strict`: clean. `WebTransportClient --list` still reports 40 scenarios after the catalogue split. The CI gate is NOT yet wired: it stays unwired until it can be green.
- commit: 

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
- commit: 

### AUD-0010 — No committed .clang-format and the tree is not clang-format clean

- severity: S3 | tier: B | project: P2 | status: OPEN | host: Mac14,3
- category: standards | discovered by: phase-a
- where: C99/
- evidence before: clang-format 23.1.1 is installed; git ls-files shows no .clang-format; the tree's style is hand-maintained and has never been machine-checked
- fix: 
- evidence after: 
- commit: 

### AUD-0011 — Repository convention says audit ledgers are not kept in the tree; this audit mandates committing one

- severity: S3 | tier: C | project: both | status: DONE | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/ledger.json
- evidence before: The wiki's Project Tracker states the audits' working material (ledgers, per-area findings, reports) is deliberately not kept in the tree, because a later audit should read the code rather than a finished pass
- fix: Followed the audit instruction, which is the more specific and more recent authority, and recorded the conflict here and in the final report instead of silently diverging. AUDIT/ is additive and on the audit branch only
- evidence after: This entry
- commit: 

### AUD-0012 — SwiftLint inclusive_language conflicts with RFC 8446 terminology

- severity: S2 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 8 findings, all `masterSecret` / `exporterMasterSecret` in WebTransportTLSCore
- fix: Rule disabled in the committed config with the reason: RFC 8446 section 7.1 defines the master secret, and renaming a reference implementation's symbols away from the document it implements makes it harder to read against the spec.
- evidence after: `swiftlint lint` reports no inclusive_language findings; the reason is in .swiftlint.yml and here
- commit: 

### AUD-0013 — SwiftLint trailing_comma and swift-format rewrote each other, breaking a green gate

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 43 trailing_comma findings; `swiftlint --fix` removed the trailing commas the committed .swift-format requires
- fix: Rule disabled: the formatter owns comma placement. Proven rather than asserted -- after `swiftlint --fix`, `swift format lint --strict` failed with `[TrailingComma] add trailing comma to the last element`, and `swift format --in-place` restored it.
- evidence after: `swift format lint --strict` exits 0; `swiftlint lint` reports no trailing_comma findings; 400 Swift tests pass
- commit: 

### AUD-0014 — SwiftLint opening_brace conflicts with the committed formatter's multi-line condition style

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 13 opening_brace findings that survive `swift format --in-place`
- fix: Rule disabled: after the formatter ran in place over the tree, `swiftlint lint` still reported 13 opening_brace violations, so the two cannot both be satisfied; the formatter is the CI-enforced owner.
- evidence after: `swift format lint --strict` exits 0 and no opening_brace findings remain
- commit: 

### AUD-0015 — identifier_name: rename what is internal, exclude only RFC-registry and public-API names

- severity: S3 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: 13 findings: `iv` x5, `aes128GCM_SHA256`, `fd`, `ok`, `i`/`z` x3, and two over-length names
- fix: Renamed the internal identifiers for real (InteroperableQUIC* -> *, the long producer/request-stream names, fd -> descriptor, i -> index, z -> hash, ok -> accepted, the long test suite type). Excluded only `iv` (RFC 9001's own term), `aes128GCM_SHA256` and `webTransportPyWebTransportStreamInteropDefaults` (public API; renaming would break consumers and the api-compat gate), and restored SwiftLint's DEFAULT exclusion (`id`), which setting `excluded` had silently replaced -- caught because the finding count went UP, 13 -> 43.
- evidence after: `swiftlint lint` reports zero identifier_name findings; 400 Swift tests pass; a rename that also hit the POSIX `pollfd(fd:)` label was caught by the compiler and corrected
- commit: 

### AUD-0016 — SwiftLint redundant_void_return's fix does not compile

- severity: S1 | tier: A | project: P1 | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-b
- where: .swiftlint.yml
- evidence before: `swiftlint --fix` removed an explicit `-> Void` from a closure in WebTransportLoopbackTestLockTests; `swift build --build-tests` then failed with `result of call to 'withLockAsync(label:maximumWait:filePath:_:)' is unused`
- fix: Rule disabled with the reproduction: the closure's signature participates in generic inference, so dropping `-> Void` makes `withLockAsync` return a non-Void whose result is unused under strict memory safety. The `-> Void` is restored and commented as load-bearing.
- evidence after: `swift build --build-tests` succeeds; `swift test` 400 passed; `swift format lint --strict` accepts the restored signature
- commit: 

### AUD-0017 — The API-compatibility check consumes the package by path, so it cannot catch unsafe-flags breakage

- severity: S2 | tier: B | project: P1 | status: OPEN | host: Mac14,3
- category: tests | discovered by: AUD-0008
- where: Swift/check-api-compatibility.sh
- evidence before: Found while testing AUD-0008: adding `.unsafeFlags(["-require-explicit-sendable"])` to the library targets still let `./Swift/check-api-compatibility.sh` pass. SwiftPM refuses unsafe build flags only for VERSION-BASED dependencies, and the check builds a consumer with `.package(path: ...)`, so the one gate whose job is to prove a consumer still builds is structurally unable to catch a change that stops consumers building.
- fix: 
- evidence after: 
- commit: 

