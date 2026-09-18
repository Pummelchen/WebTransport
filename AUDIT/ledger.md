# AUDIT — ledger

Generated from `AUDIT/ledger.json` by `AUDIT/render-ledger.sh`. Do not edit by hand.

Branch `audit/2026-09-18` | primary host Mac14,3 (macOS 27.0, Xcode 27.0, Swift 6.4) | baseline `397b047`

## Status counts

| status | count |
| --- | --- |
| BLOCKED | 1 |
| DONE | 10 |
| OPEN | 5 |

Non-terminal (open): 5
Terminal: 11

## Tasks

| id | severity | tier | project | status | title | file:line |
| --- | --- | --- | --- | --- | --- | --- |
| AUD-0001 | S3 | C | both | DONE | Record the pinned toolchain per language on the primary host | AUDIT/environment.md |
| AUD-0002 | S1 | C | both | BLOCKED | Phase E needs one independent host; none is provisioned | AUDIT/environment.md |
| AUD-0003 | S3 | C | both | DONE | Inventory, dependency graph, trust boundaries and tier table | AUDIT/inventory.md |
| AUD-0004 | S3 | C | both | DONE | Baseline both projects on the primary host | AUDIT/baseline.md |
| AUD-0005 | S2 | C | both | OPEN | Tool-coverage and language-standard proofs for every delegated check | AUDIT/tool-coverage.md |
| AUD-0006 | S1 | A | P1 | OPEN | SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force | Package.swift |
| AUD-0007 | S1 | A | both | DONE | Ruff has no config, so B, E722, S101 and PT are not enabled | AUDIT/environment.md |
| AUD-0008 | S2 | A | P1 | OPEN | -require-explicit-sendable is enforced only per-invocation in CI, not in the build config | Package.swift:12-17 |
| AUD-0009 | S2 | B | P2 | OPEN | No C99 coverage measurement exists, so one baseline metric is missing | C99/CMakeLists.txt |
| AUD-0010 | S3 | B | P2 | OPEN | No committed .clang-format and the tree is not clang-format clean | C99/ |
| AUD-0011 | S3 | C | both | DONE | Repository convention says audit ledgers are not kept in the tree; this audit mandates committing one | AUDIT/ledger.json |
| AUD-0012 | S2 | A | P1 | DONE | SwiftLint inclusive_language conflicts with RFC 8446 terminology | .swiftlint.yml |
| AUD-0013 | S1 | A | P1 | DONE | SwiftLint trailing_comma and swift-format rewrote each other, breaking a green gate | .swiftlint.yml |
| AUD-0014 | S1 | A | P1 | DONE | SwiftLint opening_brace conflicts with the committed formatter's multi-line condition style | .swiftlint.yml |
| AUD-0015 | S3 | A | P1 | DONE | identifier_name: rename what is internal, exclude only RFC-registry and public-API names | .swiftlint.yml |
| AUD-0016 | S1 | A | P1 | DONE | SwiftLint redundant_void_return's fix does not compile | .swiftlint.yml |

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

- severity: S2 | tier: C | project: both | status: OPEN | host: Mac14,3
- category: process | discovered by: phase-a
- where: AUDIT/tool-coverage.md
- evidence before: No proof that any delegated check is actually enforced; SwiftLint and Ruff are not even configured
- fix: In progress: Swift language-standard, C language-standard, swift-format, Ruff and gitleaks proofs recorded in AUDIT/tool-coverage.md. Outstanding: SwiftLint (blocked on AUD-0006), and cppcheck/scan-build/trivy coverage proofs.
- evidence after: 
- commit: 

### AUD-0006 — SwiftLint is installed but has no committed config and is not run, so the mandated Swift linter is not in force

- severity: S1 | tier: A | project: P1 | status: OPEN | host: Mac14,3
- category: standards | discovered by: phase-a
- where: Package.swift
- evidence before: git ls-files shows no .swiftlint.yml; no workflow step invokes swiftlint; `swiftlint lint Swift/Sources` reports 317 findings (292 warning, 25 error) that nothing consumes
- fix: In progress. Added the committed .swiftlint.yml the standard requires: SwiftLint's default rules plus opt_in force_unwrapping, line_length aligned to the committed .swift-format 160 and file_length to the repository's documented 1000-line ceiling, with five justified rule deviations each carrying its own task (AUD-0012..AUD-0016). Fixed every non-structural finding: 10 force_unwraps and 1 force-try (production and tests), 3 lossy String(decoding:), 4 orphaned doc comments, 18 naming findings, and the mechanical correctables.
- evidence after: Unconfigured `swiftlint lint`: 556 findings -> 85 with the committed config. Remaining: 39 function_body_length, 18 cyclomatic_complexity, 11 type_body_length (68 structural, S2 refactors), 10 line_length (lines over 160 that swift-format cannot split), 3 function_parameter_count, 2 large_tuple, 2 nesting. `swift test` 400 passed; `swift format lint --strict` clean. The CI gate is NOT wired yet, because wiring it before the structural findings are refactored would add a red gate, and configuring the thresholds up would be the weakening the standard forbids.
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

- severity: S2 | tier: A | project: P1 | status: OPEN | host: Mac14,3
- category: standards | discovered by: phase-a
- where: Package.swift:12-17
- evidence before: swift-ci.yml passes -Xswiftc -require-explicit-sendable; Package.swift carries strictMemorySafety and treatAllWarnings but not the flag, so a local `swift build`/`swift test` accepts a public type that omits Sendable
- fix: 
- evidence after: 
- commit: 

### AUD-0009 — No C99 coverage measurement exists, so one baseline metric is missing

- severity: S2 | tier: B | project: P2 | status: OPEN | host: Mac14,3
- category: tests | discovered by: phase-a
- where: C99/CMakeLists.txt
- evidence before: No gcovr/lcov installed and no coverage configuration in the CMake tree; `C99/scripts/build-and-test.sh` runs 97 tests without instrumentation
- fix: 
- evidence after: 
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

