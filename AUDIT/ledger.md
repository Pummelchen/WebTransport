# AUDIT — ledger

Generated from `AUDIT/ledger.json` by `AUDIT/render-ledger.sh`. Do not edit by hand.

Branch `audit/2026-09-18` | primary host Mac14,3 (macOS 27.0, Xcode 27.0, Swift 6.4) | baseline `397b047`

## Status counts

| status | count |
| --- | --- |
| BLOCKED | 1 |
| DONE | 5 |
| OPEN | 5 |

Non-terminal (open): 5
Terminal: 6

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
- fix: 
- evidence after: 
- commit: 

### AUD-0007 — Ruff has no config, so B, E722, S101 and PT are not enabled

- severity: S1 | tier: A | project: both | status: DONE | host: Mac14,3
- category: standards | discovered by: phase-a
- where: AUDIT/environment.md
- evidence before: No ruff.toml/pyproject.toml; `ruff check` over the 16 tracked Python files reports 22 findings from the default rule set only, which does not include the bare-except, assert or pytest-style rules the standard names
- fix: Added ruff.toml: one pinned interpreter, line-length 120, and an explicit select of E/F/W plus the standard's B, E722, S101, PT, plus EXE (a tool-default rule that flags a shebang without an exec bit). Fixed the 5 findings the configured set reports (1 F401 unused import, 1 E401 multiple imports, 3 F841 dead variables - two of which were dead duplicates of the real render_vectors output, not missing output), ran ruff format over the tree (12 files), and set 7 exec bits. Added a python-lint job to c99-ci.yml running ruff check . and ruff format --check . so the config is in force rather than decorative.
- evidence after: ruff check . -> 'All checks passed!'; ruff format --check . -> '48 files already formatted'; C99/scripts/check-vectors.sh -> all 5 vectors still reproduce after the reformat; rule proofs (B006/E722/S101/PT011) in AUDIT/tool-coverage.md; workflows parse (C99/scripts/check-workflows.py)
- commit: 

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

