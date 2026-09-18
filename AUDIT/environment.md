# AUDIT — environment record

Phase A, task AUD-0001 (record the toolchain). One pinned toolchain per language, one
primary host, recorded with name, version, install method and host.

## Primary host

| Fact | Value |
| --- | --- |
| Host | `Mac14,3` (Apple Silicon, arm64), macOS 27.0 (26A428) |
| Memory | 8 GB — one heavy job at a time (§1b). Serialized, never two. |
| Disk | 42 GiB free |
| Xcode | Xcode 27.0, build 27A266a — `xcode-select -p` = `/Applications/Xcode.app/Contents/Developer` |
| Swift | Apple Swift 6.4 (swiftlang-6.4.0.34.1, clang-2100.3.34.1), target `arm64-apple-macosx27.0.0` |
| Role | Primary host for both projects (Apple-platform work: Swift + the C99 tree's macOS/Darwin work) |

`xcodebuild -version` and `swift --version` both report the mandated floor (Swift 6.4 /
Xcode 27), so the Swift language standard is not BLOCKED.

**Independent host for Phase E: none assigned.** §1b requires one independent host to run
the single final verification. No second host has been provisioned, and §1b says to ask
before provisioning a VPS. Phase E is therefore not satisfiable yet; it is recorded as a
human task with a named owner rather than worked around by calling a fresh clone on this
host "independent". See the ledger (`AUD-0002`, BLOCKED).

## Pinned toolchain

Install method for everything outside Xcode is Homebrew (`/opt/homebrew`, formula
versions shown). The secret scanner and the dependency/CVE scanner are pinned to the same
versions CI uses.

| Language | Tool | Role | Version | Install | Host |
| --- | --- | --- | --- | --- | --- |
| Swift | `swift` / `swiftc` | compiler, type checker | 6.4 (Xcode 27.0) | Xcode 27 | Mac14,3 |
| Swift | `swift-format` | formatter + linter | 603.0.0 | `brew install swift-format` | Mac14,3 |
| Swift | `swiftlint` | linter (`--strict`) | 0.65.1 | CI installs the pinned release: `portable_swiftlint.zip` from the 0.65.1 GitHub release, sha256 `c1e429b0599cf1b516f369a2d9ec04eaf0e436f3c12b637df8851fa52ff694d0`. The release publishes no checksum file, so the digest was taken from the downloaded asset and is asserted in `swift-ci.yml`; the asset unpacks to a universal binary reporting `0.65.1` | Mac14,3 |
| C | Apple `clang` (`/usr/bin/clang`) | compiler for the CMake tree | Apple clang 21.0.0 (clang-2100.3.34.2) | Xcode 27 | Mac14,3 |
| C | Homebrew `clang` | second compiler for portability probes | Homebrew clang 23.1.1 | `brew install llvm` | Mac14,3 |
| C | `clang-format` | formatter | 23.1.1 (llvm) | `brew install llvm` | Mac14,3 |
| C | `scan-build` (Clang Static Analyzer) | SAST | from llvm 23.1.1 | `brew install llvm` | Mac14,3 |
| C | `cppcheck` | SAST | 2.21.0 | `brew install cppcheck` | Mac14,3 |
| C | ASan / UBSan | sanitizer/memory checker | toolchain runtimes | Xcode 27 | Mac14,3 |
| C | `cmake` / `ninja` | build system | 4.4.3 / 1.13.2 | `brew install cmake ninja` | Mac14,3 |
| Python | `python3` | interpreter for test/glue scripts | 3.14.7 | `brew install python@3.14` | Mac14,3 |
| Python | `ruff` | formatter + linter (`--fix`) | 0.16.7 | `brew install ruff` | Mac14,3 |
| Python | `pip-audit` | dependency CVE scan | **not installed** | `brew install pip-audit` | — |
| Any | `gitleaks` | secret scan, full history | 8.30.1 | `brew install gitleaks` | Mac14,3 |
| Any | `trivy` | dependency/config CVE scan | 0.74.0 | `brew install trivy` | Mac14,3 |
| Shell | `shellcheck` | linter for the 41 tracked shell scripts | 0.11.0 | `brew install shellcheck` | Mac14,3 |
| Shell | `shfmt` | formatter for the same | 3.14.1 | `brew install shfmt` | Mac14,3 |
| Any | `jq` | required by two repo check scripts | 1.8.2 | `brew install jq` | Mac14,3 |

Notes on the two "missing" entries:

- `pip-audit` is not installed **and is not applicable as a gate**: the repository has no
  `requirements.txt`, `pyproject.toml`, `poetry.lock` or `Pipfile` (checked with
  `git ls-files`), and the 16 Python files are test/glue scripts that import only the
  standard library plus (in the interop peers) wheels installed inside container images
  built in CI. §1 says to run `pip-audit` once at baseline *if* a requirements/lock file
  exists. It does not, so this is recorded as not-applicable rather than BLOCKED. If a
  lock file is added later this becomes a real task.
- `scan-build --version` is not a supported option in llvm 23.1.1; the analyzer version is
  the llvm formula's 23.1.1, recorded above.

## Language standards, as actually in force

§3 requires recording the standard actually enforced, not the intended one. `SWIFT_VERSION`
/ `SWIFT_STRICT_CONCURRENCY` / `SWIFT_TREAT_WARNINGS_AS_ERRORS` are Xcode build settings;
this repository is SwiftPM-only, so the equivalent settings are the `swiftSettings` in the
two `Package.swift` files. The mapping and the current state:

| Standard requirement | SwiftPM equivalent | State at baseline |
| --- | --- | --- |
| Swift 6 language mode | `.swiftLanguageMode(.v6)` (default for `swift-tools-version: 6.4`) | **implicit** — tools-version 6.4 defaults to Swift 6 mode; not stated in the manifest |
| Complete strict concurrency | default under Swift 6 language mode | **in force** (proven below) |
| Warnings as errors | `.treatAllWarnings(as: .error)` (`Package.swift:17`) | **in force** |
| `-require-explicit-sendable` | `.unsafeFlags(["-require-explicit-sendable"])` or an upcoming feature | **only per-invocation** in `swift-ci.yml`; not in build config → finding |
| Committed formatter config, run | `.swift-format` is committed | **in force** (CI runs `swift format lint --strict`) |
| Committed SwiftLint config, run `--strict` | `.swiftlint.yml` | **present**, and run `--strict` by the `Lint with SwiftLint` step in `swift-ci.yml`; the tree is at zero findings (AUD-0006 closed) |
| Strict memory safety | `.strictMemorySafety()` (`Package.swift:12`) | **in force** (beyond the standard) |

| Standard requirement | CMake equivalent | State at baseline |
| --- | --- | --- |
| C99, no extensions | `C_STANDARD 99`, `C_STANDARD_REQUIRED ON`, `C_EXTENSIONS OFF` (`C99/cmake/WTCompilerWarnings.cmake:62-67`) | **in force** |
| `-pedantic-errors` | `-Wpedantic` + `-Werror` (`:26-27`) | **equivalent** — with `-Werror` every pedantic diagnostic is an error; proven below |
| warnings-as-errors | `-Werror` (`:26`), `/WX` for MSVC (`:20`) | **in force** |
| `-Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wwrite-strings -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes` | all present, plus `-Wcast-align -Wmissing-declarations -Wold-style-definition -Wredundant-decls -Wundef -Wpointer-arith -Wfloat-equal -Wswitch-enum -Wvla -Wnull-dereference -Wdouble-promotion` (`:23-48`) | **in force** (superset) |

| Standard requirement | State at baseline |
| --- | --- |
| Python: one pinned interpreter, Ruff for format+lint with `--fix` | interpreter pinned (3.14.7); Ruff installed but **no config**, so B / E722 / S101 / PT are not enabled → finding |
| Python: no mypy/pyright, no per-file coverage targets, no matrix | correctly de-scoped by the standard; nothing to do |

## Tool-coverage and language-standard proofs

Both proofs are recorded in `AUDIT/tool-coverage.md`, with the violating snippet and the
tool's own output. A delegation is only counted as covered where the tool was seen to
reject the violation.
