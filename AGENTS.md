# WebTransport

<!-- agent-harnesses:begin -->
> **One instruction file.** This is it. Codex, DeepSeek Harness, OpenCode,
> Qwen Code, Qoder and Zed read `AGENTS.md` directly, and Claude Code reads it
> through the committed `CLAUDE.md`, which contains nothing but `@AGENTS.md`.
> **Edit only this file** — do not add a second set of instructions anywhere.
>
> Do **not** add `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
> `.github/copilot-instructions.md` or `AGENT.md`. Zed takes the *first match*
> from that list, **ahead of `AGENTS.md`**, so any one of them silently
> replaces this file for every Zed user.
<!-- agent-harnesses:end -->

A reference implementation of WebTransport over HTTP/3, shipped as **two
independent libraries in one repository**: a Swift package (async client/server API
plus layered QUIC/TLS/HTTP-3 modules and two CLI peers) and, under `C99/`, a
separate CMake C99 library with its own CLI tools and test suite. The two are
built and tested separately and versioned in lockstep from a single `VERSION` file,
so a caller pairing them knows the pair is compatible. Both are released together
(`1.5.2`, one artifact per library under one tag); the C99 side is built and
exercised — 97 CTest tests, ASan/UBSan, Windows under Wine and natively, and
FreeBSD in a VM. The
audience is protocol implementers reading a
reference implementation, so exact wire behaviour matters more than convenience.
Open work is tracked on the repository's wiki — [Project Tracker](https://github.com/Pummelchen/WebTransport/wiki/Project-Tracker)
and the C99 tree's [Project Tracker C99](https://github.com/Pummelchen/WebTransport/wiki/Project-Tracker-C99) —
not as TODO markers in the tree.

## Layout

- `Package.swift` — repo root; the supported SwiftPM entry point for applications.
- `Swift/Package.swift` — nested manifest adding smoke executables and test
  support over the same sources. Both manifests compile `Swift/Sources/`.
- `Swift/Sources/` — every SwiftPM target's sources live here: `WebTransport`
  (public API), `WebTransportNetworkRuntime`, `WebTransportHTTP3Core`,
  `WebTransportQUICCore`, `WebTransportTLSCore`, `WebTransportCryptoApple`,
  `WebTransportUDPApple`, `WebTransportSecurityShim`, `WebTransportCLIConformance`,
  `WebTransportClient` / `WebTransportServer`, and — declared by the nested
  manifest only — `WebTransportTestSupport`, `LibrarySmokeClient` /
  `LibrarySmokeServer`.
- `C99/` — a self-contained CMake project: `cmake/`, `docs/`,
  `include/webtransport/`, `platform/`, `scripts/`,
  `src/{api,cli,core,crypto,http3,quic,runtime,tls,webtransport}`,
  `apps/{wt-client-c99,wt-server-c99,wt-conformance-c99,wt-api-sample,support}`,
  `tests/`, `third_party/`. `out/` is generated build output (only its
  `.gitignore` and `README.md` are tracked).

## Build, test, run

```bash
# Swift
swift build                                   # or: swift build --package-path Swift
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all

# C99 — the documented loop, or the CI invocation verbatim:
C99/scripts/build-and-test.sh                 # --release | --sanitize | --all
cmake -S C99 -B C99/out/ci/build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DWEBTRANSPORT_C99_BUILD_APPS=ON
cmake --build C99/out/ci/build
ctest --test-dir C99/out/ci/build --output-on-failure
```

The C99 build produces `wt-client-c99`, `wt-server-c99` and `wt-conformance-c99`.
Note the two writing to different places: the script uses
`C99/out/<platform>/<config>`, the CI invocation `C99/out/ci/build`.
`--scenario all` is the conformance suite the two Swift CLIs share (40 scenarios,
one catalog for the client and the server); the two Release scenarios need the
repository as the working directory (see Traps). The C99 conformance tool has its own
`--scenario all`, a separate suite of 57 scenarios and not the same catalog.

## Identity

**The two libraries always carry the same version number**, even when only one of
them changed — a caller pairing them has no other way to know the pair is
compatible, so the unchanged one is recompiled at the new number rather than left
behind.

**The lockstep is landed and enforced.** `VERSION` at the repository root (currently
`1.5.2`) is the single source; it is mirrored in
`C99/include/webtransport/version.h` (`WT_VERSION_MAJOR/MINOR/PATCH`) and in
`Swift/Sources/WebTransport/WebTransportVersion.swift` (`WebTransportVersion.library`).
A bump is one edit plus one command: write `VERSION`, then run
`./Swift/check-version-sync.sh --write`. `Swift/check-version-sync.sh` fails when the
three disagree, and the C99 CMake configure fails on the same mismatch, so a
C99-only build cannot produce a library whose filename and whose
`wt_version_string()` disagree. The C99 tests derive the expected string from the
header (`WT_TEST_VERSION_STRING`) instead of repeating a literal, because a literal
is a second place to bump.

The **ABI version** (`WT_ABI_VERSION`) and the **protocol draft** are separate axes:
they do not follow the library version and must not be bumped with it.

## Gates

- Swift (`.github/workflows/swift-ci.yml`, image `xcode-27`): `./Swift/check-toolchain.sh 6.4 27.0`,
  `./Swift/check-manifest-sync.sh`, `./Swift/check-version-sync.sh`,
  `./Swift/check-target-imports.sh`,
  `./Swift/check-pkcs12-keychain-free.sh` (resolves a PKCS#12 identity while the default
  keychain is locked, which is the only state in which the memory-only import is
  distinguishable from one that files the key),
  `swift format lint --strict --recursive --parallel Swift/Sources Swift/Tests Package.swift Swift/Package.swift`,
  both manifests built under
  `-warnings-as-errors -strict-concurrency=complete -require-explicit-sendable`,
  the DocC catalog validated, `./check-api-compatibility.sh`,
  `./build-release-apple-silicon.sh`, the package tests, the nested manifest's own
  test target (`swift test --package-path Swift --filter WebTransportTestSupportTests`),
  the library smoke pair (`Swift/run-library-smoke.sh`), the client and server CLI
  conformance suites (`--scenario all`), a 20000-iteration ASan fuzz run, and a
  thread-sanitizer job that skips `CLIProcess` / `ReleaseArtifacts`.
- C99 (`.github/workflows/c99-ci.yml`): a macOS and `ubuntu-24.04` matrix (gcc and
  clang) building Debug and Release and running the suite under ASan+UBSan, a
  `linux-debian13` job in a `debian:trixie` container, and a `freebsd` job that boots
  a FreeBSD VM on an Ubuntu runner and runs the same configure, build and ctest there;
  `check-vectors.sh`,
  `check-package.sh` (builds a consumer of the installed package and *runs* all
  three installed tools), `check-matrix.sh`, `check-portability.sh`,
  `check-static-analysis.sh` (Clang Static Analyzer), `check-cppcheck.sh`,
  `check-workflows.py`, and a CLI smoke step. A CMake configure fails when the
  version mirrors disagree. Three Windows checks: `check-windows-platform.sh`,
  `check-windows-build.sh` and `check-windows-wine.sh` on the Ubuntu leg, plus the
  **enforced** `windows-native` job on `windows-latest` (MSYS2 MINGW64). Two more
  Windows jobs run the same configure, build and ctest under the compilers the plan's
  Phase 12 matrix names: `msvc` and `clang-cl`.
- `security-scan.yml`: gitleaks 8.30.1 over full history, trivy 0.74.0.

## Traps

- **Two libraries that share a repository and nothing else.** Editing `C99/` does
  not affect `Package.swift`. Their versions ARE tied by the lockstep gate, so bump
  `VERSION` and run `./Swift/check-version-sync.sh --write` rather than editing the
  mirrors by hand.
- **The C99 packaging scripts use different build directories from the dev loop.**
  `C99/platform/*/compile-*.sh` write `out/<platform>/build-install` and install to
  `out/<platform>/install`; `C99/scripts/build-and-test.sh` configures
  `out/<platform>/build{,-release,-sanitize}` with Ninja. The two use different
  generators, so pointing them at one directory fails with "Does not match the
  generator used previously".
- **`check-manifest-sync.sh` is not a version gate.** It diffs shared SwiftPM
  targets (path/type/dependencies) between the two manifests via
  `swift package dump-package`, and exits 1 if `jq` is not on `PATH`.
- **The formatting gate covers both manifests.** CI runs `swift format lint` over
  `Swift/Sources Swift/Tests Package.swift Swift/Package.swift`, so a tree formatted
  over the sources alone still fails it. The in-place command is
  `swift format --in-place --recursive Swift/Sources Swift/Tests Package.swift Swift/Package.swift`.
- Swift requires macOS 26+, Xcode 27 and Swift 6.4 (`swift-tools-version: 6.4`,
  `.macOS(.v26)`).
- `Swift/build-release-apple-silicon.sh` builds `--arch arm64` and **fails unless
  `lipo -archs` returns exactly `arm64`**; it then rebuilds cleanly and compares
  normalized Mach-O hashes for reproducibility. arm64 only — no universal binary
  is produced or accepted.
- C99 needs CMake ≥ 3.28, Ninja and OpenSSL 3.0 (`find_package(OpenSSL 3.0
  REQUIRED)`); any crypto backend other than `openssl` is a hard `FATAL_ERROR` at
  configure time.
- **C99 sanitizers need their own configure directory**
  (`-DWEBTRANSPORT_C99_SANITIZE=ON`). CMake caches compiler flags, so enabling them
  in an existing build directory silently does nothing.
- Darwin has no LeakSanitizer and aborts if `detect_leaks` is requested — leaks
  are found by the Linux CI leg, not by a local macOS run.
- Two CLI conformance scenarios read `Package.swift` and
  `Swift/build-release-apple-silicon.sh` **relative to the working directory**.
  Run from an assets-only directory and the suite reports
  `passed=38 failed=0 skipped=2` and exits **3** — a pass that looks like a failure.
- The built-in development certificate is refused on any non-loopback bind
  address, so a server that previously bound `0.0.0.0` now fails at startup by
  design.

## Releasing

**Read [`RELEASE.md`](RELEASE.md) before cutting a release.** It is this repository's
own release standard — edited here, not deployed from anywhere — and it carries both
the general rules and this repository's own section. Do not improvise a release.
The cut itself is `./release-macos-arm64.sh` — a dry run unless given `--publish`
(or `--republish`) — and it packs both libraries under one tag.

The non-negotiables:

- **Apple Silicon only** — build native `arm64` (M1–M6). Never `--arch x86_64`,
  never `ARCHS=arm64 x86_64`, and never `lipo -create`, which is how a universal
  binary gets made.
- **Assert it** — `lipo -archs <binary>` must report exactly `arm64`. A build that
  silently produced a fat binary is a release defect, not a build option.
- **Every release carries the artifacts.** A tag alone is not a release.
- **Identity is single-sourced and enforced** — never bump one declaration of the
  version or build number on its own; the build or CI must fail on a mismatch.
- **Dry run first**; publish only on an explicit flag.
- **Never fetch a model, dataset or dependency to make a gate pass.** A check that
  cannot run is reported *not checked*, and the release notes must name it.
