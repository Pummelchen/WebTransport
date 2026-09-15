# WebTransport

A reference implementation of WebTransport over HTTP/3, shipped as **two
independent libraries in one repository**: a Swift package (async client/server API
plus layered QUIC/TLS/HTTP-3 modules and two CLI peers) and, under `C99/`, a
separate CMake C99 library with its own CLI tools and test suite. The two are
built, tested and versioned separately, and nothing in the build ties one's version
to the other's. The Swift side is released (`1.3.8`); the C99 side is built and
exercised — 97 CTest tests, ASan/UBSan, Windows-under-Wine, FreeBSD by hand — but
still declares a pre-1.0 identity. The audience is protocol implementers reading a
reference implementation, so exact wire behaviour matters more than convenience.

## Layout

- `Package.swift` — repo root; the supported SwiftPM entry point for applications.
- `Swift/Package.swift` — nested manifest adding smoke executables and test
  support over the same sources. Both manifests compile `Swift/Sources/`.
- `Swift/Sources/` — `WebTransport` (public API), `WebTransportNetworkRuntime`,
  `WebTransportHTTP3Core`, `WebTransportQUICCore`, `WebTransportTLSCore`,
  `WebTransportCryptoApple`, `WebTransportUDPApple`, `WebTransportClient` /
  `WebTransportServer`, `WebTransportCLIConformance`.
- `C99/` — a self-contained CMake project: `include/webtransport/`,
  `src/{core,crypto,quic,tls,http3,runtime,webtransport}`,
  `apps/{wt-client-c99,wt-server-c99,wt-conformance-c99}`, `tests/`, `scripts/`,
  `platform/`.
- `AUDIT/` — the repository's own audit ledger and findings.

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

## Identity

**The two libraries must always carry the same version number**, even when only one
of them changed — at that point a simple re-compile is enough to keep them
compatible. That lockstep is being introduced by the open pull request
`release/single-version-source`: a root `VERSION` file as the single source, CMake
reading it and failing on a malformed value or a `version.h` that disagrees, and
`Swift/check-version-sync.sh` as the gate.

**Until that merges, `main` has no in-repo version at all.** The Swift side's
identity is the git tag and the README install pin (`1.3.8`); the C99 side declares
`0.1.0` in `C99/include/webtransport/version.h` (`WT_VERSION_MAJOR/MINOR/PATCH`) and
repeats it as `project(... VERSION 0.1.0)` in `C99/CMakeLists.txt` and as literals
in `C99/tests/unit/test_version.c` and `test_public_api.c`. The **ABI version**
(`WT_ABI_VERSION`) and the **protocol draft** are separate axes: they do not follow
the library version and must not be bumped with it.

## Gates

- Swift (`.github/workflows/swift-ci.yml`): `./Swift/check-toolchain.sh 6.4 27.0`,
  `./Swift/check-manifest-sync.sh`, `./Swift/check-target-imports.sh`,
  `swift format lint --strict --recursive --parallel …`, `./check-api-compatibility.sh`,
  `./build-release-apple-silicon.sh`, tests under
  `-warnings-as-errors -strict-concurrency=complete -require-explicit-sendable`,
  a 20000-iteration ASan fuzz run, and a thread-sanitizer job that skips
  `CLIProcess` / `ReleaseArtifacts`.
- C99 (`.github/workflows/c99-ci.yml`): `check-vectors.sh`, `check-package.sh`,
  `check-matrix.sh`, `check-portability.sh`, `check-static-analysis.sh` (Clang
  Static Analyzer), `check-cppcheck.sh`, `check-workflows.py`, plus Windows
  cross-build/Wine legs.
- `security-scan.yml`: gitleaks 8.30.1 over full history, trivy 0.74.0.

## Traps

- **Two libraries that share a repository and nothing else.** Editing `C99/` does
  not affect `Package.swift`, and no gate currently requires the two versions to
  match — so a version bump must be applied to both by hand until the lockstep gate
  lands.
- **`check-manifest-sync.sh` is not a version gate.** It diffs shared SwiftPM
  targets (path/type/dependencies) between the two manifests via
  `swift package dump-package`, and exits 1 if `jq` is not on `PATH`.
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

<!-- release-rules:begin -->
## Releasing

**Read [`RELEASE.md`](RELEASE.md) before cutting a release.** It carries the
generic rules every Pummelchen repository follows, plus this repository's own
section. Do not improvise a release.

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
<!-- release-rules:end -->
