# §3 Baseline — captured before any change (Phase A)

Branch `audit/2026-09-15`, base commit `196324e`. Every later state is compared to this.

## Swift (mandated toolchain: Swift 6.4 / Xcode 27)

| Metric | Baseline | Command |
| --- | --- | --- |
| Toolchain | Swift 6.4 (swiftlang-6.4.0.34.1), Xcode 27.0 (27A266a), target `arm64-apple-macosx27.0.0` | `swift --version`, `xcodebuild -version` |
| Root manifest build (`/Package.swift`, 18 targets) | **FAILS** — `swift build --build-tests` exit 1 | `swift build --build-tests` |
| `Swift/` manifest build (`Swift/Package.swift`, 21 targets) | **FAILS** — same link failure | `swift build --package-path Swift --build-tests` |
| Failure | linker: `Undefined symbols for architecture arm64` — `WebTransportTLSCore.TLSExtension.decodeList`, `.TLSCertificate.decode`, `.TLSClientHello.decode`, `.TLSServerHello.decode`, `.TLSHandshakeMessage.decodeAll`, `.TLSCertificateVerify.decode`, all referenced from `WebTransportHTTP3CoreTests`'s `PeerInputFuzzTests.o` | both logs |
| Tests | **not run** — the test bundle does not link, so there is no test result at all on Swift 6.4 | `swift test` (blocked by the build) |
| Warnings | **25** in the root-manifest build; 10 of them in `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift`, 2 in `WebTransportNetworkRuntime`, 1 in `Package.swift` | `grep -c warning:` |
| Coverage | not measurable while the test bundle does not link | -- |

Both manifests declare the same (insufficient) dependency set for the failing test target:
`dependencies: ["WebTransportHTTP3Core", "WebTransportQUICCore"]`, while `Swift/Tests/WebTransportHTTP3CoreTests/PeerInputFuzzTests.swift`
imports `WebTransportTLSCore`. Per-target import survey: `WebTransportHTTP3CoreTests`,
`WebTransportNetworkRuntimeTests` and `WebTransportCryptoAppleTests` all import `WebTransportTLSCore`
(their declared dependency lists must be checked one by one in the fix).

## C99 (`C99/`, CMake + Ninja, macOS 26 arm64)

| Metric | Baseline | Command |
| --- | --- | --- |
| Configure/build | clean (warnings-as-errors in the project's own flags) | `cmake --build C99/out/macos26/build` |
| CTest | **97 of 97 passed**, ~20 s | `ctest --test-dir C99/out/macos26/build` |
| Unit checks | 84 programs / 91,552 checks (per `C99/README.md`), plus a 200,000-input parser fuzz run | `ctest` |
| Sanitizers | ASan+UBSan build configured locally (`C99/out/macos26/sanitize`), 97/97 passed before this audit | `cmake -DWEBTRANSPORT_C99_SANITIZE=ON` |
| Windows | cross-compile + Wine run green (85 executables) in CI; native Windows 97/98 before this audit | `.github/workflows/c99-ci.yml` |
| Coverage | not yet measured (gcovr 8.6 installed for it) | -- |
| Secret scan / CVE scan | not yet run (gitleaks 8.30.1, trivy 0.74.0 installed) | -- |

## Repository hygiene (L0 observations, to be numbered as tasks)

- `build/` at the repository root contains committed CMake output, including `.o` object files and a generated
  `webtransport_c99ConfigVersion.cmake`.
- Two Swift manifests coexist with different package names (`WebTransport` vs `WebTransportSwift`).

## Toolchain inventory (versions)

```
swift-format   603.0.0
swiftlint      0.65.1
clang-tidy     Homebrew LLVM 23.1.1
cppcheck       Cppcheck 2.21.0
gitleaks       gitleaks 8.30.1
trufflehog     trufflehog 3.97.4
trivy          Version: 0.74.0
semgrep        (installed via brew; `--version` needs a venv-free run — recorded in environment.md)
gcovr          gcovr 8.6
valgrind       MISSING on arm64 macOS (Darwin) — BLOCKED, alternative is ASan/LSan in a Linux container
```
