# Audit environment (Phase A, §1/§1b)

Reproducibility rule: everything below is re-installable from this file alone.

## Hosts

| Host | Role | Reachability | OS / arch |
| --- | --- | --- | --- |
| `local` (this machine) | Swift/Xcode builds, Apple-platform tests, Docker, C sanitizer builds | local shell | macOS 26.x, arm64 (M-series) |
| `node1`..`node4` (4x Mac Mini M2, 8 GB) | Mac-fleet distribution for Xcode/Swift work | SSH keys | macOS, arm64 |
| `vps` `root@91.99.176.243` | Linux/x86 work only (Docker, C sanitizers, Python matrix) — **not yet used; needs approval per §1b** | SSH key | Debian 13 (Trixie), x86_64 |

## Toolchain versions

| Tool | Version | Install method / path | Host |
| --- | --- | --- | --- |
| Swift | 6.4 (swiftlang-6.4.0.34.1, clang-2100.3.34.1) | Xcode 27.0 (27A266a) `/usr/bin/swift` | local |
| Xcode | 27.0 (27A266a) | App Store / developer.apple.com | local |
| Python | 3.14 | python.org framework `/Library/Frameworks/Python.framework/Versions/3.14/bin/python3` | local |
| CMake | see `cmake --version` | Homebrew | local |
| Ninja | see `ninja --version` | Homebrew | local |
| clang (system) | Apple clang (Xcode 27) | `/usr/bin/clang` | local |
| clang-tidy | Homebrew LLVM | `/opt/homebrew/opt/llvm/bin/clang-tidy` | local |
| llvm-cov | Homebrew LLVM | `/opt/homebrew/opt/llvm/bin/llvm-cov` | local |
| Docker | Docker Desktop | `/opt/homebrew/bin/docker` | local |

## Tools to install (Phase A, §1 minimum coverage)

Install method: `brew install <formula>` on `local` unless noted. Installed tools are recorded
here with their version once present; anything that cannot be installed is logged as BLOCKED in
`AUDIT/ledger.md` with the reason.

| Need | Tool | Formula | Status |
| --- | --- | --- | --- |
| Swift formatter | swift-format | `swift-format` (brew) | installing |
| Swift linter | SwiftLint | `swiftlint` (brew) | installing |
| C static analyzer | clang-tidy | present (Homebrew LLVM) | present |
| C static analyzer 2 | cppcheck | `cppcheck` | installing |
| C memory checker | valgrind | not available on arm64 macOS for Darwin binaries | BLOCKED (see ledger) |
| C memory checker (alt) | ASan/UBSan + LeakSanitizer on Linux | clang in a Debian container | planned |
| Secret scan (full history) | gitleaks | `gitleaks` | installing |
| Secret scan (alt) | trufflehog | `trufflehog` | installing |
| Dependency/CVE scan | trivy | `trivy` | installing |
| SAST | semgrep | `semgrep` | installing |
| Coverage (Swift) | llvm-cov | present | present |
| Coverage (C) | gcovr + lcov via CMake | `gcovr` | installing |
| .NET | n/a (no .NET project in this repo) | -- | n/a |

## Commands used (re-runnable)

```sh
brew install swift-format swiftlint cppcheck gitleaks trufflehog trivy semgrep gcovr
```
