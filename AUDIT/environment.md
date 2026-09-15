# Audit environment (Phase A, §1/§1b)

Reproducibility rule: everything below is re-installable from this file alone.

## Hosts

| Host | Role | Reachability | OS / arch |
| --- | --- | --- | --- |
| `local` (this machine) | Swift/Xcode builds, Apple-platform tests, Docker, C sanitizer builds | local shell | macOS 26.x, arm64 (M-series) |
| `node1`..`node4` (4x Mac Mini M2, 8 GB) | Mac-fleet distribution for Xcode/Swift work | SSH keys | macOS, arm64 |
| `vps` `root@91.99.176.243` | Linux/x86 work (Docker, C sanitizers, Python matrix); **Phase E independent host** and **Swift-on-Linux probe host** (both owner-approved) | SSH key | Debian 13 (Trixie), x86_64, 8 cores |

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
| Swift (Linux) | 6.4 (swift-6.4-RELEASE) | swift.org tarball for Debian 13, GPG-verified, `/opt/swift-toolchains/swift-6.4` → `/usr/local/bin/swift` | vps |
| Swift (Linux, previous) | 6.3.2 | kept side by side at `/opt/swift-toolchains/swift-6.3.2` | vps |
| gcc | 14.2 | Debian 13 packages | vps |
| CMake / Ninja | distro packages | `apt-get install cmake ninja-build` | vps |
| OpenSSL | 3.x (system) | Debian 13 packages | vps |

## Swift 6.4 on the VPS (installed 2026-09-15 UTC, `F-repo-ops-20`)

Reproducible from a bare Debian 13 host. The tarball is verified with the Swift release key
**before** it is extracted; a `BAD signature` means the toolchain is not used.

```sh
# 1. Swift's documented Debian 12/13 runtime and build dependencies.
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  binutils-gold gcc g++ git libcurl4-openssl-dev libedit-dev libicu-dev libncurses-dev \
  libpython3-dev libsqlite3-dev libxml2-dev pkg-config tzdata uuid-dev libz3-dev \
  zlib1g-dev unzip zip gnupg2

# 2. Download toolchain + detached signature.
D=/opt/swift-toolchains
B=https://download.swift.org/swift-6.4.0-release/debian13/swift-6.4.0-RELEASE
mkdir -p "$D" && cd "$D"
curl -fLO "$B/swift-6.4.0-RELEASE-debian13.tar.gz"
curl -fLO "$B/swift-6.4.0-RELEASE-debian13.tar.gz.sig"
sha256sum swift-6.4.0-RELEASE-debian13.tar.gz
# b623947404e7ea9843cfc315ed8624e85410fae571eb353339780ed222243737  (2026-09-15)

# 3. Verify the signature BEFORE anything is extracted.
curl -fsSL --compressed -o /tmp/swift-all-keys.asc https://www.swift.org/keys/all-keys.asc  # --compressed: swift.org serves the .asc gzip-encoded
gpg --batch --import /tmp/swift-all-keys.asc
gpg --verify swift-6.4.0-RELEASE-debian13.tar.gz.sig swift-6.4.0-RELEASE-debian13.tar.gz
# GOODSIG EF80A866B47A981F Swift 6.x Release Signing Key <swift-infrastructure@forums.swift.org>
# VALIDSIG 52BB7E3DE28A71BE22EC05FFEF80A866B47A981F 2026-09-14

# 4. Install. The Debian 13 tarball roots at swift-6.4.0-RELEASE-debian13/usr, so extract it
#    INTO /opt/swift-toolchains (extracting "into a directory of the same name" double-nests,
#    which is how the first attempt on the VPS ended up one level too deep).
tar -xzf swift-6.4.0-RELEASE-debian13.tar.gz
ln -sfn /opt/swift-toolchains/swift-6.4.0-RELEASE-debian13 /opt/swift-toolchains/swift-6.4
for t in swift swiftc swift-format sourcekit-lsp; do
  ln -sfn /opt/swift-toolchains/swift-6.4/usr/bin/$t /usr/local/bin/$t
done

# 5. Smoke test.
swift --version   # Swift version 6.4 (swift-6.4-RELEASE) / Target: x86_64-unknown-linux-gnu
```

Verified after install: `swiftc -O` compiles and runs a Foundation program; `swift package init
--type executable`, `swift build` and `swift run` produce `Hello, world!` in 5.23 s. The one
diagnostic seen is SwiftPM's `warning: safeExec: signal(33, SIG_DFL) failed: Invalid argument`,
which does not affect the build; it is recorded rather than suppressed. `swift-6.3.2` remains
installed at `/opt/swift-toolchains/swift-6.3.2/usr/bin` for comparison.

### Per-target Linux build matrix (Swift 6.4, Debian 13, fresh clone of `96d75c8`)

`swift build --package-path Swift --target T` for all 11 library targets; logs in
`/var/wt-swift-linux-probe/out/`.

| Target | Result | Reason |
| --- | --- | --- |
| `WebTransportQUICCore` | **PASS** | Foundation only |
| `WebTransportHTTP3Core` | **PASS** | Foundation only |
| `WebTransportUDPApple` | FAIL | `no such module 'Darwin'` (`QUICUDPPort.swift:1`) |
| `WebTransportCryptoApple` | FAIL | `no such module 'CryptoKit'` (`QUICInitialKeyDerivation.swift:1`) |
| `WebTransportTLSCore` | FAIL | `no such module 'CryptoKit'` (`TLS13KeyAgreement.swift:1`) |
| `WebTransportTestSupport` | FAIL | `no such module 'CryptoKit'` (via `WebTransportTLSCore`) |
| `WebTransportSecurityShim` | FAIL | `'CoreFoundation/CoreFoundation.h' file not found` (`include/WebTransportSecurityShim.h:22`) |
| `WebTransportNetworkRuntime` | FAIL | same `CoreFoundation` header, via the shim |
| `WebTransportLoopbackTestSupport` | FAIL | `no such module 'Darwin'` (`WebTransportLoopbackTestLock.swift:1`) |
| `WebTransport` | FAIL | same `CoreFoundation` header, via the shim |
| `WebTransportCLIConformance` | FAIL | same `CoreFoundation` header, via the shim |
| whole `Swift/` package, whole root package | FAIL | same, aggregated |

So the Linux-portable surface is exactly the two wire-format cores, and they build there under
`.strictMemorySafety()` and `.treatAllWarnings(as: .error)` with **0 warnings**.

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

The VPS toolchain install is the command block in *Swift 6.4 on the VPS* above; the per-target
Linux build matrix is reproduced by

```sh
git clone --branch audit/2026-09-15 https://github.com/Pummelchen/WebTransport.git
cd WebTransport
for t in WebTransportQUICCore WebTransportHTTP3Core; do swift build --package-path Swift --target "$t"; done
swift build --package-path Swift   # fails: nine targets need Darwin, CryptoKit or CoreFoundation
```

