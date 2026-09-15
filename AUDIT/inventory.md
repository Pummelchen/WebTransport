# §2 Scope discovery — inventory (Phase A)

Committed before Phase 3 (auditing) begins, per §2.

## 2.1 Projects / modules, language, build system, host class

| # | Unit | Language | Build system | Entry points | Host class |
| --- | --- | --- | --- | --- | --- |
| 1 | Root Swift package (`/Package.swift`, "WebTransport") | Swift 6.4 | SwiftPM | libraries only (products) | Mac |
| 2 | `Swift/` package (`Swift/Package.swift`, "WebTransportSwift") | Swift 6.4 | SwiftPM | libraries, 3 executables, tests | Mac |
| 3 | `Swift/Sources/WebTransportQUICCore` | Swift | SwiftPM target | library | Mac |
| 4 | `Swift/Sources/WebTransportUDPApple` | Swift | SwiftPM target | library | Mac |
| 5 | `Swift/Sources/WebTransportCryptoApple` | Swift | SwiftPM target | library (CryptoKit/Security shim) | Mac |
| 6 | `Swift/Sources/WebTransportTLSCore` | Swift | SwiftPM target | library | Mac |
| 7 | `Swift/Sources/WebTransportHTTP3Core` | Swift | SwiftPM target | library | Mac |
| 8 | `Swift/Sources/WebTransportNetworkRuntime` | Swift | SwiftPM target | library (Network.framework) | Mac |
| 9 | `Swift/Sources/WebTransport` | Swift | SwiftPM target | library (umbrella) | Mac |
| 10 | `Swift/Sources/WebTransportClient` / `WebTransportServer` (products) | Swift | SwiftPM | library | Mac |
| 11 | `Swift/Sources/WebTransportCLIConformance` | Swift | SwiftPM | `wt-conformance`, `wt-client`, `wt-server` executables | Mac |
| 12 | `Swift/Sources/LibrarySmokeServer` / `LibrarySmokeClient` | Swift | SwiftPM | executables | Mac |
| 13 | `Swift/Tests/*` (7 test targets) | Swift | SwiftPM/XCTest | tests | Mac |
| 14 | `C99/` (own CMake project) | C99 | CMake + Ninja | library, 3 CLI tools, tests, fuzz | both (Linux CI + Mac dev + Windows cross) |
| 15 | `C99/src/{core,crypto,quic,tls,http3,qpack,webtransport,api,cli,runtime}` | C99 | CMake | library modules | both |
| 16 | `C99/apps/{wt-client-c99,wt-server-c99,wt-conformance-c99,wt-api-sample}` | C99 | CMake | executables | both |
| 17 | `C99/tests/{unit,fuzz,integration,interop,package,vectors,windows}` | C99 | CMake/CTest | 84 unit programs + scripts | both |
| 18 | `C99/scripts/*.sh`, `C99/scripts/*.py` | POSIX sh + Python | -- | checks, matrix, interop runner | both |
| 19 | `Swift/Scripts`/repo scripts, `.github/workflows/{swift,c99}-ci.yml` | YAML/sh | GitHub Actions | CI | cloud |
| 20 | `AUDIT/` (this audit) | Markdown/JSON | -- | -- | -- |

Total: **2 products** (Swift reference implementation, portable C99 implementation) expressed as
**39 SwiftPM targets** across **2 manifests** and **~30 CMake targets**; **18 Python files** (scripts only);
**2 CI workflows**. The brief's "20+ interdependent projects" maps to the SwiftPM target graph plus the C99
module/target graph — there is no second repository or service tier.

## 2.2 Cross-project dependency graph (including implicit coupling)

- **Swift → C99: none.** The two implementations share no source, no build, and no generated file; this is
  deliberate (C99/README.md). Coupling is *by contract* only: the same draft (`draft-ietf-webtrans-http3-16`),
  the same compliance matrix shape, the same interop peers.
- **Intra-Swift:** `WebTransport` → `WebTransportClient`/`Server` → `NetworkRuntime` → `HTTP3Core` →
  `{QUICCore, TLSCore}` → `{UDPApple, CryptoApple}`; `WebTransportSecurityShim` (C shim) is consumed by
  `CryptoApple`/`TLSCore`; `WebTransportTestSupport` is consumed by test targets only.
- **Implicit coupling to check in Phase B:** the two Swift manifests must agree on targets/products/settings
  (CI claims to check this); C99's CMake target list vs `C99/tests/CMakeLists.txt`; shared constants that exist
  in both languages (ALPN `h3`, retry token, transport-parameter codepoints, `WebTransport` error codes) —
  divergence between the Swift and C99 wire constants is a cross-project contract risk.
- **External coupling:** third-party interop peers (aioquic, quinn, quiche, h3-webtransport, erlang-webtransport)
  over the network; the Apple platform trust store; OpenSSL 3 for C99.
- **Config/env surface:** `WT_*` environment variables used by C99 tools/scripts and Swift conformance checks
  (log paths, fixture dirs); no `.env` files, no databases, no queues, no IPC beyond UDP sockets.

## 2.3 Trust boundaries

| Boundary | Untrusted input | Holds credentials | Network-reachable |
| --- | --- | --- | --- |
| Swift `WebTransportServer` listener | peer bytes (QUIC/HTTP-3/WebTransport), certificates | server TLS identity (injected) | yes (UDP, any interface unless local-only) |
| Swift `WebTransportClient` | server certificates, server bytes | none (client has no key) | yes (outbound) |
| Swift CLI conformance tools | argv, fixtures, source tree | none | only in scenarios that listen/connect |
| C99 `wt-server-c99` / `wt-client-c99` | peer bytes, argv, trust fixtures | server identity (self-signed, generated) | yes |
| C99 library (`api`, `quic`, `tls`, `http3`, `webtransport`) | all peer bytes | traffic secrets, X25519 private key | via its caller |
| Tests / fixtures (`*/vectors`, trust fixtures) | fixture files on disk | test keys (not production) | no |
| CI workflows | repository content, GH token (outside repo) | CI-injected secrets (not in-repo) | yes (runners) |

## 2.4 Blast radius (>1 consumer ⇒ higher severity)

| Module | Consumers | Severity multiplier |
| --- | --- | --- |
| Swift `WebTransportQUICCore` | all Swift layers + tests | **highest** — every Swift product depends on it |
| Swift `WebTransportCryptoApple` (++ shim) | TLSCore, QUICCore, tests | high |
| C99 `src/core` (buffer/checked/writer/cursor) | every C99 module | **highest** |
| C99 `src/crypto` | tls, quic | high |
| C99 `src/quic` | http3, webtransport, runtime, api | high |
| `Package.swift` (root) | SwiftPM consumers of the library products | high (packaging contract) |
| `Swift/Package.swift` | the Swift test/CLI build | high |
| `C99/CMakeLists.txt` + `platform/` | all C99 targets, packaging | high |
| `C99/include/**` | every C99 consumer + `wt-api-sample` | high (public API) |

## 2.5 Placeholders / committed artifacts seen during discovery (to be worked as tasks)

- `build/` (repository root) contains **committed CMake build output**, including `.o` object files and a
  generated `webtransport_c99ConfigVersion.cmake`.
- Two Swift manifests exist (`/Package.swift`, `/Swift/Package.swift`) with different package names
  (`WebTransport` vs `WebTransportSwift`) and different target counts (18 vs 21).
Both become Phase B tasks; nothing is changed in Phase A.
