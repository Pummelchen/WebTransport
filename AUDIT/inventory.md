# AUDIT — inventory, dependency graph, trust boundaries, tiers

Phase A (§2.1–§2.4). Committed before any fix, as required. Every module has a tier; the
tier coverage is restated in the final report so reduced inspection is disclosed.

## 2.1 Projects, languages, build systems, entry points

| Id | Project | Language | Build system | Entry points | Primary host |
| --- | --- | --- | --- | --- | --- |
| P1 | Swift package (`Package.swift`, plus the nested `Swift/Package.swift` over the same sources) | Swift 6 | SwiftPM 6.4 | Executables `WebTransportClient`, `WebTransportServer`; library products `WebTransport` + six lower-level libraries; nested-only smoke pair `LibrarySmokeClient/Server` | Mac14,3 |
| P2 | C99 library (`C99/CMakeLists.txt`) | C99 | CMake 4.4.3 + Ninja | Executables `wt-client-c99`, `wt-server-c99`, `wt-conformance-c99`, `wt-api-sample`; `libwebtransport` static + shared | Mac14,3 |

The two projects share no code and no build. They share exactly two things, both treated
as contracts below: the WebTransport wire protocol and the version lockstep.

Non-production trees: `Swift/Tests`, `C99/tests`, `C99/tests/vectors`, `C99/tests/interop`,
`Swift/interop-docker`, `docs/`, `C99/docs/`, the shell scripts under `Swift/*.sh`,
`C99/scripts/`, `C99/platform/`, and `.github/workflows/`.

## 2.2 Dependency graph (depth cap 2)

### P1 — Swift targets (from `swift package dump-package`)

```
WebTransport        -> HTTP3Core, NetworkRuntime, QUICCore
NetworkRuntime      -> CryptoApple, HTTP3Core, QUICCore, SecurityShim, TLSCore, UDPApple
CLIConformance      -> WebTransport, HTTP3Core, QUICCore, TLSCore, UDPApple
WebTransportClient  -> WebTransport, CLIConformance, HTTP3Core, NetworkRuntime
WebTransportServer  -> WebTransport, CLIConformance, HTTP3Core, NetworkRuntime
CryptoApple         -> QUICCore
TLSCore             -> QUICCore
HTTP3Core           -> QUICCore
QUICCore            -> (none)          SecurityShim -> (none)          UDPApple -> (none)
```

Beneath `NetworkRuntime` every path reaches a leaf in one hop, so the cap is not binding.
`NetworkRuntime` is the fan-in node: six direct dependencies, and it is the only target
that touches the OS (sockets, Security.framework, CryptoKit) — the densest boundary in P1.

### P2 — C99 modules (layering, from `C99/src/`)

```
core  <- quic <- tls, http3 <- webtransport <- runtime <- api <- cli
apps/{wt-client-c99, wt-server-c99, wt-conformance-c99} -> api (+ cli, support)
```

No third-party source is vendored (`C99/third_party/` carries no sources); the only
external dependency is the platform OpenSSL 3 (`find_package(OpenSSL 3.0 REQUIRED)`).

### Cross-project contracts (2 hops)

| Contract | Producer | Consumers | Tier |
| --- | --- | --- | --- |
| `draft-ietf-webtrans-http3-16` wire behaviour | both libraries, independently | P1 and P2 (each is the other's expected-behaviour reference) | **A** |
| Version lockstep: `VERSION` ↔ `WT_VERSION_*` ↔ `WebTransportVersion.library` | root `VERSION` | P1, P2, and the release script | **A** |
| CLI scenario catalog (`--scenario all`), one catalog for client and server | `WebTransportCLIConformance` | `WebTransportClient`, `WebTransportServer` | **A** |
| Interop runner variables (`WEBTRANSPORT_VPS_INTEROP_ADDRESS`/`_AUTHORITY`, `WEBTRANSPORT_DOCKER_INTEROP_TIMEOUT_MS`, `WEBTRANSPORT_CLI_SOAK_ROUNDS`) | runners under `Swift/`, `C99/scripts/`, `C99/tests/interop/` | peer containers | B |

Anything coupling at 2 hops is Tier A by rule; the three Tier A rows above are the only
contracts that reach that depth.

## 2.3 Trust boundaries

| Boundary | Where | Why it is a boundary |
| --- | --- | --- |
| Untrusted QUIC datagrams | `WebTransportQUICCore` (`QUICPacket*`, `QUICLongHeaderPacket`, `QUICConnectionID`, varints, transport parameters); `C99/src/quic` | Every byte is attacker-controlled; parsing, length arithmetic and connection-ID handling happen here |
| Untrusted HTTP/3 frames, SETTINGS, QPACK | `WebTransportHTTP3Core`; `C99/src/http3` | Peer-controlled framing, Huffman/HPACK/QPACK decoding, dynamic-table state |
| Untrusted TLS handshake messages and extensions | `WebTransportTLSCore`; `C99/src/tls` | Certificate parsing/verification, key schedule, extensions, exporter |
| Untrusted WebTransport session control | `WebTransportNetworkRuntime` session layer; `C99/src/webtransport` | Capsules, datagrams, flow-control arithmetic, buffered early streams |
| Network-reachable listener | `NetworkRuntime` server (`NetworkListener<QUIC>`); `C99/src/runtime` + `wt-server-c99` | Reachable surface; admission policy, connection limits, graceful shutdown |
| Credential holders | server identity `.pkcs12`/`.certificateChain`/dev self-signed (`WebTransportServerIdentity`); client `WebTransportQUICPeerTrustPolicy`; C99 `--trust` and identity files | Private keys and trust decisions |
| Native-interop seams | `WebTransportSecurityShim` (Objective-C/C shim: `WTSecPKCS12ImportCatchingExceptions`, `sec_identity_t`); `WebTransportUDPApple` (POSIX sockets); `WebTransportCryptoApple`; the generated `WebTransportSecurityShim.modulemap`; `C99/platform/*` (POSIX/Win32) | Pointer lifetimes, `Unmanaged`, `unsafe` blocks, `String(cString:)`, ownership — the boundary §2.3 calls the most bug-dense |
| Secrets | none live; only test fixtures (`*.pem`, `*.p12`, `*.der` under test resources) | Fixtures are not credentials, but a live-looking credential anywhere is a finding |

There is **no** authentication/authorization layer, no persistent data store, no money
mutation, no migration or backfill, and no LLM or external-model output in the tree. The
irreversible-operation category is therefore empty, and no task is created for it.

## 2.4 Tier table

Tier A = deep manual; B = tool-first; C = scanner-only.

| Module / tree | Project | Tier | Reason |
| --- | --- | --- | --- |
| `WebTransportQUICCore` | P1 | A | Untrusted parsing, native-length arithmetic |
| `WebTransportTLSCore` | P1 | A | Untrusted parsing, crypto, certificate verification |
| `WebTransportHTTP3Core` | P1 | A | Untrusted parsing, QPACK state machine |
| `WebTransportCryptoApple` | P1 | A | Crypto primitives, native (CommonCrypto/CryptoKit) |
| `WebTransportSecurityShim` | P1 | A | Native-interop seam (ObjC/C, `Unmanaged`, pointers) |
| `WebTransportUDPApple` | P1 | A | Native sockets, untrusted datagram ingress |
| `WebTransportNetworkRuntime` | P1 | A | Network-facing, credentials/trust, session lifecycle |
| `WebTransport` (public API) | P1 | A | Public contract, trust policy entry |
| `WebTransportClient`, `WebTransportServer` | P1 | A | Network-reachable CLIs, identity handling |
| `WebTransportCLIConformance` | P1 | B | Production-path harness, no untrusted-input parsing of its own |
| `C99/src/{core,quic,tls,crypto,http3,webtransport,runtime,api,cli}` | P2 | A | Native memory in every module; rule: all of it |
| `C99/apps/*` | P2 | A | Network-facing tools; `support/` is glue for them |
| `C99/platform/*` | P2 | A | OS syscall layer, native memory, cross-platform divergence |
| `C99/tests/**`, `Swift/Tests/**` | both | C | Tests (except where a Tier A module is exercised — that is coverage, not tier) |
| `Swift/interop-docker/**`, `C99/tests/interop/**` | both | C | Peer containers and fixtures |
| `Swift/*.sh`, `C99/scripts/**` | both | C | Build/check tooling; no production data, no migrations |
| `docs/`, `*.md`, `.github/workflows/**` | both | C | Documentation and CI config |

There are no migration or backfill scripts, so no Tier A promotion from that rule applies.
Tier A is large because the repository **is** a protocol implementation: untrusted parsing
and native memory are the product, not a corner of it.
