<!--
AI onboarding file.
Mode: bootstrap
Indexed commit: 742358be03922065f4aca3af823d36df5993204d
Last generated: 2026-06-26T15:16:55+02:00
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# AI Index: WebTransport

## Snapshot

| Field | Value |
|---|---|
| Repository | `Pummelchen/WebTransport` |
| Purpose | Native WebTransport over HTTP/3 implementations. |
| Mode | `bootstrap` |
| Indexed commit | `742358be03922065f4aca3af823d36df5993204d` |
| Last generated | `2026-06-26T15:16:55+02:00` |
| Active implementation | Swift package and CLI apps |
| Draft target | `draft-ietf-webtrans-http3-15` |

## First facts

- Root `Package.swift` is a SwiftPM package using Swift tools `6.3`, macOS `.v26`, and Swift language mode `.v6`.
- The Swift implementation is active and production-oriented. C99 and C++ directories are documented plans/skeletons, not active implementations.
- CI is `.github/workflows/swift-ci.yml` on `macos-26`; it builds, validates DocC, checks API compatibility, verifies release artifacts, runs tests, and runs both CLI conformance suites.
- Real CLI network sessions use packet transport. Frame transport is only for lower-level conformance scenarios.
- Default runtime trust is platform/system trust; local self-signed trust is explicit and loopback-limited.

Evidence:
- `README.md`
- `Package.swift`
- `Swift/Package.swift`
- `Swift/README.md`
- `.github/workflows/swift-ci.yml`
- `Swift/Sources/WebTransport/WebTransport.swift`
- `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift`
- `Swift/Sources/WebTransportClient/main.swift`
- `Swift/Sources/WebTransportServer/main.swift`

## Architecture summary

```text
Public API / CLIs
  -> WebTransport
  -> WebTransportNetworkRuntime
  -> WebTransportHTTP3Core + WebTransportQUICCore + WebTransportTLSCore
  -> WebTransportCryptoApple + WebTransportUDPApple
```

`WebTransport` exposes the public Swift concurrency API. `WebTransportNetworkRuntime` routes network I/O through Apple Network.framework QUIC/TLS/HTTP/3. `WebTransportHTTP3Core` owns HTTP/3, QPACK, WebTransport session, stream, datagram, and flow-control behavior. `WebTransportQUICCore`, `WebTransportTLSCore`, and `WebTransportCryptoApple` provide lower-level protocol and crypto helpers. `WebTransportUDPApple` is a Darwin loopback UDP helper for tests and local packet probes.

## Directory map

| Path | Responsibility |
|---|---|
| `Package.swift` | Root public SwiftPM package. |
| `Swift/Package.swift` | Swift subpackage with smoke executables and test support. |
| `Swift/Sources/WebTransport/` | Public API and DocC. |
| `Swift/Sources/WebTransportNetworkRuntime/` | Network.framework runtime, trust, sessions, datagrams. |
| `Swift/Sources/WebTransportHTTP3Core/` | HTTP/3, QPACK, WebTransport protocol state. |
| `Swift/Sources/WebTransportQUICCore/` | QUIC wire/state primitives. |
| `Swift/Sources/WebTransportTLSCore/` | TLS 1.3 for QUIC pieces. |
| `Swift/Sources/WebTransportCryptoApple/` | Apple crypto-backed QUIC helpers. |
| `Swift/Sources/WebTransportUDPApple/` | Loopback-only UDP helper. |
| `Swift/Sources/WebTransportClient/` | Client CLI. |
| `Swift/Sources/WebTransportServer/` | Server CLI. |
| `Swift/Tests/` | Swift Testing suites. |
| `Swift/*.sh` | API, release, and interop scripts. |
| `C99/`, `CPP/` | Planned implementation skeletons and plans. |

## Main commands

```sh
swift build
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all
swift run WebTransportServer --listen 127.0.0.1:4433 --transport packet
swift run WebTransportClient --connect 127.0.0.1:4433 --transport packet --trust local-self-signed
cd Swift && ./check-api-compatibility.sh
cd Swift && ./build-release-apple-silicon.sh
cd Swift && ./run-third-party-interop.sh
```

See [`.ai/COMMANDS.md`](./.ai/COMMANDS.md).

## Common task map

| Task | Start here |
|---|---|
| Public API | `Swift/Sources/WebTransport/WebTransport.swift`, DocC, public API tests. |
| CLI behavior | `Swift/Sources/WebTransportClient/main.swift`, `Swift/Sources/WebTransportServer/main.swift`, process tests. |
| Runtime/trust/networking | `Swift/Sources/WebTransportNetworkRuntime/`, public API tests, process tests. |
| HTTP/3/QPACK/session/flow | `Swift/Sources/WebTransportHTTP3Core/`, HTTP3Core tests. |
| QUIC/TLS/crypto | `Swift/Sources/WebTransportQUICCore/`, `Swift/Sources/WebTransportTLSCore/`, `Swift/Sources/WebTransportCryptoApple/`. |
| UDP helper | `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift`, UDP tests. |
| C99/C++ planning | `C99/IMPLEMENTATION_PLAN.md`, `CPP/IMPLEMENTATION_PLAN.md`. |
| CI/release | `.github/workflows/swift-ci.yml`, `Swift/*.sh`. |

## Caution areas

- Preserve sanitized logging and public error redaction.
- Do not broaden local self-signed trust beyond explicit loopback use.
- Do not claim C99/C++ implementation status beyond their READMEs.
- Avoid editing `.build/`, `Swift/.build/`, `.webtransport-cli-logs/`, `C99/out/`, and `CPP/out/`.

## Recommended first-read order

1. `AI_INDEX.md`
2. `AGENTS.md`
3. `.ai/START_HERE.md`
4. `.ai/PROJECT_MAP.md`
5. `.ai/ARCHITECTURE.md`
6. `.ai/COMMANDS.md`
7. `.ai/TESTING.md`
8. `.ai/SECURITY.md`
9. `.ai/COMPONENTS.md`
10. `.ai/PLAYBOOKS.md`
11. `.ai/KNOWN_UNKNOWNS.md`

## Bootstrap note

This is the first generated vendor-neutral onboarding index. There is no previous indexed commit.
