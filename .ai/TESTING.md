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
# Testing

The repository uses Swift Testing; inspected tests import `Testing`.

Evidence:
- `Package.swift`
- `Swift/Package.swift`
- `Swift/Tests/WebTransportTests/WebTransportProcessTests.swift`
- `Swift/Tests/WebTransportTests/WebTransportPublicAPITests.swift`

## Test targets

| Target | Path |
|---|---|
| `WebTransportTests` | `Swift/Tests/WebTransportTests/` |
| `WebTransportNetworkRuntimeTests` | `Swift/Tests/WebTransportNetworkRuntimeTests/` |
| `WebTransportQUICCoreTests` | `Swift/Tests/WebTransportQUICCoreTests/` |
| `WebTransportUDPAppleTests` | `Swift/Tests/WebTransportUDPAppleTests/` |
| `WebTransportCryptoAppleTests` | `Swift/Tests/WebTransportCryptoAppleTests/` |
| `WebTransportTLSCoreTests` | `Swift/Tests/WebTransportTLSCoreTests/` |
| `WebTransportHTTP3CoreTests` | `Swift/Tests/WebTransportHTTP3CoreTests/` |

## Main checks

- All tests: `swift test`
- Swift subpackage tests: `cd Swift && swift test`
- Public API focus: `swift test --filter WebTransportPublicAPITests`
- Process focus: `swift test --filter WebTransportProcessTests`
- UDP focus: `swift test --filter QUICUDPPortTests`
- Client CLI conformance: `swift run WebTransportClient --scenario all`
- Server CLI conformance: `swift run WebTransportServer --scenario all`

## Coverage noted from inspected tests

Public API tests cover loopback connection/echo, close lifecycle, sanitized log events, IPv4/IPv6 endpoint parsing, unsupported transport rejection, and public error redaction.

Process tests cover help/list output, invalid scenarios, JSON contracts, scenario grouping, selected scenarios, failure logs, loopback packet transport, frame-mode rejection for real sessions, occupied ports, concurrent clients, soak behavior, external interop hooks, release artifact executability, and API compatibility script presence.

## Environment-sensitive checks

External interop, VPS interop, release artifact verification, process concurrency, and soak checks are environment-sensitive. Do not claim they passed unless they were actually run.

## Minimum validation map

| Change type | Expected checks |
|---|---|
| Markdown/onboarding | Link check, manifest JSON parse, generated-file review. |
| Public API | `swift build`, `swift test`, API compatibility script. |
| CLI | `swift test`, client/server scenario suites. |
| Runtime/trust | Public API tests, process tests, loopback packet checks. |
| HTTP/3/QPACK/session | HTTP3Core tests and conformance scenarios. |
| QUIC/TLS/crypto | Corresponding core tests plus integration when needed. |
| Release | Release artifact script and CI review. |
