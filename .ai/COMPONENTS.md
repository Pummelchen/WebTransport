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
# Components

## `WebTransport`

Public Swift concurrency client/server/session API.

- Key files: `Swift/Sources/WebTransport/WebTransport.swift`, DocC catalog.
- Interfaces: client/server configs, endpoints, client/server actors, listener, session, bidirectional stream, logger, public error helper.
- Tests: public API tests, process tests, API compatibility script.
- Main risk: public API compatibility and sanitized output.

## `WebTransportNetworkRuntime`

Network.framework QUIC/TLS/HTTP/3 runtime.

- Key files: `WebTransportInteroperableNetworkRuntime.swift`, `WebTransportNetworkTypes.swift`.
- Interfaces: QUIC client/server, network session, endpoint, trust policy.
- Depends on CryptoApple, HTTP3Core, QUICCore, TLSCore, UDPApple.
- Main risk: trust policy, endpoint parsing, datagrams, timeouts, concurrency.

## `WebTransportHTTP3Core`

HTTP/3, QPACK, WebTransport CONNECT/session/datagram/stream/flow behavior.

- Key files: `HTTP3Connection.swift`, `HTTP3Frame.swift`, `QPACK.swift`, `QPACKHuffman.swift`, `WebTransportSession.swift`.
- Depends on QUICCore.
- Main risk: peer-controlled parsing, buffer bounds, flow-control correctness.

## `WebTransportQUICCore`

QUIC byte cursors, varints, packets, frames, transport parameters, and core state.

- Key path: `Swift/Sources/WebTransportQUICCore/`.
- Tests: QUICCore tests.
- Main risk: wire compatibility and malformed-input handling.

## `WebTransportTLSCore`

TLS 1.3 handshake, certificate verification, key schedule, and QUIC TLS state.

- Key path: `Swift/Sources/WebTransportTLSCore/`.
- Tests: TLSCore tests.
- Main risk: trust gating and security regression.

## `WebTransportCryptoApple`

Apple crypto-backed QUIC initial key derivation and packet protection helpers.

- Key files: `QUICInitialKeyDerivation.swift`, `QUICPacketProtection.swift`.
- Tests: CryptoApple tests.

## `WebTransportUDPApple`

Darwin loopback UDP helper for tests/local probes.

- Key file: `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift`.
- Invariant: only accepts `localhost`, `127.0.0.1`, and `::1`.
- Tests: UDP tests and process loopback tests.

## `WebTransportCLIConformance`

Shared conformance scenario harness for client/server CLIs.

- Key path: `Swift/Sources/WebTransportCLIConformance/`.
- Tests: process tests and client/server `--scenario all`.

## Planned implementation folders

- `C99/`: planned C99 skeleton and implementation plan; no protocol implementation/build/CLI/tests yet.
- `CPP/`: planned C++23 skeleton and implementation plan; no protocol implementation/build/CLI/tests yet.
