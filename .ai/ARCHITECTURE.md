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
# Architecture

## High-level view

```text
WebTransport public API and CLIs
  -> Network.framework runtime
  -> HTTP/3 + WebTransport session core
  -> QUIC/TLS/crypto/UDP helper modules
```

Swift is the active implementation. C99 and C++ currently contain implementation plans and skeleton folders only.

## Client runtime flow

1. `WebTransportClient` parses CLI arguments or public API configuration.
2. Real network sessions reject non-packet transport.
3. `WebTransportQUICClient` applies trust policy and opens a Network.framework QUIC connection.
4. Client exchanges HTTP/3 control streams.
5. Client sends WebTransport extended CONNECT on a bidirectional request stream.
6. Response headers are validated and a `WebTransportNetworkSession` is created.
7. Streams, datagrams, drain, and close route through the session object.

Evidence: `Swift/Sources/WebTransportClient/main.swift`, `Swift/Sources/WebTransport/WebTransport.swift`, `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift`.

## Server runtime flow

1. `WebTransportServer` parses `--listen` or public API listener configuration.
2. Real network sessions reject non-packet transport.
3. `WebTransportQUICServer` creates a TLS identity and Network.framework listener.
4. Server accepts a QUIC connection and exchanges HTTP/3 control streams.
5. Server decodes CONNECT request headers.
6. `WebTransportServerSessionPolicy` checks authority, path, origin, and supported protocols.
7. Server sends response headers and creates a `WebTransportNetworkSession`.

Evidence: `Swift/Sources/WebTransportServer/main.swift`, `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift`, `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift`.

## Component responsibilities

- `WebTransport`: public client/server/session/stream API and sanitized output helpers.
- `WebTransportNetworkRuntime`: Network.framework QUIC/TLS/HTTP/3 runtime, endpoint parsing, trust policy, sessions.
- `WebTransportHTTP3Core`: HTTP/3 frames/settings, QPACK, WebTransport CONNECT/session/datagram/stream/flow logic.
- `WebTransportQUICCore`: QUIC packets, frames, varints, transport parameters, stream IDs, core state.
- `WebTransportTLSCore`: TLS 1.3 handshake/key/certificate behavior for QUIC.
- `WebTransportCryptoApple`: Apple crypto-backed QUIC key/protection helpers.
- `WebTransportUDPApple`: Darwin loopback UDP helper for tests/local probes.

## Trust boundaries

- CLI input: argument parsing, endpoint parsing, packet-only real sessions.
- Network peer input: HTTP/3/QPACK/QUIC/TLS parsers, WebTransport session policy, bounded buffers.
- Trust policy: system trust default; local self-signed mode explicit and loopback-limited.
- Logging/errors: public surfaces avoid sensitive runtime detail and peer payload detail.
- External interop: environment-configured endpoint tests write proof outputs under `.build/`.

## CI flow

```text
push / PR / manual dispatch
  -> swift build
  -> DocC conversion
  -> API compatibility sample
  -> release artifact verification
  -> swift test
  -> WebTransportClient --scenario all
  -> WebTransportServer --scenario all
```

Evidence: `.github/workflows/swift-ci.yml`.

## Risks

- Parser and protocol code handles adversarial peer input.
- Trust-policy changes can weaken real-network security.
- Public logging/error changes can leak details if not kept sanitized.
- Root and `Swift/` package manifests have different product sets.
- C99/C++ plans must not be mistaken for implemented behavior.
