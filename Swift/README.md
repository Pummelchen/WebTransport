# Swift WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-15`, dated 2026-03-02.

Draft-15 score: **90%**

## Current Status

Swift is the active implementation.

Implemented:

- Public package product: `WebTransport`.
- Network runtime package product: `WebTransportNetworkRuntime`.
- CLI products: `WebTransportClient` and `WebTransportServer`.
- HTTP/3 frame, SETTINGS, control stream, request stream, GOAWAY, and error mapping logic.
- WebTransport extended CONNECT session establishment and rejection policy.
- Structured Fields parsing/serialization for `WT-Protocol` and `WT-Available-Protocols`.
- QPACK static, literal, Huffman, dynamic table, Base, and post-Base behavior covered by tests.
- WebTransport streams, datagrams, buffering, rejection, close, drain, reset, stop-sending, and flow-control behavior.
- TLS/QUIC primitive state, QUIC packet protection helpers, transport-parameter codecs, packet-protected QUIC Initial CRYPTO flight probe over UDP, UDP loopback support, and prompt-free identity/trust test paths.
- Packet-protected QUIC Initial CRYPTO flight probe mode for separate-process `WebTransportClient` / `WebTransportServer` networking, with raw-frame probe compatibility mode.
- CLI conformance harness with 35 scenarios shared by `WebTransportClient` and `WebTransportServer`.
- Apple Silicon release script for production CLI binaries.

Known limitation:

- WebTransport sessions still do not run over a complete external QUIC/TLS/HTTP/3 network connection.

## Commands

```sh
swift build
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all
swift run WebTransportServer --listen 127.0.0.1:4433 --transport packet
swift run WebTransportClient --connect 127.0.0.1:4433 --transport packet
swift run WebTransportClient
swift run WebTransportServer
./build-release-apple-silicon.sh
```
