# Swift WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-15`, dated 2026-03-02.

Draft-15 score: **96%**

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
- TLS/QUIC state with application-key readiness gated on certificate trust, CertificateVerify, Finished, ALPN h3, and QUIC transport parameters; QUIC packet protection helpers, transport-parameter codecs, packet-protected QUIC Initial CRYPTO flight validation including Certificate, CertificateVerify, and Finished, transcript-derived 1-RTT packet keys for protected HTTP/3 WebTransport CONNECT/DATAGRAM session probing over UDP, UDP loopback support, and prompt-free identity/trust test paths.
- Packet-protected QUIC Initial CRYPTO flight mode with ALPN h3, QUIC transport-parameter validation, deterministic Certificate/CertificateVerify/Finished validation, validated-handshake 1-RTT key derivation, and protected HTTP/3 WebTransport CONNECT/DATAGRAM session probing for separate-process `WebTransportClient` / `WebTransportServer` networking, with raw-frame probe compatibility mode.
- CLI conformance harness with 40 scenarios shared by `WebTransportClient` and `WebTransportServer`, including positive/negative interop matrices for CONNECT, streams, datagrams, GOAWAY, close/drain, malformed input, and flow-control errors.
- Deterministic parser/property hardening tests for QPACK, HTTP/3 frames, capsules, QUIC varints, QUIC transport parameters, WebTransport stream prefixes, resource limits, malformed peers, ordering, replay, exhaustion, and close/reset races.
- Apple Silicon release script for production CLI binaries.

Known limitation:

- The separate-process network mode is still a deterministic runtime probe rather than a complete external QUIC/TLS/HTTP/3 network stack.

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
