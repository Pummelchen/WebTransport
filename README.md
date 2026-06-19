# WebTransport

Native HTTP/3 WebTransport implementation project.

Protocol reference: IETF `draft-ietf-webtrans-http3-15`, dated 2026-03-02.
Datatracker: <https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>

## Implementation Status

| Implementation | Status | Draft-15 Score |
| --- | --- | ---: |
| Swift | Active implementation. Protocol core, package product, deterministic client/server CLI facade, packet-protected QUIC Initial CRYPTO flight probe over UDP, conformance scenarios, and release packaging are present. | 90% |
| C99 | Placeholder only. No protocol implementation is present. | 0% |
| C++ (`CPP`) | Placeholder only. No protocol implementation is present. | 0% |

## Swift

Swift is the only active implementation in this repository.

Current Swift coverage includes:

- HTTP/3 frame, SETTINGS, control stream, request stream, GOAWAY, and error mapping logic.
- WebTransport extended CONNECT session establishment and rejection policy.
- `WT-Protocol` and `WT-Available-Protocols` Structured Fields handling.
- QPACK static, literal, Huffman, dynamic table, Base, and post-Base handling needed by the current tests.
- WebTransport stream prefixes, bidirectional streams, unidirectional streams, datagrams, buffering, rejection, close, drain, reset, and stop-sending behavior.
- WebTransport flow-control capsules, monotonic limit handling, disabled/zero/unlimited state distinction, and receive-side violation close behavior.
- TLS/QUIC primitive state, packet protection, transport-parameter codecs, packet-protected QUIC Initial CRYPTO flight probe over UDP, UDP loopback support, and prompt-free identity/trust test paths.
- Public Swift package product: `WebTransport`.
- Network runtime package product: `WebTransportNetworkRuntime`.
- CLI products: `WebTransportClient` and `WebTransportServer`.

Important limitation: the Swift client/server CLI now has a packet-protected QUIC Initial CRYPTO flight probe over UDP, but WebTransport sessions still do not run over a complete external QUIC/TLS/HTTP/3 network connection.

Useful Swift commands:

```sh
swift test --package-path Swift
swift run --package-path Swift WebTransportClient --scenario all
swift run --package-path Swift WebTransportServer --scenario all
swift run --package-path Swift WebTransportServer --listen 127.0.0.1:4433 --transport packet
swift run --package-path Swift WebTransportClient --connect 127.0.0.1:4433 --transport packet
swift run --package-path Swift WebTransportClient
swift run --package-path Swift WebTransportServer
cd Swift && ./build-release-apple-silicon.sh
```

## C99

The C99 implementation has not started. The `C99/` directory currently contains documentation only.

## C++

The C++ implementation has not started. The implementation directory is named `CPP/` to avoid `+` characters in paths.
