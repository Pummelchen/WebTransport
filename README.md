# WebTransport

Native HTTP/3 WebTransport implementation project.

Protocol reference: IETF `draft-ietf-webtrans-http3-15`, dated 2026-03-02.
Datatracker: <https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>

## Implementation Status

| Implementation | Status | Draft-15 Score |
| --- | --- | ---: |
| Swift | Active implementation. Protocol core, public network-backed package facade, separate-process CLI, Network.framework QUIC/TLS/HTTP/3 session path, packet-protected QUIC Initial CRYPTO validation, transcript-derived 1-RTT packet keys, explicit TLS/QUIC application-key readiness gating, positive/negative interop conformance scenarios, parser/resource hardening tests, process/stress/artifact/API compatibility tests, three-endpoint external interop proof, macOS Swift CI matrix, sanitized production logging/error surfaces, and reproducibility-checked release packaging are present. | 98% |
| C99 | Not implemented. No protocol implementation is present. | 0% |
| C++ (`CPP`) | Not implemented. No protocol implementation is present. | 0% |

## Swift

Swift is the only active implementation in this repository.

Current Swift coverage includes:

- HTTP/3 frame, SETTINGS, control stream, request stream, GOAWAY, and error mapping logic.
- WebTransport extended CONNECT session establishment and rejection policy.
- `WT-Protocol` and `WT-Available-Protocols` Structured Fields handling.
- QPACK static, literal, Huffman, dynamic table, Base, and post-Base handling needed by the current tests.
- WebTransport stream prefixes, bidirectional streams, unidirectional streams, datagrams, buffering, rejection, close, drain, reset, and stop-sending behavior.
- WebTransport flow-control capsules, monotonic limit handling, disabled/zero/unlimited state distinction, and receive-side violation close behavior.
- TLS/QUIC state with application-key readiness gated on certificate trust, CertificateVerify, Finished, ALPN h3, and QUIC transport parameters; packet protection, transport-parameter codecs, packet-protected QUIC Initial CRYPTO flight validation including Certificate, CertificateVerify, and Finished, transcript-derived 1-RTT packet keys for protected HTTP/3 WebTransport CONNECT/DATAGRAM session signaling over UDP, UDP loopback support, and prompt-free identity/trust test paths.
- CLI positive/negative interop matrices for CONNECT, streams, datagrams, GOAWAY, close/drain, malformed input, and flow-control errors.
- Deterministic parser/property hardening tests for QPACK, HTTP/3 frames, capsules, QUIC varints, QUIC transport parameters, WebTransport stream prefixes, resource limits, malformed peers, ordering, replay, exhaustion, and close/reset races.
- Process-level CLI tests for help/list/error/scenario exit codes and IPv4/IPv6 frame/packet loopback.
- Concurrent multi-session stress, repeatable soak, datagram load, backpressure, network impairment, and runtime security-negative tests.
- Release artifact smoke tests and a standalone public API compatibility sample build.
- Public `WebTransport` package facade backed by the Network.framework QUIC/TLS/HTTP/3 runtime; the former public in-process client/server and placeholder stream/session types are no longer part of the production API.
- External interoperability proof runners via `Swift/run-third-party-interop.sh` and `Swift/run-pywebtransport-interop.sh`. The three-endpoint runner launches independent `pywebtransport`/`aioquic`, `web-transport-quinn`, and `web-transport-quiche` echo endpoints and records QUIC/TLS/HTTP/3 CONNECT plus reliable WebTransport stream echo proofs in `.build/external-interop/third-party-latest.json`. Configured public endpoint probing remains available through `Swift/run-external-interop.sh`.
- macOS 26 arm64 CI matrix over explicit Xcode 26 toolchains.
- Reproducibility-checked Apple Silicon release artifacts with `SHA256SUMS`.
- Sanitized opt-in production logging and public error descriptions that avoid TLS secrets, packet bytes, datagram payloads, raw session IDs, and close reason text.
- Public Swift package product: `WebTransport`.
- Network runtime package product: `WebTransportNetworkRuntime`.
- CLI products: `WebTransportClient` and `WebTransportServer`.

Important note: the Swift client/server CLI routes `--listen/--connect` sessions through the Network.framework QUIC/TLS/HTTP/3 transport. The runtime defaults to platform trust. The `local-self-signed` trust mode is test-only and rejected for non-loopback hosts; the CLI auto-selects it only for localhost loopback development endpoints.

Useful Swift commands:

```sh
swift test --package-path Swift
swift run --package-path Swift WebTransportClient --scenario all
swift run --package-path Swift WebTransportServer --scenario all
swift run --package-path Swift WebTransportServer --listen 127.0.0.1:4433 --transport packet
swift run --package-path Swift WebTransportClient --connect 127.0.0.1:4433 --transport packet
swift run --package-path Swift WebTransportServer --listen '[::1]:4433' --transport packet
swift run --package-path Swift WebTransportClient --connect '[::1]:4433' --transport packet
swift run --package-path Swift WebTransportClient
swift run --package-path Swift WebTransportServer
cd Swift && ./run-pywebtransport-interop.sh
cd Swift && ./run-third-party-interop.sh
cd Swift && ./build-release-apple-silicon.sh
cd Swift && ./check-api-compatibility.sh
```

## C99

The C99 implementation has not started. The `C99/` directory currently contains documentation only.

## C++

The C++ implementation has not started. The implementation directory is named `CPP/` to avoid `+` characters in paths.
