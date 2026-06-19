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
- TLS/QUIC state with application-key readiness gated on certificate trust, CertificateVerify, Finished, ALPN h3, and QUIC transport parameters; QUIC packet protection helpers, transport-parameter codecs, packet-protected QUIC Initial CRYPTO flight validation including Certificate, CertificateVerify, and Finished, transcript-derived 1-RTT packet keys for protected HTTP/3 WebTransport CONNECT/DATAGRAM session signaling over UDP, UDP loopback support, and prompt-free identity/trust test paths.
- Packet-protected QUIC Initial CRYPTO flight mode with ALPN h3, QUIC transport-parameter validation, validated Certificate/CertificateVerify/Finished handling, validated-handshake 1-RTT key derivation, and protected HTTP/3 WebTransport CONNECT/DATAGRAM session signaling for separate-process `WebTransportClient` / `WebTransportServer` networking, with raw-frame compatibility mode.
- CLI conformance harness with 40 scenarios shared by `WebTransportClient` and `WebTransportServer`, including positive/negative interop matrices for CONNECT, streams, datagrams, GOAWAY, close/drain, malformed input, and flow-control errors.
- Deterministic parser/property hardening tests for QPACK, HTTP/3 frames, capsules, QUIC varints, QUIC transport parameters, WebTransport stream prefixes, resource limits, malformed peers, ordering, replay, exhaustion, and close/reset races.
- Process-level CLI tests for help/list/error/scenario exit codes and IPv4/IPv6 frame/packet loopback.
- Concurrent multi-session stress, repeatable soak, datagram load, backpressure, network impairment, and runtime security-negative tests.
- Release artifact smoke tests and a standalone public API compatibility sample build.
- External interoperability proof runners via `./run-third-party-interop.sh` and `./run-pywebtransport-interop.sh`. The three-endpoint runner launches independent `pywebtransport`/`aioquic`, `web-transport-quinn`, and `web-transport-quiche` echo endpoints and records QUIC/TLS/HTTP/3 CONNECT plus reliable WebTransport stream echo proofs in `.build/external-interop/third-party-latest.json`. Configured public endpoint probing remains available through `./run-external-interop.sh`.
- macOS 26 arm64 CI matrix over explicit Xcode 26 toolchains.
- Sanitized opt-in production logging and public error descriptions that avoid TLS secrets, packet bytes, datagram payloads, raw session IDs, and close reason text.
- Apple Silicon release script for reproducibility-checked production CLI binaries with `SHA256SUMS`.

Recent status:

- The separate-process `--transport packet` and `--transport frame` paths are wired to the Network.framework QUIC/TLS/HTTP/3 runtime. Platform trust is the runtime default; the CLI explicitly opts into its localhost self-signed development identity for loopback tests.

## Public API Surface

The high-level `WebTransport` product exposes:

- `WebTransportClientConfiguration` and `WebTransportServerConfiguration` for authority, path, origin, and subprotocol policy.
- `WebTransportClient` and `WebTransportServer` actors for Swift concurrency session establishment.
- `WebTransportSendStream`, `WebTransportReceiveStream`, and `WebTransportBidirectionalStream` with bounded async byte delivery.
- `WebTransportClientSession` through the `WebTransportSession` protocol for datagram send/receive and close.
- `WebTransportLogger` and `WebTransportLogEvent` for sanitized opt-in production events.
- `WebTransportErrorSurface.publicDescription(for:)` for user-visible/logged error text that redacts peer-controlled detail.

The logger never emits TLS secrets, certificate material, QUIC connection IDs, raw session IDs, packet bytes, datagram payloads, or close reason text.

Release artifacts are written to `.build/release-artifacts/` by `./build-release-apple-silicon.sh` after two clean release builds produce matching product hashes.

## Commands

```sh
swift build
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all
swift run WebTransportServer --listen 127.0.0.1:4433 --transport packet
swift run WebTransportClient --connect 127.0.0.1:4433 --transport packet
swift run WebTransportServer --listen '[::1]:4433' --transport packet
swift run WebTransportClient --connect '[::1]:4433' --transport packet
swift run WebTransportClient
swift run WebTransportServer
./run-pywebtransport-interop.sh
./run-third-party-interop.sh
./build-release-apple-silicon.sh
./check-api-compatibility.sh
```

## External Interop

`./run-third-party-interop.sh` is the release proof for three independent draft-15-compatible endpoints. It installs local tool dependencies under `.build/` as needed, including a Python-wheel CMake for the Quiche/BoringSSL build when no system `cmake` exists. It then launches:

- `pywebtransport==0.1.2` / `aioquic`
- `web-transport-quinn 0.11.9`
- `web-transport-quiche 0.4.1`

The runner records per-endpoint logs plus a consolidated pass/fail report in `.build/external-interop/third-party-latest.json`.

`./run-pywebtransport-interop.sh` installs `pywebtransport==0.1.2` into `.build/external-interop/pywebtransport-venv`, starts a local independent `pywebtransport`/`aioquic` echo server, runs the Swift client against it, and records the result in `.build/external-interop/pywebtransport-latest.json`. This proof covers QUIC/TLS/HTTP/3 CONNECT and reliable WebTransport stream echo. QUIC DATAGRAM interop remains a separate gate because the current Network.framework runtime reports datagrams unavailable against external peers.

`./run-external-interop.sh` runs the Swift client against a configured independent WebTransport endpoint and records the result in `.build/external-interop/latest.json`. Configure the target with:

```sh
WEBTRANSPORT_EXTERNAL_INTEROP_ENDPOINT=host:443 \
WEBTRANSPORT_EXTERNAL_INTEROP_AUTHORITY=host \
WEBTRANSPORT_EXTERNAL_INTEROP_PATH=/ \
WEBTRANSPORT_EXTERNAL_INTEROP_TRUST=system \
./run-external-interop.sh
```
