# Swift implementation

This directory contains the native Swift implementation and its implementation-level tools. The repository root is the supported SwiftPM integration point for applications.

The protocol target is [draft-ietf-webtrans-http3-16](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/16/), published 6 July 2026. The implementation is actively developed as a reference-quality codebase; conformance results are engineering evidence, not a standards certification.

## Requirements

- macOS 26 or later
- Swift 6.3
- Apple Silicon for release artifact generation

## Package structure

| Module | Responsibility |
| --- | --- |
| `WebTransport` | Public client, server, session, stream, datagram, drain, and close APIs |
| `WebTransportNetworkRuntime` | Network.framework-backed QUIC/TLS/HTTP/3 runtime |
| `WebTransportHTTP3Core` | HTTP/3, QPACK, capsules, and WebTransport framing |
| `WebTransportQUICCore` | QUIC transport parameters, packet protection, and flow control |
| `WebTransportTLSCore` | TLS handshake state and exporter bindings |
| `WebTransportCryptoApple` | Apple Security and CryptoKit integration |
| `WebTransportUDPApple` | Loopback packet-probe support used by tests |
| `WebTransportClient` / `WebTransportServer` | Command-line conformance and packet-mode tools |

The nested package also includes smoke-test utilities and implementation fixtures. Product applications should depend on the package at the repository root.

## Build and test

From this directory:

```sh
swift build
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all
./check-api-compatibility.sh
```

Run a local packet-mode session in separate terminals:

```sh
swift run WebTransportServer --listen 127.0.0.1:4433 --transport packet
swift run WebTransportClient \
  --connect 127.0.0.1:4433 \
  --transport packet \
  --trust local-self-signed
```

`local-self-signed` is restricted to explicit loopback testing. Normal deployments use platform trust and application-defined authentication and authorization.

## Interoperability and release checks

```sh
./run-pywebtransport-interop.sh
./run-third-party-interop.sh
./run-vps-third-party-interop.sh
./build-release-apple-silicon.sh
```

Interop reports are written below `.build/external-interop/`. Release artifacts and `SHA256SUMS` are written below `.build/release-artifacts/` after two clean builds produce matching hashes.

The VPS runner depends on separately provisioned infrastructure and is not part of the default local test suite.

## Documentation

- [Project overview](../README.md)
- [Implementation status](https://github.com/Pummelchen/WebTransport/wiki/Implementation-Status)
- [Development and testing](https://github.com/Pummelchen/WebTransport/wiki/Development-and-Testing)
- [Release and interoperability](https://github.com/Pummelchen/WebTransport/wiki/Release-and-Interoperability)
- [Security and trust](https://github.com/Pummelchen/WebTransport/wiki/Security-and-Trust)
