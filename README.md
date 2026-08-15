<p align="center">
  <img width="820" alt="Conceptual WebTransport infographic showing HTTP/3 over QUIC and UDP, reliable streams, optional datagrams, security properties, use cases, and a comparison with WebSockets and WebRTC DataChannel" src="https://github.com/user-attachments/assets/32af02c3-ee01-4fc6-962c-6d618cead8f5">
</p>

# WebTransport

[![Swift CI](https://github.com/Pummelchen/WebTransport/actions/workflows/swift-ci.yml/badge.svg?branch=main)](https://github.com/Pummelchen/WebTransport/actions/workflows/swift-ci.yml)
[![Release](https://img.shields.io/github/v/release/Pummelchen/WebTransport?display_name=tag)](https://github.com/Pummelchen/WebTransport/releases/latest)
[![License](https://img.shields.io/github/license/Pummelchen/WebTransport)](LICENSE)

A native Swift reference implementation of WebTransport over HTTP/3.

The project provides a high-level Swift concurrency API, layered HTTP/3, QUIC, and TLS modules, command-line peers, conformance scenarios, and independent interoperability tooling. The current protocol target is [`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/), published on 6 July 2026.

<p align="center"><em>Conceptual overview of WebTransport. Project-specific implementation coverage and limitations are documented below.</em></p>

> This is an actively developed reference implementation for macOS. Review the [known limitations](https://github.com/Pummelchen/WebTransport/wiki/Known-Limitations) before adopting it in production systems.

## Current baseline

| | |
| --- | --- |
| Latest release | [1.3.1](https://github.com/Pummelchen/WebTransport/releases/tag/1.3.1) |
| Platform | macOS 26 or later |
| Toolchain | Xcode 26.6 or later, Swift 6.3.3 or later, Swift language mode 6 |
| Runtime | Network.framework QUIC with Apple Security and CryptoKit |
| Protocol | WebTransport over HTTP/3, draft 16 |

The Swift conformance matrix passes in full. C99 and C++ directories contain planning material only; they are not protocol implementations.

1.3.0 added server TLS identity injection, graceful shutdown, connection admission
limits, and certificate expiry reporting, and was the first release verified end to
end against a browser. 1.3.1 fixes an inbound stream delivered twice by the
transport being processed twice, which was the main cause of sessions failing to
establish. The code audit for the 1.3 series was performed by Claude Opus 5.

One change is deliberately not backwards compatible: the built-in development
certificate is now **refused on any non-loopback bind address**. A server that
previously bound `0.0.0.0` with default settings now fails at startup with an
error naming the fix, rather than starting and being unreachable by every real
client.

Session establishment is close to but not fully reliable: about 0.07% of loopback
sessions still fail and end in a timeout, from one cause that has not yet been
reproduced under instrumentation. Treat a connect timeout as retryable, and read
the
[known limitations](https://github.com/Pummelchen/WebTransport/wiki/Known-Limitations)
before adopting this in production.

## Add the package

```swift
.package(
    url: "https://github.com/Pummelchen/WebTransport.git",
    exact: "1.3.1"
)
```

Add the `WebTransport` product to the target that owns your client or server code.

## Minimal client

```swift
import Foundation
import WebTransport

let client = WebTransportClient(configuration: WebTransportClientConfiguration(
    authority: "example.com",
    path: "/wt",
    origin: "https://example.com",
    availableProtocols: ["demo.v1"]
))

let session = try await client.connect(
    to: WebTransportEndpoint(host: "example.com", port: 443)
)
let stream = try await session.openBidirectionalStream()
try await stream.send(Data("hello".utf8), endOfStream: true)
let response = try await stream.receive()
try await session.close()
```

Platform certificate trust is the client default. The local self-signed mode is explicit and restricted to loopback development endpoints.

A server needs a real identity. The default development certificate is refused on
any non-loopback bind address, because a self-signed certificate cannot be
validated by a peer for a routable name:

```swift
let server = WebTransportServer(configuration: WebTransportServerConfiguration(
    authority: "example.com",
    identity: .pkcs12(data: bundle, passphrase: passphrase),
    admission: .publicFacing
))
```

Serving browsers additionally requires `settingsValidation: .interoperable`. The
default is `.draft16Strict`, which is the point of this implementation but
rejects peers still on earlier revisions — browsers among them.

## What is implemented

- WebTransport extended CONNECT, protocol negotiation, streams, datagrams, close, and drain.
- Draft-16 optimistic capsules, directional flow control, close-message limits, and TLS exporter binding.
- HTTP/3 settings and frames, QPACK, QUIC wire/state primitives, and TLS 1.3 handshake support.
- A Network.framework-backed client/server runtime with sanitized logging and public error surfaces.
- Server TLS identity injection (PKCS#12 or DER chain), graceful shutdown with GOAWAY and drain, connection admission limits, and tunable QUIC transport parameters.
- Deterministic protocol tests, malformed-input and resource-limit coverage, parser fuzzing, sanitizer and soak runs, CLI conformance, and reproducible release builds.
- Independent stream and datagram interoperability against pywebtransport/aioquic, Quinn, and Quiche, plus verified browser sessions with Chrome.

See [Implementation Status](https://github.com/Pummelchen/WebTransport/wiki/Implementation-Status) for the precise coverage boundary.

## Prebuilt binaries

The [1.3.1 release](https://github.com/Pummelchen/WebTransport/releases/tag/1.3.1)
ships `WebTransportClient` and `WebTransportServer` as Apple Silicon Mach-O
binaries. They are thin arm64 and run natively on every Apple Silicon Mac, M1 and
later. They are ad-hoc signed rather than Developer ID signed, and are not
notarized, so Gatekeeper quarantines them on first run; clear it after verifying
the checksums:

```sh
shasum -a 256 -c SHA256SUMS
xattr -d com.apple.quarantine WebTransportClient WebTransportServer
./WebTransportServer --scenario all
```

Both builds are reproducible: `./Swift/build-release-apple-silicon.sh` performs
two clean builds and compares normalized Mach-O hashes, so the published
checksums can be rebuilt from source.

## Build and verify

```sh
swift build
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all
```

Interoperability against independent implementations, and a connection-churn soak:

```sh
./Swift/run-docker-interop.sh
./Swift/run-soak.sh
```

Release and interoperability checks live under `Swift/`:

```sh
cd Swift
./check-api-compatibility.sh
./build-release-apple-silicon.sh
./run-third-party-interop.sh
```

CI validates the Swift 6.3.3 toolchain baseline, strict memory and concurrency diagnostics, the build, DocC catalog, public API sample, reproducible artifacts, package tests, and both command-line conformance suites.

## Documentation

- [Getting Started](https://github.com/Pummelchen/WebTransport/wiki/Getting-Started)
- [Architecture](https://github.com/Pummelchen/WebTransport/wiki/Architecture)
- [Implementation Status](https://github.com/Pummelchen/WebTransport/wiki/Implementation-Status)
- [Development and Testing](https://github.com/Pummelchen/WebTransport/wiki/Development-and-Testing)
- [Security and Trust](https://github.com/Pummelchen/WebTransport/wiki/Security-and-Trust)
- [Release and Interoperability](https://github.com/Pummelchen/WebTransport/wiki/Release-and-Interoperability)
- [Changelog](https://github.com/Pummelchen/WebTransport/wiki/Changelog)
- [Known Limitations](https://github.com/Pummelchen/WebTransport/wiki/Known-Limitations)

The [Wiki](https://github.com/Pummelchen/WebTransport/wiki) is the maintained technical reference. Public API documentation is also available through the package's DocC catalog.

## Security

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/Pummelchen/WebTransport/security/advisories/new). Do not disclose security issues in public GitHub issues.

## License

WebTransport is available under the [MIT License](LICENSE).
