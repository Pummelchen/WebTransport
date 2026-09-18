<p align="center">
  <img width="820" alt="Conceptual WebTransport infographic showing HTTP/3 over QUIC and UDP, reliable streams, optional datagrams, security properties, use cases, and a comparison with WebSockets and WebRTC DataChannel" src="https://github.com/user-attachments/assets/32af02c3-ee01-4fc6-962c-6d618cead8f5">
</p>

# WebTransport

[![Swift CI](https://github.com/Pummelchen/WebTransport/actions/workflows/swift-ci.yml/badge.svg?branch=main)](https://github.com/Pummelchen/WebTransport/actions/workflows/swift-ci.yml)
[![Release](https://img.shields.io/github/v/release/Pummelchen/WebTransport?display_name=tag)](https://github.com/Pummelchen/WebTransport/releases/latest)
[![License](https://img.shields.io/github/license/Pummelchen/WebTransport)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Pummelchen/WebTransport?style=flat-square&logo=github&label=Stars&color=e3b341)](https://github.com/Pummelchen/WebTransport/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/Pummelchen/WebTransport?style=flat-square&logo=git&label=Last%20Commit&color=2ea44f)](https://github.com/Pummelchen/WebTransport/commits/main)
[![Contact](https://img.shields.io/badge/Contact-0xa0b1%40gmail.com-blue?style=flat-square&logo=gmail&logoColor=white)](mailto:0xa0b1@gmail.com)

A native Swift reference implementation of WebTransport over HTTP/3.

The project provides a high-level Swift concurrency API, layered HTTP/3, QUIC, and TLS modules, command-line peers, conformance scenarios, and independent interoperability tooling. The current protocol target is [`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/), published on 6 July 2026.

<p align="center"><em>Conceptual overview of WebTransport. Project-specific implementation coverage and limitations are documented below.</em></p>

> This is an actively developed reference implementation for macOS. Review the [known limitations](https://github.com/Pummelchen/WebTransport/wiki/Known-Limitations) before adopting it in production systems.

## Current baseline

| | |
| --- | --- |
| Latest release | [1.6](https://github.com/Pummelchen/WebTransport/releases/tag/1.6) |
| Platform | macOS 26 or later |
| Toolchain | Xcode 27 or later, Swift 6.4 or later, Swift language mode 6 |
| Runtime | Network.framework QUIC with Apple Security and CryptoKit |
| Protocol | WebTransport over HTTP/3, draft 16 |

Both libraries implement the draft-16 session layer, and both are exercised against independent
implementations rather than only against themselves: the Swift conformance matrix passes in full,
the C99 suite is 105 CTest tests plus a 57-scenario conformance tool, and the C99 client completes
sessions and message exchanges against five third-party implementations on a routable host with
system trust.

What works today, and what does not, is on the wiki --
[Implementation Status](https://github.com/Pummelchen/WebTransport/wiki/Implementation-Status) and
[Known Limitations](https://github.com/Pummelchen/WebTransport/wiki/Known-Limitations) -- with the
per-release evidence in
[Release and Interoperability](https://github.com/Pummelchen/WebTransport/wiki/Release-and-Interoperability).
The phase-by-phase development record is in the git history and the release notes.

## Add the package

```swift
.package(
    url: "https://github.com/Pummelchen/WebTransport.git",
    exact: "1.6"
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

Platform certificate trust is the client default, and the certificate is verified against the configured
`authority` rather than against the address dialled: `to:` may be an address the name is merely reachable at
(a load balancer, a tailnet address, an `/etc/hosts` entry), while a certificate that does not cover the
authority is still refused. The local self-signed mode is explicit and restricted to loopback development
endpoints.

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
- Draft-16 optimistic capsules, close-message limits, and TLS exporter binding.
- Directional flow control implemented and conformance-tested in `WebTransportHTTP3Core`; the Network.framework runtime does not negotiate the `SETTINGS_WT_INITIAL_MAX_*` limits and serves one WebTransport session per connection.
- HTTP/3 settings and frames, QPACK, QUIC wire/state primitives, and TLS 1.3 handshake support.
- A Network.framework-backed client/server runtime with sanitized logging and public error surfaces.
- Server TLS identity injection (PKCS#12 or DER chain), graceful shutdown with GOAWAY and drain, connection admission limits, and tunable QUIC transport parameters.
- Deterministic protocol tests, malformed-input and resource-limit coverage, parser fuzzing, sanitizer and soak runs, CLI conformance, and reproducible release builds.
- Independent stream and datagram interoperability against five implementations — pywebtransport/aioquic, Quinn, Quiche, hyperium/h3-webtransport and erlang-webtransport — verified both in containers and over a routable network path with platform system trust, plus verified browser sessions with Chrome.

See [Implementation Status](https://github.com/Pummelchen/WebTransport/wiki/Implementation-Status) for the precise coverage boundary.

## Prebuilt binaries

The [1.6 release](https://github.com/Pummelchen/WebTransport/releases/tag/1.6)
carries **both libraries** of this repository, at the same version, with the source of
both as the Release's own source archives:

- `WebTransport-swift-1.6-macos-arm64.tar.gz` — `WebTransportClient`,
  `WebTransportServer`, `SHA256SUMS`, `LICENSE`, `THIRD_PARTY_NOTICES.md` and a
  `README-binaries.txt`.
- `WebTransport-c99-1.6-macos-arm64.tar.gz` — `libwebtransport.1.6.dylib` and
  `libwebtransport.a`, the 64 public headers, the `find_package(webtransport_c99)`
  CMake package, the three `wt-*-c99` tools, `LICENSE`, `THIRD_PARTY_NOTICES.md` and a
  `README-binaries.txt` that names the OpenSSL 3 runtime dependency.

Each archive has its SHA-256 beside it as `<archive>.sha256`. Every Mach-O in both is
thin arm64 and runs natively on every Apple Silicon Mac, M1 and later. They are
ad-hoc signed rather than Developer ID signed, and are not notarized, so Gatekeeper
quarantines them on first run; an archive unpacks with its modes, so verify the
digest, unpack, then clear the quarantine flag:

```sh
shasum -a 256 -c WebTransport-swift-1.6-macos-arm64.tar.gz.sha256
tar -xzf WebTransport-swift-1.6-macos-arm64.tar.gz
shasum -a 256 -c SHA256SUMS
xattr -dr com.apple.quarantine WebTransportClient WebTransportServer
./WebTransportServer --scenario all
```

`./release-macos-arm64.sh` builds and packs both archives and is a dry run unless given
`--publish` (or `--republish`, to correct a published Release in place); it asserts
`lipo -archs` is exactly `arm64` on every Mach-O it ships before it packages them.

Two of the forty conformance scenarios assert properties of the source tree -- they
read `Package.swift` and `Swift/build-release-apple-silicon.sh` from the working
directory -- so run them from a checkout; the other 38 exercise the transport and
run anywhere. From a directory that holds only the assets the suite reports
`passed=38 failed=0 skipped=2` and exits **3**: nothing failed, but two scenarios
could not be attempted, and the report says which and why rather than failing them
(WT-186).

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

CI validates the Swift 6.4 toolchain baseline, strict memory and concurrency diagnostics, the build, DocC catalog, public API sample, reproducible artifacts, package tests, and both command-line conformance suites.

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

## Contact

Questions, bug reports and suggestions are always welcome. You can contact André Borchert by email at [0xa0b1@gmail.com](mailto:0xa0b1@gmail.com).
