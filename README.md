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
| Latest release | [1.4.0](https://github.com/Pummelchen/WebTransport/releases/tag/1.4.0) |
| Platform | macOS 26 or later |
| Toolchain | Xcode 27 or later, Swift 6.4 or later, Swift language mode 6 |
| Runtime | Network.framework QUIC with Apple Security and CryptoKit |
| Protocol | WebTransport over HTTP/3, draft 16 |

The Swift conformance matrix passes in full. The C99 implementation is **Phases 0
to 9 complete and Phase 11 (the interop matrix) complete, with Phase 10's test port and Phase 12's CI
legs under way**: it builds with CMake as a static and shared
library with three CLI tools and carries the whole stack -- the core utilities, a QUIC wire core and
crypto layer whose vectors are extracted from the RFCs rather than transcribed, a TLS 1.3 handshake
that runs end to end over CRYPTO frames, the QUIC connection runtime, HTTP/3, QPACK including its
dynamic table, the draft-16 WebTransport session layer, and the public consumer API. It **runs
sessions**: the conformance tool stands up both endpoints in one process over IPv4 and IPv6,
`wt-client-c99` and `wt-server-c99` exchange a session in two processes, and
`C99/scripts/run-container-interop.sh` completes a whole session **and the message exchange** against
an independent implementation (`pywebtransport`/`aioquic`) in a container -- the peer logs
`stream in: 13 bytes` / `stream echoed` and the client reports `received 13 byte(s)`. Outside a
container, `C99/scripts/run-vps-third-party-interop.sh` completes all seven Phase 11 proofs against
**five independent implementations** on a routable host with `--trust system`, so the certificate
chain is validated against the platform trust store and the name is checked rather than bypassed.
84 test programs and 64,731 checks pass on macOS 26 (64,778 on Debian 13; the Wine runner sums 64,900
over the 85 Windows executables), plus a 200,000-input parser fuzz run and a Clang Static
Analyzer pass over all 94 sources. Every suite runs again under AddressSanitizer and
UndefinedBehaviorSanitizer, on macOS and Linux in CI: **97 CTest tests pass on macOS 26 and
Ubuntu 24.04** (the workflow's two `ubuntu-24.04` legs). The tree also compiles, links and
**runs** on Windows (85 of 85 test executables
under Wine, including a Windows-only test of the datagram layer) and FreeBSD 15.1 (the whole suite
on a real kernel) -- and running the Windows branch is what found and fixed `WT-199` and `WT-200`.
Windows is covered by two CI legs: `windows-wine` (enforced -- mingw cross-build, then every test
under Wine) and `windows-native` on `windows-latest` (MSYS2 MINGW64, present but
`continue-on-error: true` until it has been seen green). FreeBSD 15.1 has no CI leg. Of the plan's
nine completion criteria **8 are met and 1 is partial** (the CI *job* for the FreeBSD leg,
`WT-223`, and an enforced native Windows leg, `WT-224`, not the code on them; the outstanding
work is listed on the [C99 tracker](https://github.com/Pummelchen/WebTransport/wiki/Project-Tracker-C99)). All 34 of the
draft-16 compliance-matrix rows are exercised by a test. See
[C99/README.md](C99/README.md) and the
[C99 implementation plan](C99/IMPLEMENTATION_PLAN.md).

1.3.0 added server TLS identity injection, graceful shutdown, connection admission
limits, and certificate expiry reporting, and was the first release verified end to
end against a browser. 1.3.1 refuses an inbound stream that the transport delivers
twice, which a QUIC connection never legitimately does. 1.3.3 attributes the
remaining establishment failures to the transport and names them in the error it
reports. 1.3.4 brings the QPACK Required Insert Count onto the encoding RFC 9204
specifies and bounds the CRYPTO reassembly buffer. The code audit for the 1.3 series was performed by Claude Opus 5.

1.3.6 is a defect-fix release from a further audit of the codecs, the runtime and the
command-line tools. The one with the widest reach is a **timed-out accept**, which used
to leave a waiter at the head of the connection queue and swallow the next connection:
under the documented accept loop every client arriving slower than the one-second
timeout was lost. Several conformance gaps are closed too — `NEW_CONNECTION_ID` and
long-header validity, HKDF output length, transport-parameter values, and the
`retire_prior_to` watermark — and a PKCS#12 bundle whose certificate carries explicit
curve parameters now throws a catchable error instead of terminating the process. See
the [changelog](CHANGELOG.md) for the full list.

1.3.8 reports a peer that ends a stream before sending the bytes that stream has to
begin with as exactly that, instead of as `QUICCodecError.truncated(needed: 1,
available: 0)`. The runtime read the first chunk of a stream and dropped the
`endOfStream` flag, so a peer that FINed an inbound stream without writing to it
produced a message that reads like an internal truncation rather than a peer that is
not following the protocol. `WebTransportNetworkRuntimeError.peerClosedStreamWithoutData(streamID:)`
names the stream and the cause, and a read that returns no bytes while the stream is
still open is now waited out, so "nothing yet" and "the peer is done" cannot be
confused. Reported in issue #24.

1.3.7 fixes a listener that stopped accepting for the rest of its life once it had
served `maxConcurrentConnections` sessions in total. The ceiling was handed to
Network.framework's `newConnectionLimit`, which counts connections over the
listener's whole life rather than at one time — measured with a minimal listener, a
limit of 2 accepts two connections and never a third, however long ago the first two
ended. The default of 16 is low enough to reach in normal operation, and the failure
was silent: the process stayed healthy, every other transport it served kept working,
and only new WebTransport sessions timed out. The runtime now counts in-flight
connections itself and returns each slot when a session ends, and a connection over
the ceiling is still refused before its handshake is driven. Reported in issue #23;
see the [changelog](CHANGELOG.md) for the full list.

One change is deliberately not backwards compatible: the built-in development
certificate is now **refused on any non-loopback bind address**. A server that
previously bound `0.0.0.0` with default settings now fails at startup with an
error naming the fix, rather than starting and being unreachable by every real
client.

Session establishment is reliable on a machine that is not saturated, and degrades
under heavy CPU contention. On four idle Macs, 4000 loopback sessions per release
completed without a single failure; with every core saturated on those same
machines, roughly 1% failed to establish.

The cause is below this package. Network.framework can drop an inbound QUIC stream
on a saturated host, and when the stream it drops is the peer's HTTP/3 control
stream, both ends wait for each other. This reproduces with about 50 lines of
plain `NetworkConnection<QUIC>` and no WebTransport code at all, at 13 connections
in 1600. Nothing here can recover such a connection, because the stream is never
resent — which is also why a longer timeout does not help. The runtime reports
`peerControlStreamNotDelivered` rather than a bare timeout so the condition is
recognisable; **treat it as a signal to open a new connection**. See the
[known limitations](https://github.com/Pummelchen/WebTransport/wiki/Known-Limitations)
before adopting this in production.

## Add the package

```swift
.package(
    url: "https://github.com/Pummelchen/WebTransport.git",
    exact: "1.4.0"
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
- Draft-16 optimistic capsules, close-message limits, and TLS exporter binding.
- Directional flow control implemented and conformance-tested in `WebTransportHTTP3Core`; the Network.framework runtime does not negotiate the `SETTINGS_WT_INITIAL_MAX_*` limits and serves one WebTransport session per connection.
- HTTP/3 settings and frames, QPACK, QUIC wire/state primitives, and TLS 1.3 handshake support.
- A Network.framework-backed client/server runtime with sanitized logging and public error surfaces.
- Server TLS identity injection (PKCS#12 or DER chain), graceful shutdown with GOAWAY and drain, connection admission limits, and tunable QUIC transport parameters.
- Deterministic protocol tests, malformed-input and resource-limit coverage, parser fuzzing, sanitizer and soak runs, CLI conformance, and reproducible release builds.
- Independent stream and datagram interoperability against five implementations — pywebtransport/aioquic, Quinn, Quiche, hyperium/h3-webtransport and erlang-webtransport — verified both in containers and over a routable network path with platform system trust, plus verified browser sessions with Chrome.

See [Implementation Status](https://github.com/Pummelchen/WebTransport/wiki/Implementation-Status) for the precise coverage boundary.

## Prebuilt binaries

The [1.4.0 release](https://github.com/Pummelchen/WebTransport/releases/tag/1.4.0)
carries **both libraries** of this repository, at the same version, with the source of
both as the Release's own source archives:

- `WebTransport-swift-1.4.0-macos-arm64.tar.gz` — `WebTransportClient`,
  `WebTransportServer`, `SHA256SUMS`, `LICENSE`, `THIRD_PARTY_NOTICES.md` and a
  `README-binaries.txt`.
- `WebTransport-c99-1.4.0-macos-arm64.tar.gz` — `libwebtransport.1.4.0.dylib` and
  `libwebtransport.a`, the 64 public headers, the `find_package(webtransport_c99)`
  CMake package, the three `wt-*-c99` tools, `LICENSE`, `THIRD_PARTY_NOTICES.md` and a
  `README-binaries.txt` that names the OpenSSL 3 runtime dependency.

Each archive has its SHA-256 beside it as `<archive>.sha256`. Every Mach-O in both is
thin arm64 and runs natively on every Apple Silicon Mac, M1 and later. They are
ad-hoc signed rather than Developer ID signed, and are not notarized, so Gatekeeper
quarantines them on first run; an archive unpacks with its modes, so verify the
digest, unpack, then clear the quarantine flag:

```sh
shasum -a 256 -c WebTransport-swift-1.4.0-macos-arm64.tar.gz.sha256
tar -xzf WebTransport-swift-1.4.0-macos-arm64.tar.gz
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
