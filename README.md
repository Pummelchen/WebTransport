<img width="1055" height="1491" alt="WebTransport project status infographic showing Swift draft-15 compatibility and planned C99 and C++ implementations" src="https://github.com/user-attachments/assets/32af02c3-ee01-4fc6-962c-6d618cead8f5" />

# WebTransport

A native WebTransport over HTTP/3 implementation for Swift, with planned C99 and C++ ports.

The implementation targets `draft-ietf-webtrans-http3-15`. As of 11 August 2026, the latest IETF revision is
[`draft-ietf-webtrans-http3-16`](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/),
published on 6 July 2026. The compatibility score below applies only to draft 15.

Full project documentation is available in the [WebTransport Wiki](https://github.com/Pummelchen/WebTransport/wiki).

## Status

| Implementation | Draft-15 compatibility | Status |
| --- | ---: | --- |
| Swift | 100% | Production SwiftPM package and CLI apps. |
| C99 | 0% | Planned. No protocol implementation yet. |
| C++ (`CPP`) | 0% | Planned. No protocol implementation yet. |

License: [MIT](LICENSE).

## Swift

The Swift implementation is the active implementation and is exposed as a normal Swift package from the repository root.
It requires macOS 26 or later, Swift 6.3, and Swift language mode 6.

```swift
.package(url: "https://github.com/Pummelchen/WebTransport.git", exact: "1.0.0")
```

Products:

- `WebTransport`
- `WebTransportNetworkRuntime`
- `WebTransportHTTP3Core`
- `WebTransportQUICCore`
- `WebTransportTLSCore`
- `WebTransportCryptoApple`
- `WebTransportUDPApple`
- `WebTransportClient`
- `WebTransportServer`

Minimal client example:

```swift
import Foundation
import WebTransport

let client = WebTransportClient(configuration: WebTransportClientConfiguration(
    authority: "example.com",
    path: "/wt",
    origin: "https://example.com",
    availableProtocols: ["demo.v1"]
))

let session = try await client.connect(to: WebTransportEndpoint(host: "example.com", port: 443))
let stream = try await session.openBidirectionalStream()
try await stream.send(Data("hello".utf8), endOfStream: true)
let response = try await stream.receive()
```

Release 1.0.0 was validated on 20 June 2026 against five independent WebTransport implementations.
The complete point-in-time matrix, proof requirements, and caveats are documented in
[Release and Interoperability](https://github.com/Pummelchen/WebTransport/wiki/Release-and-Interoperability).

Generate the local third-party proof with:

```sh
cd Swift && ./run-third-party-interop.sh
```

Generate the remote VPS matrix with:

```sh
cd Swift && ./run-vps-third-party-interop.sh
```

Core local checks:

```sh
swift build
swift test
swift run WebTransportClient --scenario all
swift run WebTransportServer --scenario all
```

Release checks:

```sh
cd Swift && ./check-api-compatibility.sh
cd Swift && ./build-release-apple-silicon.sh
```

## C99

Planned implementation. The `C99/` directory currently contains the C99 implementation plan, source/API/test skeleton, platform build-support folders, generated artifact layout, and an `Experiments/` folder. No protocol implementation exists yet.

## C++

Planned implementation. The `CPP/` directory contains the C++23 implementation plan, source/API/test/application skeleton,
platform build-support folders, generated artifact layout, and an `Experiments/` folder. No protocol implementation exists yet.
