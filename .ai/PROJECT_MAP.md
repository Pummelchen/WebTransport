<!--
AI onboarding file.
Mode: bootstrap
Indexed commit: 742358be03922065f4aca3af823d36df5993204d
Last generated: 2026-06-26T15:16:55+02:00
Generator: generic high-end AI coding agent
Purpose: Help future AI sessions understand this repository quickly.
Audience: Any high-capability AI coding agent, regardless of vendor or model family.
Human edits are allowed. Future refreshes should preserve valid human edits.
-->
# Project Map

This repository has one active Swift implementation and two planned implementation directories.

## Key paths

- `Package.swift`: root SwiftPM manifest.
- `Swift/Package.swift`: Swift subpackage manifest with additional smoke tools.
- `Swift/Sources/WebTransport/`: public API.
- `Swift/Sources/WebTransportNetworkRuntime/`: Network.framework runtime.
- `Swift/Sources/WebTransportHTTP3Core/`: HTTP/3 and WebTransport protocol logic.
- `Swift/Sources/WebTransportQUICCore/`: QUIC primitives.
- `Swift/Sources/WebTransportTLSCore/`: TLS core.
- `Swift/Sources/WebTransportCryptoApple/`: Apple crypto helpers.
- `Swift/Sources/WebTransportUDPApple/`: Darwin UDP loopback helper.
- `Swift/Sources/WebTransportClient/main.swift`: client CLI.
- `Swift/Sources/WebTransportServer/main.swift`: server CLI.
- `Swift/Tests/`: Swift tests.
- `C99/`: planned C99 implementation skeleton.
- `CPP/`: planned C++23 implementation skeleton.
- `.github/workflows/swift-ci.yml`: CI workflow.

## Package graph

`WebTransport` depends on HTTP3Core, NetworkRuntime, and QUICCore. NetworkRuntime depends on CryptoApple, HTTP3Core, QUICCore, TLSCore, and UDPApple. HTTP3Core, TLSCore, and CryptoApple depend on QUICCore.

Evidence: `Package.swift`, `Swift/Package.swift`, `Swift/README.md`.
