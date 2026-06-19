#!/bin/sh
set -eu

cd "$(dirname "$0")"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/webtransport-api-compat.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/Sources/APICompat"

cat > "$tmpdir/Package.swift" <<EOF
// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "APICompat",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "$PWD")
    ],
    targets: [
        .executableTarget(
            name: "APICompat",
            dependencies: [
                .product(name: "WebTransport", package: "Swift"),
                .product(name: "WebTransportNetworkRuntime", package: "Swift")
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)
EOF

cat > "$tmpdir/Sources/APICompat/main.swift" <<'EOF'
import Foundation
import WebTransport
import WebTransportNetworkRuntime

let clientConfig = WebTransportClientConfiguration(
    authority: "localhost",
    path: "/wt",
    origin: "https://localhost",
    availableProtocols: ["demo.v1"]
)
let serverConfig = WebTransportServerConfiguration(
    authority: "localhost",
    path: "/wt",
    origin: "https://localhost",
    supportedProtocols: ["demo.v1"]
)
let logger = WebTransportLogger { event in
    _ = event.description
}
_ = WebTransportClient(configuration: clientConfig, logger: logger)
_ = WebTransportServer(configuration: serverConfig, logger: logger)
_ = WebTransportEndpoint(host: "127.0.0.1", port: 4433)
_ = try WebTransportEndpoint.parse("[::1]:4433")
WebTransportLogger.disabled.record(.sessionEstablished(role: "api-compat"))
_ = WebTransportNetworkEndpoint(host: "127.0.0.1", port: 4433)
_ = WebTransportQUICClient(trustPolicy: .systemTrust)
_ = WebTransportErrorSurface.publicDescription(for: WebTransportSampleError())

struct WebTransportSampleError: Error {}

func exercisePublicSessionAPI(_ session: WebTransportSession) async throws {
    let stream: WebTransportBidirectionalStream = try await session.openBidirectionalStream()
    _ = stream.id
    try await stream.send(Data("hello".utf8))
    _ = try await stream.receive()
    try await session.sendDatagram(Data("datagram".utf8))
    _ = try await session.receiveDatagram()
    try await session.drain()
    try await session.close(applicationErrorCode: 0, reason: "done")
}

func exercisePublicListenerAPI(_ listener: WebTransportListeningServer) {
    listener.shutdown()
}
EOF

swift build --package-path "$tmpdir"
