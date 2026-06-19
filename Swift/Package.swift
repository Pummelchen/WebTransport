// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "WebTransportSwift",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .library(
            name: "WebTransport",
            targets: ["WebTransport"]
        ),
        .library(
            name: "WebTransportQUICCore",
            targets: ["WebTransportQUICCore"]
        ),
        .library(
            name: "WebTransportUDPApple",
            targets: ["WebTransportUDPApple"]
        ),
        .library(
            name: "WebTransportCryptoApple",
            targets: ["WebTransportCryptoApple"]
        ),
        .library(
            name: "WebTransportTLSCore",
            targets: ["WebTransportTLSCore"]
        ),
        .library(
            name: "WebTransportHTTP3Core",
            targets: ["WebTransportHTTP3Core"]
        ),
        .executable(
            name: "WebTransportClient",
            targets: ["WebTransportClient"]
        ),
        .executable(
            name: "WebTransportServer",
            targets: ["WebTransportServer"]
        )
    ],
    targets: [
        .target(
            name: "WebTransport",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore"
            ]
        ),
        .target(
            name: "WebTransportQUICCore"
        ),
        .target(
            name: "WebTransportUDPApple"
        ),
        .target(
            name: "WebTransportCryptoApple",
            dependencies: ["WebTransportQUICCore"]
        ),
        .target(
            name: "WebTransportTLSCore",
            dependencies: [
                "WebTransportQUICCore"
            ]
        ),
        .target(
            name: "WebTransportHTTP3Core",
            dependencies: [
                "WebTransportQUICCore"
            ]
        ),
        .executableTarget(
            name: "AppleQUICSpike"
        ),
        .executableTarget(
            name: "NativeQUICCoreSpike",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple"
            ]
        ),
        .executableTarget(
            name: "WebTransportClient",
            dependencies: ["WebTransport"]
        ),
        .executableTarget(
            name: "WebTransportServer",
            dependencies: ["WebTransport"]
        ),
        .testTarget(
            name: "WebTransportTests",
            dependencies: ["WebTransport"]
        ),
        .testTarget(
            name: "WebTransportQUICCoreTests",
            dependencies: ["WebTransportQUICCore"]
        ),
        .testTarget(
            name: "WebTransportUDPAppleTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportUDPApple"
            ]
        ),
        .testTarget(
            name: "WebTransportCryptoAppleTests",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportTLSCore"
            ]
        ),
        .testTarget(
            name: "WebTransportTLSCoreTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportTLSCore"
            ]
        ),
        .testTarget(
            name: "WebTransportHTTP3CoreTests",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore"
            ]
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
