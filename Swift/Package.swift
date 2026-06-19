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
        .library(
            name: "WebTransportNetworkRuntime",
            targets: ["WebTransportNetworkRuntime"]
        ),
        .executable(
            name: "WebTransportClient",
            targets: ["WebTransportClient"]
        ),
        .executable(
            name: "WebTransportServer",
            targets: ["WebTransportServer"]
        )
        .executable(
            name: "LibrarySmokeServer",
            targets: ["LibrarySmokeServer"]
        ),
        .executable(
            name: "LibrarySmokeClient",
            targets: ["LibrarySmokeClient"]
        )
    ],
    targets: [
        .target(
            name: "WebTransport",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime",
                "WebTransportQUICCore"
            ]
        ),
        .target(
            name: "WebTransportCLIConformance",
            dependencies: [
                "WebTransport",
                "WebTransportCryptoApple",
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple"
            ]
        ),
        .target(
            name: "WebTransportNetworkRuntime",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple"
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
        .target(
            name: "WebTransportTestSupport",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore"
            ]
        ),
        .executableTarget(
            name: "WebTransportClient",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime"
            ]
        ),
        .executableTarget(
            name: "WebTransportServer",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime"
            ]
        ),
        .executableTarget(
            name: "ServerCLI",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple"
            ]
        ),
        .executableTarget(
            name: "ClientCLI",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple"
            ]
        ),
        .executableTarget(
            name: "LibrarySmokeServer",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple"
            ]
        ),
        .executableTarget(
            name: "LibrarySmokeClient",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple"
            ]
        ),
        .testTarget(
            name: "WebTransportTests",
            dependencies: ["WebTransport"]
        ),
        .testTarget(
            name: "WebTransportNetworkRuntimeTests",
            dependencies: ["WebTransportNetworkRuntime"]
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
