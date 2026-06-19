// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "WebTransport",
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
    ],
    targets: [
        .target(
            name: "WebTransport",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime",
                "WebTransportQUICCore"
            ],
            path: "Swift/Sources/WebTransport"
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
            ],
            path: "Swift/Sources/WebTransportCLIConformance"
        ),
        .target(
            name: "WebTransportNetworkRuntime",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple"
            ],
            path: "Swift/Sources/WebTransportNetworkRuntime"
        ),
        .target(
            name: "WebTransportQUICCore",
            path: "Swift/Sources/WebTransportQUICCore"
        ),
        .target(
            name: "WebTransportUDPApple",
            path: "Swift/Sources/WebTransportUDPApple"
        ),
        .target(
            name: "WebTransportCryptoApple",
            dependencies: ["WebTransportQUICCore"],
            path: "Swift/Sources/WebTransportCryptoApple"
        ),
        .target(
            name: "WebTransportTLSCore",
            dependencies: [
                "WebTransportQUICCore"
            ],
            path: "Swift/Sources/WebTransportTLSCore"
        ),
        .target(
            name: "WebTransportHTTP3Core",
            dependencies: [
                "WebTransportQUICCore"
            ],
            path: "Swift/Sources/WebTransportHTTP3Core"
        ),
        .executableTarget(
            name: "WebTransportClient",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime"
            ],
            path: "Swift/Sources/WebTransportClient"
        ),
        .executableTarget(
            name: "WebTransportServer",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime"
            ],
            path: "Swift/Sources/WebTransportServer"
        ),
        .testTarget(
            name: "WebTransportTests",
            dependencies: ["WebTransport"],
            path: "Swift/Tests/WebTransportTests"
        ),
        .testTarget(
            name: "WebTransportNetworkRuntimeTests",
            dependencies: ["WebTransportNetworkRuntime"],
            path: "Swift/Tests/WebTransportNetworkRuntimeTests"
        ),
        .testTarget(
            name: "WebTransportQUICCoreTests",
            dependencies: ["WebTransportQUICCore"],
            path: "Swift/Tests/WebTransportQUICCoreTests"
        ),
        .testTarget(
            name: "WebTransportUDPAppleTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportUDPApple"
            ],
            path: "Swift/Tests/WebTransportUDPAppleTests"
        ),
        .testTarget(
            name: "WebTransportCryptoAppleTests",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportTLSCore"
            ],
            path: "Swift/Tests/WebTransportCryptoAppleTests"
        ),
        .testTarget(
            name: "WebTransportTLSCoreTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportTLSCore"
            ],
            path: "Swift/Tests/WebTransportTLSCoreTests"
        ),
        .testTarget(
            name: "WebTransportHTTP3CoreTests",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore"
            ],
            path: "Swift/Tests/WebTransportHTTP3CoreTests"
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
