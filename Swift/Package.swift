// swift-tools-version: 6.3
import PackageDescription

let strictSwiftSettings: [SwiftSetting] = [
    .strictMemorySafety()
]

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
        ),
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
            ],
            swiftSettings: strictSwiftSettings
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
            swiftSettings: strictSwiftSettings
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
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportQUICCore",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportUDPApple",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportCryptoApple",
            dependencies: ["WebTransportQUICCore"],
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportTLSCore",
            dependencies: [
                "WebTransportQUICCore"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportHTTP3Core",
            dependencies: [
                "WebTransportQUICCore"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportTestSupport",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "WebTransportClient",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "WebTransportServer",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "LibrarySmokeServer",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "LibrarySmokeClient",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTests",
            dependencies: ["WebTransport"],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportNetworkRuntimeTests",
            dependencies: ["WebTransportNetworkRuntime"],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportQUICCoreTests",
            dependencies: ["WebTransportQUICCore"],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportUDPAppleTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportUDPApple"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportCryptoAppleTests",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportTLSCore"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTLSCoreTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportTLSCore"
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportHTTP3CoreTests",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore"
            ],
            swiftSettings: strictSwiftSettings
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
