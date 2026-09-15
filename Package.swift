// swift-tools-version: 6.4
import PackageDescription

let strictSwiftSettings: [SwiftSetting] = [
    .strictMemorySafety()
]

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
            path: "Swift/Sources/WebTransport",
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
            path: "Swift/Sources/WebTransportCLIConformance",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportNetworkRuntime",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportSecurityShim",
                "WebTransportTLSCore",
                "WebTransportUDPApple"
            ],
            path: "Swift/Sources/WebTransportNetworkRuntime",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportSecurityShim",
            path: "Swift/Sources/WebTransportSecurityShim"
        ),
        .target(
            name: "WebTransportQUICCore",
            path: "Swift/Sources/WebTransportQUICCore",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportUDPApple",
            path: "Swift/Sources/WebTransportUDPApple",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportCryptoApple",
            dependencies: ["WebTransportQUICCore"],
            path: "Swift/Sources/WebTransportCryptoApple",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportTLSCore",
            dependencies: [
                "WebTransportQUICCore"
            ],
            path: "Swift/Sources/WebTransportTLSCore",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportHTTP3Core",
            dependencies: [
                "WebTransportQUICCore"
            ],
            path: "Swift/Sources/WebTransportHTTP3Core",
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
            path: "Swift/Sources/WebTransportClient",
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
            path: "Swift/Sources/WebTransportServer",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTests",
            dependencies: ["WebTransport"],
            path: "Swift/Tests/WebTransportTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportNetworkRuntimeTests",
            dependencies: ["WebTransportNetworkRuntime"],
            path: "Swift/Tests/WebTransportNetworkRuntimeTests",
            resources: [
                .copy("Resources/README.md"),
                .copy("Resources/libressl-explicit-curve-identity.p12"),
                .copy("Resources/libressl-rsa-identity.p12"),
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportQUICCoreTests",
            dependencies: ["WebTransportQUICCore"],
            path: "Swift/Tests/WebTransportQUICCoreTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportUDPAppleTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportUDPApple"
            ],
            path: "Swift/Tests/WebTransportUDPAppleTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportCryptoAppleTests",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportTLSCore"
            ],
            path: "Swift/Tests/WebTransportCryptoAppleTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTLSCoreTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportTLSCore"
            ],
            path: "Swift/Tests/WebTransportTLSCoreTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportHTTP3CoreTests",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                // PeerInputFuzzTests calls WebTransportTLSCore's parsers directly. The dependency was
                // implicit and resolved through eager linking before the Swift 6.4 build system, which
                // no longer surfaces transitive symbols: the test bundle failed to link with
                // "Undefined symbols for architecture arm64" until this became explicit.
                "WebTransportTLSCore"
            ],
            path: "Swift/Tests/WebTransportHTTP3CoreTests",
            swiftSettings: strictSwiftSettings
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
