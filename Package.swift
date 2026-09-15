// swift-tools-version: 6.3
//
// A-0005: 6.3 is deliberate, not a stale copy of the mandated toolchain.
// `swift-tools-version` declares the OLDEST SwiftPM that may read this manifest,
// and Swift/check-toolchain.sh records 6.3.3 / Xcode 26.6 as the project's
// development floor. The mandate (Swift 6.4 / Xcode 27) is asserted separately
// by CI (`./Swift/check-toolchain.sh 6.4 27.0`), so raising this line to 6.4
// would lock a contributor on the documented floor out of the package without
// enabling any manifest feature this file uses. Revisit only when the 6.3.3
// floor itself moves.
import PackageDescription

let strictSwiftSettings: [SwiftSetting] = [
    .strictMemorySafety(),
    // A-0004: §1 of the audit brief mandates warnings-as-errors for Swift. The
    // setting lives here, in the project's own build settings, so a new warning
    // fails `swift build` for every contributor and for CI, instead of being
    // visible only on a command line that happens to pass -warnings-as-errors.
    .treatAllWarnings(as: .error),
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
                "WebTransportQUICCore",
            ],
            path: "Swift/Sources/WebTransport",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportCLIConformance",
            dependencies: [
                "WebTransport",
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple",
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
                "WebTransportUDPApple",
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
                "WebTransportQUICCore",
            ],
            path: "Swift/Sources/WebTransportTLSCore",
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportHTTP3Core",
            dependencies: [
                "WebTransportQUICCore",
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
        // F-swift-perf-tests-10: the loopback tests in both test targets serialise
        // across processes, so they share one lock implementation instead of each
        // carrying a copy.
        .target(
            name: "WebTransportLoopbackTestSupport",
            path: "Swift/Tests/WebTransportLoopbackTestSupport",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTests",
            dependencies: [
                "WebTransport",
                "WebTransportHTTP3Core",
                "WebTransportLoopbackTestSupport",
                "WebTransportNetworkRuntime",
                "WebTransportQUICCore",
            ],
            path: "Swift/Tests/WebTransportTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportNetworkRuntimeTests",
            dependencies: [
                "WebTransportNetworkRuntime",
                "WebTransportCryptoApple",
                "WebTransportHTTP3Core",
                "WebTransportLoopbackTestSupport",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple",
            ],
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
                "WebTransportUDPApple",
            ],
            path: "Swift/Tests/WebTransportUDPAppleTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportCryptoAppleTests",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportTLSCore",
                "WebTransportQUICCore",
            ],
            path: "Swift/Tests/WebTransportCryptoAppleTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTLSCoreTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportTLSCore",
            ],
            path: "Swift/Tests/WebTransportTLSCoreTests",
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportHTTP3CoreTests",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
            ],
            path: "Swift/Tests/WebTransportHTTP3CoreTests",
            swiftSettings: strictSwiftSettings
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
