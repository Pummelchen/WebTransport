// swift-tools-version: 6.4
//
// A-0005 kept this at 6.3 while the project's documented development floor
// (6.3.3 / Xcode 26.6) was older than the mandate: `swift-tools-version` declares
// the OLDEST SwiftPM that may read the manifest, and raising it would lock a floor
// contributor out. The toolchain-baseline commit raised the floor itself to Swift
// 6.4 / Xcode 27, so the manifest declares it -- identically in the root manifest,
// which check-manifest-sync.sh compares.
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
        ),
    ],
    targets: [
        .target(
            name: "WebTransport",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime",
                "WebTransportQUICCore",
            ],
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
            swiftSettings: strictSwiftSettings
        ),
        .target(
            name: "WebTransportSecurityShim"
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
                "WebTransportTLSCore",
            ],
            swiftSettings: strictSwiftSettings
        ),
        // F-swift-perf-tests-10: the loopback tests in both test targets serialise
        // across processes, so they share one lock implementation instead of each
        // carrying a copy.
        .target(
            name: "WebTransportLoopbackTestSupport",
            path: "Tests/WebTransportLoopbackTestSupport",
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "WebTransportClient",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "WebTransportServer",
            dependencies: [
                "WebTransport",
                "WebTransportCLIConformance",
                "WebTransportHTTP3Core",
                "WebTransportNetworkRuntime",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "LibrarySmokeServer",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .executableTarget(
            name: "LibrarySmokeClient",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                "WebTransportTestSupport",
                "WebTransportUDPApple",
            ],
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
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportUDPAppleTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportUDPApple",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportCryptoAppleTests",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportTLSCore",
                "WebTransportQUICCore",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportTLSCoreTests",
            dependencies: [
                "WebTransportQUICCore",
                "WebTransportTLSCore",
            ],
            swiftSettings: strictSwiftSettings
        ),
        .testTarget(
            name: "WebTransportHTTP3CoreTests",
            dependencies: [
                "WebTransportHTTP3Core",
                "WebTransportQUICCore",
                // Kept identical to the root manifest; Swift/check-manifest-sync.sh fails the build
                // when a shared target's dependencies diverge between the two. The root manifest
                // carries the reason: PeerInputFuzzTests calls these parsers directly and the 6.4
                // build system no longer resolves the transitive symbol (A-0001).
                "WebTransportTLSCore",
            ],
            swiftSettings: strictSwiftSettings
        ),
        // F-swift-line-security-10: `WebTransportTestSupport` is declared only by
        // this manifest (the root manifest deliberately excludes the shared test
        // support), so a test for it can only live in this package too.
        .testTarget(
            name: "WebTransportTestSupportTests",
            dependencies: [
                "WebTransportTestSupport"
            ],
            swiftSettings: strictSwiftSettings
        ),
    ],
    swiftLanguageModes: [
        .v6
    ]
)
