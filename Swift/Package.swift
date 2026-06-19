// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "WebTransportSwift",
    platforms: [
        .macOS(.v26)
    ],
    products: [
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
        .executable(
            name: "AppleQUICSpike",
            targets: ["AppleQUICSpike"]
        ),
        .executable(
            name: "NativeQUICCoreSpike",
            targets: ["NativeQUICCoreSpike"]
        )
    ],
    targets: [
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
        .executableTarget(
            name: "AppleQUICSpike"
        ),
        .executableTarget(
            name: "NativeQUICCoreSpike",
            dependencies: [
                "WebTransportCryptoApple",
                "WebTransportQUICCore",
                "WebTransportTLSCore",
                "WebTransportUDPApple"
            ]
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
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
