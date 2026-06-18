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
        .executableTarget(
            name: "AppleQUICSpike"
        ),
        .executableTarget(
            name: "NativeQUICCoreSpike",
            dependencies: [
                "WebTransportQUICCore",
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
            dependencies: ["WebTransportCryptoApple"]
        )
    ],
    swiftLanguageModes: [
        .v6
    ]
)
