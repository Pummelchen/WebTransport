// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "WebTransportSwift",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .executable(
            name: "AppleQUICSpike",
            targets: ["AppleQUICSpike"]
        )
    ],
    targets: [
        .executableTarget(
            name: "AppleQUICSpike"
        )
    ]
)
