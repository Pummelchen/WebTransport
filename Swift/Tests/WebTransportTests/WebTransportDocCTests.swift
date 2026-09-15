import Foundation
import Testing

/// F-swift-architecture-10: the shipped DocC overview promised a
/// unidirectional-stream API the `WebTransport` product does not have, and
/// claimed the deterministic protocol helpers were kept out of the public release
/// surface while five of them ship as library products.
///
/// This pins the overview to the facts that make those claims false, so the two
/// cannot silently drift apart again: if the public session API gains
/// unidirectional streams, or the products are narrowed, this test fails and the
/// overview has to be updated with them.
@Test
func webTransportDocCOverviewMatchesTheShippedProductSurface() throws {
    let root = repositoryRoot()
    let overview = try String(
        contentsOf: root.appending(path: "Swift/Sources/WebTransport/WebTransport.docc/WebTransport.md"),
        encoding: .utf8
    )
    let publicSessionAPI = try String(
        contentsOf: root.appending(path: "Swift/Sources/WebTransport/WebTransport.swift"),
        encoding: .utf8
    )
    let manifest = try String(contentsOf: root.appending(path: "Package.swift"), encoding: .utf8)

    // Fact: the shipped `WebTransport` session API exposes bidirectional streams
    // only, so the overview must not list unidirectional streams among what the
    // module exposes.
    #expect(!publicSessionAPI.contains("openUnidirectionalStream"))
    #expect(!publicSessionAPI.contains("acceptUnidirectionalStream"))
    #expect(
        !overview.contains("bidirectional streams, unidirectional streams"),
        "the DocC overview still promises a unidirectional-stream API the WebTransport product lacks")

    // Fact: the deterministic protocol cores are published library products, so
    // the overview must not claim they are kept out of the public release surface.
    for product in [
        "WebTransportQUICCore",
        "WebTransportTLSCore",
        "WebTransportHTTP3Core",
        "WebTransportUDPApple",
        "WebTransportCryptoApple",
    ] {
        #expect(
            manifest.contains("name: \"\(product)\""),
            "expected \(product) to remain a published library product")
    }
    #expect(
        !overview.contains("out of the public release surface"),
        "the DocC overview still claims the published protocol cores are not public")
}

/// Repository root, derived from this file's compile-time path
/// (`Swift/Tests/WebTransportTests/<file>` -> repository root).
private func repositoryRoot(filePath: String = #filePath) -> URL {
    URL(fileURLWithPath: filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}
