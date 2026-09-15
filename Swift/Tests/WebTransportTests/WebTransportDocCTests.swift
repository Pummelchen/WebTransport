import Foundation
import Testing

/// F-swift-architecture-10: the shipped DocC overview promised a
/// unidirectional-stream API the `WebTransport` product did not have, and
/// claimed the deterministic protocol helpers were kept out of the public release
/// surface while five of them ship as library products.
///
/// F-swift-line-security-05b then shipped a unidirectional-stream API, but only
/// the receive-only accept side. This pins the overview to the facts that make
/// the earlier claims false and the new claim exact, so the three cannot silently
/// drift apart again: if the public session API gains or loses unidirectional
/// streams, or the overview stops saying the accepted stream is receive-only,
/// this test fails and the overview has to be updated with them.
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

    // Fact: the shipped `WebTransport` session API accepts peer-initiated
    // unidirectional streams as receive-only streams, but does not open a
    // unidirectional stream, so the overview has to describe exactly that.
    #expect(
        publicSessionAPI.contains("acceptUnidirectionalStream"),
        "the public session API lost the unidirectional accept the overview documents")
    #expect(
        !publicSessionAPI.contains("openUnidirectionalStream"),
        "the public session API gained a unidirectional open the overview does not describe")
    #expect(
        !overview.contains("bidirectional streams, unidirectional streams"),
        "the DocC overview returned to the stale phrasing the F-swift-architecture-10 guard pinned")
    #expect(
        overview.contains("receive-only"),
        "the DocC overview no longer says the accepted unidirectional stream is receive-only")
    #expect(
        overview.contains("WebTransportUnidirectionalStream"),
        "the DocC overview does not name the unidirectional stream type it documents")

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
