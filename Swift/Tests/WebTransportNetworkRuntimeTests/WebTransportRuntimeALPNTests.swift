import Testing
import WebTransportHTTP3Core
@testable import WebTransportNetworkRuntime

/// F-swift-architecture-09: the ALPN identifier the runtime offers over QUIC and
/// the one `WebTransportALPNPolicy` validates must be a single source of truth.
///
/// They previously existed as a hard-coded `"h3"` in `makeBaseQUIC` and as
/// `WebTransportALPNPolicy.requiredHTTP3Protocol` in HTTP3Core, with nothing
/// tying the offer to the validation, so the two could diverge without a build or
/// test failure. The runtime now builds its QUIC configuration from the policy
/// constant; this pins that structure.
@Test
func runtimeOffersThePolicyHTTP3ALPNProtocol() throws {
    #expect(
        InteroperableQUICRuntime.alpnProtocols == [WebTransportALPNPolicy.requiredHTTP3Protocol],
        "the runtime QUIC configuration must offer the policy's HTTP/3 ALPN identifier")
    try WebTransportALPNPolicy.validateOfferedProtocols(InteroperableQUICRuntime.alpnProtocols)
    try WebTransportALPNPolicy.validateNegotiatedProtocol(WebTransportALPNPolicy.requiredHTTP3Protocol)
}
