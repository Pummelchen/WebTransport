import Foundation
import Testing
import WebTransportHTTP3Core
@testable import WebTransportNetworkRuntime

/// F-swift-architecture-13: dead declarations in the runtime.
///
/// `renderSettings` was defined byte-identically once in `WebTransportQUICClient`
/// and once in `WebTransportQUICServer`, and
/// `makeRequestStreamPayload(streamID:requestFrame:)` accepted a `streamID` it
/// never used. Both now have a single definition and no unused parameter; these
/// pin the shared helper's output and the payload the runtime builds from a
/// request frame.
@Test
func runtimeRendersSettingsThroughTheSingleSharedHelper() throws {
    var settings = HTTP3Settings.webTransportDraft16Defaults
    try settings.set(2, for: 0x01)
    #expect(
        InteroperableQUICRuntime.renderSettings(settings)
            == "0x1=2 0x8=1 0x33=1 0x2c7cf000=1",
        "settings must render as sorted 0xid=value pairs")
}

@Test
func runtimeEncodesRequestStreamPayloadWithoutAVestigialStreamID() throws {
    let frame = try HTTP3Frame(type: HTTP3FrameType.headers, payload: Data([0x01, 0x02, 0x03]))
    #expect(
        try InteroperableQUICHelpers.makeRequestStreamPayload(requestFrame: frame) == frame.encode(),
        "the CONNECT payload is the encoded frame")
}

/// F-swift-line-security-07: the compliance matrix listed "pinned trust" among the
/// shipped security capabilities, but no shipped client path can pin anything.
/// `WebTransportQUICPeerTrustPolicy` offers only `systemTrust` and
/// `localDevelopmentSelfSigned`, `WebTransportNetworkRuntime` delegates all
/// certificate and signature validation to Network.framework, and
/// `TLSPinnedCertificateTrustPolicy` / `TLSCertificateVerifier` are reachable only
/// from direct users of `WebTransportTLSCore`. The row has to record that boundary
/// rather than claim the control is wired.
@Test
func webTransportDraft16PinnedTrustClaimMatchesTheShippedRuntimeBoundary() throws {
    guard
        let security = WebTransportDraft16ComplianceMatrix.definitionOfDone.first(where: {
            $0.requirementFamily == "Security and identity handling without prompts"
        })
    else {
        Issue.record("the security compliance item is missing")
        return
    }

    #expect(
        security.status.rawValue == "PARTIAL",
        "pinned trust is not wired into the shipped runtime, so the family is not a full pass")
    #expect(security.documentedBehavior.contains("TLSPinnedCertificateTrustPolicy"))
    #expect(security.documentedBehavior.contains("not wired"))
    #expect(security.documentedBehavior.contains("WebTransportNetworkRuntime"))

    // The invariant behind the wording: the shipped client trust surface has no
    // pinned policy, so nothing running through the runtime can pin a leaf.
    #expect(throws: WebTransportNetworkRuntimeError.self) {
        _ = try WebTransportQUICPeerTrustPolicy.parse("pinned")
    }
}
