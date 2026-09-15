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
