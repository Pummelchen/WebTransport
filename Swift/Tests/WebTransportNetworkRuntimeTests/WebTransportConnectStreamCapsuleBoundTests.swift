import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore
@testable import WebTransportNetworkRuntime

/// F-swift-architecture-01: the CONNECT-stream reader must reject a
/// peer-declared capsule length above the draft-16 maximum as soon as it has
/// the capsule header, instead of waiting for — and buffering — the announced
/// payload.
@Test
func connectStreamCapsuleReaderRejectsDeclaredLengthAboveDraft16Maximum() throws {
    var buffer = Data()
    buffer.append(try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule))
    buffer.append(
        try QUICVarInt.encode(UInt64(WebTransportNetworkSession.maximumConnectStreamCapsulePayloadBytes) + 1))
    // The peer never has to send the payload: announcing a capsule larger than
    // any CONNECT-stream capsule draft-16 permits is itself the violation, and
    // the reader must not sit waiting for the rest of it.
    buffer.append(Data(repeating: 0x41, count: 8))

    #expect(throws: Error.self) {
        _ = try WebTransportNetworkSession.popCompleteCapsule(from: &buffer)
    }
}

/// The bound must not reject the largest capsule draft-16 permits, and a
/// not-yet-complete capsule inside the bound must stay pending rather than
/// being treated as an error.
@Test
func connectStreamCapsuleReaderAcceptsCapsulesUpToDraft16Maximum() throws {
    let maximumPayloadBytes = WebTransportNetworkSession.maximumConnectStreamCapsulePayloadBytes
    var payload = Data([0x00, 0x00, 0x00, 0x01])
    payload.append(Data(repeating: 0x61, count: maximumPayloadBytes - payload.count))

    var capsule = Data()
    capsule.append(try QUICVarInt.encode(WebTransportHTTP3DraftConstants.current.wtCloseSessionCapsule))
    capsule.append(try QUICVarInt.encode(UInt64(payload.count)))
    capsule.append(payload)
    #expect(payload.count == WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes + 4)

    var complete = capsule
    #expect(try WebTransportNetworkSession.popCompleteCapsule(from: &complete) == capsule)
    #expect(complete.isEmpty)

    var partial = capsule
    partial.removeLast()
    #expect(try WebTransportNetworkSession.popCompleteCapsule(from: &partial) == nil)
    #expect(partial.count == capsule.count - 1)
}
