import Foundation
import Testing
import WebTransportCryptoApple
import WebTransportQUICCore

/// RFC 9001 appendix A.4's Retry packet, its Original Destination Connection ID (from A.2's client Initial)
/// and the integrity tag the appendix prints with it. The tag is what a client uses to tell a Retry the server
/// sent from one an attacker injected (section 5.8), so the value this implementation produces is asserted
/// against the RFC's own bytes rather than against a round trip through the same code — a constant that is
/// simply wrong, or a pseudo-packet that is built in the wrong order, passes a round trip and fails this.
@Suite("QUIC Retry integrity tag (RFC 9001 section 5.8)")
struct QUICRetryIntegrityTagTests {
    private static let retryPacket = Data([
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    ])
    private static let originalDestinationConnectionID = Data([0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
    private static let expectedTag = Data([
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    ])

    private static func pseudoPacket(of packet: QUICRetryPacket) throws -> Data {
        try QUICRetryPacket.integrityPseudoPacket(
            originalDestinationConnectionID: originalDestinationConnectionID,
            retryPacketWithoutIntegrityTag: try packet.encodedWithoutIntegrityTag()
        )
    }

    /// The constants are the RFC's, and this is the assertion that says so: the tag computed here for A.4's
    /// packet is the tag A.4 prints.
    @Test("the computed tag is the one RFC 9001 A.4 prints")
    func computedTagMatchesTheRFC() throws {
        let packet = try QUICRetryPacket.decode(Self.retryPacket)
        #expect(try QUICRetryIntegrityTag.compute(pseudoPacket: try Self.pseudoPacket(of: packet)) == Self.expectedTag)
    }

    @Test("the RFC's tag verifies, and a tampered packet's does not")
    func verificationAcceptsTheRFCTagAndRejectsTampering() throws {
        let packet = try QUICRetryPacket.decode(Self.retryPacket)
        let pseudoPacket = try Self.pseudoPacket(of: packet)
        #expect(QUICRetryIntegrityTag.verify(pseudoPacket: pseudoPacket, integrityTag: packet.retryIntegrityTag))

        // One bit in each part of the pseudo-packet: the tag stops authenticating the moment any of the
        // connection ID, the header or the token changes, which is the whole point of the check.
        for index in [0, 1, 8, 9, 28] {
            var tampered = pseudoPacket
            tampered[index] ^= 0x01
            #expect(
                !QUICRetryIntegrityTag.verify(pseudoPacket: tampered, integrityTag: packet.retryIntegrityTag),
                "flipping pseudo-packet byte \(index) must fail the tag"
            )
        }
        var tamperedTag = packet.retryIntegrityTag
        tamperedTag[0] ^= 0x01
        #expect(!QUICRetryIntegrityTag.verify(pseudoPacket: pseudoPacket, integrityTag: tamperedTag))
        #expect(
            !QUICRetryIntegrityTag.verify(pseudoPacket: pseudoPacket, integrityTag: Data()),
            "a tag of the wrong length is a failure, not an authenticated packet"
        )
    }

    /// The two entry points together: a client that has the connection ID it chose gets either the packet or a
    /// refusal, and never a Retry whose tag it did not check (`WT-1`).
    @Test("the verifying decode accepts the RFC's packet and refuses a forged one")
    func verifyingDecodeRefusesAnInvalidTag() throws {
        let packet = try QUICRetryPacket.decode(
            Self.retryPacket,
            originalDestinationConnectionID: Self.originalDestinationConnectionID,
            integrityTagVerifier: QUICRetryIntegrityTag.verify
        )
        #expect(packet.retryToken == Data("token".utf8))

        var forged = Self.retryPacket
        forged[forged.count - 1] ^= 0x01
        #expect(throws: (any Error).self, "a tag that does not validate must fail the decode") {
            _ = try QUICRetryPacket.decode(
                forged,
                originalDestinationConnectionID: Self.originalDestinationConnectionID,
                integrityTagVerifier: QUICRetryIntegrityTag.verify
            )
        }
        // The same packet against the wrong connection ID is a forged packet too: the ID is authenticated
        // through the pseudo-packet even though it never appears in the Retry.
        #expect(throws: (any Error).self, "the tag is bound to the original connection ID") {
            _ = try QUICRetryPacket.decode(
                Self.retryPacket,
                originalDestinationConnectionID: Data(repeating: 0, count: 8),
                integrityTagVerifier: QUICRetryIntegrityTag.verify
            )
        }
    }
}
