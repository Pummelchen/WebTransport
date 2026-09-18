import Foundation

public enum QUICPacketType: UInt8, Equatable, Sendable {
    case initial = 0x00
    case zeroRTT = 0x01
    case handshake = 0x02
    case retry = 0x03
}

public struct QUICLongHeaderPacket: Equatable, Sendable {
    public var packetType: QUICPacketType
    public var version: UInt32
    public var destinationConnectionID: Data
    public var sourceConnectionID: Data
    public var token: Data
    public var packetNumber: UInt64
    public var packetNumberLength: Int
    public var payload: Data

    public init(
        packetType: QUICPacketType,
        version: UInt32,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        token: Data = Data(),
        packetNumber: UInt64,
        packetNumberLength: Int,
        payload: Data
    ) {
        self.packetType = packetType
        self.version = version
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.token = token
        self.packetNumber = packetNumber
        self.packetNumberLength = packetNumberLength
        self.payload = payload
    }

    public func encode() throws -> Data {
        guard packetType != .retry else {
            throw QUICCodecError.malformed("Retry packets use QUICRetryPacket")
        }
        guard destinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        guard sourceConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        guard (1...4).contains(packetNumberLength) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        var output = Data()
        let first = UInt8(0xc0) | (packetType.rawValue << 4) | UInt8(packetNumberLength - 1)
        output.append(first)
        var buffer = QUICByteBuffer()
        buffer.appendUInt32(version)
        output.append(buffer.data)
        output.append(UInt8(destinationConnectionID.count))
        output.append(destinationConnectionID)
        output.append(UInt8(sourceConnectionID.count))
        output.append(sourceConnectionID)

        if packetType == .initial {
            output.append(try QUICVarInt.encode(UInt64(token.count)))
            output.append(token)
        }

        let packetNumberBytes = try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength)
        output.append(try QUICVarInt.encode(UInt64(packetNumberBytes.count + payload.count)))
        output.append(packetNumberBytes)
        output.append(payload)
        return output
    }

    /// Decodes a long header that has **already had header protection removed**. RFC 9001 section 5.4 protects
    /// the low four bits of the first byte — the reserved bits and the packet number length this parser reads —
    /// so on wire bytes those bits are a mask rather than a value, and a caller that has not unmasked them must
    /// not use this parser to judge a packet. (The C99 library reports a set reserved bit to the authenticating
    /// caller instead of refusing at this layer, for the reason recorded as `WT-167`; the refusal below is only
    /// sound because of the precondition stated here — `WT-228`.)
    public static func decode(_ data: Data, largestAcknowledged: UInt64? = nil) throws -> QUICLongHeaderPacket {
        var cursor = QUICByteCursor(data)
        let first = try cursor.readUInt8()
        let packetType = try longHeaderPacketType(from: first)
        let packetNumberLength = Int(first & 0x03) + 1
        let version = try cursor.readUInt32()
        let (destinationConnectionID, sourceConnectionID) = try readConnectionIDs(from: &cursor)

        let token: Data
        if packetType == .initial {
            let tokenLength = try checkedLength(try QUICVarInt.decode(from: &cursor))
            token = try cursor.readBytes(count: tokenLength)
        } else {
            token = Data()
        }

        let length = try QUICVarInt.decode(from: &cursor)
        guard length >= UInt64(packetNumberLength), length <= UInt64(cursor.remaining) else {
            throw QUICCodecError.malformed("invalid long header packet length")
        }
        let packetNumberData = try cursor.readBytes(count: packetNumberLength)
        let truncated = packetNumberData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncated,
            byteCount: packetNumberLength,
            largestAcknowledged: largestAcknowledged
        )
        let payloadLength = Int(length) - packetNumberLength
        let payload = try cursor.readBytes(count: payloadLength)

        return QUICLongHeaderPacket(
            packetType: packetType,
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: token,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: payload
        )
    }

    /// The first byte's type and validity, before anything else is read.
    ///
    /// RFC 9000 section 17.2: "Packets that have the Fixed Bit set to 0 ... are not valid
    /// packets in this version and MUST be discarded." The short-header decoder already
    /// enforces this; without the same check here a long-header packet with the bit
    /// cleared would be processed despite being invalid. RFC 9001 section 5.4 requires the
    /// two reserved bits to be zero after header protection is removed.
    private static func longHeaderPacketType(from first: UInt8) throws -> QUICPacketType {
        guard (first & 0x80) != 0 else {
            throw QUICCodecError.malformed("not a long header packet")
        }
        guard (first & 0x40) != 0 else {
            throw QUICCodecError.malformed("long header fixed bit is not set")
        }
        guard (first & 0x0c) == 0 else {
            throw QUICCodecError.malformed("long header reserved bits are not zero")
        }
        guard let packetType = QUICPacketType(rawValue: (first >> 4) & 0x03) else {
            throw QUICCodecError.malformed("unknown long header packet type")
        }
        guard packetType != .retry else {
            throw QUICCodecError.malformed("Retry packets use QUICRetryPacket")
        }
        return packetType
    }

    /// Both connection IDs, each length-prefixed and each capped at RFC 9000's 20 bytes.
    private static func readConnectionIDs(from cursor: inout QUICByteCursor) throws -> (Data, Data) {
        let destinationLength = Int(try cursor.readUInt8())
        guard destinationLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        let destination = try cursor.readBytes(count: destinationLength)
        let sourceLength = Int(try cursor.readUInt8())
        guard sourceLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        return (destination, try cursor.readBytes(count: sourceLength))
    }

    private static func checkedLength(_ value: UInt64) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw QUICCodecError.valueOutOfRange("length exceeds Int.max")
        }
        return Int(value)
    }
}

public struct QUICRetryPacket: Equatable, Sendable {
    public var version: UInt32
    public var destinationConnectionID: Data
    public var sourceConnectionID: Data
    public var retryToken: Data
    public var retryIntegrityTag: Data
    /// RFC 9000 section 17.2.5's `Unused (4)` field: the low four bits of the first byte, whose value "is set
    /// to an arbitrary value by the server" and which a client must ignore. It is kept rather than dropped for
    /// one reason: the Retry Integrity Tag of RFC 9001 section 5.8 is computed over the packet *as received*,
    /// so re-encoding has to reproduce these bits or the pseudo-packet a verifier builds is not the one the
    /// server tagged — RFC 9001 appendix A.4's own Retry carries `0xf` here (`WT-227`).
    public var unusedBits: UInt8

    public init(
        version: UInt32,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        retryToken: Data,
        retryIntegrityTag: Data,
        unusedBits: UInt8 = 0
    ) {
        self.version = version
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.retryToken = retryToken
        self.retryIntegrityTag = retryIntegrityTag
        self.unusedBits = unusedBits & 0x0f
    }

    public func encode() throws -> Data {
        guard destinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        guard sourceConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        guard retryIntegrityTag.count == 16 else {
            throw QUICCodecError.malformed("Retry integrity tag must be 16 bytes")
        }

        var output = Data()
        output.append(0xf0 | (unusedBits & 0x0f))
        var buffer = QUICByteBuffer()
        buffer.appendUInt32(version)
        output.append(buffer.data)
        output.append(UInt8(destinationConnectionID.count))
        output.append(destinationConnectionID)
        output.append(UInt8(sourceConnectionID.count))
        output.append(sourceConnectionID)
        output.append(retryToken)
        output.append(retryIntegrityTag)
        return output
    }

    /// The packet as it goes on the wire, without the trailing 16-byte Retry Integrity Tag — the bytes RFC 9001
    /// section 5.8's pseudo-packet is built from. `encode()` is the inverse of `decode(_:)` for a Retry, so
    /// re-encoding drops exactly the tag that was parsed; it also fails on a tag that is not 16 bytes.
    public func encodedWithoutIntegrityTag() throws -> Data {
        Data(try encode().dropLast(retryIntegrityTag.count))
    }

    /// RFC 9001 section 5.8's Retry Pseudo-Packet: the Original Destination Connection ID Length as one byte,
    /// that connection ID, then the Retry packet without its integrity tag. The tag is computed over exactly
    /// these bytes with an empty associated data value, which is why a verifier needs the connection ID the
    /// client put in its Initial — it is authenticated by the tag but deliberately absent from the wire packet.
    public static func integrityPseudoPacket(
        originalDestinationConnectionID: Data,
        retryPacketWithoutIntegrityTag: Data
    ) throws -> Data {
        guard originalDestinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("original destination connection ID exceeds 20 bytes")
        }
        var pseudoPacket = Data([UInt8(originalDestinationConnectionID.count)])
        pseudoPacket.append(originalDestinationConnectionID)
        pseudoPacket.append(retryPacketWithoutIntegrityTag)
        return pseudoPacket
    }

    /// Parses a Retry packet's structure. **This does not validate the Retry Integrity Tag.** RFC 9000
    /// section 17.2.5.2 requires a client to discard a Retry whose tag cannot be validated, and the tag covers
    /// the original Destination Connection ID, which is not on the wire — so a packet that came from a peer must
    /// go through `decode(_:originalDestinationConnectionID:integrityTagVerifier:)`, and this entry point is for
    /// bytes whose authenticity is already established (a self-test, or a re-parse of a verified packet).
    public static func decode(_ data: Data) throws -> QUICRetryPacket {
        var cursor = QUICByteCursor(data)
        let first = try cursor.readUInt8()
        guard (first & 0x80) != 0 else {
            throw QUICCodecError.malformed("not a long header packet")
        }
        // A Retry packet is a long header packet, so RFC 9000 section 17.2's Fixed Bit rule
        // applies to it like any other.
        guard (first & 0x40) != 0 else {
            throw QUICCodecError.malformed("Retry packet fixed bit is not set")
        }
        // RFC 9000 section 17.2.5 gives a Retry an `Unused (4)` field where the protected packet types put the
        // reserved bits and the packet number length: "The value in the Unused field is set to an arbitrary
        // value by the server; a client MUST ignore these bits." Section 17.2's non-zero-reserved-bits rule is
        // scoped to packets that were header-protected ("after removing both packet and header protection"),
        // and a Retry has no header protection, so there is deliberately no test on that nibble here. Demanding
        // zero refused RFC 9001 appendix A.4's own Retry, which begins 0xff, and every Retry a conformant
        // server writes with those bits set; the integrity tag covers the field, so a forged value is caught by
        // the verifying decode below instead (`WT-227`).
        guard ((first >> 4) & 0x03) == QUICPacketType.retry.rawValue else {
            throw QUICCodecError.malformed("not a Retry packet")
        }

        let version = try cursor.readUInt32()
        let destinationLength = Int(try cursor.readUInt8())
        guard destinationLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        let destinationConnectionID = try cursor.readBytes(count: destinationLength)
        let sourceLength = Int(try cursor.readUInt8())
        guard sourceLength <= 20 else {
            throw QUICCodecError.valueOutOfRange("source connection ID length exceeds 20")
        }
        let sourceConnectionID = try cursor.readBytes(count: sourceLength)
        // RFC 9000 section 17.2.5: "A client MUST discard a Retry packet with a
        // zero-length Retry Token field." Sixteen bytes are the integrity tag, so
        // anything beyond that is the token and it must not be empty.
        guard cursor.remaining > 16 else {
            throw QUICCodecError.malformed("Retry packet has a zero-length token")
        }
        let token = try cursor.readBytes(count: cursor.remaining - 16)
        let tag = try cursor.readBytes(count: 16)

        return QUICRetryPacket(
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            retryToken: token,
            retryIntegrityTag: tag,
            unusedBits: first & 0x0f
        )
    }

    /// Decodes a Retry packet and validates its integrity tag in one step — the only form a client may act on:
    /// RFC 9000 section 17.2.5.2, "Clients MUST discard Retry packets that have a Retry Integrity Tag that
    /// cannot be validated". The AEAD lives outside this module, so the caller supplies the verifier
    /// (`WebTransportCryptoApple.QUICRetryIntegrityTag.verify`); it receives the pseudo-packet and the tag, and
    /// a `false` result — or a thrown error — fails the decode rather than returning an unauthenticated packet.
    public static func decode(
        _ data: Data,
        originalDestinationConnectionID: Data,
        integrityTagVerifier: (Data, Data) throws -> Bool
    ) throws -> QUICRetryPacket {
        let packet = try decode(data)
        let pseudoPacket = try integrityPseudoPacket(
            originalDestinationConnectionID: originalDestinationConnectionID,
            retryPacketWithoutIntegrityTag: packet.encodedWithoutIntegrityTag()
        )
        guard try integrityTagVerifier(pseudoPacket, packet.retryIntegrityTag) else {
            throw QUICCodecError.malformed("Retry integrity tag does not validate (RFC 9001 section 5.8)")
        }
        return packet
    }
}

public struct QUICShortHeaderPacket: Equatable, Sendable {
    public var destinationConnectionID: Data
    public var keyPhase: Bool
    public var packetNumber: UInt64
    public var packetNumberLength: Int
    public var payload: Data

    public init(
        destinationConnectionID: Data,
        keyPhase: Bool = false,
        packetNumber: UInt64,
        packetNumberLength: Int,
        payload: Data
    ) {
        self.destinationConnectionID = destinationConnectionID
        self.keyPhase = keyPhase
        self.packetNumber = packetNumber
        self.packetNumberLength = packetNumberLength
        self.payload = payload
    }

    public func encode() throws -> Data {
        guard destinationConnectionID.count <= 20 else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }
        guard (1...4).contains(packetNumberLength) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        var output = Data()
        var first = UInt8(0x40) | UInt8(packetNumberLength - 1)
        if keyPhase {
            first |= 0x04
        }
        output.append(first)
        output.append(destinationConnectionID)
        output.append(try QUICPacketNumber.encodeTruncated(packetNumber, byteCount: packetNumberLength))
        output.append(payload)
        return output
    }

    public static func decode(
        _ data: Data,
        destinationConnectionIDLength: Int,
        largestAcknowledged: UInt64? = nil
    ) throws -> QUICShortHeaderPacket {
        guard (0...20).contains(destinationConnectionIDLength) else {
            throw QUICCodecError.valueOutOfRange("destination connection ID length exceeds 20")
        }

        var cursor = QUICByteCursor(data)
        let first = try cursor.readUInt8()
        guard (first & 0x80) == 0 else {
            throw QUICCodecError.malformed("not a short header packet")
        }
        guard (first & 0x40) != 0 else {
            throw QUICCodecError.malformed("short header fixed bit is not set")
        }
        // RFC 9001 section 5.4: the short header's two reserved bits (0x18) must
        // be zero once header protection has been removed. A non-zero value is a
        // PROTOCOL_VIOLATION, and it is rejected here for the same reason the
        // long-header and Retry decoders reject their reserved bits. That this
        // decoder runs after header protection removal is the caller's step, as
        // the long-header comment states.
        guard (first & 0x18) == 0 else {
            throw QUICCodecError.malformed("short header reserved bits are not zero")
        }

        let packetNumberLength = Int(first & 0x03) + 1
        let keyPhase = (first & 0x04) != 0
        let destinationConnectionID = try cursor.readBytes(count: destinationConnectionIDLength)
        let packetNumberData = try cursor.readBytes(count: packetNumberLength)
        let truncated = packetNumberData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let packetNumber = try QUICPacketNumber.decodeTruncated(
            truncated,
            byteCount: packetNumberLength,
            largestAcknowledged: largestAcknowledged
        )

        return QUICShortHeaderPacket(
            destinationConnectionID: destinationConnectionID,
            keyPhase: keyPhase,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength,
            payload: try cursor.readBytes(count: cursor.remaining)
        )
    }
}
