import Foundation

public struct QUICTransportParameters: Equatable, Sendable {
    public private(set) var values: [UInt64: Data]

    public init(values: [UInt64: Data] = [:]) {
        self.values = values
    }

    public subscript(id: UInt64) -> Data? {
        get { values[id] }
        set { values[id] = newValue }
    }

    public mutating func setInteger(_ value: UInt64, for id: UInt64) throws {
        values[id] = try QUICVarInt.encode(value)
    }

    /// Enforces the value rules of RFC 9000 section 18.2.
    ///
    /// `decode` deliberately checks only framing and duplicates, because it is also the
    /// parser for the TLS extension and a peer may legitimately send a parameter this
    /// build does not model. Its errors do not say "this is a protocol violation", and
    /// tightening it would change what the extension parser accepts. This is the
    /// separate, opt-in entry point for a caller that wants the connection-error
    /// judgement, so that a `TRANSPORT_PARAMETER_ERROR` is raised only where someone
    /// asked for it.
    ///
    /// - Throws: ``QUICCodecError/malformed(_:)`` naming the offending parameter.
    public func validated() throws {
        // RFC 9000 section 18.2: max_udp_payload_size below 1200 is a violation.
        if let value = try integer(for: QUICTransportParameterID.maxUDPPayloadSize), value < 1_200 {
            throw QUICCodecError.malformed("max_udp_payload_size must be at least 1200, got \(value)")
        }
        // ack_delay_exponent must be at most 20.
        if let value = try integer(for: QUICTransportParameterID.ackDelayExponent), value > 20 {
            throw QUICCodecError.malformed("ack_delay_exponent must be at most 20, got \(value)")
        }
        // max_ack_delay must be less than 2^14 milliseconds.
        if let value = try integer(for: QUICTransportParameterID.maxAckDelay), value >= 1 << 14 {
            throw QUICCodecError.malformed("max_ack_delay must be below 16384, got \(value)")
        }
        // active_connection_id_limit must be at least 2.
        if let value = try integer(for: QUICTransportParameterID.activeConnectionIDLimit), value < 2 {
            throw QUICCodecError.malformed("active_connection_id_limit must be at least 2, got \(value)")
        }
        // A stateless_reset_token is exactly 16 bytes.
        if let token = values[QUICTransportParameterID.statelessResetToken], token.count != 16 {
            throw QUICCodecError.malformed("stateless_reset_token must be 16 bytes, got \(token.count)")
        }
        // `max_datagram_frame_size` is deliberately not checked for zero: RFC 9221
        // section 3 defines 0 as meaning "DATAGRAM frames are not supported", which is
        // also the default when the parameter is absent, so an explicit zero is
        // conforming rather than a violation.
        // Connection IDs: RFC 9000 section 18.2 caps these at 20 bytes, and section 7.3
        // says that "if a zero-length connection ID is selected, the corresponding
        // transport parameter is included with a zero-length value" — so zero is valid
        // for the parameters that carry the endpoint's own Source Connection ID.
        // `original_destination_connection_id` is the exception: section 7.2 requires the
        // client's first Destination Connection ID to be at least 8 bytes, so it is never
        // zero.
        if let original = values[QUICTransportParameterID.originalDestinationConnectionID],
            original.isEmpty || original.count > 20
        {
            throw QUICCodecError.malformed(
                "original_destination_connection_id must be 1...20 bytes, got \(original.count)"
            )
        }
        for (id, name) in [
            (QUICTransportParameterID.initialSourceConnectionID, "initial_source_connection_id"),
            (QUICTransportParameterID.retrySourceConnectionID, "retry_source_connection_id"),
        ] {
            if let connectionID = values[id], connectionID.count > 20 {
                throw QUICCodecError.malformed(
                    "\(name) must be at most 20 bytes, got \(connectionID.count)"
                )
            }
        }
    }

    public func integer(for id: UInt64) throws -> UInt64? {
        guard let value = values[id] else {
            return nil
        }
        var cursor = QUICByteCursor(value)
        let decoded = try QUICVarInt.decode(from: &cursor)
        guard cursor.isAtEnd else {
            throw QUICCodecError.malformed("transport parameter \(id) has trailing bytes")
        }
        return decoded
    }

    public func encode() throws -> Data {
        var output = Data()
        for id in values.keys.sorted() {
            guard let value = values[id] else {
                continue
            }
            output.append(try QUICVarInt.encode(id))
            output.append(try QUICVarInt.encode(UInt64(value.count)))
            output.append(value)
        }
        return output
    }

    public static func decode(_ data: Data) throws -> QUICTransportParameters {
        var cursor = QUICByteCursor(data)
        var values: [UInt64: Data] = [:]

        while !cursor.isAtEnd {
            let id = try QUICVarInt.decode(from: &cursor)
            let length = try QUICVarInt.decode(from: &cursor)
            guard length <= UInt64(Int.max) else {
                throw QUICCodecError.valueOutOfRange("transport parameter too large")
            }
            if values[id] != nil {
                throw QUICCodecError.malformed("duplicate transport parameter \(id)")
            }
            values[id] = try cursor.readBytes(count: Int(length))
        }

        return QUICTransportParameters(values: values)
    }
}

public enum QUICTransportParameterID {
    public static let originalDestinationConnectionID: UInt64 = 0x00
    public static let maxIdleTimeout: UInt64 = 0x01
    public static let statelessResetToken: UInt64 = 0x02
    public static let maxUDPPayloadSize: UInt64 = 0x03
    public static let initialMaxData: UInt64 = 0x04
    public static let initialMaxStreamDataBidiLocal: UInt64 = 0x05
    public static let initialMaxStreamDataBidiRemote: UInt64 = 0x06
    public static let initialMaxStreamDataUni: UInt64 = 0x07
    public static let initialMaxStreamsBidi: UInt64 = 0x08
    public static let initialMaxStreamsUni: UInt64 = 0x09
    public static let ackDelayExponent: UInt64 = 0x0a
    public static let maxAckDelay: UInt64 = 0x0b
    public static let disableActiveMigration: UInt64 = 0x0c
    public static let activeConnectionIDLimit: UInt64 = 0x0e
    public static let initialSourceConnectionID: UInt64 = 0x0f
    public static let retrySourceConnectionID: UInt64 = 0x10
    public static let maxDatagramFrameSize: UInt64 = 0x20
    // The registered identifier of the reliable-stream-reset extension
    // (draft-ietf-quic-reliable-stream-reset-09 section 8.1), which draft-16 requires of both roles.
    // The pre-registration value 0x17f7_586d_2cb5_71 is greased, so it must not be what is advertised.
    public static let resetStreamAt: UInt64 = 0x1d
}
