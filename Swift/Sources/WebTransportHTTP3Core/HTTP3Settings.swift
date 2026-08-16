import Foundation
import WebTransportQUICCore

public struct HTTP3Settings: Equatable, Sendable {
    private var values: [UInt64: UInt64]

    public init(_ values: [UInt64: UInt64] = [:]) throws {
        for (identifier, value) in values {
            try Self.validate(identifier: identifier, value: value)
        }
        self.values = values
    }

    private init(unchecked values: [UInt64: UInt64]) {
        self.values = values
    }

    public subscript(_ identifier: UInt64) -> UInt64? {
        values[identifier]
    }

    public var entries: [UInt64: UInt64] {
        values
    }

    public mutating func set(_ value: UInt64, for identifier: UInt64) throws {
        try Self.validate(identifier: identifier, value: value)
        values[identifier] = value
    }

    public func encodePayload() throws -> Data {
        var output = Data()
        for identifier in values.keys.sorted() {
            guard let value = values[identifier] else {
                continue
            }
            output.append(try QUICVarInt.encode(identifier))
            output.append(try QUICVarInt.encode(value))
        }
        return output
    }

    public func frame() throws -> HTTP3Frame {
        try HTTP3Frame(type: HTTP3FrameType.settings, payload: encodePayload())
    }

    public static func decodePayload(_ data: Data) throws -> HTTP3Settings {
        var cursor = QUICByteCursor(data)
        var values: [UInt64: UInt64] = [:]
        while !cursor.isAtEnd {
            let identifier = try QUICVarInt.decode(from: &cursor)
            let value = try QUICVarInt.decode(from: &cursor)
            try validate(identifier: identifier, value: value)
            guard values[identifier] == nil else {
                throw QUICCodecError.malformed("duplicate HTTP/3 SETTINGS identifier")
            }
            values[identifier] = value
        }
        return try HTTP3Settings(values)
    }

    public static func decodeFrame(_ frame: HTTP3Frame) throws -> HTTP3Settings {
        guard frame.type == HTTP3FrameType.settings else {
            throw QUICCodecError.malformed("HTTP/3 SETTINGS decoder received non-SETTINGS frame")
        }
        return try decodePayload(frame.payload)
    }

    static func validate(identifier: UInt64, value: UInt64) throws {
        guard identifier <= QUICVarInt.maximum else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 SETTINGS identifier exceeds QUIC varint range")
        }
        guard value <= QUICVarInt.maximum else {
            throw QUICCodecError.valueOutOfRange("HTTP/3 SETTINGS value exceeds QUIC varint range")
        }
        guard !HTTP3SettingID.isReservedHTTP2Setting(identifier) else {
            throw QUICCodecError.malformed("reserved HTTP/2 SETTINGS identifier is invalid in HTTP/3")
        }
    }

    public static let webTransportDraft16Defaults = HTTP3Settings(unchecked: [
        WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol: 1,
        WebTransportHTTP3DraftConstants.current.settingsH3Datagram: 1,
        WebTransportHTTP3DraftConstants.current.settingsWTEnabled: 1,
    ])

    /// Draft-16 settings plus the pre-draft-16 identifiers deployed peers look for.
    ///
    /// The draft-16 set is sent unchanged and in full; the legacy identifiers are
    /// added, never substituted. A conforming draft-16 peer ignores the extras
    /// per RFC 9114 §7.2.4.1, so this changes nothing for a peer that speaks the
    /// current draft — it only makes the server visible to peers that speak an
    /// earlier one. Current Chromium requires `legacyWebTransportMaxSessions`
    /// and closes the connection before CONNECT without it.
    public static let webTransportChromiumInteropDefaults = HTTP3Settings(unchecked: [
        WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol: 1,
        WebTransportHTTP3DraftConstants.current.settingsH3Datagram: 1,
        WebTransportHTTP3DraftConstants.current.settingsWTEnabled: 1,
        HTTP3SettingID.legacyEnableWebTransport: 1,
        HTTP3SettingID.legacyWebTransportMaxSessionsDraft02: 1,
        HTTP3SettingID.legacyWebTransportMaxSessions: 1,
        HTTP3SettingID.legacyH3DatagramDraft04: 1,
    ])

    public static let webTransportPyWebTransportStreamInteropDefaults = HTTP3Settings(unchecked: [
        WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol: 1
    ])
}
