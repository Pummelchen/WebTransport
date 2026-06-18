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
}
