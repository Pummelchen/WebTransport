import Foundation

public enum QUICVarInt {
    public static let maximum: UInt64 = 0x3fff_ffff_ffff_ffff

    public static func encodedLength(_ value: UInt64) throws -> Int {
        switch value {
        case 0..<64:
            1
        case 0..<16_384:
            2
        case 0..<1_073_741_824:
            4
        case 0...maximum:
            8
        default:
            throw QUICCodecError.valueOutOfRange("QUIC varint exceeds 62 bits")
        }
    }

    public static func encode(_ value: UInt64) throws -> Data {
        switch value {
        case 0..<64:
            Data([UInt8(value)])
        case 0..<16_384:
            Data([
                UInt8((value >> 8) | 0x40),
                UInt8(value & 0xff)
            ])
        case 0..<1_073_741_824:
            Data([
                UInt8((value >> 24) | 0x80),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ])
        case 0...maximum:
            Data([
                UInt8((value >> 56) | 0xc0),
                UInt8((value >> 48) & 0xff),
                UInt8((value >> 40) & 0xff),
                UInt8((value >> 32) & 0xff),
                UInt8((value >> 24) & 0xff),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ])
        default:
            throw QUICCodecError.valueOutOfRange("QUIC varint exceeds 62 bits")
        }
    }

    public static func decode(from cursor: inout QUICByteCursor) throws -> UInt64 {
        let first = try cursor.readUInt8()
        let prefix = first >> 6
        let length = 1 << Int(prefix)
        var value = UInt64(first & 0x3f)

        guard length > 1 else {
            return value
        }

        for _ in 1..<length {
            value = (value << 8) | UInt64(try cursor.readUInt8())
        }
        return value
    }
}
