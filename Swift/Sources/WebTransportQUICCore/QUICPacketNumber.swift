import Foundation

public enum QUICPacketNumber {
    public static func encodeTruncated(_ packetNumber: UInt64, byteCount: Int) throws -> Data {
        guard (1...4).contains(byteCount) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        var output = Data()
        for shift in stride(from: (byteCount - 1) * 8, through: 0, by: -8) {
            output.append(UInt8((packetNumber >> UInt64(shift)) & 0xff))
        }
        return output
    }

    public static func decodeTruncated(_ truncated: UInt64, byteCount: Int, largestAcknowledged: UInt64?) throws -> UInt64 {
        guard (1...4).contains(byteCount) else {
            throw QUICCodecError.valueOutOfRange("packet number length must be 1...4")
        }

        let expected = (largestAcknowledged ?? 0) + 1
        let packetNumberBits = UInt64(byteCount * 8)
        let packetNumberWindow = UInt64(1) << packetNumberBits
        let packetNumberHalfWindow = packetNumberWindow / 2
        let packetNumberMask = packetNumberWindow - 1
        var candidate = (expected & ~packetNumberMask) | truncated

        if candidate + packetNumberHalfWindow <= expected && candidate < (1 << 62) - packetNumberWindow {
            candidate += packetNumberWindow
        } else if candidate > expected + packetNumberHalfWindow && candidate >= packetNumberWindow {
            candidate -= packetNumberWindow
        }

        return candidate
    }
}
