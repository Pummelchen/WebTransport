import Foundation
import WebTransportQUICCore

struct HuffmanCode: Sendable {
    let code: UInt32
    let bitCount: UInt8
}

public enum QPACKHuffman {
    public static func encode(_ bytes: Data) -> Data {
        var output = Data()
        var accumulator: UInt64 = 0
        var bitCount = 0

        for byte in bytes {
            let entry = table[Int(byte)]
            accumulator = (accumulator << UInt64(entry.bitCount)) | UInt64(entry.code)
            bitCount += Int(entry.bitCount)
            while bitCount >= 8 {
                bitCount -= 8
                output.append(UInt8((accumulator >> UInt64(bitCount)) & 0xff))
            }
        }

        if bitCount > 0 {
            let padding = (1 << (8 - bitCount)) - 1
            output.append(UInt8(((accumulator << UInt64(8 - bitCount)) | UInt64(padding)) & 0xff))
        }
        return output
    }

    public static func decode(_ bytes: Data) throws -> Data {
        let root = decodeTree
        var node = root
        var output = Data()
        var trailingBits = 0
        var trailingValue = 0

        for byte in bytes {
            for bitIndex in stride(from: 7, through: 0, by: -1) {
                let bit = Int((byte >> UInt8(bitIndex)) & 0x01)
                trailingBits += 1
                trailingValue = ((trailingValue << 1) | bit) & 0xff
                guard let next = bit == 0 ? node.zero : node.one else {
                    throw QUICCodecError.malformed("QPACK Huffman string contains an invalid code")
                }
                node = next
                if let symbol = node.symbol {
                    guard symbol < 256 else {
                        throw QUICCodecError.malformed("QPACK Huffman string must not contain EOS")
                    }
                    output.append(UInt8(symbol))
                    node = root
                    trailingBits = 0
                    trailingValue = 0
                }
            }
        }

        guard node === root || isValidEOSPadding(bitCount: trailingBits, value: trailingValue) else {
            throw QUICCodecError.malformed("QPACK Huffman string has invalid padding")
        }
        return output
    }

    private static func isValidEOSPadding(bitCount: Int, value: Int) -> Bool {
        bitCount > 0 && bitCount <= 7 && value == (1 << bitCount) - 1
    }

    private static let decodeTree: HuffmanNode = {
        let root = HuffmanNode()
        for (symbol, entry) in table.enumerated() {
            var node = root
            for shift in stride(from: Int(entry.bitCount) - 1, through: 0, by: -1) {
                let bit = (entry.code >> UInt32(shift)) & 0x01
                if bit == 0 {
                    if node.zero == nil {
                        node.zero = HuffmanNode()
                    }
                    node = node.zero!
                } else {
                    if node.one == nil {
                        node.one = HuffmanNode()
                    }
                    node = node.one!
                }
            }
            node.symbol = symbol
        }
        return root
    }()

    // RFC 7541 Appendix B static Huffman code table, reused by QPACK.
    private static let table: [HuffmanCode] = [
        HuffmanCode(code: 0x1ff8, bitCount: 13), HuffmanCode(code: 0x7fffd8, bitCount: 23),
        HuffmanCode(code: 0xfffffe2, bitCount: 28), HuffmanCode(code: 0xfffffe3, bitCount: 28),
        HuffmanCode(code: 0xfffffe4, bitCount: 28), HuffmanCode(code: 0xfffffe5, bitCount: 28),
        HuffmanCode(code: 0xfffffe6, bitCount: 28), HuffmanCode(code: 0xfffffe7, bitCount: 28),
        HuffmanCode(code: 0xfffffe8, bitCount: 28), HuffmanCode(code: 0xffffea, bitCount: 24),
        HuffmanCode(code: 0x3ffffffc, bitCount: 30), HuffmanCode(code: 0xfffffe9, bitCount: 28),
        HuffmanCode(code: 0xfffffea, bitCount: 28), HuffmanCode(code: 0x3ffffffd, bitCount: 30),
        HuffmanCode(code: 0xfffffeb, bitCount: 28), HuffmanCode(code: 0xfffffec, bitCount: 28),
        HuffmanCode(code: 0xfffffed, bitCount: 28), HuffmanCode(code: 0xfffffee, bitCount: 28),
        HuffmanCode(code: 0xfffffef, bitCount: 28), HuffmanCode(code: 0xffffff0, bitCount: 28),
        HuffmanCode(code: 0xffffff1, bitCount: 28), HuffmanCode(code: 0xffffff2, bitCount: 28),
        HuffmanCode(code: 0x3ffffffe, bitCount: 30), HuffmanCode(code: 0xffffff3, bitCount: 28),
        HuffmanCode(code: 0xffffff4, bitCount: 28), HuffmanCode(code: 0xffffff5, bitCount: 28),
        HuffmanCode(code: 0xffffff6, bitCount: 28), HuffmanCode(code: 0xffffff7, bitCount: 28),
        HuffmanCode(code: 0xffffff8, bitCount: 28), HuffmanCode(code: 0xffffff9, bitCount: 28),
        HuffmanCode(code: 0xffffffa, bitCount: 28), HuffmanCode(code: 0xffffffb, bitCount: 28),
        HuffmanCode(code: 0x14, bitCount: 6), HuffmanCode(code: 0x3f8, bitCount: 10),
        HuffmanCode(code: 0x3f9, bitCount: 10), HuffmanCode(code: 0xffa, bitCount: 12),
        HuffmanCode(code: 0x1ff9, bitCount: 13), HuffmanCode(code: 0x15, bitCount: 6),
        HuffmanCode(code: 0xf8, bitCount: 8), HuffmanCode(code: 0x7fa, bitCount: 11),
        HuffmanCode(code: 0x3fa, bitCount: 10), HuffmanCode(code: 0x3fb, bitCount: 10),
        HuffmanCode(code: 0xf9, bitCount: 8), HuffmanCode(code: 0x7fb, bitCount: 11),
        HuffmanCode(code: 0xfa, bitCount: 8), HuffmanCode(code: 0x16, bitCount: 6),
        HuffmanCode(code: 0x17, bitCount: 6), HuffmanCode(code: 0x18, bitCount: 6),
        HuffmanCode(code: 0x0, bitCount: 5), HuffmanCode(code: 0x1, bitCount: 5),
        HuffmanCode(code: 0x2, bitCount: 5), HuffmanCode(code: 0x19, bitCount: 6),
        HuffmanCode(code: 0x1a, bitCount: 6), HuffmanCode(code: 0x1b, bitCount: 6),
        HuffmanCode(code: 0x1c, bitCount: 6), HuffmanCode(code: 0x1d, bitCount: 6),
        HuffmanCode(code: 0x1e, bitCount: 6), HuffmanCode(code: 0x1f, bitCount: 6),
        HuffmanCode(code: 0x5c, bitCount: 7), HuffmanCode(code: 0xfb, bitCount: 8),
        HuffmanCode(code: 0x7ffc, bitCount: 15), HuffmanCode(code: 0x20, bitCount: 6),
        HuffmanCode(code: 0xffb, bitCount: 12), HuffmanCode(code: 0x3fc, bitCount: 10),
        HuffmanCode(code: 0x1ffa, bitCount: 13), HuffmanCode(code: 0x21, bitCount: 6),
        HuffmanCode(code: 0x5d, bitCount: 7), HuffmanCode(code: 0x5e, bitCount: 7),
        HuffmanCode(code: 0x5f, bitCount: 7), HuffmanCode(code: 0x60, bitCount: 7),
        HuffmanCode(code: 0x61, bitCount: 7), HuffmanCode(code: 0x62, bitCount: 7),
        HuffmanCode(code: 0x63, bitCount: 7), HuffmanCode(code: 0x64, bitCount: 7),
        HuffmanCode(code: 0x65, bitCount: 7), HuffmanCode(code: 0x66, bitCount: 7),
        HuffmanCode(code: 0x67, bitCount: 7), HuffmanCode(code: 0x68, bitCount: 7),
        HuffmanCode(code: 0x69, bitCount: 7), HuffmanCode(code: 0x6a, bitCount: 7),
        HuffmanCode(code: 0x6b, bitCount: 7), HuffmanCode(code: 0x6c, bitCount: 7),
        HuffmanCode(code: 0x6d, bitCount: 7), HuffmanCode(code: 0x6e, bitCount: 7),
        HuffmanCode(code: 0x6f, bitCount: 7), HuffmanCode(code: 0x70, bitCount: 7),
        HuffmanCode(code: 0x71, bitCount: 7), HuffmanCode(code: 0x72, bitCount: 7),
        HuffmanCode(code: 0xfc, bitCount: 8), HuffmanCode(code: 0x73, bitCount: 7),
        HuffmanCode(code: 0xfd, bitCount: 8), HuffmanCode(code: 0x1ffb, bitCount: 13),
        HuffmanCode(code: 0x7fff0, bitCount: 19), HuffmanCode(code: 0x1ffc, bitCount: 13),
        HuffmanCode(code: 0x3ffc, bitCount: 14), HuffmanCode(code: 0x22, bitCount: 6),
        HuffmanCode(code: 0x7ffd, bitCount: 15), HuffmanCode(code: 0x3, bitCount: 5),
        HuffmanCode(code: 0x23, bitCount: 6), HuffmanCode(code: 0x4, bitCount: 5),
        HuffmanCode(code: 0x24, bitCount: 6), HuffmanCode(code: 0x5, bitCount: 5),
        HuffmanCode(code: 0x25, bitCount: 6), HuffmanCode(code: 0x26, bitCount: 6),
        HuffmanCode(code: 0x27, bitCount: 6), HuffmanCode(code: 0x6, bitCount: 5),
        HuffmanCode(code: 0x74, bitCount: 7), HuffmanCode(code: 0x75, bitCount: 7),
        HuffmanCode(code: 0x28, bitCount: 6), HuffmanCode(code: 0x29, bitCount: 6),
        HuffmanCode(code: 0x2a, bitCount: 6), HuffmanCode(code: 0x7, bitCount: 5),
        HuffmanCode(code: 0x2b, bitCount: 6), HuffmanCode(code: 0x76, bitCount: 7),
        HuffmanCode(code: 0x2c, bitCount: 6), HuffmanCode(code: 0x8, bitCount: 5),
        HuffmanCode(code: 0x9, bitCount: 5), HuffmanCode(code: 0x2d, bitCount: 6),
        HuffmanCode(code: 0x77, bitCount: 7), HuffmanCode(code: 0x78, bitCount: 7),
        HuffmanCode(code: 0x79, bitCount: 7), HuffmanCode(code: 0x7a, bitCount: 7),
        HuffmanCode(code: 0x7b, bitCount: 7), HuffmanCode(code: 0x7ffe, bitCount: 15),
        HuffmanCode(code: 0x7fc, bitCount: 11), HuffmanCode(code: 0x3ffd, bitCount: 14),
        HuffmanCode(code: 0x1ffd, bitCount: 13), HuffmanCode(code: 0xffffffc, bitCount: 28),
        HuffmanCode(code: 0xfffe6, bitCount: 20), HuffmanCode(code: 0x3fffd2, bitCount: 22),
        HuffmanCode(code: 0xfffe7, bitCount: 20), HuffmanCode(code: 0xfffe8, bitCount: 20),
        HuffmanCode(code: 0x3fffd3, bitCount: 22), HuffmanCode(code: 0x3fffd4, bitCount: 22),
        HuffmanCode(code: 0x3fffd5, bitCount: 22), HuffmanCode(code: 0x7fffd9, bitCount: 23),
        HuffmanCode(code: 0x3fffd6, bitCount: 22), HuffmanCode(code: 0x7fffda, bitCount: 23),
        HuffmanCode(code: 0x7fffdb, bitCount: 23), HuffmanCode(code: 0x7fffdc, bitCount: 23),
        HuffmanCode(code: 0x7fffdd, bitCount: 23), HuffmanCode(code: 0x7fffde, bitCount: 23),
        HuffmanCode(code: 0xffffeb, bitCount: 24), HuffmanCode(code: 0x7fffdf, bitCount: 23),
        HuffmanCode(code: 0xffffec, bitCount: 24), HuffmanCode(code: 0xffffed, bitCount: 24),
        HuffmanCode(code: 0x3fffd7, bitCount: 22), HuffmanCode(code: 0x7fffe0, bitCount: 23),
        HuffmanCode(code: 0xffffee, bitCount: 24), HuffmanCode(code: 0x7fffe1, bitCount: 23),
        HuffmanCode(code: 0x7fffe2, bitCount: 23), HuffmanCode(code: 0x7fffe3, bitCount: 23),
        HuffmanCode(code: 0x7fffe4, bitCount: 23), HuffmanCode(code: 0x1fffdc, bitCount: 21),
        HuffmanCode(code: 0x3fffd8, bitCount: 22), HuffmanCode(code: 0x7fffe5, bitCount: 23),
        HuffmanCode(code: 0x3fffd9, bitCount: 22), HuffmanCode(code: 0x7fffe6, bitCount: 23),
        HuffmanCode(code: 0x7fffe7, bitCount: 23), HuffmanCode(code: 0xffffef, bitCount: 24),
        HuffmanCode(code: 0x3fffda, bitCount: 22), HuffmanCode(code: 0x1fffdd, bitCount: 21),
        HuffmanCode(code: 0xfffe9, bitCount: 20), HuffmanCode(code: 0x3fffdb, bitCount: 22),
        HuffmanCode(code: 0x3fffdc, bitCount: 22), HuffmanCode(code: 0x7fffe8, bitCount: 23),
        HuffmanCode(code: 0x7fffe9, bitCount: 23), HuffmanCode(code: 0x1fffde, bitCount: 21),
        HuffmanCode(code: 0x7fffea, bitCount: 23), HuffmanCode(code: 0x3fffdd, bitCount: 22),
        HuffmanCode(code: 0x3fffde, bitCount: 22), HuffmanCode(code: 0xfffff0, bitCount: 24),
        HuffmanCode(code: 0x1fffdf, bitCount: 21), HuffmanCode(code: 0x3fffdf, bitCount: 22),
        HuffmanCode(code: 0x7fffeb, bitCount: 23), HuffmanCode(code: 0x7fffec, bitCount: 23),
        HuffmanCode(code: 0x1fffe0, bitCount: 21), HuffmanCode(code: 0x1fffe1, bitCount: 21),
        HuffmanCode(code: 0x3fffe0, bitCount: 22), HuffmanCode(code: 0x1fffe2, bitCount: 21),
        HuffmanCode(code: 0x7fffed, bitCount: 23), HuffmanCode(code: 0x3fffe1, bitCount: 22),
        HuffmanCode(code: 0x7fffee, bitCount: 23), HuffmanCode(code: 0x7fffef, bitCount: 23),
        HuffmanCode(code: 0xfffea, bitCount: 20), HuffmanCode(code: 0x3fffe2, bitCount: 22),
        HuffmanCode(code: 0x3fffe3, bitCount: 22), HuffmanCode(code: 0x3fffe4, bitCount: 22),
        HuffmanCode(code: 0x7ffff0, bitCount: 23), HuffmanCode(code: 0x3fffe5, bitCount: 22),
        HuffmanCode(code: 0x3fffe6, bitCount: 22), HuffmanCode(code: 0x7ffff1, bitCount: 23),
        HuffmanCode(code: 0x3ffffe0, bitCount: 26), HuffmanCode(code: 0x3ffffe1, bitCount: 26),
        HuffmanCode(code: 0xfffeb, bitCount: 20), HuffmanCode(code: 0x7fff1, bitCount: 19),
        HuffmanCode(code: 0x3fffe7, bitCount: 22), HuffmanCode(code: 0x7ffff2, bitCount: 23),
        HuffmanCode(code: 0x3fffe8, bitCount: 22), HuffmanCode(code: 0x1ffffec, bitCount: 25),
        HuffmanCode(code: 0x3ffffe2, bitCount: 26), HuffmanCode(code: 0x3ffffe3, bitCount: 26),
        HuffmanCode(code: 0x3ffffe4, bitCount: 26), HuffmanCode(code: 0x7ffffde, bitCount: 27),
        HuffmanCode(code: 0x7ffffdf, bitCount: 27), HuffmanCode(code: 0x3ffffe5, bitCount: 26),
        HuffmanCode(code: 0xfffff1, bitCount: 24), HuffmanCode(code: 0x1ffffed, bitCount: 25),
        HuffmanCode(code: 0x7fff2, bitCount: 19), HuffmanCode(code: 0x1fffe3, bitCount: 21),
        HuffmanCode(code: 0x3ffffe6, bitCount: 26), HuffmanCode(code: 0x7ffffe0, bitCount: 27),
        HuffmanCode(code: 0x7ffffe1, bitCount: 27), HuffmanCode(code: 0x3ffffe7, bitCount: 26),
        HuffmanCode(code: 0x7ffffe2, bitCount: 27), HuffmanCode(code: 0xfffff2, bitCount: 24),
        HuffmanCode(code: 0x1fffe4, bitCount: 21), HuffmanCode(code: 0x1fffe5, bitCount: 21),
        HuffmanCode(code: 0x3ffffe8, bitCount: 26), HuffmanCode(code: 0x3ffffe9, bitCount: 26),
        HuffmanCode(code: 0xffffffd, bitCount: 28), HuffmanCode(code: 0x7ffffe3, bitCount: 27),
        HuffmanCode(code: 0x7ffffe4, bitCount: 27), HuffmanCode(code: 0x7ffffe5, bitCount: 27),
        HuffmanCode(code: 0xfffec, bitCount: 20), HuffmanCode(code: 0xfffff3, bitCount: 24),
        HuffmanCode(code: 0xfffed, bitCount: 20), HuffmanCode(code: 0x1fffe6, bitCount: 21),
        HuffmanCode(code: 0x3fffe9, bitCount: 22), HuffmanCode(code: 0x1fffe7, bitCount: 21),
        HuffmanCode(code: 0x1fffe8, bitCount: 21), HuffmanCode(code: 0x7ffff3, bitCount: 23),
        HuffmanCode(code: 0x3fffea, bitCount: 22), HuffmanCode(code: 0x3fffeb, bitCount: 22),
        HuffmanCode(code: 0x1ffffee, bitCount: 25), HuffmanCode(code: 0x1ffffef, bitCount: 25),
        HuffmanCode(code: 0xfffff4, bitCount: 24), HuffmanCode(code: 0xfffff5, bitCount: 24),
        HuffmanCode(code: 0x3ffffea, bitCount: 26), HuffmanCode(code: 0x7ffff4, bitCount: 23),
        HuffmanCode(code: 0x3ffffeb, bitCount: 26), HuffmanCode(code: 0x7ffffe6, bitCount: 27),
        HuffmanCode(code: 0x3ffffec, bitCount: 26), HuffmanCode(code: 0x3ffffed, bitCount: 26),
        HuffmanCode(code: 0x7ffffe7, bitCount: 27), HuffmanCode(code: 0x7ffffe8, bitCount: 27),
        HuffmanCode(code: 0x7ffffe9, bitCount: 27), HuffmanCode(code: 0x7ffffea, bitCount: 27),
        HuffmanCode(code: 0x7ffffeb, bitCount: 27), HuffmanCode(code: 0xffffffe, bitCount: 28),
        HuffmanCode(code: 0x7ffffec, bitCount: 27), HuffmanCode(code: 0x7ffffed, bitCount: 27),
        HuffmanCode(code: 0x7ffffee, bitCount: 27), HuffmanCode(code: 0x7ffffef, bitCount: 27),
        HuffmanCode(code: 0x7fffff0, bitCount: 27), HuffmanCode(code: 0x3ffffee, bitCount: 26),
        HuffmanCode(code: 0x3fffffff, bitCount: 30)
    ]
}

private final class HuffmanNode: @unchecked Sendable {
    var zero: HuffmanNode?
    var one: HuffmanNode?
    var symbol: Int?
}
