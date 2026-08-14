import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

// Systematic malformed-input fuzzing of every parser that consumes peer bytes.
//
// The existing suite tests malformed input the authors thought of. This drives
// each parser with a large, mechanically generated corpus instead, so the
// coverage does not depend on anticipating the failure. The contract under test
// is narrow and absolute: a parser handed arbitrary bytes must either return a
// value or throw. It must never trap — no array bounds trap, no force-unwrap of
// nil, no integer overflow, no unbounded allocation, no hang.
//
// A trap in any of these is remotely triggerable by an unauthenticated peer,
// because every one of them runs on bytes received before a session is
// established.
//
// The generator is seeded and fully deterministic, so a failure reproduces
// exactly. `WEBTRANSPORT_FUZZ_ITERATIONS` raises the per-parser budget for
// longer local runs; CI uses the default.

/// Deterministic PRNG. Reproducibility matters more than statistical quality:
/// a crash found in CI has to be replayable from the seed alone.
private struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { self.state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

private struct FuzzCorpus {
    var generator: SplitMix64

    init(seed: UInt64) { generator = SplitMix64(seed: seed) }

    mutating func bytes(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    /// A QUIC variable-length integer, biased toward boundary encodings where
    /// length-prefix bugs live.
    mutating func varInt() -> Data {
        let choices: [UInt64] = [0, 1, 63, 64, 16_383, 16_384, 1_073_741_823,
                                 1_073_741_824, 4_611_686_018_427_387_903,
                                 UInt64.random(in: 0...UInt64(Int.max), using: &generator)]
        let value = choices.randomElement(using: &generator) ?? 0
        return (try? QUICVarInt.encode(value)) ?? Data([0])
    }

    /// Structured-ish input: a type varint, a length varint that frequently lies
    /// about the body that follows, then a body. Most real parsers reject pure
    /// noise in the first byte, so this reaches deeper paths.
    mutating func framed() -> Data {
        var data = varInt()
        let declared = UInt64.random(in: 0...4096, using: &generator)
        data.append((try? QUICVarInt.encode(declared)) ?? Data([0]))
        let actual = Int.random(in: 0...256, using: &generator)
        data.append(bytes(count: actual))
        return data
    }

    mutating func mutate(_ seed: Data) -> Data {
        guard !seed.isEmpty else { return bytes(count: Int.random(in: 0...32, using: &generator)) }
        var out = [UInt8](seed)
        switch Int.random(in: 0..<6, using: &generator) {
        case 0:  // bit flip
            let i = Int.random(in: 0..<out.count, using: &generator)
            out[i] ^= UInt8(1 << Int.random(in: 0..<8, using: &generator))
        case 1:  // truncate — exercises every "read past end" path
            out = Array(out.prefix(Int.random(in: 0..<out.count, using: &generator)))
        case 2:  // extend with noise
            out.append(contentsOf: [UInt8](bytes(count: Int.random(in: 1...64, using: &generator))))
        case 3:  // byte overwrite with a boundary value
            let i = Int.random(in: 0..<out.count, using: &generator)
            out[i] = [0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff]
                .randomElement(using: &generator) ?? 0xff
        case 4:  // splice against fresh noise
            let cut = Int.random(in: 0..<out.count, using: &generator)
            out = Array(out.prefix(cut)) + [UInt8](bytes(count: Int.random(in: 0...64, using: &generator)))
        default: // duplicate, to trip accumulating-length logic
            out += out
        }
        return Data(out)
    }
}

/// Every parser reachable from peer-controlled bytes, as `(name, invoke)`.
///
/// The closures deliberately discard results: the assertion is that control
/// returns at all, by value or by thrown error. `nonisolated(unsafe)` is sound
/// here — the table is immutable after initialization and every entry is a
/// stateless static call.
private nonisolated(unsafe) let peerInputParsers: [(name: String, run: @Sendable (Data) throws -> Void)] = [
    ("QUICVarInt.decode", { data in
        var cursor = QUICByteCursor(data)
        _ = try QUICVarInt.decode(from: &cursor)
    }),
    ("QUICFrame.decodeFrames", { _ = try QUICFrame.decodeFrames($0) }),
    ("QUICTransportParameters.decode", { _ = try QUICTransportParameters.decode($0) }),
    ("QUICLongHeaderPacket.decode", { _ = try QUICLongHeaderPacket.decode($0) }),
    ("QUICRetryPacket.decode", { _ = try QUICRetryPacket.decode($0) }),

    ("HTTP3Frame.decodeFrames", { _ = try HTTP3Frame.decodeFrames($0) }),
    ("HTTP3Frame.decodePrefix", { _ = try HTTP3Frame.decodePrefix($0) }),
    ("HTTP3Settings.decodePayload", { _ = try HTTP3Settings.decodePayload($0) }),
    ("HTTP3StreamTypeParser.parsePrefix", { _ = try HTTP3StreamTypeParser.parsePrefix($0) }),

    ("QPACK.decodeFieldSection", { _ = try QPACK.decodeFieldSection($0) }),
    ("QPACK.decodeEncoderStreamInstructions", { _ = try QPACK.decodeEncoderStreamInstructions($0) }),
    ("QPACK.decodeDecoderStreamInstructions", { _ = try QPACK.decodeDecoderStreamInstructions($0) }),
    ("QPACKHuffman.decode", { _ = try QPACKHuffman.decode($0) }),

    ("WebTransportFlowCapsuleCodec.parse", { _ = try WebTransportFlowCapsuleCodec.parse($0) }),
    ("WebTransportDatagramSignaling.parse", { _ = try WebTransportDatagramSignaling.parse($0) }),
    ("WebTransportStreamSignaling.parsePrefix", { _ = try WebTransportStreamSignaling.parsePrefix($0) }),
    ("WebTransportStreamSignaling.hasStreamPrefix", { _ = WebTransportStreamSignaling.hasStreamPrefix($0) }),

    ("TLSHandshakeMessage.decodeAll", { _ = try TLSHandshakeMessage.decodeAll($0) }),
    ("TLSExtension.decodeList", { _ = try TLSExtension.decodeList($0) }),
    ("TLSClientHello.decode", { _ = try TLSClientHello.decode($0) }),
    ("TLSServerHello.decode", { _ = try TLSServerHello.decode($0) }),
    ("TLSCertificate.decode", { _ = try TLSCertificate.decode($0) }),
    ("TLSCertificateVerify.decode", { _ = try TLSCertificateVerify.decode($0) })
]

private var fuzzIterations: Int {
    if let raw = ProcessInfo.processInfo.environment["WEBTRANSPORT_FUZZ_ITERATIONS"],
       let parsed = Int(raw), parsed > 0 {
        return parsed
    }
    return 400
}

@Test
func peerFacingParsersNeverTrapOnArbitraryInput() throws {
    let iterations = fuzzIterations
    var corpus = FuzzCorpus(seed: 0x5EED_1234_ABCD_0001)

    // Shared inputs, so every parser sees the same bytes and a body that is
    // valid for one parser is fed to all the others too.
    var inputs: [Data] = [
        Data(), Data([0x00]), Data([0xff]), Data([0x40]), Data([0xc0]),
        Data(repeating: 0xff, count: 1024)
    ]
    for _ in 0..<iterations {
        inputs.append(corpus.framed())
        inputs.append(corpus.bytes(count: Int.random(in: 0...512, using: &corpus.generator)))
        inputs.append(corpus.varInt())
    }
    // Second generation: mutate the first.
    for index in 0..<inputs.count {
        inputs.append(corpus.mutate(inputs[index]))
    }

    for parser in peerInputParsers {
        for input in inputs {
            // Reaching the next line at all is the assertion. A trap inside the
            // parser terminates the process and fails the run with a stack
            // trace pointing at the offending parser.
            do {
                try parser.run(input)
            } catch {
                // Throwing is correct behavior for malformed input.
            }
        }
    }

    #expect(inputs.count > iterations)
}

@Test
func peerFacingParsersRejectOversizedInputWithoutExhaustingMemory() throws {
    // A peer can claim an enormous length in a few bytes. The parser must not
    // pre-allocate on that claim; it must fail against the bytes it actually has.
    var oversized = Data()
    oversized.append(try QUICVarInt.encode(0x3f))                          // type
    oversized.append(try QUICVarInt.encode(4_611_686_018_427_387_903))     // absurd length
    oversized.append(Data(repeating: 0x41, count: 64))                     // tiny body

    for parser in peerInputParsers {
        do {
            try parser.run(oversized)
        } catch {
            // Expected.
        }
    }

    // Same claim, zero body. The length is the largest a QUIC varint can carry;
    // Int.max does not fit in 62 bits and the encoder rightly rejects it.
    var headerOnly = Data()
    headerOnly.append(try QUICVarInt.encode(0x01))
    headerOnly.append(try QUICVarInt.encode(4_611_686_018_427_387_903))
    for parser in peerInputParsers {
        do {
            try parser.run(headerOnly)
        } catch {
            // Expected.
        }
    }
}

@Test
func huffmanDecoderTerminatesOnAdversarialPadding() throws {
    // The Huffman decoder walks a trie per bit, so a crafted run of set bits is
    // the natural place to look for a non-terminating or trapping path.
    var corpus = FuzzCorpus(seed: 0x5EED_0000_1111_2222)
    for length in [1, 2, 3, 7, 8, 9, 31, 32, 33, 255, 256, 1024] {
        for filler in [UInt8(0x00), 0xff, 0xaa, 0x55, 0xfe, 0x7f] {
            do {
                _ = try QPACKHuffman.decode(Data(repeating: filler, count: length))
            } catch {
                // Expected for most inputs.
            }
        }
        for _ in 0..<64 {
            do {
                _ = try QPACKHuffman.decode(corpus.bytes(count: length))
            } catch {
                // Expected.
            }
        }
    }
}
