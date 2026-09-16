import Foundation
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple
@testable import WebTransportNetworkRuntime

enum WebTransportNetworkProbeCodec {
    private static let probePrefix = Data("WT-NET-PROBE\0".utf8)
    private static let ackPrefix = Data("WT-NET-ACK\0".utf8)

    static func encodeProbePacket(message: String) throws -> Data {
        try QUICFrame.encodeFrames([.datagram(probePrefix + Data(message.utf8))])
    }

    static func encodeAckPacket(message: String) throws -> Data {
        try QUICFrame.encodeFrames([.datagram(ackPrefix + Data(message.utf8))])
    }

    static func decodeProbePacket(_ packet: Data) throws -> String {
        try decode(packet, expectedPrefix: probePrefix)
    }

    static func decodeAckPacket(_ packet: Data) throws -> String {
        try decode(packet, expectedPrefix: ackPrefix)
    }

    private static func decode(_ packet: Data, expectedPrefix: Data) throws -> String {
        let frames = try QUICFrame.decodeFrames(packet)
        guard frames.count == 1, case .datagram(let payload) = frames[0] else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }
        guard payload.starts(with: expectedPrefix) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let messageBytes = payload.dropFirst(expectedPrefix.count)
        guard let message = String(data: Data(messageBytes), encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return message
    }
}
