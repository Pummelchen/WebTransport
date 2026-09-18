import Foundation
import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple
@testable import WebTransportNetworkRuntime

final class WebTransportQUICPacketProbeServer: @unchecked Sendable {
    private let port: QUICUDPPort
    private var bufferedInitialPackets: [String: [BufferedInitialPacket]] = [:]
    private let bufferLock = NSLock()

    private struct BufferedInitialPacket: Sendable {
        let remote: QUICUDPEndpoint
        let bytes: Data
    }

    var localEndpoint: WebTransportNetworkEndpoint {
        WebTransportNetworkEndpoint(
            host: port.localEndpoint.host,
            port: port.localEndpoint.port
        )
    }

    init(bindPort: UInt16) throws {
        self.port = try QUICUDPPort(bindPort: bindPort)
    }

    @discardableResult
    func serveOne(timeoutMilliseconds: Int32 = 1_000) throws -> WebTransportNetworkSessionResult {
        let (bytes, remote) = try receiveOrTakePendingInitial(timeoutMilliseconds: timeoutMilliseconds)
        let decoded = try WebTransportQUICPacketProbeCodec.decodeClientInitial(bytes)
        let handshakeContext = try WebTransportQUICPacketProbeCodec.serverHandshakeContext(
            request: decoded,
            message: decoded.message
        )
        let response = try WebTransportQUICPacketProbeCodec.encodeServerInitial(handshakeContext: handshakeContext)
        try port.send(response, to: remote)
        let (requestBytes, _) = try receiveApplicationPacket(
            forRemote: remote,
            timeoutMilliseconds: timeoutMilliseconds
        )
        let applicationRequest = try WebTransportQUICPacketProbeCodec.decodeClientApplicationRequest(
            requestBytes,
            handshakeContext: handshakeContext
        )
        guard applicationRequest.message == decoded.message else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let applicationResponse = try WebTransportQUICPacketProbeCodec.encodeServerApplicationResponse(
            handshakeContext: handshakeContext,
            message: applicationRequest.message
        )
        try port.send(applicationResponse, to: remote)
        return WebTransportNetworkSessionResult(
            localEndpoint: localEndpoint,
            remoteEndpoint: WebTransportNetworkEndpoint(host: remote.host, port: remote.port),
            message: applicationRequest.message,
            transport: .packet,
            sessionEstablished: true
        )
    }

    private func receiveOrTakePendingInitial(timeoutMilliseconds: Int32) throws -> (Data, QUICUDPEndpoint) {
        if let (bytes, remote) = consumePendingInitialPacket() {
            return (bytes, remote)
        }
        return try port.receive(timeoutMilliseconds: timeoutMilliseconds)
    }

    private func receiveApplicationPacket(
        forRemote remote: QUICUDPEndpoint,
        timeoutMilliseconds: Int32
    ) throws -> (Data, QUICUDPEndpoint) {
        let deadline = Date().addingTimeInterval(TimeInterval(max(0, timeoutMilliseconds)) / 1_000)
        if let (bytes, bufferedRemote) = consumePendingInitialPacket(for: remote) {
            return (bytes, bufferedRemote)
        }

        while true {
            let remainingTimeout = Int32(
                max(0, Int(ceil(deadline.timeIntervalSinceNow * 1_000)))
            )
            guard remainingTimeout > 0 else {
                throw QUICUDPError.timeout
            }

            let (bytes, packetRemote) = try port.receive(timeoutMilliseconds: remainingTimeout)
            if packetRemote == remote {
                return (bytes, packetRemote)
            }
            bufferInitialPacket(remote: packetRemote, bytes: bytes)
        }
    }

    private func key(for remote: QUICUDPEndpoint) -> String {
        "\(remote.host):\(remote.port)"
    }

    private func bufferInitialPacket(remote: QUICUDPEndpoint, bytes: Data) {
        bufferLock.lock()
        defer { bufferLock.unlock() }
        let item = BufferedInitialPacket(remote: remote, bytes: bytes)
        bufferedInitialPackets[key(for: remote), default: []].append(item)
    }

    private func consumePendingInitialPacket(
        for expectedRemote: QUICUDPEndpoint? = nil
    ) -> (Data, QUICUDPEndpoint)? {
        bufferLock.lock()
        defer { bufferLock.unlock() }

        if let expectedRemote {
            let expectedKey = key(for: expectedRemote)
            if var packets = bufferedInitialPackets.removeValue(forKey: expectedKey),
                let buffered = packets.first
            {
                packets.removeFirst()
                if packets.isEmpty {
                    return (buffered.bytes, buffered.remote)
                }
                bufferedInitialPackets[expectedKey] = packets
                return (buffered.bytes, buffered.remote)
            }
            return nil
        }

        guard let entry = bufferedInitialPackets.first(where: { !$0.value.isEmpty }) else {
            return nil
        }
        var packets = entry.value
        guard let packet = packets.first else {
            bufferedInitialPackets.removeValue(forKey: entry.key)
            return nil
        }
        packets.removeFirst()
        let remotePort = entry.key
        let remote = packet.remote
        if packets.isEmpty {
            bufferedInitialPackets.removeValue(forKey: remotePort)
        } else {
            bufferedInitialPackets[remotePort] = packets
        }
        return (packet.bytes, remote)
    }
}

struct WebTransportQUICPacketProbeClient: Sendable {
    var localPort: UInt16

    init(localPort: UInt16 = 0) {
        self.localPort = localPort
    }

    @discardableResult
    func run(
        to endpoint: WebTransportNetworkEndpoint,
        message: String,
        timeoutMilliseconds: Int32 = 1_000
    ) throws -> WebTransportNetworkSessionResult {
        let port = try QUICUDPPort(bindPort: localPort)
        let packet = try WebTransportQUICPacketProbeCodec.encodeClientInitial(message: message)
        let request = try WebTransportQUICPacketProbeCodec.decodeClientInitial(packet)
        try port.send(packet, to: endpoint.udpEndpoint)
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let remoteEndpoint = WebTransportNetworkEndpoint(host: remote.host, port: remote.port)
        guard remoteEndpoint == endpoint else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let handshakeContext = try WebTransportQUICPacketProbeCodec.decodeServerInitialContext(
            bytes,
            request: request
        )
        guard handshakeContext.message == message else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        let applicationRequest = try WebTransportQUICPacketProbeCodec.encodeClientApplicationRequest(
            handshakeContext: handshakeContext,
            message: message
        )
        try port.send(applicationRequest, to: endpoint.udpEndpoint)
        let (applicationResponseBytes, applicationResponseRemote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        guard WebTransportNetworkEndpoint(host: applicationResponseRemote.host, port: applicationResponseRemote.port) == endpoint else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let applicationMessage = try WebTransportQUICPacketProbeCodec.decodeServerApplicationResponse(
            applicationResponseBytes,
            handshakeContext: handshakeContext
        )
        guard applicationMessage == message else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return WebTransportNetworkSessionResult(
            localEndpoint: WebTransportNetworkEndpoint(
                host: port.localEndpoint.host,
                port: port.localEndpoint.port
            ),
            remoteEndpoint: remoteEndpoint,
            message: applicationMessage,
            transport: .packet,
            sessionEstablished: true
        )
    }
}

final class WebTransportNetworkProbeServer: @unchecked Sendable {
    private let port: QUICUDPPort

    var localEndpoint: WebTransportNetworkEndpoint {
        WebTransportNetworkEndpoint(
            host: port.localEndpoint.host,
            port: port.localEndpoint.port
        )
    }

    init(bindPort: UInt16) throws {
        self.port = try QUICUDPPort(bindPort: bindPort)
    }

    @discardableResult
    func serveOne(timeoutMilliseconds: Int32 = 1_000) throws -> WebTransportNetworkSessionResult {
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let message = try WebTransportNetworkProbeCodec.decodeProbePacket(bytes)
        let response = try WebTransportNetworkProbeCodec.encodeAckPacket(message: message)
        try port.send(response, to: remote)
        return WebTransportNetworkSessionResult(
            localEndpoint: localEndpoint,
            remoteEndpoint: WebTransportNetworkEndpoint(host: remote.host, port: remote.port),
            message: message,
            transport: .frame
        )
    }
}

struct WebTransportNetworkProbeClient: Sendable {
    var localPort: UInt16

    init(localPort: UInt16 = 0) {
        self.localPort = localPort
    }

    @discardableResult
    func run(
        to endpoint: WebTransportNetworkEndpoint,
        message: String,
        timeoutMilliseconds: Int32 = 1_000
    ) throws -> WebTransportNetworkSessionResult {
        let port = try QUICUDPPort(bindPort: localPort)
        let packet = try WebTransportNetworkProbeCodec.encodeProbePacket(message: message)
        try port.send(packet, to: endpoint.udpEndpoint)
        let (bytes, remote) = try port.receive(timeoutMilliseconds: timeoutMilliseconds)
        let remoteEndpoint = WebTransportNetworkEndpoint(host: remote.host, port: remote.port)
        guard remoteEndpoint == endpoint else {
            throw WebTransportNetworkRuntimeError.unexpectedPacket
        }
        let responseMessage = try WebTransportNetworkProbeCodec.decodeAckPacket(bytes)
        guard responseMessage == message else {
            throw WebTransportNetworkRuntimeError.invalidPayload
        }
        return WebTransportNetworkSessionResult(
            localEndpoint: WebTransportNetworkEndpoint(
                host: port.localEndpoint.host,
                port: port.localEndpoint.port
            ),
            remoteEndpoint: remoteEndpoint,
            message: responseMessage,
            transport: .frame
        )
    }
}

struct WebTransportQUICPacketProbeRequest: Equatable, Sendable {
    var message: String
    var packetNumber: UInt64
    var destinationConnectionID: Data
    var sourceConnectionID: Data
    var handshakeMessages: [TLSHandshakeMessage]

    init(
        message: String,
        packetNumber: UInt64,
        destinationConnectionID: Data,
        sourceConnectionID: Data,
        handshakeMessages: [TLSHandshakeMessage] = []
    ) {
        self.message = message
        self.packetNumber = packetNumber
        self.destinationConnectionID = destinationConnectionID
        self.sourceConnectionID = sourceConnectionID
        self.handshakeMessages = handshakeMessages
    }
}

struct WebTransportQUICPacketHandshakeContext: Equatable, Sendable {
    var request: WebTransportQUICPacketProbeRequest
    var message: String
    var serverHandshakeMessages: [TLSHandshakeMessage]
    var clientApplicationKeys: QUICPacketProtectionKeys
    var serverApplicationKeys: QUICPacketProtectionKeys
}

struct WebTransportQUICPacketApplicationRequest: Equatable, Sendable {
    var message: String
    var packetNumber: UInt64
    var requestHeaders: [HTTPFieldLine]
}
