import Foundation
import Network
import Security

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

private enum InteroperableQUICDebug {
    static let enabled = ProcessInfo.processInfo.environment["WEBTRANSPORT_INTEROP_DEBUG"] == "1"

    static func log(_ message: @autoclosure () -> String) {
        guard enabled else {
            return
        }
        let text = "[interoperable-quic] \(message())\n"
        if let data = text.data(using: .utf8) {
            FileHandle.standardError.write(data)
        }
    }
}

public struct WebTransportQUICInteroperablePacketProbeClient: Sendable {
    public var localPort: UInt16

    public init(localPort: UInt16 = 0) {
        self.localPort = localPort
    }

    @discardableResult
    public func run(
        to endpoint: WebTransportNetworkEndpoint,
        message: String,
        timeoutMilliseconds: Int32 = 1_000
    ) async throws -> WebTransportNetworkProbeResult {
        let host: NWEndpoint.Host = endpoint.host == "127.0.0.1"
            ? .ipv4(.loopback)
            : .init(endpoint.host)
        let destination = NWEndpoint.hostPort(
            host: host,
            port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any
        )
        InteroperableQUICDebug.log("client connecting to \(endpoint.host):\(endpoint.port)")
        let connection = NetworkConnection(to: destination) {
            InteroperableQUICRuntime.makeClientQUIC()
        }
        InteroperableQUICDebug.log("client state before start: \(connection.state)")
        InteroperableQUICDebug.log("client started")

        let started = Date()
        func remainingTimeout() -> Int32 {
            InteroperableQUICHelpers.remainingTimeout(
                timeoutMilliseconds: timeoutMilliseconds,
                started: started
            )
        }
        func runWithTimeout(_ operation: @Sendable @escaping () async throws -> Void) async throws {
            let remaining = remainingTimeout()
            guard remaining > 0 else {
                throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
            }
            try await InteroperableQUICHelpers.withTimeout(remaining, operation)
        }

        try await InteroperableQUICHelpers.waitForReady(
            connection: connection,
            role: "client",
            start: { _ = connection.start() },
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client ready")

        let inboundStreams = InteroperableQUICInboundStreamCollector()
        let inboundTask = Task {
            do {
                try await connection.inboundStreams { stream in
                    await inboundStreams.enqueue(stream, direction: InteroperableQUICHelpers.streamDirectionKey(stream.directionality))
                }
            } catch {
                await inboundStreams.fail(error)
            }
        }
        defer {
            inboundTask.cancel()
        }

        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(connection)
        InteroperableQUICDebug.log("client datagrams usable=\(useDatagrams)")

        var http3 = HTTP3ConnectionState(role: .client)
        let localControlPayload = try http3.localControlStreamBytes()
        let localControlStream = try await InteroperableQUICHelpers.withTimeout(
            remainingTimeout()
        ) {
            try await connection.openStream(directionality: .unidirectional)
        }
        InteroperableQUICDebug.log("client opened local control stream \(localControlStream.streamID)")
        try await runWithTimeout {
            try await localControlStream.send(localControlPayload, endOfStream: true)
        }
        InteroperableQUICDebug.log("client sent local control payload")

        let peerControlStream = try await inboundStreams.next(
            direction: InteroperableQUICHelpers.unidirectionalStreamDirection,
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client got peer control stream \(peerControlStream.streamID)")
        let peerControlBytes = try await InteroperableQUICHelpers.readStream(
            peerControlStream,
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client peer control bytes=\(peerControlBytes.count)")
        _ = try http3.receivePeerControlStream(peerControlBytes)
        var manager = WebTransportSessionManager(http3: http3)

        let requestStream = try await InteroperableQUICHelpers.withTimeout(
            remainingTimeout()
        ) {
            try await connection.openStream(directionality: .bidirectional)
        }
        let requestStreamID = requestStream.streamID
        InteroperableQUICDebug.log("client opened request stream \(requestStreamID)")
        let request = try WebTransportSessionRequest(
            authority: InteroperableQUICRuntime.defaultAuthority,
            path: InteroperableQUICRuntime.defaultPath,
            origin: InteroperableQUICRuntime.defaultOrigin,
            availableProtocols: [InteroperableQUICRuntime.defaultProtocol]
        )
        let requestFrame = try manager.makeClientSessionRequest(streamID: requestStreamID, request: request)
        let connectPayload = try InteroperableQUICHelpers.makeRequestStreamPayload(
            streamID: requestStreamID,
            requestFrame: requestFrame
        )
        try await runWithTimeout {
            try await requestStream.send(connectPayload, endOfStream: true)
        }
        InteroperableQUICDebug.log("client sent connect payload")

        let responseData = try await InteroperableQUICHelpers.readStream(
            requestStream,
            timeoutMilliseconds: remainingTimeout()
        )
        InteroperableQUICDebug.log("client got response bytes=\(responseData.count)")
        let responseFrames = try HTTP3Frame.decodeFrames(responseData)
        guard let responseFrame = responseFrames.first(where: { $0.type == HTTP3FrameType.headers }) else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }

        _ = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: responseFrame)
        let sessionID = try WebTransportSessionID.fromRequestStreamID(requestStreamID)

        let responseMessage: String
        if useDatagrams {
            InteroperableQUICDebug.log("client using datagram path")
            let datagrams = try await connection.datagrams
            let datagramPayload = try manager.makeDatagramFrame(sessionID: sessionID, payload: Data(message.utf8))
            try await runWithTimeout {
                try await datagrams.send(datagramPayload.datagramPayload)
            }
            InteroperableQUICDebug.log("client sent datagram")

            let receivedDatagram = try await InteroperableQUICHelpers.withTimeout(remainingTimeout()) {
                try await datagrams.receive().content
            }
            InteroperableQUICDebug.log("client received datagram bytes=\(receivedDatagram.count)")
            let responseSessionID = try manager.receiveDatagramFrame(.datagram(receivedDatagram))
            guard let responsePayload = manager.popDatagramPayload(sessionID: responseSessionID) else {
                throw WebTransportNetworkRuntimeError.invalidProbePayload
            }
            guard let responseMessageValue = String(data: responsePayload, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidProbePayload
            }
            responseMessage = responseMessageValue
        } else {
            InteroperableQUICDebug.log("client using stream fallback path")
            let fallbackStream = try await InteroperableQUICHelpers.withTimeout(
                remainingTimeout()
            ) {
                try await connection.openStream(directionality: .bidirectional)
            }
            try await runWithTimeout {
                try await fallbackStream.send(Data(message.utf8), endOfStream: true)
            }
            let fallbackPayload = try await InteroperableQUICHelpers.readStream(
                fallbackStream,
                timeoutMilliseconds: remainingTimeout()
            )
            guard let responseMessageValue = String(data: fallbackPayload, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidProbePayload
            }
            responseMessage = responseMessageValue
        }

        return WebTransportNetworkProbeResult(
            localEndpoint: WebTransportNetworkEndpoint(host: endpoint.host, port: endpoint.port),
            remoteEndpoint: endpoint,
            message: responseMessage,
            transport: .packet,
            sessionEstablished: true
        )
    }
}
public final class WebTransportQUICInteroperablePacketProbeServer: @unchecked Sendable {
    public var localEndpoint: WebTransportNetworkEndpoint

    private let listener: NetworkListener<QUIC>
    private let acceptedConnections: InteroperableQUICConnectionQueue
    private let listenerTask: Task<Void, Never>

    public init(bindPort: UInt16, maxConcurrentConnections: Int = 16) throws {
        InteroperableQUICDebug.log("server init bindPort=\(bindPort)")
        let identity = try InteroperableTLSIdentity.create()
        let parameters = NWParametersBuilder(auto: {
            InteroperableQUICRuntime.makeServerQUIC(identity: identity)
        })
        .localEndpoint(
            .hostPort(
                host: .ipv4(.loopback),
                port: NWEndpoint.Port(rawValue: bindPort) ?? .any
            )
        )
        .localOnly(true)

        listener = try NetworkListener<QUIC>(using: parameters)
            .newConnectionLimit(max(1, max(8, maxConcurrentConnections)))
        acceptedConnections = InteroperableQUICConnectionQueue()
        localEndpoint = WebTransportNetworkEndpoint(host: "127.0.0.1", port: bindPort)
        listener.onStateUpdate { _, state in
            InteroperableQUICDebug.log("server listener state update: \(state)")
        }

        let listener = self.listener
        let acceptedConnections = self.acceptedConnections
        listenerTask = Task {
            do {
                try await listener.run { connection in
                    InteroperableQUICDebug.log("server accepted connection")
                    _ = connection.start()
                    await acceptedConnections.enqueue(connection)
                }
            } catch {
                await acceptedConnections.fail(error)
            }
        }
    }

    public func waitForListening(timeoutMilliseconds: Int32 = 5_000) async throws -> WebTransportNetworkEndpoint {
        let port = try await InteroperableQUICHelpers.withTimeout(timeoutMilliseconds) {
            try await Self.resolveListenerPort(self.listener)
        }
        localEndpoint = WebTransportNetworkEndpoint(host: localEndpoint.host, port: port.rawValue)
        return localEndpoint
    }

    deinit {
        listenerTask.cancel()
    }

    @discardableResult
    public func serveOne(timeoutMilliseconds: Int32 = 1_000) async throws -> WebTransportNetworkProbeResult {
        let connection = try await InteroperableQUICHelpers.withTimeout(timeoutMilliseconds) {
            try await self.acceptedConnections.dequeue()
        }
        InteroperableQUICDebug.log("server serveOne dequeued")
        InteroperableQUICDebug.log("server serveOne connection state before wait: \(connection.state)")
        connection.onStateUpdate { _, state in
            InteroperableQUICDebug.log("server connection state update: \(state)")
        }

        do {
            try await InteroperableQUICHelpers.waitForReady(
                connection: connection,
                role: "server",
                timeoutMilliseconds: timeoutMilliseconds
            )
        } catch {
            _ = connection.state
            throw error
        }

        return try await serveSession(
            on: connection,
            timeoutMilliseconds: timeoutMilliseconds
        )
    }

    private func serveSession(
        on connection: NetworkConnection<QUIC>,
        timeoutMilliseconds: Int32
    ) async throws -> WebTransportNetworkProbeResult {
        let started = Date()
        let remainingTimeout: @Sendable () -> Int32 = { [timeoutMilliseconds] () -> Int32 in
            InteroperableQUICHelpers.remainingTimeout(
                timeoutMilliseconds: timeoutMilliseconds,
                started: started
            )
        }

        func runWithTimeout(_ operation: @Sendable @escaping () async throws -> Void) async throws {
            let remaining = remainingTimeout()
            guard remaining > 0 else {
                throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
            }
            try await InteroperableQUICHelpers.withTimeout(remaining, operation)
        }

        func runWithTimeout<T: Sendable>(_ operation: @Sendable @escaping () async throws -> T) async throws -> T {
            let remaining = remainingTimeout()
            guard remaining > 0 else {
                throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
            }
            return try await InteroperableQUICHelpers.withTimeout(remaining, operation)
        }

        InteroperableQUICDebug.log("server serveSession start")
        let inboundStreams = InteroperableQUICInboundStreamCollector()
        let inboundTask = Task {
            do {
                try await connection.inboundStreams { stream in
                    InteroperableQUICDebug.log("server inbound stream direction=\(stream.directionality) id=\(stream.streamID)")
                    await inboundStreams.enqueue(
                        stream,
                        direction: InteroperableQUICHelpers.streamDirectionKey(stream.directionality)
                    )
                }
            } catch {
                await inboundStreams.fail(error)
            }
        }
        defer {
            inboundTask.cancel()
        }

        let useDatagrams = InteroperableQUICHelpers.datagramsUsable(connection)
        InteroperableQUICDebug.log("server datagrams usable=\(useDatagrams)")

        var http3 = HTTP3ConnectionState(role: .server)
        let localControlPayload = try http3.localControlStreamBytes()
        let localControlStream = try await runWithTimeout {
            try await connection.openStream(directionality: .unidirectional)
        }
        InteroperableQUICDebug.log("server opened local control stream \(localControlStream.streamID)")
        try await runWithTimeout {
            try await localControlStream.send(localControlPayload, endOfStream: true)
        }
        InteroperableQUICDebug.log("server sent local control payload")

        let controlStream = try await runWithTimeout {
            try await inboundStreams.next(
                direction: InteroperableQUICHelpers.unidirectionalStreamDirection,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server got client control stream \(controlStream.streamID)")
        let controlPayload = try await runWithTimeout {
            try await InteroperableQUICHelpers.readStream(
                controlStream,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server control payload bytes=\(controlPayload.count)")
        _ = try http3.receivePeerControlStream(controlPayload)
        var manager = WebTransportSessionManager(http3: http3)

        let requestStream = try await runWithTimeout {
            try await inboundStreams.next(
                direction: InteroperableQUICHelpers.bidirectionalStreamDirection,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server got request stream \(requestStream.streamID)")
        let requestPayload = try await runWithTimeout {
            try await InteroperableQUICHelpers.readStream(
                requestStream,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        InteroperableQUICDebug.log("server request payload bytes=\(requestPayload.count)")
        let prefix = try WebTransportStreamSignaling.parsePrefix(requestPayload)
        let requestFrames = try HTTP3Frame.decodeFrames(prefix.remainingPayload)
        guard let requestFrame = requestFrames.first(where: { $0.type == HTTP3FrameType.headers }) else {
            throw WebTransportNetworkRuntimeError.unexpectedFrame
        }

        let policy = try WebTransportServerSessionPolicy(
            allowedAuthorities: [InteroperableQUICRuntime.defaultAuthority],
            allowedPaths: [InteroperableQUICRuntime.defaultPath],
            allowedOrigins: [InteroperableQUICRuntime.defaultOrigin],
            supportedProtocols: [InteroperableQUICRuntime.defaultProtocol],
            requireProtocolSelection: true
        )

        let decision = try manager.receiveClientSessionRequest(
            streamID: requestStream.streamID,
            frame: requestFrame,
            policy: policy
        )
        let responsePayload = try decision.responseFrame.encode()
        try await runWithTimeout {
            try await requestStream.send(responsePayload, endOfStream: true)
        }

        if useDatagrams {
            let datagrams = try await runWithTimeout {
                try await connection.datagrams
            }
            let incoming = try await runWithTimeout {
                try await datagrams.receive().content
            }
            let sessionID = try manager.receiveDatagramFrame(.datagram(incoming))
            guard let requestDatagram = manager.popDatagramPayload(sessionID: sessionID) else {
                throw WebTransportNetworkRuntimeError.invalidProbePayload
            }
            let echoed = requestDatagram
            let responseDatagram = try manager.makeDatagramFrame(sessionID: sessionID, payload: echoed)
            try await runWithTimeout {
                try await datagrams.send(responseDatagram.datagramPayload)
            }
            guard let echoedMessage = String(data: echoed, encoding: .utf8) else {
                throw WebTransportNetworkRuntimeError.invalidProbePayload
            }
            return WebTransportNetworkProbeResult(
                localEndpoint: localEndpoint,
                remoteEndpoint: localEndpoint,
                message: echoedMessage,
                transport: .packet,
                sessionEstablished: decision.rejectionError == nil
            )
        }

        InteroperableQUICDebug.log("server using stream fallback path")
        let fallbackStream = try await runWithTimeout {
            try await inboundStreams.next(
                direction: InteroperableQUICHelpers.bidirectionalStreamDirection,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        let fallbackPayload = try await runWithTimeout {
            try await InteroperableQUICHelpers.readStream(
                fallbackStream,
                timeoutMilliseconds: remainingTimeout()
            )
        }
        guard let echoedMessage = String(data: fallbackPayload, encoding: .utf8) else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        try await runWithTimeout {
            try await fallbackStream.send(Data(echoedMessage.utf8), endOfStream: true)
        }

        return WebTransportNetworkProbeResult(
            localEndpoint: localEndpoint,
            remoteEndpoint: localEndpoint,
            message: echoedMessage,
            transport: .packet,
            sessionEstablished: decision.rejectionError == nil
        )
    }

    private static func resolveListenerPort(_ listener: NetworkListener<QUIC>) async throws -> NWEndpoint.Port {
        let start = Date()
        while (listener.port == nil || listener.port?.rawValue == 0) && Date().timeIntervalSince(start) < 5.0 {
            try await Task.sleep(for: .milliseconds(10))
        }
        guard let port = listener.port, port.rawValue != 0 else {
            throw WebTransportNetworkRuntimeError.timeout(5_000)
        }
        return port
    }
}

private enum InteroperableQUICRuntime {
    static let defaultAuthority = "localhost"
    static let defaultPath = "/wt"
    static let defaultOrigin = "https://localhost"
    static let defaultProtocol = "demo.v1"

    static func makeBaseQUIC() -> QUIC {
        QUIC(alpn: ["h3"]) {
            UDP()
        }
        .idleTimeout(30_000)
        .initialMaxData(1_048_576)
        .initialMaxStreamDataBidirectionalLocal(262_144)
        .initialMaxStreamDataBidirectionalRemote(262_144)
        .initialMaxStreamDataUnidirectional(262_144)
        .initialMaxBidirectionalStreams(16)
        .initialMaxUnidirectionalStreams(16)
        .maxDatagramFrameSize(1_200)
    }

    static func makeClientQUIC() -> QUIC {
        makeBaseQUIC()
            .tls
            .peerAuthentication(.none)
    }

    static func makeServerQUIC(identity: sec_identity_t) -> QUIC {
        makeBaseQUIC()
            .tls.localIdentity(identity)
            .tls.peerAuthentication(.none)
    }
}

private enum InteroperableQUICHelpers {
    static let bidirectionalStreamDirection = 0
    static let unidirectionalStreamDirection = 1

    static func streamDirectionKey(_ direction: QUICStream.Directionality) -> Int {
        switch direction {
        case .unidirectional:
            return unidirectionalStreamDirection
        case .bidirectional:
            return bidirectionalStreamDirection
        @unknown default:
            return bidirectionalStreamDirection
        }
    }

    static func makeRequestStreamPayload(streamID: UInt64, requestFrame: HTTP3Frame) throws -> Data {
        let prefix = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: streamID)
        var requestPayload = prefix
        requestPayload.append(contentsOf: try requestFrame.encode())
        return requestPayload
    }

    static func waitForReady(
        connection: NetworkConnection<QUIC>,
        role: String = "client",
        start: (@Sendable () -> Void)? = nil,
        timeoutMilliseconds: Int32
    ) async throws {
        if connection.state == .ready {
            InteroperableQUICDebug.log("\(role) connection already ready")
            return
        }
        if case .setup = connection.state {
            InteroperableQUICDebug.log("\(role) connection in setup state; proceeding to stream negotiation")
            return
        }
        if case .failed(let error) = connection.state {
            InteroperableQUICDebug.log("\(role) connection already failed: \(error)")
            throw error
        }
        if case .cancelled = connection.state {
            InteroperableQUICDebug.log("\(role) connection already cancelled")
            throw WebTransportNetworkRuntimeError.timeout(0)
        }

        try await withTimeout(timeoutMilliseconds) {
            try await withCheckedThrowingContinuation { continuation in
                let completion = OneShotContinuation()
                let handleState: @Sendable (NetworkConnection<QUIC>.State) -> Void = { state in
                    Task {
                        await completion.complete {
                            InteroperableQUICDebug.log("\(role) connection state handled: \(state)")
                            switch state {
                            case .ready:
                                continuation.resume()
                            case .failed(let error):
                                continuation.resume(throwing: error)
                            case .cancelled:
                                continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                            default:
                                break
                            }
                        }
                    }
                }

                InteroperableQUICDebug.log("\(role) connection state monitor start=\(connection.state)")
                handleState(connection.state)
                connection.onStateUpdate { _, state in
                    InteroperableQUICDebug.log("connection state update: \(state)")
                    handleState(state)
                }

                if let start {
                    InteroperableQUICDebug.log("\(role) connection start requested")
                    start()
                }

                Task {
                    while true {
                        try? await Task.sleep(for: .milliseconds(50))
                        let polled = connection.state
                        InteroperableQUICDebug.log("\(role) connection state poll: \(polled)")
                        switch polled {
                        case .ready:
                            await completion.complete {
                                continuation.resume()
                            }
                            return
                        case .failed(let error):
                            await completion.complete {
                                continuation.resume(throwing: error)
                            }
                            return
                        case .cancelled:
                            await completion.complete {
                                continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                            }
                            return
                        default:
                            break
                        }
                    }
                }
            }
        }
    }

    static func datagramsUsable(_ connection: NetworkConnection<QUIC>) -> Bool {
        connection.usableDatagramFrameSize > 0
    }

    static func readStream(
        _ stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        maxBytes: Int = 8_192
    ) async throws -> Data {
        try await withTimeout(timeoutMilliseconds) {
            let chunk = try await stream.receive(atMost: maxBytes)
            return chunk.content
        }
    }

    static func remainingTimeout(timeoutMilliseconds: Int32, started: Date) -> Int32 {
        let elapsedMilliseconds = Int32(max(0.0, Date().timeIntervalSince(started) * 1_000.0))
        return max(0, timeoutMilliseconds - elapsedMilliseconds)
    }

    static func withTimeout<T: Sendable>(
        _ timeoutMilliseconds: Int32,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard timeoutMilliseconds > 0 else {
            throw WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)
        }

        return try await withCheckedThrowingContinuation { continuation in
            let gate = TimeoutCompletion()
            _ = Task.detached { @Sendable in
                do {
                    let value = try await operation()
                    if await gate.tryFinish() {
                        continuation.resume(returning: value)
                    }
                } catch {
                    if await gate.tryFinish() {
                        continuation.resume(throwing: error)
                    }
                }
            }

            _ = Task.detached { @Sendable in
                let nanoseconds = UInt64(max(1, timeoutMilliseconds)) * 1_000_000
                try? await Task.sleep(for: .nanoseconds(nanoseconds))
                if await gate.tryFinish() {
                    continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds))
                }
            }
        }
    }
}

private actor TimeoutCompletion {
    private var completed = false

    func tryFinish() -> Bool {
        if completed {
            return false
        }
        completed = true
        return true
    }
}

private actor InteroperableQUICConnectionQueue {
    private var queue: [NetworkConnection<QUIC>] = []
    private var waiters: [CheckedContinuation<NetworkConnection<QUIC>, Error>] = []
    private var failure: Error?

    func enqueue(_ connection: NetworkConnection<QUIC>) {
        guard failure == nil else {
            return
        }
        if let continuation = waiters.first {
            waiters.removeFirst()
            continuation.resume(returning: connection)
        } else {
            queue.append(connection)
        }
    }

    func dequeue() async throws -> NetworkConnection<QUIC> {
        if let failure {
            throw failure
        }
        if let connection = queue.first {
            queue.removeFirst()
            return connection
        }
        return try await withCheckedThrowingContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func fail(_ error: Error) {
        failure = error
        let waiters = self.waiters
        self.waiters.removeAll()
        for waiter in waiters {
            waiter.resume(throwing: error)
        }
    }
}

private actor InteroperableQUICInboundStreamCollector {
    private var queued: [Int: [QUIC.Stream<QUICStream>]] = [:]
    private var waiting: [Int: [CheckedContinuation<QUIC.Stream<QUICStream>, Error>]] = [:]
    private var failure: Error?

    func enqueue(_ stream: QUIC.Stream<QUICStream>, direction: Int) {
        guard failure == nil else {
            return
        }
        if var continuations = waiting[direction], !continuations.isEmpty {
            let continuation = continuations.removeFirst()
            if continuations.isEmpty {
                waiting.removeValue(forKey: direction)
            } else {
                waiting[direction] = continuations
            }
            continuation.resume(returning: stream)
            return
        }
        queued[direction, default: []].append(stream)
    }

    func next(direction: Int, timeoutMilliseconds: Int32) async throws -> QUIC.Stream<QUICStream> {
        if let failure {
            throw failure
        }

        if var streams = queued[direction], let stream = streams.first {
            streams.removeFirst()
            if streams.isEmpty {
                queued.removeValue(forKey: direction)
            } else {
                queued[direction] = streams
            }
            return stream
        }

        return try await InteroperableQUICHelpers.withTimeout(timeoutMilliseconds) {
            try await self.waitFor(direction: direction)
        }
    }

    func fail(_ error: Error) {
        failure = error
        let waitingByDirection = waiting
        waiting.removeAll()
        for (_, waiters) in waitingByDirection {
            for waiter in waiters {
                waiter.resume(throwing: error)
            }
        }
    }

    private func waitFor(direction: Int) async throws -> QUIC.Stream<QUICStream> {
        return try await withCheckedThrowingContinuation { continuation in
            if let failure {
                continuation.resume(throwing: failure)
                return
            }
            waiting[direction, default: []].append(continuation)
        }
    }
}

private actor OneShotContinuation {
    private var resumed = false

    func complete(_ operation: () -> Void) async {
        guard !resumed else {
            return
        }
        resumed = true
        operation()
    }
}

private extension QUICFrame {
    var datagramPayload: Data {
        guard case .datagram(let payload) = self else {
            return Data()
        }
        return payload
    }
}

private struct InteroperableTLSIdentity {
    static func create() throws -> sec_identity_t {
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2_048,
            kSecAttrIsPermanent: false
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server key generation failed")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server public key extraction failed")
        }
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server public key export failed")
        }

        let certificateDER = try SelfSignedCertificate.make(
            privateKey: privateKey,
            rsaPublicKeyDER: publicKeyData
        )
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server certificate generation produced invalid DER")
        }
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server identity creation failed")
        }
        guard let networkIdentity = sec_identity_create_with_certificates(identity, [certificate] as CFArray) else {
            throw WebTransportNetworkRuntimeError.invalidTransport("server QUIC identity conversion failed")
        }
        return networkIdentity
    }
}

private enum SelfSignedCertificate {
    static func make(privateKey: SecKey, rsaPublicKeyDER: Data) throws -> Data {
        let signatureAlgorithm = DER.sequence([
            try DER.objectIdentifier([1, 2, 840, 113_549, 1, 1, 11]),
            DER.null()
        ])
        let rsaAlgorithm = DER.sequence([
            try DER.objectIdentifier([1, 2, 840, 113_549, 1, 1, 1]),
            DER.null()
        ])
        let name = DER.sequence([
            DER.set([
                DER.sequence([
                    try DER.objectIdentifier([2, 5, 4, 3]),
                    DER.utf8String("localhost")
                ])
            ])
        ])
        let validity = DER.sequence([
            DER.utcTime(Date(timeIntervalSinceNow: -60)),
            DER.utcTime(Date(timeIntervalSinceNow: 86_400))
        ])
        let subjectPublicKeyInfo = DER.sequence([
            rsaAlgorithm,
            DER.bitString(rsaPublicKeyDER)
        ])
        let extensions = DER.explicit(3, DER.sequence([
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 19]),
                DER.boolean(true),
                DER.octetString(DER.sequence([DER.boolean(false)]))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 15]),
                DER.boolean(true),
                DER.octetString(DER.bitString(Data([0xa0]), unusedBits: 5))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 37]),
                DER.octetString(DER.sequence([
                    try DER.objectIdentifier([1, 3, 6, 1, 5, 5, 7, 3, 1])
                ]))
            ]),
            DER.sequence([
                try DER.objectIdentifier([2, 5, 29, 17]),
                DER.octetString(DER.sequence([
                    DER.contextSpecificPrimitive(2, Data("localhost".utf8))
                ]))
            ])
        ]))

        let tbsCertificate = DER.sequence([
            DER.explicit(0, DER.integer(Data([0x02]))),
            DER.integer(randomSerial()),
            signatureAlgorithm,
            name,
            validity,
            name,
            subjectPublicKeyInfo,
            extensions
        ])

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            tbsCertificate as CFData,
            &signError
        ) as Data? else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }

        return DER.sequence([
            tbsCertificate,
            signatureAlgorithm,
            DER.bitString(signature)
        ])
    }

    private static func randomSerial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            bytes = Array(UUID().uuidString.utf8.prefix(16))
        }
        bytes[0] &= 0x7f
        if bytes.allSatisfy({ $0 == 0 }) {
            bytes[0] = 1
        }
        return Data(bytes)
    }
}

private enum DER {
    static func sequence(_ parts: [Data]) -> Data {
        tagged(0x30, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ parts: [Data]) -> Data {
        tagged(0x31, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func explicit(_ tag: UInt8, _ content: Data) -> Data {
        tagged(0xa0 + tag, content)
    }

    static func contextSpecificPrimitive(_ tag: UInt8, _ value: Data) -> Data {
        tagged(0x80 + tag, value)
    }

    static func integer(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1 && bytes[0] == 0 && bytes[1] < 0x80 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first >= 0x80 {
            bytes.insert(0, at: 0)
        }
        return tagged(0x02, Data(bytes))
    }

    static func boolean(_ value: Bool) -> Data {
        tagged(0x01, Data([value ? 0xff : 0x00]))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        tagged(0x03, Data([unusedBits]) + value)
    }

    static func octetString(_ value: Data) -> Data {
        tagged(0x04, value)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func objectIdentifier(_ components: [UInt64]) throws -> Data {
        guard components.count >= 2 else {
            throw WebTransportNetworkRuntimeError.invalidProbePayload
        }
        let firstTwo = components[0] * 40 + components[1]
        var bytes = [UInt8(firstTwo)]
        for component in components.dropFirst(2) {
            var section = [UInt8(component & 0x7f)]
            var remaining = component >> 7
            while remaining > 0 {
                section.insert(UInt8(remaining & 0x7f) | 0x80, at: 0)
                remaining >>= 7
            }
            bytes.append(contentsOf: section)
        }
        return tagged(0x06, Data(bytes))
    }

    static func utf8String(_ value: String) -> Data {
        tagged(0x0c, Data(value.utf8))
    }

    static func utcTime(_ value: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return tagged(0x17, Data(formatter.string(from: value).utf8))
    }

    fileprivate static func tagged(_ tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + encodeLength(content.count) + content
    }

    private static func encodeLength(_ value: Int) -> Data {
        if value < 128 {
            return Data([UInt8(value)])
        }
        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}
