import Foundation
import WebTransportQUICCore

public enum WebTransportLibrarySmokeScenario: String, CaseIterable, Sendable {
    case closeDrain = "close-drain"
    case rejection = "rejection"
    case backpressure = "backpressure"
    case ordering = "ordering"
    case multiSession = "multi-session"
}

public struct WebTransportLibrarySmokeResult: Equatable, Sendable {
    public var scenario: WebTransportLibrarySmokeScenario
    public var passed: Bool
    public var detail: String

    public init(scenario: WebTransportLibrarySmokeScenario, passed: Bool, detail: String) {
        self.scenario = scenario
        self.passed = passed
        self.detail = detail
    }
}

public struct LibrarySmokeClient: Equatable, Sendable {
    public var manager: WebTransportSessionManager

    public init(manager: WebTransportSessionManager) {
        self.manager = manager
    }
}

public struct LibrarySmokeServer: Equatable, Sendable {
    public var manager: WebTransportSessionManager

    public init(manager: WebTransportSessionManager) {
        self.manager = manager
    }
}

public struct WebTransportLibrarySmokePair: Equatable, Sendable {
    public var client: LibrarySmokeClient
    public var server: LibrarySmokeServer

    public init(client: LibrarySmokeClient, server: LibrarySmokeServer) {
        self.client = client
        self.server = server
    }

    public static func connected(
        maxStreamReceiveBufferBytes: Int = 64 * 1024,
        maxDatagramFrameSize: Int = 1_200,
        maxDatagramReceiveBufferBytes: Int = 64 * 1024,
        maxBufferedStreamsPerSession: Int = 64,
        maxBufferedDatagramsPerSession: Int = 64,
        maxBufferedSessions: Int = 64
    ) throws -> WebTransportLibrarySmokePair {
        var clientHTTP3 = HTTP3ConnectionState(role: .client)
        var serverHTTP3 = HTTP3ConnectionState(role: .server)
        _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
        _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
        return WebTransportLibrarySmokePair(
            client: LibrarySmokeClient(manager: WebTransportSessionManager(
                http3: clientHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramFrameSize: maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
                maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
                maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
                maxBufferedSessions: maxBufferedSessions
            )),
            server: LibrarySmokeServer(manager: WebTransportSessionManager(
                http3: serverHTTP3,
                maxStreamReceiveBufferBytes: maxStreamReceiveBufferBytes,
                maxDatagramFrameSize: maxDatagramFrameSize,
                maxDatagramReceiveBufferBytes: maxDatagramReceiveBufferBytes,
                maxBufferedStreamsPerSession: maxBufferedStreamsPerSession,
                maxBufferedDatagramsPerSession: maxBufferedDatagramsPerSession,
                maxBufferedSessions: maxBufferedSessions
            ))
        )
    }

    @discardableResult
    public mutating func establishSession(
        streamID: UInt64,
        request: WebTransportSessionRequest
    ) throws -> WebTransportSessionID {
        try establishSession(
            streamID: streamID,
            request: request,
            policy: WebTransportServerSessionPolicy()
        )
    }

    @discardableResult
    public mutating func establishSession(
        streamID: UInt64,
        request: WebTransportSessionRequest,
        policy: WebTransportServerSessionPolicy
    ) throws -> WebTransportSessionID {
        let requestFrame = try client.manager.makeClientSessionRequest(streamID: streamID, request: request)
        let decision = try server.manager.receiveClientSessionRequest(
            streamID: streamID,
            frame: requestFrame,
            policy: policy
        )
        let clientSession = try client.manager.receiveServerSessionResponse(
            streamID: streamID,
            frame: decision.responseFrame
        )
        try require(decision.session.state == .accepted, "server accepted session \(streamID)")
        try require(clientSession.state == .accepted, "client accepted session \(streamID)")
        try require(clientSession.id == decision.session.id, "client/server session IDs match")
        return clientSession.id
    }

    @discardableResult
    public mutating func rejectSession(
        streamID: UInt64,
        request: WebTransportSessionRequest,
        policy: WebTransportServerSessionPolicy
    ) throws -> WebTransportServerSessionDecision {
        let requestFrame = try client.manager.makeClientSessionRequest(streamID: streamID, request: request)
        let decision = try server.manager.receiveClientSessionRequest(
            streamID: streamID,
            frame: requestFrame,
            policy: policy
        )
        _ = try client.manager.receiveServerSessionResponse(streamID: streamID, frame: decision.responseFrame)
        try require(decision.session.state != .accepted, "server rejected session \(streamID)")
        return decision
    }
}

public enum WebTransportLibrarySmokeMatrix {
    public static func runAll() -> [WebTransportLibrarySmokeResult] {
        WebTransportLibrarySmokeScenario.allCases.map { scenario in
            do {
                try run(scenario)
                return WebTransportLibrarySmokeResult(scenario: scenario, passed: true, detail: "passed")
            } catch {
                return WebTransportLibrarySmokeResult(
                    scenario: scenario,
                    passed: false,
                    detail: String(describing: error)
                )
            }
        }
    }

    public static func run(_ scenario: WebTransportLibrarySmokeScenario) throws {
        switch scenario {
        case .closeDrain:
            try runCloseDrain()
        case .rejection:
            try runRejection()
        case .backpressure:
            try runBackpressure()
        case .ordering:
            try runOrdering()
        case .multiSession:
            try runMultiSession()
        }
    }

    private static func runCloseDrain() throws {
        var pair = try WebTransportLibrarySmokePair.connected()
        let sessionID = try pair.establishSession(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
        let prefix = try pair.client.manager.openBidirectionalStream(streamID: 4, sessionID: sessionID)
        _ = try pair.server.manager.acceptBidirectionalStream(
            streamID: 4,
            firstBytes: prefix + Data("hello".utf8)
        )

        let drain = try pair.client.manager.makeDrainSessionCapsule(sessionID: sessionID)
        let drainCapsule = try pair.server.manager.receiveFlowControlCapsule(sessionID: sessionID, bytes: drain)
        try require(drainCapsule == .drainSession, "server received WT_DRAIN_SESSION")
        try require(
            pair.server.manager.sessionsByID[sessionID]?.state == .draining,
            "server marked session draining"
        )

        let close = try pair.client.manager.makeCloseSessionCapsule(
            sessionID: sessionID,
            applicationErrorCode: 42,
            message: "done"
        )
        let closeResult = try pair.server.manager.receiveFlowControlCapsuleWithActions(
            sessionID: sessionID,
            bytes: close
        )
        try require(closeResult.capsule == .closeSession(applicationErrorCode: 42, message: "done"), "server received WT_CLOSE_SESSION")
        try require(closeResult.terminationActions?.streamResetFrames.count == 1, "close reset active stream")
        try require(pair.server.manager.stream(for: 4) == nil, "close cleaned active stream")
    }

    private static func runRejection() throws {
        var pair = try WebTransportLibrarySmokePair.connected()
        let decision = try pair.rejectSession(
            streamID: 0,
            request: try WebTransportSessionRequest(
                authority: "example.com",
                path: "/wt",
                origin: "https://blocked.example"
            ),
            policy: try WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
        )
        try require(decision.session.state == .rejected(status: 403), "server rejected bad origin")
        try require(decision.rejectionError?.kind == .requirementsNotMet, "rejection carries requirements error")
        let clientState = pair.client.manager.session(forRequestStreamID: 0)?.state
        try require(clientState == .rejected(status: 403), "client stored rejected session")
    }

    private static func runBackpressure() throws {
        var pair = try WebTransportLibrarySmokePair.connected(maxStreamReceiveBufferBytes: 4)
        let sessionID = try pair.establishSession(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
        let prefix = try pair.client.manager.openBidirectionalStream(streamID: 4, sessionID: sessionID)
        _ = try pair.server.manager.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)

        try pair.server.manager.receiveStreamPayload(streamID: 4, payload: Data([0x01, 0x02]))
        try pair.server.manager.receiveStreamPayload(streamID: 4, payload: Data([0x03, 0x04]))
        do {
            try pair.server.manager.receiveStreamPayload(streamID: 4, payload: Data([0x05]))
        } catch let error as QUICCodecError where error == .malformed("WebTransport stream receive buffer limit exceeded") {
            return
        }
        throw QUICCodecError.malformed("stream backpressure did not reject overflow payload")
    }

    private static func runOrdering() throws {
        var pair = try WebTransportLibrarySmokePair.connected()
        let earlyDatagram = try WebTransportDatagramSignaling.serialize(
            sessionID: 0,
            payload: Data("early".utf8)
        )
        _ = try pair.server.manager.receiveDatagramFrame(.datagram(earlyDatagram))
        let earlyStream = try WebTransportStreamSignaling.serializePrefix(
            form: .bidirectional,
            sessionID: 0
        ) + Data("early-stream".utf8)
        _ = try pair.server.manager.acceptBidirectionalStream(streamID: 4, firstBytes: earlyStream)

        let sessionID = try pair.establishSession(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
        try require(pair.server.manager.popDatagramPayload(sessionID: sessionID) == Data("early".utf8), "early datagram promoted")
        try require(pair.server.manager.popStreamPayload(streamID: 4) == Data("early-stream".utf8), "early stream payload promoted")
    }

    private static func runMultiSession() throws {
        var pair = try WebTransportLibrarySmokePair.connected()
        let first = try pair.establishSession(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/one")
        )
        let second = try pair.establishSession(
            streamID: 4,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/two")
        )
        try require(first != second, "multi-session IDs are distinct")

        let firstDatagram = try pair.client.manager.makeDatagramFrame(
            sessionID: first,
            payload: Data("one".utf8)
        )
        let secondDatagram = try pair.client.manager.makeDatagramFrame(
            sessionID: second,
            payload: Data("two".utf8)
        )
        _ = try pair.server.manager.receiveDatagramFrame(firstDatagram)
        _ = try pair.server.manager.receiveDatagramFrame(secondDatagram)
        try require(pair.server.manager.popDatagramPayload(sessionID: first) == Data("one".utf8), "first session datagram routed")
        try require(pair.server.manager.popDatagramPayload(sessionID: second) == Data("two".utf8), "second session datagram routed")

        let close = try pair.client.manager.makeCloseSessionCapsule(
            sessionID: first,
            applicationErrorCode: 7,
            message: "first done"
        )
        _ = try pair.server.manager.receiveFlowControlCapsuleWithActions(sessionID: first, bytes: close)
        try require(pair.server.manager.sessionsByID[first]?.state == .closed(applicationErrorCode: 7, message: "first done"), "first session closed")
        try require(pair.server.manager.sessionsByID[second]?.state == .accepted, "second session remains accepted")
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        guard condition else {
            throw QUICCodecError.malformed("library smoke failed: \(message)")
        }
    }
}

private func require(_ condition: Bool, _ message: String) throws {
    guard condition else {
        throw QUICCodecError.malformed("library smoke failed: \(message)")
    }
}
