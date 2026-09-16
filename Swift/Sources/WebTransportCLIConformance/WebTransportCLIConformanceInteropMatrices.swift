import Foundation
import WebTransport
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore
import WebTransportUDPApple

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runConnectInteropMatrix() throws {
    var pair = try makeReadyPair()
    let request = try WebTransportSessionRequest(
        authority: "example.com",
        path: "/wt",
        origin: "https://example.com",
        availableProtocols: ["chat.v1", "chat.v2"]
    )
    let policy = try WebTransportServerSessionPolicy(
        allowedAuthorities: ["example.com"],
        allowedPaths: ["/wt"],
        allowedOrigins: ["https://example.com"],
        supportedProtocols: ["chat.v2"],
        requireProtocolSelection: true
    )
    let sessionID = try establishSession(pair: &pair, streamID: 0, request: request, policy: policy)
    try require(pair.client.session(forRequestStreamID: sessionID.rawValue)?.selectedProtocol == "chat.v2", "valid CONNECT selected protocol")
    try require(pair.server.session(forRequestStreamID: sessionID.rawValue)?.state == .accepted, "server accepted valid CONNECT")

    pair = try makeReadyPair()
    try expectThrows {
        _ = try pair.server.receiveClientSessionRequest(
            streamID: 0,
            frame: HTTP3Frame(type: HTTP3FrameType.data, payload: Data("data-before-headers".utf8)),
            policy: WebTransportServerSessionPolicy()
        )
    }

    pair = try makeReadyPair()
    let rejected = try rejectSession(
        pair: &pair,
        streamID: 0,
        request: WebTransportSessionRequest(authority: "example.com", path: "/wt", origin: "https://evil.example"),
        policy: WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
    )
    try require(rejected.session.state == .rejected(status: 403), "bad-origin CONNECT rejected")
    try require(rejected.rejectionError?.kind == .requirementsNotMet, "bad-origin CONNECT maps to requirements-not-met")

    pair = try makeReadyPair()
    _ = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: WebTransportSessionRequest(authority: "example.com", path: "/wt", availableProtocols: ["chat.v1"])
    )
    var invalidSelectedProtocolFields = try WebTransportHTTP3Headers.successfulResponse(status: 200)
    invalidSelectedProtocolFields.append(
        try HTTPFieldLine(
            name: WebTransportHeaderName.selectedProtocol,
            value: WebTransportProtocolNegotiation.encodeItem("chat.v2")
        ))
    let invalidSelectedProtocol = try QPACK.headersFrame(fields: invalidSelectedProtocolFields)
    try expectThrows {
        _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: invalidSelectedProtocol)
    }
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runStreamInteropMatrix() throws {
    var pair = try makeReadyPair()
    let sessionID = try establishDefaultSession(pair: &pair)
    let clientBidiPrefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: clientBidiPrefix + Data("client-bidi".utf8))
    try require(pair.server.popStreamPayload(streamID: 4) == Data("client-bidi".utf8), "client bidi stream delivered")

    let clientUniPrefix = try pair.client.openUnidirectionalStream(streamID: 2, sessionID: sessionID)
    _ = try pair.server.acceptUnidirectionalStream(streamID: 2, firstBytes: clientUniPrefix + Data("client-uni".utf8))
    try require(pair.server.popStreamPayload(streamID: 2) == Data("client-uni".utf8), "client uni stream delivered")

    let serverBidiPrefix = try pair.server.openBidirectionalStream(streamID: 1, sessionID: sessionID)
    _ = try pair.client.acceptBidirectionalStream(streamID: 1, firstBytes: serverBidiPrefix + Data("server-bidi".utf8))
    try require(pair.client.popStreamPayload(streamID: 1) == Data("server-bidi".utf8), "server bidi stream delivered")

    let serverUniPrefix = try pair.server.openUnidirectionalStream(streamID: 3, sessionID: sessionID)
    _ = try pair.client.acceptUnidirectionalStream(streamID: 3, firstBytes: serverUniPrefix + Data("server-uni".utf8))
    try require(pair.client.popStreamPayload(streamID: 3) == Data("server-uni".utf8), "server uni stream delivered")

    try expectThrows {
        _ = try pair.server.acceptBidirectionalStream(streamID: 1, firstBytes: clientBidiPrefix)
    }
    try expectThrows {
        _ = try pair.server.acceptUnidirectionalStream(streamID: 6, firstBytes: Data([0xff]))
    }
    try expectThrows {
        try pair.server.receiveStreamPayload(streamID: 99, payload: Data("orphan".utf8))
    }
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runDatagramInteropMatrix() throws {
    var pair = try makeReadyPair()
    let sessionID = try establishDefaultSession(pair: &pair)
    let clientDatagram = try pair.client.makeDatagramFrame(sessionID: sessionID, payload: Data("client-dgram".utf8))
    try require(try pair.server.receiveDatagramFrame(clientDatagram) == sessionID, "client datagram routed")
    try require(pair.server.popDatagramPayload(sessionID: sessionID) == Data("client-dgram".utf8), "client datagram payload delivered")

    let serverDatagram = try pair.server.makeDatagramFrame(sessionID: sessionID, payload: Data("server-dgram".utf8))
    try require(try pair.client.receiveDatagramFrame(serverDatagram) == sessionID, "server datagram routed")
    try require(pair.client.popDatagramPayload(sessionID: sessionID) == Data("server-dgram".utf8), "server datagram payload delivered")

    try expectThrows {
        _ = try pair.server.receiveDatagramFrame(.datagram(Data([0xff])))
    }
    var orphanPair = try makeReadyPair()
    try expectThrows {
        _ = try orphanPair.client.receiveDatagramFrame(
            .datagram(
                try WebTransportDatagramSignaling.serialize(sessionID: 0, payload: Data("unknown".utf8))
            ))
    }

    var smallFramePair = try makeReadyPair(maxDatagramFrameSize: 4)
    let smallSession = try establishDefaultSession(pair: &smallFramePair)
    try expectThrows {
        _ = try smallFramePair.client.makeDatagramFrame(sessionID: smallSession, payload: Data("too-large".utf8))
    }
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runGoawayCloseDrainInteropMatrix() throws {
    var pair = try WebTransportLibrarySmokePair.connectedWithFlowControl()
    let first = try pair.establishSession(streamID: 0, request: WebTransportSessionRequest(authority: "example.com", path: "/one"))
    let second = try pair.establishSession(streamID: 4, request: WebTransportSessionRequest(authority: "example.com", path: "/two"))
    try pair.client.manager.receiveControlFrame(try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 4))
    try require(pair.client.manager.sessionsByID[first]?.state == .draining, "GOAWAY drains first session")
    try require(pair.client.manager.sessionsByID[second]?.state == .draining, "GOAWAY drains second session")
    try expectThrows {
        _ = try pair.client.manager.makeClientSessionRequest(
            streamID: 8,
            request: WebTransportSessionRequest(authority: "example.com", path: "/late")
        )
    }

    var managerPair = ManagerPair(client: pair.client.manager, server: pair.server.manager)
    let drain = try managerPair.client.makeDrainSessionCapsule(sessionID: first)
    try require(try managerPair.server.receiveFlowControlCapsule(sessionID: first, bytes: drain) == .drainSession, "drain capsule received by peer")
    let serverStreamPrefix = try managerPair.server.openBidirectionalStream(streamID: 9, sessionID: first)
    _ = try managerPair.client.acceptBidirectionalStream(streamID: 9, firstBytes: serverStreamPrefix + Data("during-drain".utf8))
    try require(managerPair.client.popStreamPayload(streamID: 9) == Data("during-drain".utf8), "existing draining session still accepts stream work")

    let close = try managerPair.client.makeCloseSessionCapsule(sessionID: first, applicationErrorCode: 22, message: "interop done")
    let closeResult = try managerPair.server.receiveFlowControlCapsuleWithActions(sessionID: first, bytes: close)
    try require(closeResult.capsule == .closeSession(applicationErrorCode: 22, message: "interop done"), "close capsule received by peer")
    try require(managerPair.server.sessionsByID[first]?.state == .closed(applicationErrorCode: 22, message: "interop done"), "close marked peer session closed")
    try expectThrows {
        _ = try managerPair.server.makeDatagramFrame(sessionID: first, payload: Data("late".utf8))
    }
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runMalformedFlowInteropMatrix() throws {
    let clientHTTP3 = HTTP3ConnectionState(role: .client)
    var serverHTTP3 = HTTP3ConnectionState(role: .server)
    let clientControl = try clientHTTP3.localControlStreamBytes()
    _ = try serverHTTP3.receivePeerControlStream(clientControl)
    try expectThrows {
        _ = try serverHTTP3.receivePeerControlStream(clientControl)
    }
    try expectThrows {
        try serverHTTP3.receiveControlFrame(try QPACK.headersFrame(fields: [HTTPFieldLine(name: ":status", value: "200")]))
    }

    var requestStream = HTTP3RequestStream(streamID: 0, role: .server)
    try expectThrows {
        try requestStream.receive(frame: HTTP3Frame(type: HTTP3FrameType.data, payload: Data("before headers".utf8)))
    }
    try expectThrows {
        _ = try QPACK.decodeFieldSection(Data([0x01, 0x00]))
    }
    try expectThrows {
        _ = try WebTransportFlowCapsuleCodec.parse(Data([0xff]))
    }

    let constants = WebTransportHTTP3DraftConstants.current
    var clientSettings = HTTP3Settings.webTransportDraft16Defaults
    var serverSettings = HTTP3Settings.webTransportDraft16Defaults
    try clientSettings.set(4, for: constants.settingsWTInitialMaxData)
    try serverSettings.set(4, for: constants.settingsWTInitialMaxData)
    try clientSettings.set(1, for: constants.settingsWTInitialMaxStreamsBidi)
    try serverSettings.set(1, for: constants.settingsWTInitialMaxStreamsBidi)
    var pair = try makeReadyPair(clientSettings: clientSettings, serverSettings: serverSettings)
    let sessionID = try establishDefaultSession(pair: &pair)
    let prefix = try pair.client.openBidirectionalStream(streamID: 4, sessionID: sessionID)
    _ = try pair.server.acceptBidirectionalStream(streamID: 4, firstBytes: prefix)
    try pair.server.receiveStreamPayload(streamID: 4, payload: Data("1234".utf8))
    try require(pair.server.receiveFlowState(for: sessionID)?.usedData == 4, "flow-control positive limit reached")
    try expectThrows {
        try pair.server.receiveStreamPayload(streamID: 4, payload: Data("5".utf8))
    }
    try require(
        pair.server.sessionsByID[sessionID]?.state
            == .closed(
                applicationErrorCode: UInt32(constants.wtFlowControlError),
                message: "WebTransport flow-control violation"
            ), "flow-control violation closed session")
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runClientServerAPIDemo() async throws {
    let message = "hello from WebTransportClient"
    let (connected, serverResult) = try await runClientServerAPIDemoAttempt(message: message)
    guard connected.sessionEstablished,
        serverResult.sessionEstablished,
        connected.message == message,
        serverResult.message == message
    else {
        throw QUICCodecError.malformed("WebTransport network API did not complete echo session")
    }
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func runClientServerAPIDemoAttempt(
    message: String
) async throws -> (WebTransportConnectionResult, WebTransportConnectionResult) {
    var lastError: Error?
    for _ in 0..<3 {
        do {
            let server = WebTransportServer(
                configuration: WebTransportServerConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    supportedProtocols: ["demo.v1"],
                    timeoutMilliseconds: 12_000
                ))
            let client = WebTransportClient(
                configuration: WebTransportClientConfiguration(
                    authority: "localhost",
                    path: "/wt",
                    origin: "https://localhost",
                    availableProtocols: ["demo.v1"],
                    trustPolicy: .localDevelopmentSelfSigned,
                    timeoutMilliseconds: 12_000
                ))
            let listener = try await server.listen(on: WebTransportEndpoint(host: "127.0.0.1", port: 0))
            async let served = listener.serveOne()
            let connected = try await client.echo(to: listener.localEndpoint, message: message)
            let serverResult = try await served
            return (connected, serverResult)
        } catch {
            lastError = error
            try await Task.sleep(for: .milliseconds(100))
        }
    }
    throw lastError ?? QUICCodecError.malformed("WebTransport network API demo failed")
}

// internal because the scenario catalogue in WebTransportCLIConformanceScenarios.swift calls it
internal func expectThrows(_ operation: () throws -> Void) throws {
    do {
        try operation()
    } catch {
        return
    }
    throw QUICCodecError.malformed("expected operation to throw")
}
