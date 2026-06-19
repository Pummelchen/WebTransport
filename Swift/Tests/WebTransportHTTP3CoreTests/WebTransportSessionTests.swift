import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func webTransportClientBuildsExtendedConnectRequestAndMapsSession() throws {
    var pair = try makeReadyManagers()
    let request = try WebTransportSessionRequest(
        authority: "example.com",
        path: "/wt",
        origin: "https://example.com",
        availableProtocols: ["chat.v1", "chat.v2"]
    )

    let frame = try pair.client.makeClientSessionRequest(streamID: 0, request: request)
    let fields = try QPACK.decodeHeadersFrame(frame)

    try WebTransportHTTP3Headers.validateConnectRequest(fields)
    #expect(fields.contains(try HTTPFieldLine(name: ":protocol", value: "webtransport-h3")))
    #expect(fields.contains(try HTTPFieldLine(
        name: WebTransportHeaderName.availableProtocols,
        value: "\"chat.v1\", \"chat.v2\""
    )))
    #expect(pair.client.session(forRequestStreamID: 0)?.state == .requested)
    #expect(pair.client.session(forRequestStreamID: 0)?.availableProtocols == ["chat.v1", "chat.v2"])
    #expect(pair.client.sessionsByID[WebTransportSessionID(rawValue: 0)]?.path == "/wt")
}

@Test
func webTransportServerAcceptsSessionAndClientProcessesResponse() throws {
    var pair = try makeReadyManagers()
    let request = try WebTransportSessionRequest(
        authority: "example.com",
        path: "/wt",
        origin: "https://example.com",
        availableProtocols: ["chat.v1", "chat.v2"]
    )
    let requestFrame = try pair.client.makeClientSessionRequest(streamID: 0, request: request)
    let policy = try WebTransportServerSessionPolicy(
        allowedAuthorities: ["example.com"],
        allowedPaths: ["/wt"],
        allowedOrigins: ["https://example.com"],
        supportedProtocols: ["chat.v2"],
        requireProtocolSelection: true
    )

    let decision = try pair.server.receiveClientSessionRequest(streamID: 0, frame: requestFrame, policy: policy)
    #expect(decision.session.state == .accepted)
    #expect(decision.session.selectedProtocol == "chat.v2")
    #expect(pair.server.session(forRequestStreamID: 0) == decision.session)

    let clientSession = try pair.client.receiveServerSessionResponse(streamID: 0, frame: decision.responseFrame)
    #expect(clientSession.state == .accepted)
    #expect(clientSession.selectedProtocol == "chat.v2")
    #expect(pair.client.session(forRequestStreamID: 0) == clientSession)
}

@Test
func webTransportServerRejectsByPathOriginAndProtocolPolicy() throws {
    var pair = try makeReadyManagers()
    let badPathFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/missing")
    )
    let pathPolicy = try WebTransportServerSessionPolicy(allowedPaths: ["/wt"])
    let pathDecision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: badPathFrame,
        policy: pathPolicy
    )
    #expect(pathDecision.session.state == .rejected(status: 404))
    #expect(try WebTransportSessionTestSupport.responseStatus(pathDecision.responseFrame) == 404)

    pair = try makeReadyManagers()
    let badOriginFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt", origin: "https://bad.example")
    )
    let originPolicy = try WebTransportServerSessionPolicy(allowedOrigins: ["https://example.com"])
    let originDecision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: badOriginFrame,
        policy: originPolicy
    )
    #expect(originDecision.session.state == .rejected(status: 403))

    pair = try makeReadyManagers()
    let protocolFrame = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: ["chat.v1"]
        )
    )
    let protocolPolicy = try WebTransportServerSessionPolicy(
        supportedProtocols: ["chat.v2"],
        requireProtocolSelection: true
    )
    let protocolDecision = try pair.server.receiveClientSessionRequest(
        streamID: 0,
        frame: protocolFrame,
        policy: protocolPolicy
    )
    #expect(protocolDecision.session.state == .rejected(status: 400))
}

@Test
func webTransportClientProcessesRejectedResponse() throws {
    var pair = try makeReadyManagers()
    _ = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
    )

    let rejected = try pair.client.receiveServerSessionResponse(
        streamID: 0,
        frame: try WebTransportSessionTestSupport.responseFrame(status: 404)
    )
    #expect(rejected.state == .rejected(status: 404))
}

@Test
func webTransportClientRejectsUnadvertisedSelectedProtocol() throws {
    var pair = try makeReadyManagers()
    _ = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(
            authority: "example.com",
            path: "/wt",
            availableProtocols: ["chat.v1"]
        )
    )
    let badResponse = try QPACK.headersFrame(fields: [
        try HTTPFieldLine(name: ":status", value: "200"),
        try HTTPFieldLine(name: WebTransportHeaderName.selectedProtocol, value: "chat.v2")
    ])

    #expect(throws: Error.self) {
        _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: badResponse)
    }
}

@Test
func webTransportSessionHeadersRejectDuplicateNegotiationFields() throws {
    var pair = try makeReadyManagers()
    let duplicateAvailableProtocols = try QPACK.headersFrame(fields: [
        try HTTPFieldLine(name: ":method", value: "CONNECT"),
        try HTTPFieldLine(name: ":scheme", value: "https"),
        try HTTPFieldLine(name: ":authority", value: "example.com"),
        try HTTPFieldLine(name: ":path", value: "/wt"),
        try HTTPFieldLine(name: ":protocol", value: "webtransport-h3"),
        try HTTPFieldLine(name: WebTransportHeaderName.availableProtocols, value: "\"a\""),
        try HTTPFieldLine(name: WebTransportHeaderName.availableProtocols, value: "\"b\"")
    ])
    #expect(throws: Error.self) {
        _ = try pair.server.receiveClientSessionRequest(
            streamID: 0,
            frame: duplicateAvailableProtocols,
            policy: try WebTransportServerSessionPolicy()
        )
    }

    pair = try makeReadyManagers()
    _ = try pair.client.makeClientSessionRequest(
        streamID: 0,
        request: try WebTransportSessionRequest(authority: "example.com", path: "/wt", availableProtocols: ["a"])
    )
    let duplicateSelectedProtocol = try QPACK.headersFrame(fields: [
        try HTTPFieldLine(name: ":status", value: "200"),
        try HTTPFieldLine(name: WebTransportHeaderName.selectedProtocol, value: "a"),
        try HTTPFieldLine(name: WebTransportHeaderName.selectedProtocol, value: "b")
    ])
    #expect(throws: Error.self) {
        _ = try pair.client.receiveServerSessionResponse(streamID: 0, frame: duplicateSelectedProtocol)
    }
}

@Test
func webTransportSessionIDValidationRejectsNonRequestStreams() throws {
    #expect(try WebTransportSessionID.fromRequestStreamID(0).rawValue == 0)
    #expect(throws: Error.self) {
        _ = try WebTransportSessionID.fromRequestStreamID(1)
    }
    #expect(throws: Error.self) {
        _ = try WebTransportSessionID.fromRequestStreamID(2)
    }
}

@Test
func webTransportSessionEstablishmentRequiresValidatedSettings() throws {
    var client = WebTransportSessionManager(http3: HTTP3ConnectionState(role: .client))
    #expect(throws: Error.self) {
        _ = try client.makeClientSessionRequest(
            streamID: 0,
            request: try WebTransportSessionRequest(authority: "example.com", path: "/wt")
        )
    }

    var clientHTTP3 = HTTP3ConnectionState(role: .client)
    let invalidServerControl = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: try HTTP3Settings([
            WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol: 1,
            WebTransportHTTP3DraftConstants.current.settingsH3Datagram: 1
        ]).frame().encode()
    )
    #expect(throws: Error.self) {
        _ = try clientHTTP3.receivePeerControlStream(invalidServerControl)
    }
}

@Test
func webTransportProtocolNegotiationValidatesStructuredLists() throws {
    #expect(try WebTransportProtocolNegotiation.encodeList(["a", "b"]) == "\"a\", \"b\"")
    #expect(try WebTransportProtocolNegotiation.decodeList("\"a\", \"b\"") == ["a", "b"])
    #expect(WebTransportProtocolNegotiation.select(requested: ["a", "b"], supported: ["b"]) == "b")
    #expect(throws: Error.self) {
        _ = try WebTransportProtocolNegotiation.decodeList("a, b")
    }
    #expect(throws: Error.self) {
        _ = try WebTransportSessionRequest(authority: "example.com", path: "/wt", availableProtocols: ["bad,token"])
    }
}

private func makeReadyManagers() throws -> (client: WebTransportSessionManager, server: WebTransportSessionManager) {
    var clientHTTP3 = HTTP3ConnectionState(role: .client)
    var serverHTTP3 = HTTP3ConnectionState(role: .server)
    _ = try serverHTTP3.receivePeerControlStream(clientHTTP3.localControlStreamBytes())
    _ = try clientHTTP3.receivePeerControlStream(serverHTTP3.localControlStreamBytes())
    return (
        WebTransportSessionManager(http3: clientHTTP3),
        WebTransportSessionManager(http3: serverHTTP3)
    )
}

private enum WebTransportSessionTestSupport {
    static func responseFrame(status: UInt16) throws -> HTTP3Frame {
        try QPACK.headersFrame(fields: [
            try HTTPFieldLine(name: ":status", value: String(status))
        ])
    }

    static func responseStatus(_ frame: HTTP3Frame) throws -> UInt16 {
        let fields = try QPACK.decodeHeadersFrame(frame)
        guard let value = fields.first(where: { $0.name == ":status" })?.value,
              let status = UInt16(value) else {
            throw QUICCodecError.malformed("missing status")
        }
        return status
    }
}
