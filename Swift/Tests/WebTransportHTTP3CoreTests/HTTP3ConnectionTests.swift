import Foundation
import Testing
import WebTransportHTTP3Core
import WebTransportQUICCore

@Test
func http3ControlStreamsExchangeAndValidateSettings() throws {
    var client = HTTP3ConnectionState(role: .client)
    var server = HTTP3ConnectionState(role: .server)

    let clientFrames = try server.receivePeerControlStream(client.localControlStreamBytes())
    let serverFrames = try client.receivePeerControlStream(server.localControlStreamBytes())

    #expect(clientFrames.first?.type == HTTP3FrameType.settings)
    #expect(serverFrames.first?.type == HTTP3FrameType.settings)
    #expect(client.remoteSettings?.entries == HTTP3Settings.webTransportDraft15Defaults.entries)
    #expect(server.remoteSettings?.entries == HTTP3Settings.webTransportDraft15Defaults.entries)

    #expect(throws: Error.self) {
        _ = try server.receivePeerControlStream(client.localControlStreamBytes())
    }
}

@Test
func http3SettingsValidationRejectsMissingWebTransportRequirements() throws {
    var missingConnect = HTTP3Settings.webTransportDraft15Defaults
    try missingConnect.set(0, for: WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol)
    #expect(throws: Error.self) {
        try missingConnect.validateWebTransportDraft15Requirements()
    }

    let invalidControl = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: try HTTP3Settings([
            WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol: 1,
            WebTransportHTTP3DraftConstants.current.settingsH3Datagram: 1
        ]).frame().encode()
    )
    var server = HTTP3ConnectionState(role: .server)
    #expect(throws: Error.self) {
        _ = try server.receivePeerControlStream(invalidControl)
    }
}

@Test
func http3ZeroRTTSettingsCompatibilityRejectsReducedOrChangedWebTransportSettings() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var remembered = HTTP3Settings.webTransportDraft15Defaults
    try remembered.set(4, for: constants.settingsWTInitialMaxStreamsBidi)
    try remembered.set(8, for: constants.settingsWTInitialMaxData)

    var compatible = remembered
    try compatible.set(6, for: constants.settingsWTInitialMaxStreamsBidi)
    try compatible.set(16, for: constants.settingsWTInitialMaxData)
    try compatible.validateWebTransportZeroRTTCompatibility(remembered: remembered)

    var reduced = compatible
    try reduced.set(2, for: constants.settingsWTInitialMaxStreamsBidi)
    do {
        try reduced.validateWebTransportZeroRTTCompatibility(remembered: remembered)
        Issue.record("reduced remembered 0-RTT limit should throw")
    } catch let error as WebTransportDraft15Error {
        #expect(error.kind == .requirementsNotMet)
        #expect(error.code == constants.wtRequirementsNotMetError)
    }

    var changedDatagram = compatible
    try changedDatagram.set(0, for: constants.settingsH3Datagram)
    #expect(throws: Error.self) {
        try changedDatagram.validateWebTransportZeroRTTCompatibility(remembered: remembered)
    }
}

@Test
func http3ControlStreamCanValidateRememberedZeroRTTSettings() throws {
    let constants = WebTransportHTTP3DraftConstants.current
    var remembered = HTTP3Settings.webTransportDraft15Defaults
    try remembered.set(8, for: constants.settingsWTInitialMaxData)

    var current = HTTP3Settings.webTransportDraft15Defaults
    try current.set(1, for: constants.settingsWTInitialMaxData)
    let controlBytes = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: current.frame().encode()
    )

    var connection = HTTP3ConnectionState(role: .client)
    #expect(throws: WebTransportDraft15Error.self) {
        _ = try connection.receivePeerControlStream(controlBytes, zeroRTTRememberedSettings: remembered)
    }
    #expect(connection.remoteSettings == nil)
}

@Test
func http3ControlStreamRejectsRequestFramesAndProcessesGoaway() throws {
    var connection = HTTP3ConnectionState(role: .client)
    let goaway = try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 4)
    let controlBytes = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: try HTTP3Frame.encodeFrames([
            HTTP3Settings.webTransportDraft15Defaults.frame(),
            goaway
        ])
    )

    let frames = try connection.receivePeerControlStream(controlBytes)
    #expect(frames == [try HTTP3Settings.webTransportDraft15Defaults.frame(), goaway])
    #expect(connection.receivedGoawayID == 4)

    var badConnection = HTTP3ConnectionState(role: .client)
    let badControlBytes = try HTTP3StreamTypeParser.encodePrefix(
        type: HTTP3StreamType.control,
        payload: try HTTP3Frame.encodeFrames([
            HTTP3Settings.webTransportDraft15Defaults.frame(),
            try HTTP3Frame(type: HTTP3FrameType.headers)
        ])
    )
    #expect(throws: Error.self) {
        _ = try badConnection.receivePeerControlStream(badControlBytes)
    }
    #expect(!badConnection.receivedPeerControlStream)
    #expect(badConnection.remoteSettings == nil)
}

@Test
func http3RequestStreamLifecycleCarriesWebTransportConnectHeaders() throws {
    var clientConnection = HTTP3ConnectionState(role: .client)
    var serverConnection = HTTP3ConnectionState(role: .server)
    var clientStream = try clientConnection.openRequestStream(streamID: 0)
    var serverStream = try serverConnection.acceptRequestStream(streamID: 0)

    let requestHeaders = try WebTransportHTTP3Headers.connectRequest(
        authority: "example.com",
        path: "/wt",
        origin: "https://example.com"
    )
    let requestFrame = try clientStream.makeRequestHeadersFrame(requestHeaders)
    try serverStream.receive(frame: requestFrame)
    try serverStream.receive(frame: try HTTP3Frame(type: 0x40, payload: Data([0x01])))

    #expect(clientStream.state == .open)
    #expect(serverStream.requestHeaders == requestHeaders)
    #expect(serverStream.state == .open)

    let responseHeaders = try WebTransportHTTP3Headers.successfulResponse()
    let responseFrame = try serverStream.makeResponseHeadersFrame(responseHeaders)
    try clientStream.receive(frame: responseFrame)

    #expect(serverStream.state == .open)
    #expect(clientStream.responseHeaders == responseHeaders)
    #expect(clientStream.state == .open)

    clientConnection.storeRequestStream(clientStream)
    serverConnection.storeRequestStream(serverStream)
    #expect(clientConnection.requestStreams[0]?.state == .open)
    #expect(serverConnection.requestStreams[0]?.state == .open)
}

@Test
func http3RequestStreamsRejectInvalidIDsDuplicateHeadersAndDataByDefault() throws {
    var clientConnection = HTTP3ConnectionState(role: .client)
    #expect(throws: Error.self) {
        _ = try clientConnection.openRequestStream(streamID: 2)
    }

    var serverStream = HTTP3RequestStream(streamID: 0, role: .server)
    let requestFrame = try WebTransportHTTP3Headers.connectRequestHeadersFrame(authority: "example.com", path: "/wt")
    try serverStream.receive(frame: requestFrame)
    #expect(throws: Error.self) {
        try serverStream.receive(frame: requestFrame)
    }
    #expect(throws: Error.self) {
        try serverStream.receive(frame: try HTTP3Frame(type: HTTP3FrameType.data, payload: Data("nope".utf8)))
    }
}

@Test
func http3DataFramesCanBeBufferedWhenCallerAllowsThem() throws {
    var stream = HTTP3RequestStream(streamID: 0, role: .server)
    try stream.receive(frame: try WebTransportHTTP3Headers.connectRequestHeadersFrame(authority: "example.com", path: "/wt"))
    try stream.receive(
        frame: try HTTP3Frame(type: HTTP3FrameType.data, payload: Data("payload".utf8)),
        dataPolicy: .buffer
    )

    #expect(stream.dataChunks == [Data("payload".utf8)])
}

@Test
func http3GoawaySendAndApplicationErrorMapping() throws {
    var connection = HTTP3ConnectionState(role: .server)
    let goaway = try connection.makeGoawayFrame(streamID: 0)
    let expectedGoaway = try HTTP3Frame(type: HTTP3FrameType.goaway, varIntValue: 0)
    #expect(goaway == expectedGoaway)
    #expect(connection.sentGoawayID == 0)

    #expect(connection.closeFrame(
        error: .settingsError,
        reason: "bad settings",
        frameType: HTTP3FrameType.settings
    ) == .connectionClose(
        errorCode: HTTP3ApplicationErrorCode.settingsError.rawValue,
        frameType: HTTP3FrameType.settings,
        reason: Data("bad settings".utf8)
    ))
}
