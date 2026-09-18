import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTestSupport
import WebTransportUDPApple

struct LibrarySmokeRunner {
    enum Error: Swift.Error, CustomStringConvertible {
        case syntax(String)
        case runtime(String)
        case transport(String)

        var description: String {
            switch self {
            case .syntax(let message):
                return "syntax error: \(message)"
            case .runtime(let message):
                return "runtime error: \(message)"
            case .transport(let message):
                return "transport error: \(message)"
            }
        }
    }

    struct Config {
        var host = "127.0.0.1"
        var port: UInt16 = 45500
        var iterations = 4
        var maxDatagramFrameSize = 1_200
        var maxDatagramReceiveBufferBytes = 64 * 1024
        var runSuite = true
    }

    let config: Config
    let client: QUICUDPPort
    let serverEndpoint: QUICUDPEndpoint
    var manager: WebTransportSessionManager
    var nextClientRequestStreamIndex: UInt64 = 0
    var nextClientBidiStreamIndex: UInt64 = 1
    var nextClientUniStreamIndex: UInt64 = 0
    var nextServerBidiStreamIndex: UInt64 = 0
    var nextServerUniStreamIndex: UInt64 = 1

    init(config: Config) throws {
        self.config = config
        self.client = try QUICUDPPort()
        self.serverEndpoint = QUICUDPEndpoint(host: config.host, port: config.port)
        self.manager = WebTransportSessionManager(
            http3: HTTP3ConnectionState(role: .client),
            maxDatagramFrameSize: config.maxDatagramFrameSize,
            maxDatagramReceiveBufferBytes: config.maxDatagramReceiveBufferBytes
        )
        print("LibrarySmokeClient local port: \(client.localEndpoint.port)")
        print("LibrarySmokeClient running in \(config.runSuite ? "suite" : "quick") mode")
    }

    mutating func run() throws {
        let scenarioID: Phase11Scenario = .echoStreams

        try send(Phase11Envelope(scenario: scenarioID, kind: .hello))
        _ = try receive(expect: .helloAck)

        let localControl = try manager.http3.localControlStreamBytes()
        try send(
            Phase11Envelope(
                scenario: scenarioID,
                kind: .control,
                payload: localControl
            )
        )
        let controlAck = try receive(expect: .controlAck)
        guard let peerControl = controlAck.payload else {
            throw Error.transport("missing control response payload")
        }
        _ = try manager.receivePeerControlStream(peerControl)

        if config.runSuite {
            try runSuite()
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .result,
                    success: true,
                    message: "suite complete"
                )
            )
        } else {
            try runQuick()
            try send(
                Phase11Envelope(
                    scenario: scenarioID,
                    kind: .result,
                    success: true,
                    message: "checks complete"
                )
            )
        }

        _ = try receive(expect: .result)
    }

    mutating func runQuick() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let streamID = nextBidirectionalStreamID()

        let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: prefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        let outbound = Phase11Payload.utf8("stream-hello")
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamData,
                streamID: streamID,
                payload: outbound
            )
        )
        let echoed = try receive(expect: .streamEcho)
        guard echoed.payload == outbound else {
            throw Error.runtime("stream echo payload mismatch")
        }

        try runEchoDatagrams(session: session, scenario: .echoDatagrams)
        print("client: quick smoke checks passed")
    }
}

extension LibrarySmokeRunner {
    mutating func runSessionRequest(
        requestFrame: HTTP3Frame,
        requestStreamID: UInt64,
        scenario: Phase11Scenario,
        expectedAccepted: Bool
    ) throws -> Phase11Envelope {
        try send(
            Phase11Envelope(
                scenario: scenario,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            )
        )

        let response = try receive(expect: .sessionResponse)
        guard let payload = response.payload else {
            throw Error.runtime("missing session response payload")
        }
        let responseFrame = try Phase11FramePacket.decodeHTTP3Frame(payload)
        _ = try manager.receiveServerSessionResponse(streamID: requestStreamID, frame: responseFrame)
        print("client: manager has session? \(manager.session(forRequestStreamID: requestStreamID) != nil)")

        if expectedAccepted && response.status != nil {
            throw Error.runtime("session rejected unexpectedly with status \(String(describing: response.status))")
        }
        if !expectedAccepted && response.status == nil {
            throw Error.runtime("session accepted unexpectedly")
        }
        return response
    }

    mutating func send(_ envelope: Phase11Envelope) throws {
        let encoded = try Phase11Protocol.encode(envelope)
        try client.send(encoded, to: serverEndpoint)
    }

    mutating func receive(expect expected: Phase11MessageKind? = nil) throws -> Phase11Envelope {
        let (bytes, _) = try client.receive(timeoutMilliseconds: 10_000)
        let envelope = try Phase11Protocol.decode(bytes)
        if let expected,
            envelope.kind != expected
        {
            throw Error.transport("expected \(expected) got \(envelope.kind)")
        }
        return envelope
    }

    mutating func nextRequestStreamID() -> UInt64 {
        let streamID = nextClientRequestStreamIndex
        nextClientRequestStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .client)
    }

    mutating func nextServerBidiStreamID() -> UInt64 {
        let streamID = nextServerBidiStreamIndex
        nextServerBidiStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .server)
    }

    mutating func nextServerUniStreamID() -> UInt64 {
        let streamID = nextServerUniStreamIndex
        nextServerUniStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .unidirectional, initiator: .server)
    }

    mutating func nextBidirectionalStreamID() -> UInt64 {
        let streamID = nextClientBidiStreamIndex
        nextClientBidiStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .bidirectional, initiator: .client)
    }

    mutating func nextUnidirectionalStreamID() -> UInt64 {
        let streamID = nextClientUniStreamIndex
        nextClientUniStreamIndex += 2
        return QUICStreamID.make(index: streamID, direction: .unidirectional, initiator: .client)
    }
}

extension LibrarySmokeRunner {
    mutating func runSuite() throws {
        let suiteStart = Date()
        print("client: starting smoke suite")

        try Self.runStep("echo streams (multi-stream)") { try runEchoStreamsScenario() }
        try Self.runStep("control stream reuse") { try runControlStreamReuseScenario() }
        try Self.runStep("datagram burst") { try runEchoDatagramBurst() }
        try Self.runStep(
            "datagram ordering and buffer boundary",
            succeeded: "datagram ordering",
            failed: "datagram ordering"
        ) { try runDatagramOrderingScenario() }
        try Self.runStep("interleaved stream flow") { try runInterleavedStreamScenario() }
        try Self.runStep("concurrent sessions") { try runConcurrentSessionsScenario() }
        try Self.runStep("protocol negotiation") { try runProtocolNegotiationScenario() }
        try Self.runStep("flow-control capsules") { try runFlowControlCapsuleScenario() }
        try Self.runStep("stream identity + duplicate open") { try runStreamIdentityAndDuplicateOpenScenario() }
        try Self.runStep("malformed stream open") { try runMalformedStreamScenario() }
        try Self.runStep("datagram/session integrity") { try runDatagramIntegrityScenario() }
        try Self.runStep("malformed datagram frame") { try runMalformedDatagramScenario() }
        try Self.runStep("duplicate session request") { try runDuplicateSessionRequestScenario() }
        try Self.runStep("malformed session request") { try runMalformedSessionRequestScenario() }
        try Self.runStep("close/reset path") { try runCloseAndResetScenario() }
        try Self.runStep("session rejection") { try runRejectedSessionScenario() }
        try Self.runStep("oversized datagram rejection") { try runOversizedDatagramScenario() }
        try Self.runStep("malformed stream open", succeeded: "malformed frame path", failed: "malformed frame") { try runMalformedFrameScenario() }

        let elapsed = Date().timeIntervalSince(suiteStart)
        print("client: full suite checks passed in \(formatDuration(elapsed))s")
    }

    /// Runs one suite step, reporting its duration and naming it in any failure.
    ///
    /// The running, success and failure labels are separate because two steps genuinely
    /// differ: "datagram ordering and buffer boundary" reports as "datagram ordering", and the
    /// malformed-frame step is announced as "malformed stream open" but reported as
    /// "malformed frame path". Collapsing them would have changed this tool's output.
    private static func runStep(
        _ running: String,
        succeeded: String? = nil,
        failed: String? = nil,
        _ body: () throws -> Void
    ) throws {
        let start = Date()
        print("client: running \(running)")
        do {
            try body()
            print("client: ✓ \(succeeded ?? running) in \(formatDuration(Date().timeIntervalSince(start)))s")
        } catch {
            throw Error.runtime("suite step \(failed ?? running) failed: \(error)")
        }
    }

    mutating func establishAcceptedSession(
        authority: String,
        path: String,
        includeOrigin: Bool = false,
        availableProtocols: [String] = ["wt-echo"],
        requestStreamID: UInt64
    ) throws -> WebTransportSession {
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: authority,
            path: path,
            includeOrigin: includeOrigin,
            availableProtocols: availableProtocols
        )
        _ = try runSessionRequest(
            requestFrame: requestFrame,
            requestStreamID: requestStreamID,
            scenario: .echoStreams,
            expectedAccepted: true
        )

        guard let session = manager.session(forRequestStreamID: requestStreamID) else {
            throw Error.runtime("client session missing after request")
        }
        print("client: established session id \(session.id.rawValue) on request stream \(requestStreamID)")
        return session
    }

    mutating func establishRejectedSession() throws {
        let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
        let requestStreamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: request.authority,
            path: request.path
        )
        let encoded = try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
        try send(
            Phase11Envelope(
                scenario: .rejectedSession,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: encoded
            )
        )
        let response = try receive(expect: .sessionResponse)
        _ = try Phase11FramePacket.decodeHTTP3Frame(response.payload ?? Data())
        _ = response.status
    }

    mutating func makeSessionRequestFrame(
        requestStreamID: UInt64,
        authority: String,
        path: String,
        includeOrigin: Bool = false,
        availableProtocols: [String] = ["wt-echo"]
    ) throws -> HTTP3Frame {
        let request = try WebTransportSessionRequest(
            authority: authority,
            path: path,
            origin: includeOrigin ? "https://\(authority)" : nil,
            availableProtocols: availableProtocols
        )
        return try manager.makeClientSessionRequest(streamID: requestStreamID, request: request)
    }
}
