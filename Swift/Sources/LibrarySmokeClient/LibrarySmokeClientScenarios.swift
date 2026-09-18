import Foundation
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTestSupport
import WebTransportUDPApple

extension LibrarySmokeRunner {
    mutating func runMalformedDatagramScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        try send(
            Phase11Envelope(
                scenario: .oversizedDatagram,
                kind: .datagram,
                sessionID: session.id.rawValue,
                payload: Data([0x00, 0x01, 0x02, 0x03])
            )
        )
        _ = try receive(expect: .error)
        print("client: malformed datagram scenario passed")
    }

    mutating func runControlStreamReuseScenario() throws {
        let localControl = try manager.http3.localControlStreamBytes()
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .control,
                payload: localControl
            )
        )
        let response = try receive(expect: .error)
        if response.kind != .error {
            throw Error.runtime("control stream duplicate should be rejected")
        }
        print("client: control stream reuse scenario passed")
    }

    mutating func runDatagramOrderingScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let count = max(2, min(config.iterations, 12))
        for index in 0..<count {
            let payload = Phase11Payload.utf8("ordered-\(index)")
            let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
            try send(
                Phase11Envelope(
                    scenario: .echoDatagrams,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(frame)
                )
            )
            let echoed = try receive(expect: .datagramEcho)
            guard echoed.payload == payload else {
                throw Error.runtime("datagram ordering failed at index \(index)")
            }
        }
        print("client: datagram ordering scenario passed")
    }

    mutating func runInterleavedStreamScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let streamCount = max(2, min(config.iterations, 4))
        let opened = try openInterleavedStreams(session: session, streamCount: streamCount)
        let bidirectionalStreams = opened.bidirectional
        let unidirectionalStreams = opened.unidirectional

        try sendInterleavedPayloads(
            bidirectionalStreams: bidirectionalStreams,
            unidirectionalStreams: unidirectionalStreams
        )

        var expectedPayloads: [UInt64: Set<String>] = [:]
        var observedPayloads: [UInt64: Set<String>] = [:]
        for index in 0..<streamCount {
            expectedPayloads[bidirectionalStreams[index], default: Set<String>()].insert("bidi-\(index)")
            expectedPayloads[unidirectionalStreams[index], default: Set<String>()].insert("uni-\(index)")
        }

        for _ in 0..<(streamCount * 2) {
            let response = try receive(expect: .streamEcho)
            guard let streamID = response.streamID, let payload = response.payload,
                let text = String(data: payload, encoding: .utf8)
            else {
                throw Error.runtime("interleaved stream response missing stream/payload")
            }
            observedPayloads[streamID, default: Set<String>()].insert(text)
        }

        try verifyEchoes(
            expected: expectedPayloads,
            observed: observedPayloads,
            streams: bidirectionalStreams,
            label: "bidi"
        )
        try verifyEchoes(
            expected: expectedPayloads,
            observed: observedPayloads,
            streams: unidirectionalStreams,
            label: "uni"
        )

        print("client: interleaved stream scenario passed")
    }

    /// Opens `streamCount` bidirectional and as many unidirectional streams, and waits for
    /// each to be acknowledged before opening the next.
    private mutating func openInterleavedStreams(
        session: WebTransportSession,
        streamCount: Int
    ) throws -> (bidirectional: [UInt64], unidirectional: [UInt64]) {
        var bidirectionalStreams: [UInt64] = []
        var unidirectionalStreams: [UInt64] = []
        for _ in 0..<streamCount {
            let bidiID = nextBidirectionalStreamID()
            let bidiPrefix = try manager.openBidirectionalStream(streamID: bidiID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamOpen,
                    streamID: bidiID,
                    streamKind: .bidirectional,
                    payload: bidiPrefix
                )
            )
            _ = try receive(expect: .streamOpenAck)
            bidirectionalStreams.append(bidiID)

            let uniID = nextUnidirectionalStreamID()
            let uniPrefix = try manager.openUnidirectionalStream(streamID: uniID, sessionID: session.id)
            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamOpen,
                    streamID: uniID,
                    streamKind: .unidirectional,
                    payload: uniPrefix
                )
            )
            _ = try receive(expect: .streamOpenAck)
            unidirectionalStreams.append(uniID)
        }
        return (bidirectionalStreams, unidirectionalStreams)
    }

    /// Sends one payload per stream, alternating directions so the echoes interleave.
    private mutating func sendInterleavedPayloads(
        bidirectionalStreams: [UInt64],
        unidirectionalStreams: [UInt64]
    ) throws {
        for index in 0..<bidirectionalStreams.count {
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: bidirectionalStreams[index],
                    payload: Phase11Payload.utf8("bidi-\(index)")
                )
            )
            try send(
                Phase11Envelope(
                    scenario: .closeAndReset,
                    kind: .streamData,
                    streamID: unidirectionalStreams[index],
                    payload: Phase11Payload.utf8("uni-\(index)")
                )
            )
        }
    }

    /// Every stream's expected payload set must equal what came back, or the interleaving is
    /// not deterministic.
    private func verifyEchoes(
        expected: [UInt64: Set<String>],
        observed: [UInt64: Set<String>],
        streams: [UInt64],
        label: String
    ) throws {
        for (index, streamID) in streams.enumerated() {
            let expectedForStream = expected[streamID] ?? []
            let observedForStream = observed[streamID] ?? []
            if expectedForStream != observedForStream {
                throw Error.runtime("\(label) interleaved echo mismatch at index \(index)")
            }
        }
    }

    mutating func runStreamIdentityAndDuplicateOpenScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let truncatedPrefix = try WebTransportStreamSignaling.serializePrefix(
            form: .unidirectional,
            sessionID: session.id.rawValue
        ).prefix(1)
        let streamID = nextBidirectionalStreamID()
        try send(
            Phase11Envelope(
                scenario: .malformedFrame,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: Data(truncatedPrefix)
            )
        )
        let mismatch = try receive()
        if mismatch.kind != .error {
            throw Error.runtime("malformed stream prefix should be rejected")
        }

        let validStreamID = nextBidirectionalStreamID()
        let validPrefix = try manager.openBidirectionalStream(streamID: validStreamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: validStreamID,
                streamKind: .bidirectional,
                payload: validPrefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: validStreamID,
                streamKind: .bidirectional,
                payload: validPrefix
            )
        )
        let duplicate = try receive()
        if duplicate.kind != .error {
            throw Error.runtime("duplicate stream open should be rejected")
        }

        print("client: stream identity and duplicate open scenario passed")
    }

    mutating func runDatagramIntegrityScenario() throws {
        _ = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let unknownSessionFrame = try Phase11FramePacket.encodeQUICFrame(
            .datagram(
                try WebTransportDatagramSignaling.serialize(
                    sessionID: 0x1234_5678_90ab_cdef,
                    payload: Phase11Payload.utf8("unknown-session")
                )
            )
        )
        try send(
            Phase11Envelope(
                scenario: .oversizedDatagram,
                kind: .datagram,
                sessionID: 0x1234_5678_90ab_cdef,
                payload: unknownSessionFrame
            )
        )
        _ = try receive(expect: .error)

        try send(
            Phase11Envelope(
                scenario: .malformedFrame,
                kind: .sessionRequest,
                requestStreamID: nextRequestStreamID(),
                payload: Data([0x00, 0x01, 0x02, 0x03, 0x04])
            )
        )
        _ = try receive(expect: .error)

        let closedLikeStreamID = nextBidirectionalStreamID()
        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamData,
                streamID: closedLikeStreamID,
                payload: Phase11Payload.utf8("pre-open")
            )
        )
        _ = try receive(expect: .error)
        print("client: datagram/session integrity scenario passed")
    }

    mutating func runMalformedSessionRequestScenario() throws {
        let requestStreamID = nextRequestStreamID()
        try send(
            Phase11Envelope(
                scenario: .malformedFrame,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: Data([0x00, 0x00, 0x00, 0x00, 0x00])
            )
        )
        let response = try receive()
        if response.kind != .error {
            throw Error.runtime("malformed session request should be rejected")
        }
        print("client: malformed session request scenario passed")
    }

    mutating func runEchoStreamsScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        for index in 0..<config.iterations {
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

            let message = "stream-bidi-\(index)"
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: streamID,
                    payload: Phase11Payload.utf8(message)
                )
            )
            let echoed = try receive(expect: .streamEcho)
            guard let payload = echoed.payload,
                let response = String(data: payload, encoding: .utf8),
                response == message
            else {
                throw Error.runtime("stream echo mismatch for scenario stream #\(index)")
            }
        }
        print("client: stream echo scenario passed")
    }

    mutating func runEchoDatagrams(session: WebTransportSession, scenario: Phase11Scenario) throws {
        for index in 0..<config.iterations {
            let payload = Phase11Payload.utf8("dg-\(index)")
            let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
            try send(
                Phase11Envelope(
                    scenario: scenario,
                    kind: .datagram,
                    sessionID: session.id.rawValue,
                    payload: try Phase11FramePacket.encodeQUICFrame(frame)
                )
            )
            let echoed = try receive(expect: .datagramEcho)
            guard echoed.payload == payload else {
                throw Error.runtime("datagram echo mismatch for message #\(index)")
            }
        }
    }

    mutating func runEchoDatagramBurst() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        try runEchoDatagrams(session: session, scenario: .echoDatagrams)
        print("client: datagram burst scenario passed")
    }

    mutating func runUnidirectionalStreamScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let streamID = nextUnidirectionalStreamID()
        let prefix = try manager.openUnidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .unidirectional,
                payload: prefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        let payload = Phase11Payload.utf8("stream-uni")
        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamData,
                streamID: streamID,
                payload: payload
            )
        )
        let echoed = try receive(expect: .streamEcho)
        guard echoed.payload == payload else {
            throw Error.runtime("unidirectional stream echo mismatch")
        }
        print("client: unidirectional stream scenario passed")
    }

    mutating func runMalformedStreamScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let mismatchPrefix = try WebTransportStreamSignaling.serializePrefix(
            form: .unidirectional,
            sessionID: session.id.rawValue
        )
        let streamID = nextBidirectionalStreamID()
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: mismatchPrefix
            )
        )
        let mismatchResponse = try receive()
        if mismatchResponse.kind != .error {
            throw Error.runtime("stream prefix mismatch should be rejected")
        }

        let peerInitiatorStreamID = nextServerBidiStreamID()
        let invalidRolePrefix = try WebTransportStreamSignaling.serializePrefix(
            form: .bidirectional,
            sessionID: session.id.rawValue
        )
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: peerInitiatorStreamID,
                streamKind: .bidirectional,
                payload: invalidRolePrefix
            )
        )
        let roleResponse = try receive()
        if roleResponse.kind != .error {
            throw Error.runtime("peer-initiated stream sent by local client should be rejected")
        }

        print("client: stream prefix/initiator validation scenario passed")
    }

    mutating func runConcurrentSessionsScenario() throws {
        let sessionCount = max(2, min(config.iterations, 5))
        var sessions: [WebTransportSession] = []

        for index in 0..<sessionCount {
            let session = try establishAcceptedSession(
                authority: "example.com",
                path: "/wt",
                requestStreamID: nextRequestStreamID()
            )
            sessions.append(session)

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

            let message = "parallel-\(index)"
            try send(
                Phase11Envelope(
                    scenario: .echoStreams,
                    kind: .streamData,
                    streamID: streamID,
                    payload: Phase11Payload.utf8(message)
                )
            )
            let echoed = try receive(expect: .streamEcho)
            if echoed.payload != Phase11Payload.utf8(message) {
                throw Error.runtime("parallel session #\(index) stream echo mismatch")
            }
        }

        if sessions.count != sessionCount {
            throw Error.runtime("concurrent session setup failed")
        }
        print("client: concurrent sessions scenario passed")
    }

    mutating func runProtocolNegotiationScenario() throws {
        let streamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: streamID,
            authority: "example.com",
            path: "/wt",
            availableProtocols: ["proto-other", "wt-echo", "unused"]
        )
        let response = try runSessionRequest(
            requestFrame: requestFrame,
            requestStreamID: streamID,
            scenario: .echoDatagrams,
            expectedAccepted: true
        )
        guard response.status == nil else {
            throw Error.runtime("server unexpectedly rejected protocol negotiation")
        }
        guard let session = manager.session(forRequestStreamID: streamID),
            session.selectedProtocol == "wt-echo"
        else {
            throw Error.runtime("protocol negotiation did not select wt-echo")
        }
        print("client: protocol negotiation scenario passed")
    }

    mutating func runFlowControlCapsuleScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        try verifyDatagramFlowControl(session: session)

        _ = try manager.receiveFlowControlCapsule(
            sessionID: session.id,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 1))
        )
        // The limit is expected to be refused; the catch is the recovery path rather than a
        // failure, which is why the two blocks are separate helpers and not one.
        let streamID: UInt64
        do {
            streamID = try verifyStreamLimitRefusal(session: session)
        } catch {
            streamID = try recoverAfterStreamLimit(session: session)
        }
        try verifyMaxDataLift(session: session, streamID: streamID)

        // Allow another stream after an update to unlimited.
        _ = try manager.receiveFlowControlCapsule(
            sessionID: session.id,
            bytes: try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
        )
        let recoveryStream = nextBidirectionalStreamID()
        _ = try manager.openBidirectionalStream(streamID: recoveryStream, sessionID: session.id)

        print("client: flow-control capsule scenario passed")
    }

    /// `max_data` caps the datagram size, and the cap is what makes the oversized send fail.
    private mutating func verifyDatagramFlowControl(session: WebTransportSession) throws {
        let maxDataCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 64))
        _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: maxDataCapsule)

        do {
            let payload = Data(repeating: 0x55, count: 128)
            let frame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
            _ = try Phase11FramePacket.encodeQUICFrame(frame)
            throw Error.runtime("oversized datagram unexpectedly allowed under maxData")
        } catch {
            // Expected: max_data reached.
        }

        let payload = Data(repeating: 0x22, count: 32)
        let safeFrame = try manager.makeDatagramFrame(sessionID: session.id, payload: payload)
        try send(
            Phase11Envelope(
                scenario: .echoDatagrams,
                kind: .datagram,
                sessionID: session.id.rawValue,
                payload: try Phase11FramePacket.encodeQUICFrame(safeFrame)
            )
        )
        let echoed = try receive(expect: .datagramEcho)
        guard echoed.payload == payload else {
            throw Error.runtime("flow control datagram check failed")
        }
    }

    /// Opens the first stream under the limit and confirms the second is refused, with a
    /// STREAMS_BLOCKED capsule queued for it.
    private mutating func verifyStreamLimitRefusal(session: WebTransportSession) throws -> UInt64 {
        let firstStream = nextBidirectionalStreamID()
        let firstPrefix = try manager.openBidirectionalStream(streamID: firstStream, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: firstStream,
                streamKind: .bidirectional,
                payload: firstPrefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        let secondStream = nextBidirectionalStreamID()
        do {
            _ = try manager.openBidirectionalStream(streamID: secondStream, sessionID: session.id)
            throw Error.runtime("second stream unexpectedly opened under stream limit")
        } catch {
            guard let queued = try manager.popFlowControlCapsule(sessionID: session.id) else {
                throw Error.runtime("expected blocked stream flow capsule")
            }
            let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
            if case .streamsBlockedBidi(let limit) = parsed.capsule {
                guard limit > 0 else {
                    throw Error.runtime("invalid streamsBlockedBidi limit \(limit)")
                }
            }
        }
        return firstStream
    }

    /// The recovery path when the limit was hit before the first stream opened: lift it and
    /// open one. A missing queued capsule is tolerated here, which is what distinguishes this
    /// from the refusal check above.
    private mutating func recoverAfterStreamLimit(session: WebTransportSession) throws -> UInt64 {
        if let queued = try manager.popFlowControlCapsule(sessionID: session.id) {
            let parsed = try WebTransportFlowCapsuleCodec.parse(queued)
            if case .streamsBlockedBidi(let limit) = parsed.capsule {
                guard limit > 0 else {
                    throw Error.runtime("invalid streamsBlockedBidi limit \(limit)")
                }
            }
        }

        let liftedStreamCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxStreamsBidi(limit: 3))
        _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: liftedStreamCapsule)

        let streamID = nextBidirectionalStreamID()
        let recoveryPrefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: recoveryPrefix
            )
        )
        _ = try receive(expect: .streamOpenAck)
        return streamID
    }

    /// `max_data` rejects an oversized inbound stream payload, and raising it accepts one.
    private mutating func verifyMaxDataLift(session: WebTransportSession, streamID: UInt64) throws {
        do {
            try manager.receiveStreamPayload(streamID: streamID, payload: Data(repeating: 0x77, count: 128))
            throw Error.runtime("local flow-control maxData should reject oversized inbound stream payload")
        } catch {
            // expected
        }

        let baselinePayload = Data(repeating: 0x55, count: 24)
        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamData,
                streamID: streamID,
                payload: baselinePayload
            )
        )
        let streamBaselineEcho = try receive(expect: .streamEcho)
        guard streamBaselineEcho.payload == baselinePayload else {
            throw Error.runtime("flow-control maxData baseline payload should echo")
        }

        let liftedDataCapsule = try WebTransportFlowCapsuleCodec.serialize(.maxData(limit: 256))
        _ = try manager.receiveFlowControlCapsule(sessionID: session.id, bytes: liftedDataCapsule)

        let liftPayload = Data(repeating: 0x33, count: 24)
        try manager.receiveStreamPayload(streamID: streamID, payload: liftPayload)
        let localRecoveredPayload = manager.popStreamPayload(streamID: streamID)
        guard localRecoveredPayload == liftPayload else {
            throw Error.runtime("flow-control maxData lift should allow inbound stream payload")
        }

        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .streamData,
                streamID: streamID,
                payload: liftPayload
            )
        )
        let streamEcho = try receive(expect: .streamEcho)
        guard streamEcho.payload == liftPayload else {
            throw Error.runtime("stream data should be accepted after maxData raised")
        }
    }

    mutating func runDuplicateSessionRequestScenario() throws {
        let requestStreamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: "example.com",
            path: "/wt",
            availableProtocols: ["wt-echo"]
        )

        _ = try runSessionRequest(
            requestFrame: requestFrame,
            requestStreamID: requestStreamID,
            scenario: .echoStreams,
            expectedAccepted: true
        )

        try send(
            Phase11Envelope(
                scenario: .echoStreams,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            )
        )
        let duplicate = try receive()
        if duplicate.kind != .error {
            throw Error.runtime("duplicate session request should be rejected")
        }
        print("client: duplicate session request scenario passed")
    }

    mutating func runCloseAndResetScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let streamID = nextBidirectionalStreamID()
        let prefix = try manager.openBidirectionalStream(streamID: streamID, sessionID: session.id)
        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: prefix
            )
        )
        _ = try receive(expect: .streamOpenAck)

        try send(
            Phase11Envelope(
                scenario: .closeAndReset,
                kind: .streamReset,
                streamID: streamID,
                errorCode: 0x54
            )
        )
        let resetAck = try receive(expect: .streamResetAck)
        guard let payload = resetAck.payload else {
            throw Error.runtime("missing stream reset frame from server")
        }
        _ = try Phase11FramePacket.decodeQUICFrame(payload)
        print("client: close/reset scenario passed")
    }

    mutating func runOversizedDatagramScenario() throws {
        let session = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )
        let hugePayload = Data(repeating: 0x66, count: config.maxDatagramFrameSize + 10)
        let oversized = try WebTransportDatagramSignaling.serialize(sessionID: session.id.rawValue, payload: hugePayload)
        let datagramFrame = QUICFrame.datagram(oversized)
        try send(
            Phase11Envelope(
                scenario: .oversizedDatagram,
                kind: .datagram,
                sessionID: session.id.rawValue,
                payload: try Phase11FramePacket.encodeQUICFrame(datagramFrame)
            )
        )
        let response = try receive(expect: .error)
        if response.success == true {
            throw Error.runtime("server should reject oversized datagram")
        }
        print("client: oversized datagram scenario passed")
    }

    mutating func runMalformedFrameScenario() throws {
        _ = try establishAcceptedSession(
            authority: "example.com",
            path: "/wt",
            requestStreamID: nextRequestStreamID()
        )

        let streamID = nextBidirectionalStreamID()
        try send(
            Phase11Envelope(
                scenario: .malformedFrame,
                kind: .streamOpen,
                streamID: streamID,
                streamKind: .bidirectional,
                payload: Data([0x00, 0x00])
            )
        )
        let response = try receive()
        if response.kind != .error {
            throw Error.runtime("malformed stream open should be rejected")
        }
        print("client: malformed frame scenario passed")
    }

    mutating func runRejectedSessionScenario() throws {
        let request = try WebTransportSessionRequest(authority: "forbidden.example", path: "/missing")
        let requestStreamID = nextRequestStreamID()
        let requestFrame = try makeSessionRequestFrame(
            requestStreamID: requestStreamID,
            authority: request.authority,
            path: request.path
        )
        try send(
            Phase11Envelope(
                scenario: .rejectedSession,
                kind: .sessionRequest,
                requestStreamID: requestStreamID,
                payload: try Phase11FramePacket.encodeHTTP3Frame(requestFrame)
            )
        )
        let response = try receive(expect: .sessionResponse)
        guard let status = response.status, status != 0 else {
            throw Error.runtime("server rejected session did not return status")
        }
        print("client: rejected-session scenario passed (\(status))")
    }

}
