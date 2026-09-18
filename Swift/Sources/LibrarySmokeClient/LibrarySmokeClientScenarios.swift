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

}
