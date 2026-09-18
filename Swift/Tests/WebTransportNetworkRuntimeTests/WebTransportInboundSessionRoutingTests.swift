import Foundation
import Testing
import WebTransportHTTP3Core
@testable import WebTransportNetworkRuntime

/// F-swift-architecture-07: an inbound WebTransport stream whose prefix names a
/// session the connection does not serve must be refused at the protocol level,
/// not read, buffered, and dropped with `unexpectedFrame`.
///
/// The runtime serves exactly one session per connection, so it can classify a
/// prefix before the session manager sees the bytes. The manager's server role
/// deliberately buffers a stream whose CONNECT may still be in flight
/// (`WebTransportLibrarySmokeMatrix.runOrdering`), so the manager cannot make
/// this distinction itself; the decision belongs to the runtime and has to be
/// exact about what it claims.
///
/// These pin the classification the runtime's `acceptBidirectionalStream` uses:
/// only a well-formed bidirectional prefix naming a different session is
/// foreign. Everything else is left to the manager, which owns the prefix
/// grammar and reports the protocol error for it.
@Test
func runtimeClassifiesForeignSessionPrefixedStreamsForRefusal() throws {
    let servedSessionID: UInt64 = 0

    // The prefix for the session this connection serves is not foreign.
    let matching = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: servedSessionID)
    expectNotForeign(matching, expectedSessionID: servedSessionID)

    // A bidirectional prefix that names another session is foreign, and the
    // named session ID is reported so the caller can reset the stream.
    let foreign = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: 8)
    expectForeign(foreign, expectedSessionID: servedSessionID, names: 8)
    // Whatever payload follows the prefix does not change the classification.
    let foreignWithPayload = foreign + Data("payload".utf8)
    expectForeign(foreignWithPayload, expectedSessionID: servedSessionID, names: 8)

    // No WebTransport marker: the manager owns the grammar and reports the
    // malformed-stream error, so this is not a foreign-session refusal.
    expectNotForeign(Data("not-a-prefix".utf8), expectedSessionID: servedSessionID)

    // A unidirectional marker on a bidirectional accept is a grammar error, not
    // a foreign session, so it is left to the manager too.
    let unidirectional = try WebTransportStreamSignaling.serializeUnidirectionalPrefix(sessionID: 8)
    expectNotForeign(unidirectional, expectedSessionID: servedSessionID)

    // F-swift-line-security-05b: the same classification is applied on the
    // unidirectional accept path, where a unidirectional prefix naming another
    // session *is* foreign and must be refused before the manager registers or
    // buffers it.
    expectForeign(unidirectional, expectedSessionID: servedSessionID, form: .unidirectional, names: 8)
    // The prefix for the session this connection serves is not foreign in either
    // form.
    let matchingUnidirectional = try WebTransportStreamSignaling.serializeUnidirectionalPrefix(
        sessionID: servedSessionID
    )
    expectNotForeign(matchingUnidirectional, expectedSessionID: servedSessionID, form: .unidirectional)
    // A bidirectional prefix on a unidirectional accept is a grammar error, so it
    // is still left to the manager rather than reported as a foreign session.
    expectNotForeign(matching, expectedSessionID: servedSessionID, form: .unidirectional)

    // A truncated prefix is malformed, not foreign.
    expectNotForeign(Data([0x41]), expectedSessionID: servedSessionID)
}

/// F-swift-architecture-08: the connection-scoped datagram channel cannot hand a
/// datagram back once it has been read, so a datagram naming a session this
/// connection does not serve must be classified before the session manager can
/// retain its payload, and reported as a foreign session rather than as an
/// invalid payload.
@Test
func runtimeClassifiesForeignSessionDatagramsForRefusal() throws {
    let servedSessionID: UInt64 = 0

    // A datagram for the session this connection serves is not foreign.
    let matching = try WebTransportDatagramSignaling.serialize(
        sessionID: servedSessionID,
        payload: Data("served".utf8)
    )
    #expect(
        try InteroperableQUICHelpers.foreignDatagramSessionID(
            inDatagram: matching,
            expectedSessionID: servedSessionID
        ) == nil)

    // A datagram that names another session is foreign, and the named session ID
    // is reported so the caller can name the condition.
    let foreign = try WebTransportDatagramSignaling.serialize(
        sessionID: 8,
        payload: Data("foreign".utf8)
    )
    #expect(
        try InteroperableQUICHelpers.foreignDatagramSessionID(
            inDatagram: foreign,
            expectedSessionID: servedSessionID
        ) == 8)

    // A datagram with no decodable prefix is a WebTransport ID error, matching
    // what the session manager reports for the same bytes — not a silent drop
    // and not a foreign-session report.
    do {
        _ = try InteroperableQUICHelpers.foreignDatagramSessionID(
            inDatagram: Data(),
            expectedSessionID: servedSessionID
        )
        Issue.record("an empty datagram should be reported as a WebTransport ID error")
    } catch let error as WebTransportDraft16Error {
        #expect(error.kind == .h3ID)
    }
}

/// Asserts the classifier reports the stream as naming another session.
private func expectForeign(
    _ stream: Data,
    expectedSessionID: UInt64,
    form: WebTransportStreamForm = .bidirectional,
    names expected: UInt64
) {
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: stream,
            expectedSessionID: expectedSessionID,
            form: form
        ) == expected)
}

/// Asserts the classifier leaves the stream to the manager: it is not a prefix, not foreign,
/// or a grammar error for this direction.
private func expectNotForeign(
    _ stream: Data,
    expectedSessionID: UInt64,
    form: WebTransportStreamForm = .bidirectional
) {
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: stream,
            expectedSessionID: expectedSessionID,
            form: form
        ) == nil)
}
