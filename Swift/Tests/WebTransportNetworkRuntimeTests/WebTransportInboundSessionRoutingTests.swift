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
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: matching,
            expectedSessionID: servedSessionID
        ) == nil)

    // A bidirectional prefix that names another session is foreign, and the
    // named session ID is reported so the caller can reset the stream.
    let foreign = try WebTransportStreamSignaling.serializeBidirectionalPrefix(sessionID: 8)
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: foreign,
            expectedSessionID: servedSessionID
        ) == 8)
    // Whatever payload follows the prefix does not change the classification.
    let foreignWithPayload = foreign + Data("payload".utf8)
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: foreignWithPayload,
            expectedSessionID: servedSessionID
        ) == 8)

    // No WebTransport marker: the manager owns the grammar and reports the
    // malformed-stream error, so this is not a foreign-session refusal.
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: Data("not-a-prefix".utf8),
            expectedSessionID: servedSessionID
        ) == nil)

    // A unidirectional marker on a bidirectional accept is a grammar error, not
    // a foreign session, so it is left to the manager too.
    let unidirectional = try WebTransportStreamSignaling.serializeUnidirectionalPrefix(sessionID: 8)
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: unidirectional,
            expectedSessionID: servedSessionID
        ) == nil)

    // A truncated prefix is malformed, not foreign.
    #expect(
        InteroperableQUICHelpers.foreignSessionID(
            inPrefixedStream: Data([0x41]),
            expectedSessionID: servedSessionID
        ) == nil)
}
