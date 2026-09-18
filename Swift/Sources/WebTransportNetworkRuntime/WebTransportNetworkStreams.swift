// The WebTransport session and the stream handles it hands out over one QUIC
// connection.

import Foundation
import CryptoKit
import Network
import Security
import Synchronization

import WebTransportCryptoApple
import WebTransportHTTP3Core
import WebTransportQUICCore
import WebTransportTLSCore

// SAFETY: The wrapper is immutable after initialization. Prefix and initial
// payload state are isolated in `WebTransportNetworkStreamState`; the stored
// Network.framework stream handle is used only through async send/receive calls.
public final class WebTransportNetworkBidirectionalStream: @unchecked Sendable {
    public let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let prefix: Data?
    private let state: WebTransportNetworkStreamState
    private let manager: WebTransportNetworkSessionManagerState?

    init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        prefix: Data? = nil,
        initialPayload: Data = Data(),
        manager: WebTransportNetworkSessionManagerState? = nil
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.prefix = prefix
        self.state = WebTransportNetworkStreamState(prefix: prefix, initialPayload: initialPayload)
        self.manager = manager
    }

    public func send(
        _ data: Data,
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        if let manager {
            _ = try await manager.withManager { manager in
                try manager.sendStreamPayload(
                    streamID: self.streamID,
                    payload: data,
                    fin: endOfStream
                )
            }
        }
        var mutablePayload = Data()
        if let prefix = await state.consumeOutboundPrefix() {
            mutablePayload.append(prefix)
        }
        mutablePayload.append(data)
        let payload = mutablePayload
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.stream.send(payload, endOfStream: endOfStream)
        }
    }

    public func receive(
        maximumBytes: Int = 64 * 1024,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> Data {
        // A stream accepted from the wire carries the prefix-stripped remainder of
        // its first chunk. That buffer is served first, and it is a read like any
        // other: it must return at most `maximumBytes` and keep the unread
        // remainder for the next call, or the bound the caller asked for is only
        // honoured on the network path.
        if let initialPayload = await state.consumeInitialPayload(maximumBytes: maximumBytes) {
            if !initialPayload.isEmpty, let manager {
                _ = await manager.withManager { manager in
                    manager.popStreamPayload(streamID: self.streamID)
                }
            }
            return initialPayload
        }
        let payload = try await InteroperableQUICHelpers.readStream(
            stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            maxBytes: maximumBytes
        )
        if let manager {
            return try await manager.withManager { manager in
                try manager.receiveAndPopStreamPayload(streamID: self.streamID, payload: payload)
            }
        }
        return payload
    }
}

/// A peer-initiated unidirectional WebTransport stream, accepted from the wire.
///
/// RFC 9000 section 2.1 gives a unidirectional stream to its initiator only, so a
/// stream the peer initiated is receive-only here: this type has no send method,
/// and the session manager refuses a send-side call on the same stream (see
/// `WebTransportSessionManager.sendStreamPayload`). That is the difference from
/// ``WebTransportNetworkBidirectionalStream``, which owns both halves. No abort
/// operation is exposed either: the only signal the receive half could produce is
/// STOP_SENDING, and Network.framework offers no per-stream STOP_SENDING.
public final class WebTransportNetworkUnidirectionalStream: Sendable {
    public let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let state: WebTransportNetworkStreamState
    private let manager: WebTransportNetworkSessionManagerState?

    init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        initialPayload: Data = Data(),
        manager: WebTransportNetworkSessionManagerState? = nil
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.state = WebTransportNetworkStreamState(prefix: nil, initialPayload: initialPayload)
        self.manager = manager
    }

    /// Reads the next bytes of the peer's stream.
    ///
    /// The arguments and the buffered-first-chunk behaviour mirror
    /// ``WebTransportNetworkBidirectionalStream/receive(maximumBytes:timeoutMilliseconds:)``;
    /// only the send half is absent.
    public func receive(
        maximumBytes: Int = 64 * 1024,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws -> Data {
        if let initialPayload = await state.consumeInitialPayload(maximumBytes: maximumBytes) {
            if !initialPayload.isEmpty, let manager {
                _ = await manager.withManager { manager in
                    manager.popStreamPayload(streamID: self.streamID)
                }
            }
            return initialPayload
        }
        let payload = try await InteroperableQUICHelpers.readStream(
            stream,
            timeoutMilliseconds: overrideTimeoutMilliseconds ?? timeoutMilliseconds,
            maxBytes: maximumBytes
        )
        if let manager {
            return try await manager.withManager { manager in
                try manager.receiveAndPopStreamPayload(streamID: self.streamID, payload: payload)
            }
        }
        return payload
    }
}

/// Test-support handle for a peer-side unidirectional stream.
///
/// The shipped runtime accepts peer-initiated unidirectional streams
/// (``WebTransportNetworkSession/acceptUnidirectionalStream(maximumInitialBytes:timeoutMilliseconds:)``)
/// but does not open them, so a loopback test that needs a peer to initiate one
/// has no producer. This retains the local QUIC stream for as long as the
/// receiver is reading it — releasing the last handle would let the transport
/// cancel the receive side before the bytes arrive — and writes the WebTransport
/// unidirectional prefix once, before the first payload.
///
/// Internal on purpose: opening a unidirectional stream is not part of the
/// shipped surface, and the finding this supports is about accepting one.
final class UnidirectionalStreamProducer: Sendable {
    let streamID: UInt64

    private let stream: QUIC.Stream<QUICStream>
    private let timeoutMilliseconds: Int32
    private let state: WebTransportNetworkStreamState

    init(
        stream: QUIC.Stream<QUICStream>,
        timeoutMilliseconds: Int32,
        prefix: Data
    ) {
        self.streamID = stream.streamID
        self.stream = stream
        self.timeoutMilliseconds = timeoutMilliseconds
        self.state = WebTransportNetworkStreamState(prefix: prefix, initialPayload: Data())
    }

    /// Sends `data`, writing the WebTransport stream prefix first on the first
    /// call so the peer's `acceptUnidirectionalStream` sees a prefixed stream.
    func send(
        _ data: Data,
        endOfStream: Bool = false,
        timeoutMilliseconds overrideTimeoutMilliseconds: Int32? = nil
    ) async throws {
        var payload = Data()
        if let prefix = await state.consumeOutboundPrefix() {
            payload.append(prefix)
        }
        payload.append(data)
        let outbound = payload
        try await InteroperableQUICHelpers.withTimeout(overrideTimeoutMilliseconds ?? timeoutMilliseconds) {
            try await self.stream.send(outbound, endOfStream: endOfStream)
        }
    }
}

// SAFETY: Endpoint/session metadata are immutable. Mutable WebTransport state is
// isolated in `WebTransportNetworkSessionManagerState`; inbound stream queues are
// actors; the Network.framework connection is only accessed through async APIs.

private actor WebTransportNetworkStreamState {
    private var outboundPrefix: Data?
    private var initialPayload: Data?

    init(prefix: Data?, initialPayload: Data) {
        self.outboundPrefix = prefix
        self.initialPayload = initialPayload
    }

    func consumeOutboundPrefix() -> Data? {
        let value = outboundPrefix
        outboundPrefix = nil
        return value
    }

    func consumeInitialPayload(maximumBytes: Int) -> Data? {
        guard let buffered = initialPayload, !buffered.isEmpty else {
            return nil
        }
        let limit = max(0, maximumBytes)
        guard buffered.count > limit else {
            initialPayload = nil
            return buffered
        }
        let returned = Data(buffered.prefix(limit))
        let remainder = Data(buffered.dropFirst(limit))
        initialPayload = remainder.isEmpty ? nil : remainder
        return returned
    }
}
