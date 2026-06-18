# Swift macOS 26 WebTransport Plan

This plan describes how to build the Swift WebTransport library for macOS 26
server and client apps using only Apple and Xcode-provided libraries. No
third-party libraries are allowed.

The project bible remains the latest IETF `draft-ietf-webtrans-http3` document
until a final RFC replaces it:

<https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>

## Non-Negotiable Constraints

- Use Swift and Apple SDK frameworks only.
- Use no third-party package, vendored source, generated protocol stack, or external
  TLS, QUIC, HTTP/3, QPACK, or WebTransport implementation.
- Build with Xcode and Swift Package Manager.
- Support both server and client use from macOS apps.
- Keep the protocol implementation auditable and traceable to the current IETF draft.

## Allowed Apple Components

- Swift standard library for core language and collections.
- Foundation for `Data`, dates, URLs, and basic utilities.
- Network framework for QUIC connections, listeners, streams, datagrams, endpoints,
  TLS parameters, and connection state.
- Security framework for certificate, identity, trust, and keychain integration.
- CryptoKit only for cryptographic helpers that are not already handled by
  Network.framework QUIC/TLS.
- Dispatch, OSLog, and XCTest for scheduling, diagnostics, and tests.

## Explicitly Avoided Components

- `URLSession` as the WebTransport transport implementation. It can use HTTP/3 for
  normal URL loading, but it does not provide the low-level server and WebTransport
  control needed here.
- Third-party QUIC stacks.
- Third-party HTTP/3 stacks.
- Third-party QPACK implementations.
- Third-party TLS libraries.

## Feasibility Gate

Before writing the library proper, build a small spike in `Swift/Spikes/AppleQUIC`
that proves these capabilities using only Network.framework:

1. Start a QUIC `NWListener` on localhost with a test certificate.
2. Connect with a QUIC `NWConnection` client.
3. Negotiate HTTP/3 ALPN.
4. Open client-initiated bidirectional streams.
5. Open client-initiated unidirectional streams.
6. Accept peer-initiated streams on the server.
7. Send and receive QUIC datagrams.
8. Surface close, reset, and application error codes.
9. Confirm that the APIs expose enough stream control to carry HTTP/3 stream types
   and WebTransport stream prefixes exactly as the draft requires.

If any item fails because Apple does not expose the needed QUIC primitive, the Swift
implementation is blocked under the no-third-party rule. The only acceptable fallback
would be to document the missing Apple API and wait for SDK support, not to import an
external stack.

## Architecture

Use a layered design where only the lowest layer talks directly to Apple networking
APIs:

```text
App
  WebTransport public API
  WebTransport session, stream, datagram, and close semantics
  HTTP/3 request, control stream, frame, SETTINGS, and capsule handling
  QPACK encoder and decoder
  Apple QUIC adapter over Network.framework
  Network.framework QUIC/TLS
```

The public WebTransport API must not expose `NWConnection` directly. Keep
Network.framework isolated behind an internal adapter so protocol tests can run
against in-memory transports.

## Swift Package Layout

```text
Swift/
  Package.swift
  Sources/
    WebTransport/
      Public/
      Session/
      Streams/
      Datagram/
    WebTransportHTTP3/
      Frames/
      Settings/
      Capsules/
      QPACK/
    WebTransportQUICApple/
      Client/
      Server/
      TLS/
      NetworkAdapter/
    WebTransportTestSupport/
      InMemoryTransport/
      TestVectors/
  Tests/
    WebTransportTests/
    WebTransportHTTP3Tests/
    WebTransportQUICAppleTests/
  Examples/
    ClientCLI/
    ServerCLI/
  Spikes/
    AppleQUIC/
```

Initial targets:

- `WebTransport`: public client/server API and shared session logic.
- `WebTransportHTTP3`: HTTP/3, QPACK, capsule, frame, and settings codecs.
- `WebTransportQUICApple`: Network.framework adapter and Apple TLS/certificate
  integration.
- `WebTransportTestSupport`: in-memory test drivers and shared draft test vectors.
- `ClientCLI` and `ServerCLI`: local manual test environments.

## Public API Shape

Keep the first API small and explicit:

```swift
public struct WebTransportClientConfiguration {
    public var serverName: String
    public var port: UInt16
    public var path: String
    public var origin: String?
}

public struct WebTransportServerConfiguration {
    public var listenHost: String
    public var port: UInt16
    public var certificateIdentity: SecIdentity
}

public protocol WebTransportSession: Sendable {
    func openBidirectionalStream() async throws -> WebTransportBidirectionalStream
    func openUnidirectionalStream() async throws -> WebTransportSendStream
    func receiveBidirectionalStreams() -> AsyncThrowingStream<WebTransportBidirectionalStream, Error>
    func receiveUnidirectionalStreams() -> AsyncThrowingStream<WebTransportReceiveStream, Error>
    func sendDatagram(_ data: Data) async throws
    func receiveDatagrams() -> AsyncThrowingStream<Data, Error>
    func close(code: UInt32, reason: String?) async
}
```

The actual API can evolve, but the first version should expose:

- Client connection and session establishment.
- Server listener and incoming session acceptance.
- Bidirectional streams.
- Unidirectional send and receive streams.
- Datagrams.
- Graceful close and error reporting.
- Backpressure through Swift concurrency rather than unbounded buffering.

## Implementation Phases

### Phase 1: Apple QUIC Spike

Deliver a minimal localhost client and server using Network.framework QUIC. Prove
stream, datagram, ALPN, TLS, and error-code behavior. This phase decides whether the
strict Apple-only implementation is viable.

### Phase 2: Core Byte Codecs

Implement and test:

- QUIC-style variable-length integers used by HTTP/3.
- Byte cursor and bounded buffer helpers.
- HTTP/3 frame headers.
- Stream type parsing.
- Draft constants as a versioned table tied to the protocol bible.

### Phase 3: Minimal QPACK

Implement enough QPACK for WebTransport session establishment:

- Static table lookup.
- Literal name and value encoding.
- Required request pseudo-headers.
- Required response pseudo-headers.
- Decoder limits and malformed-header errors.

Do not assume QPACK can be skipped. HTTP/3 HEADERS frames require QPACK-encoded
field sections even for a minimal WebTransport handshake.

### Phase 4: HTTP/3 Base Layer

Implement:

- Client and server control streams.
- SETTINGS send, receive, and validation.
- Request stream lifecycle.
- HEADERS frame handling.
- DATA frame rejection or pass-through rules where relevant.
- GOAWAY handling.
- HTTP/3 application error mapping.

Keep the feature set narrow. Implement the HTTP/3 features WebTransport requires;
do not build a general-purpose web server first.

### Phase 5: WebTransport Session Establishment

Implement the draft-defined session setup over HTTP/3:

- Client extended CONNECT request.
- Required pseudo-headers and protocol header handling.
- Server acceptance and rejection flow.
- Session ID allocation and validation.
- Mapping request streams to WebTransport sessions.
- Version and settings validation.

### Phase 6: WebTransport Streams

Implement:

- WebTransport bidirectional stream open and accept.
- WebTransport unidirectional stream open and accept.
- Stream prefix parsing and serialization.
- Reset and stop-sending behavior.
- Backpressure and receive buffering limits.
- Session-level ownership of streams.

### Phase 7: Datagrams

Implement:

- QUIC datagram support through Network.framework.
- HTTP Datagram/WebTransport datagram mapping required by the draft.
- Maximum datagram size checks.
- Per-session datagram demultiplexing.
- Loss-tolerant receive API.

### Phase 8: Flow Control and Capsules

Implement:

- WebTransport flow-control settings.
- Flow-control capsules.
- Session stream limits.
- Data limits.
- Blocked notifications.

This phase should follow the current draft closely because flow control is where
interoperability bugs become subtle.

### Phase 9: Server and Client Test Environments

Create:

- `swift run ServerCLI --port 9443 --cert local-dev`
- `swift run ClientCLI --url https://localhost:9443/demo`
- Echo tests for streams and datagrams.
- Close, reset, oversized datagram, malformed frame, and rejected-session scenarios.
- Loopback tests that run in CI without external services.

### Phase 10: Interop and Hardening

Add:

- Draft-version test vectors.
- Fuzz-style codec tests using deterministic generated inputs.
- Long-running stream and datagram stress tests.
- Concurrency cancellation tests.
- Certificate and trust failure tests.
- API documentation and examples.

## Risk Register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Network.framework QUIC does not expose a required primitive | Blocks strict Apple-only implementation | Run Phase 1 first and document exact missing API |
| HTTP/3 requires more QPACK behavior than expected | Delays handshake milestone | Build QPACK as a real internal module with strong tests |
| Server-side QUIC behavior differs from client-side APIs | Blocks local server support | Include `NWListener` in the first spike |
| Draft changes before RFC publication | Rework protocol constants and tests | Track draft number in `docs/Protocol-Bible.md` and tests |
| Swift concurrency hides backpressure bugs | Memory growth and latency issues | Use bounded buffers and explicit flow-control tests |
| TLS certificate setup is cumbersome for local testing | Poor developer experience | Provide Apple Security-based local certificate tooling |

## First Milestone Definition of Done

The first milestone is complete only when:

- `Swift/Package.swift` exists.
- The Apple QUIC spike proves client and server stream plus datagram support.
- A local server and client can negotiate QUIC with HTTP/3 ALPN.
- The result uses only Apple and Xcode-provided libraries.
- The spike documents any Apple API limitations found.

## References

- IETF WebTransport over HTTP/3 draft:
  <https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>
- Apple Network framework:
  <https://developer.apple.com/documentation/network>
- Apple `NWProtocolQUIC`:
  <https://developer.apple.com/documentation/network/nwprotocolquic>
- Apple HTTP/3 technote:
  <https://developer.apple.com/documentation/technotes/tn3102-http3-in-your-app>
- Apple networking API selection technote:
  <https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api>
