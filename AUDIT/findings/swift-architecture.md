# swift-architecture — L1 architecture + L2 module level (Swift only)

Examiner area: `swift-architecture`. Scope: `Swift/Sources/**` plus `Package.swift` and
`Swift/Package.swift`. Branch `audit/2026-09-15`, HEAD `1d38db3`. Read-only pass; nothing
was modified except this file and `swift-architecture.json`.

Method: full reads of the manifests, `WebTransport` (shipped product), all of
`WebTransportNetworkRuntime`, `WebTransportHTTP3Core` (session manager, streams, flow
control, connection, settings, headers, datagrams, exporter, errors, security policy,
compliance matrix), the C shim, `WebTransportQUICCore` (core state, byte cursor, varints,
transport parameters), `WebTransportTLSCore` (identity/trust, QUIC connection state), and
the two CLI executables; target-by-target import/dependency comparison; targeted greps for
crash constructs, dead symbols and cross-module constants. Builds were not re-run (the
brief records them green and static evidence was sufficient for every finding below;
`AUDIT/ledger.json` A-0001 already covers the Swift 6.4 link failure that the baseline
recorded).

Cross-reference: the two-manifest split is **already filed and dispositioned as
intended** in `AUDIT/ledger.json` A-0003 (enforced by `Swift/check-manifest-sync.sh`), so
it is not re-filed here. A-0006 (no imports-vs-declared-dependencies check) is the mirror
of F-swift-architecture-12 below; A-0006 is the missing-dependency direction, F-12 is a
declared-but-unused dependency.

Counts: **S0 = 1, S1 = 4, S2 = 6, S3 = 3** (14 findings).

---

## F-swift-architecture-01 — S0 — unsafe — CONNECT-stream capsule reader buffers without a size bound

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:831`
(reader 807–850, `popCompleteCapsule` 852–877)

**What is wrong.** The task that reads the WebTransport CONNECT stream accumulates bytes
into a `Data` until a complete capsule is available. How many bytes that is comes from the
peer: the capsule length is a peer-supplied varint, and the only rejection is
`payloadLength > UInt64(Int.max)`. There is no cap, no timeout on a partial capsule, and no
reset. Because the loop keeps calling `stream.receive(atMost:)` while it accumulates, it
also keeps re-opening QUIC flow-control credit, so the peer can stream forever. The result
is peer-controlled unbounded memory growth in a shipped server whose default bind is
**not** loopback (`WebTransportServerConfiguration.localOnly` defaults to `false`,
`WebTransport.swift:101`), and whose default policy accepts any peer that sends
`:authority: localhost`, `:path: /wt`.

**Evidence (quoted code, unchanged):**

```swift
// 807-850
private static func receiveConnectCapsules(from stream:..., initialBytes: Data) async {
    var buffered = initialBytes
    ...
        let received = try await stream.receive(atMost: 8_192)
        buffered.append(received.content)                    // 831: unbounded
...
// 852-877
private static func popCompleteCapsule(from buffer: inout Data) throws -> Data? {
    ...
    _ = try QUICVarInt.decode(from: &cursor)
    let payloadLength = try QUICVarInt.decode(from: &cursor) // 859: peer-controlled
    guard payloadLength <= UInt64(Int.max) else { ... }      // only bound
    let capsuleLength = headerLength + Int(payloadLength)
    guard buffer.count >= capsuleLength else { return nil }  // waits for all of it
```

A peer sends `type = 0x2843` (WT_CLOSE_SESSION) plus a length varint of, say, 2^40 and then
streams data; `popCompleteCapsule` keeps returning `nil` and `buffered` keeps growing. The
`wtCloseSessionMaxMessageBytes` (1024) cap is only enforced later, by
`WebTransportFlowCapsuleCodec.parseCloseSession`, i.e. after the whole capsule has already
been buffered (`WebTransportFlowControl.swift:169`).

**What correct looks like.** The largest legal CONNECT-stream capsule has a known size
bound: WT_CLOSE_SESSION payload ≤ 1024 bytes (`HTTP3Constants.swift:122`), the flow-control
capsules carry one varint, and WT_DRAIN_SESSION is empty. A reader therefore rejects a
declared capsule length above a documented constant, and any partial capsule that exceeds
it is a protocol violation handled by resetting/erroring the stream — never by buffering.

**Smallest correct fix.** In `popCompleteCapsule`, after decoding `payloadLength`, add

```swift
guard payloadLength <= Self.maximumConnectCapsuleBytes else {
    throw QUICCodecError.valueOutOfRange("CONNECT capsule length exceeds the permitted maximum")
}
```

with `static let maximumConnectCapsuleBytes = WebTransportHTTP3DraftConstants.current.wtCloseSessionMaxMessageBytes + 16`
(or a documented constant covering the largest flow-control capsule), and let the existing
`catch` in `receiveConnectCapsules` (846–849) reset the stream with `H3_MESSAGE_ERROR`.
Optionally bound `buffered.count` as a second line of defence.

---

## F-swift-architecture-02 — S1 — unsafe — `waitForReady` leaks its checked continuation (and the connection observer) on the timeout path

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1752`
(function 1727–1802)

**What is wrong.** `waitForReady` parks an inner `withCheckedThrowingContinuation` and
resumes it only from the `connection.onStateUpdate` handler (`handleState`). The whole
thing is wrapped in `withTimeout`, whose expiry path cancels the operation task and resumes
only its *own* continuation. `withCheckedThrowingContinuation` does not respond to task
cancellation, so on a handshake that stalls (peer completes the UDP path but never finishes
the TLS handshake — a normal hostile/broken-peer case) the inner continuation is never
resumed by this code. The abandoned task stays suspended holding the continuation, the
observer closure, `role` and the timer handle, and the observer stays registered on the
connection, so nothing can release it until the connection independently reaches
`.failed`/`.cancelled` — and if it never does, for the life of the process. This is the
"resource leak on an error path" class, on both the client and server establishment paths
(`connectSession` 189, `acceptSession` 1250).

**Evidence (quoted code):**

```swift
// 1751-1801, inside waitForReady
try await withTimeout(timeoutMilliseconds) {
    try await withCheckedThrowingContinuation { continuation in
        let completion = OneShotContinuation()
        let handleState: @Sendable (NetworkConnection<QUIC>.State) -> Void = { state in
            switch state {
            case .ready: Task { await completion.complete { continuation.resume() } }
            case .failed(let error): ... continuation.resume(throwing: ...)
            case .cancelled: ... continuation.resume(throwing: ...)
            default: break
            }
        }
        connection.onStateUpdate { _, state in handleState(state) }
        ...
    }
}
// 1978-1984, withTimeout's expiry
let timeoutTask = Task { @Sendable in
    try? await Task.sleep(for: .milliseconds(Int(timeoutMilliseconds)))
    await gate.complete {
        operationTask.cancel()                       // no resume of the inner continuation
        continuation.resume(throwing: .timeout(timeoutMilliseconds))
    }
}
```

There is no `withTaskCancellationHandler` anywhere in `waitForReady`, and no state observer
removal.

**What correct looks like.** A continuation is resumed exactly once on every path,
including timeout/cancellation, and the observer does not outlive the wait. Either the wait
registers a cancellation handler that resumes the inner continuation with a timeout error,
or the timeout is owned by `waitForReady` itself (a local task that resumes the continuation
and then removes/neutralises the observer) instead of being delegated to the generic
`withTimeout`, which is documented to abandon rather than drain.

**Smallest correct fix.** Wrap the body in
`try await withTaskCancellationHandler { ... } onCancel: { Task { await completion.complete { continuation.resume(throwing: WebTransportNetworkRuntimeError.timeout(timeoutMilliseconds)) } } }`,
so `operationTask.cancel()` from `withTimeout` resumes the inner continuation once
(`OneShotContinuation` already guarantees exactly-once). Add a regression test that calls
`waitForReady` against a stub connection whose state stays non-terminal and asserts the
continuation resolves within the timeout.

---

## F-swift-architecture-03 — S1 — bug — `datagramsUsable` is a constant `true`, so the public `datagramsAvailable` capability flag lies

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1804`
(`datagramsUsable` 1804–1811; consumers 197, 1396, 477; public surface
`Swift/Sources/WebTransport/WebTransport.swift:299`)

**What is wrong.** The runtime never inspects whether QUIC DATAGRAM was negotiated: the
helper discards its connection argument and returns `true`. That fabricated value becomes
`WebTransportNetworkSession.datagramsAvailable` (line 477) and then the public
`WebTransportSession.datagramsAvailable`, and it is what `WebTransportClient.echo` uses to
choose between the datagram and stream fallback. A user who reads the property to decide
whether datagrams are usable, or who relies on `echo`, is told "yes" for a peer that never
sent `max_datagram_frame_size`/`SETTINGS_H3_DATAGRAM` support; `sendDatagram` then fails at
the framework layer (or burns the timeout) instead of the API reporting the capability
honestly. The one test that touches it asserts the constant is `true`
(`Swift/Tests/WebTransportTests/WebTransportPublicAPITests.swift:178-179`), so the claim is
enshrined rather than verified.

**Evidence (quoted code):**

```swift
// 1804-1811
static func datagramsUsable(_: NetworkConnection<QUIC>) -> Bool {
    // Network.framework can report 0 here until the datagram channel is
    // first used, even when both peers negotiated QUIC DATAGRAM support.
    // ...
    return true
}
```

```swift
// WebTransport.swift:299 (public); 403 (behaviour depends on it)
public let datagramsAvailable: Bool
...
if session.datagramsAvailable { try await session.sendDatagram(...) } else { ...stream... }
```

**What correct looks like.** `datagramsAvailable` states a fact about the connection: true
only when the peer's transport parameters (or an explicit parameter from
Security/Network.framework) show DATAGRAM support. If the framework genuinely cannot answer
before first use, the public API must not present an unverified constant as a fact — it
should be renamed/documented as a request, or be replaced by an attempt-and-report call.

**Smallest correct fix.** Derive the value from the negotiated transport parameters where
the framework exposes them (Network.framework `QUIC` parameters); where it does not, change
the public property's documented contract and stop letting `echo` choose the datagram path
from it — try the datagram exchange and fall back to a stream on failure. Either way the
test at `WebTransportPublicAPITests.swift:178` must assert a negotiated fact, not a
constant.

---

## F-swift-architecture-04 — S1 — logic — `receive(maximumBytes:)` ignores its bound when the stream carries a buffered initial payload

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:446`
(stream `receive` 442–466; accept path 598–633)

**What is wrong.** A stream accepted from the wire carries the prefix-stripped remainder of
its first chunk as `initialPayload` (line 630). `receive(maximumBytes:)` returns that
payload whole, before it ever reaches `readStream(..., maxBytes:)`. `maximumInitialBytes`
and `maximumBytes` are independent parameters, and the first chunk is read with
`maxBytes: maximumInitialBytes` (default 64 KiB), so
`try await stream.receive(maximumBytes: 1)` can legally return ~64 KiB. The public
`WebTransportBidirectionalStream.receive(maximumBytes:)` therefore does not honour its own
contract on a normal path, and a caller that sizes a buffer from `maximumBytes` gets more
data than it asked for.

**Evidence (quoted code):**

```swift
// 446-453
if let initialPayload = await state.consumeInitialPayload(), !initialPayload.isEmpty {
    if let manager {
        _ = await manager.withManager { manager in
            manager.popStreamPayload(streamID: self.streamID)
        }
    }
    return initialPayload                    // maximumBytes never consulted
}
let payload = try await InteroperableQUICHelpers.readStream(
    stream, timeoutMilliseconds: ..., maxBytes: maximumBytes)   // bound only here
// 627-632 (accept path)
return WebTransportNetworkBidirectionalStream(
    stream: stream, timeoutMilliseconds: ..., initialPayload: prefix.remainingPayload, manager: manager)
```

**What correct looks like.** A read returns at most `maximumBytes` and the unread remainder
stays available for the next read, exactly as the network read path already behaves.

**Smallest correct fix.** Split the buffered payload:

```swift
let chunk = initialPayload.prefix(max(0, maximumBytes))
await state.restoreInitialPayload(Data(initialPayload.dropFirst(chunk.count)))
return Data(chunk)
```

(adding a `restoreInitialPayload` mutator to `WebTransportNetworkStreamState`), or make
`maximumBytes` a floor by returning `initialPayload` only when
`initialPayload.count <= maximumBytes`.

---

## F-swift-architecture-05 — S1 — logic — the magic value `16` is used as "argument not supplied", so an explicit `maxConcurrentConnections: 16` is silently ignored

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1046`
(init 1021–1162; public caller `Swift/Sources/WebTransport/WebTransport.swift:437-453`)

**What is wrong.** The listener implements precedence between the legacy
`maxConcurrentConnections` parameter and the newer `WebTransportAdmissionPolicy` by
comparing the argument against its own default, `16`. An operator who explicitly asks for
16 concurrent connections while supplying a policy that carries another limit gets the
policy's number instead: the secret-relevant resource ceiling is silently *not* what was
requested (higher, if the policy is `.publicFacing` = 256; lower if the policy is smaller).
The public `WebTransportServer.listen(on:maxConcurrentConnections:)` passes its `Int = 16`
straight through, so the bug is reachable from the shipped API, and the regression test only
covers `1` and the invalid `0`/`-1` cases
(`Swift/Tests/WebTransportNetworkRuntimeTests/WebTransportServerPolicyTests.swift:146-168`),
so nothing pins the sentinel behaviour.

**Evidence (quoted code):**

```swift
// 1045-1053
var admission = try admission.validated()
if maxConcurrentConnections != 16 {
    guard maxConcurrentConnections > 0 else { throw ... }
    admission.maxConcurrentConnections = maxConcurrentConnections
}
```

```swift
// WebTransport.swift:437-443 — explicit value forwarded verbatim
public func listen(on endpoint: WebTransportEndpoint,
                   maxConcurrentConnections: Int = 16) async throws -> WebTransportListeningServer {
    let server = try WebTransportQUICServer(
        endpoint: endpoint.networkEndpoint,
        maxConcurrentConnections: maxConcurrentConnections, ...)
```

**What correct looks like.** "Not supplied" and "supplied as 16" are distinguishable, and an
explicit value always wins (the documented intent of the `!= 16` check, and of the comment
at lines 1035–1044).

**Smallest correct fix.** Make the parameter `Int?` with default `nil` in
`WebTransportQUICServer.init`, its `convenience init`, and
`WebTransportServer.listen(on:maxConcurrentConnections:)`, and use
`if let maxConcurrentConnections { admission.maxConcurrentConnections = maxConcurrentConnections }`.
Add a test for the explicit-16-plus-non-default-policy case.

---

## F-swift-architecture-06 — S2 — incomplete — the module's WebTransport flow control, and the multi-session path it gates, are unreachable from the shipped runtime

**File:** `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift:1544`
(`webTransportFlowControlNegotiated`; also `popFlowControlCapsule` 803, `validateSessionAdmission` 1524)

**What is wrong.** `WebTransportHTTP3Core` implements draft-16 flow control end to end:
`WebTransportFlowControlState`, strictly increasing WT_MAX_* capsules, blocked capsules,
2^60 stream ceilings, directional byte accounting — and uses flow-control negotiation as the
precondition for more than one session per connection. The runtime never turns any of it on,
and never drains or transmits the capsules it produces:

* The runtime's local settings are always one of the three profiles in
  `HTTP3Settings.swift:81-107`; none of them sets
  `settingsWTInitialMaxData`/`settingsWTInitialMaxStreamsBidi`/`...Uni`
  (`HTTP3Constants.swift:101-103`). With `webTransportFlowControlNegotiated =
  localSettings.enabled(with: remoteSettings)` this is **always false** on both client and
  server, so `isEnabled` is false, `recordData`/`registerStream` no-op, and
  `enqueueBlockedFlowCapsule` can never be reached from a production session.
* `validateSessionAdmission()` therefore always throws for a second concurrent session, so
  the multi-session support the manager and the shipped `WebTransportLibrarySmokeMatrix.runMultiSession`
  exercise cannot occur through the runtime.
* `popFlowControlCapsule` — the only way a blocked capsule is ever serialised — has no
  caller in `Swift/Sources` outside `LibrarySmokeClient/main.swift:961,974`, and the runtime
  never serialises `.maxData`/`.maxStreams*`/`.dataBlocked`/`.streamsBlocked*` either
  (grep over `Swift/Sources`: emission sites are `WebTransportFlowControl.swift`
  (codec), `WebTransportSession.swift` (queueing) and the smoke client only).

The public compliance matrix nonetheless advertises this family as implemented
(`WebTransportComplianceMatrix.swift:53-59`), and the module's public API (`flowState(for:)`,
`popFlowControlCapsule`, `makeDrainSessionCapsule`'s flow-control siblings) suggests the
runtime drives it. This is a module boundary that lies: the capability lives in one module,
is exercised by the CLI, and is dead in the shipped library.

**Evidence (quoted code):**

```swift
// WebTransportSession.swift:1544-1549
private var webTransportFlowControlNegotiated: Bool {
    guard let remoteSettings = http3.remoteSettings else { return false }
    return http3.localSettings.webTransportFlowControlEnabled(with: remoteSettings)
}
// HTTP3Settings.swift:81-85 — no WT_INITIAL_MAX_* entry
public static let webTransportDraft16Defaults = HTTP3Settings(unchecked: [
    WebTransportHTTP3DraftConstants.current.settingsEnableConnectProtocol: 1,
    WebTransportHTTP3DraftConstants.current.settingsH3Datagram: 1,
    WebTransportHTTP3DraftConstants.current.settingsWTEnabled: 1,
])
// WebTransportFlowControl.swift:362-363, 383-384 — no-ops when disabled
public mutating func recordData(bytes: Int) throws { guard isEnabled else { return } ... }
public mutating func registerStream(_ form: WebTransportStreamForm) throws { guard isEnabled else { return } ... }
```

**What correct looks like.** Either the runtime negotiates WebTransport flow control (it
advertises the settings, grants credit, emits WT_MAX_* and blocked capsules, and supports
more than one session per connection), or the dead half is not shipped as if it were wired:
the unreachable path is removed from the runtime-facing API surface and the compliance claim
is corrected. A silent split — the exact class this area audits — is the one option that is
not correct.

**Smallest correct fix.** In the runtime, add the WT flow-control settings to the profile(s)
that are meant to use them, then drain `popFlowControlCapsule` for the session after any
`sendStreamPayload`/`openBidirectionalStream` failure and write the capsules on the CONNECT
stream; if that is out of scope for this release, delete the unreachable flow-control branch
from the runtime-facing path and amend the compliance item.

---

## F-swift-architecture-07 — S2 — bug — a stream whose prefix names an unknown session is read, buffered, and then dropped with `unexpectedFrame`

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:620`
(guard 620–626; manager side `WebTransportSession.swift:903-932`)

**What is wrong.** For a server-role manager, `sessionForIngressOrPending` returns `nil` for
a stream prefix naming a session that does not exist (`WebTransportSession.swift:1484-1490`).
`acceptBidirectionalStreamWithActions` treats that as "pending", buffers the stream and
returns a non-nil `prefix` (lines 923–931). The runtime then rejects the result because
`prefix.sessionID.rawValue != sessionID` and throws `unexpectedFrame` — after
`readFirstChunk` has already consumed the peer's bytes. The peer receives no RESET (the
draft requires a reset for a stream on a non-existent session) and the bytes are lost; the
manager also keeps the buffered stream in `bufferedStreamsByID` forever, because neither
`promoteBufferedStreams` (needs the session to be accepted) nor `discardBufferedIngress`
(runs only for a known session) will ever touch it. Any peer can trigger this after one
session is established by opening a bidirectional stream prefixed with a different
`sessionID`; the caller sees the misleading `unexpectedFrame` rather than
session-gone/unexpected-session.

**Evidence (quoted code):**

```swift
// 614-626
let accepted = try await manager.withManager { manager in
    try manager.acceptBidirectionalStreamWithActions(streamID: stream.streamID, firstBytes: firstChunk)
}
guard let prefix = accepted.prefix,
    accepted.rejectionFrame == nil,
    prefix.form == .bidirectional,
    prefix.sessionID.rawValue == sessionID
else {
    throw WebTransportNetworkRuntimeError.unexpectedFrame
}
```

**What correct looks like.** A stream for an unknown/other session is refused at the
protocol level: send RESET_STREAM (session-gone / buffered-stream-rejected as appropriate),
do not retain manager state for it, and report an error that names the condition
(`.sessionGone`/`.h3ID`) rather than `.unexpectedFrame`. Note the sibling `rejectionFrame`
produced by the manager for the buffered-ingress limit is likewise never sent by the
runtime; the runtime treats a non-nil `rejectionFrame` the same way.

**Smallest correct fix.** Before throwing, send the frame the manager returned
(`accepted.rejectionFrame`, or a `.resetStreamAt(...)` with the session-gone code) on the
stream; make the runtime ask the manager which session a first chunk belongs to (e.g. parse
the prefix once and compare) so a foreign-session stream is never registered/buffered, and
map the failure to `WebTransportDraft16Error(kind: .sessionGone)`.

---

## F-swift-architecture-08 — S2 — unsafe — no per-session demultiplexing for the connection-scoped datagram channel or inbound-stream queue (latent)

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:672`
(`receiveDatagram` 657–679; stream side 598–605)

**What is wrong.** A `WebTransportNetworkSession` owns one QUIC connection and reads the
connection's single datagram channel (`self.connection.datagrams`, lines 643/664) and the
connection's single inbound-stream collector. `receiveDatagram` parses the datagram's
session ID only *after* `datagrams.receive()` has removed it from the channel, and then
throws `.invalidPayload` when the ID is not this session's — the datagram is consumed and
lost with no way for the owning session to see it. The stream side is the same shape: any
`acceptBidirectionalStream` call takes the next bidirectional stream from the shared
collector regardless of which session its prefix names. Today this is latent because the
runtime serves at most one session per connection (see F-swift-architecture-06), but the
HTTP3Core manager, the shipped `WebTransportLibrarySmokeMatrix.runMultiSession` scenario and
the compliance matrix all model multiple sessions per connection, so the two layers disagree
about a contract that will be exercised the moment flow control is enabled.

**Evidence (quoted code):**

```swift
// 667-678
let receivedDatagram = try await InteroperableQUICHelpers.withTimeout(...) {
    try await datagrams.receive().content
}
return try await manager.withManager { manager in
    let responseSessionID = try manager.receiveDatagramFrame(.datagram(receivedDatagram))
    guard responseSessionID.rawValue == self.sessionID,
        let payload = manager.popDatagramPayload(sessionID: responseSessionID)
    else { throw WebTransportNetworkRuntimeError.invalidPayload }
    return payload
}
```

**What correct looks like.** The connection-scoped receive paths are demultiplexed by
session: a datagram for session B is delivered to (or parked for) session B rather than
consumed and dropped by session A, and the inbound-stream queue hands a stream only to the
session named in its prefix. Equivalently: the runtime states and enforces one session per
connection and the module-level multi-session API is not shipped as reachable.

**Smallest correct fix.** Move the datagram/stream demux above the session objects (a
per-connection dispatcher keyed by session ID), or have `receiveDatagram` requeue a
foreign-session datagram instead of discarding it — but requeue-without-demux only reorders
the race, so the dispatcher is the correct shape.

---

## F-swift-architecture-09 — S2 — deps — the ALPN identifier `h3` is duplicated across modules instead of shared

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1600`
(`makeBaseQUIC`); declaration `Swift/Sources/WebTransportHTTP3Core/WebTransportSecurityPolicy.swift:2`

**What is wrong.** `WebTransportHTTP3Core` declares the single source of truth for the
required ALPN identifier (`WebTransportALPNPolicy.requiredHTTP3Protocol = "h3"`) and exposes
validation helpers, but the production runtime hard-codes the literal in its QUIC
configuration and never calls the policy. The two can diverge with no compile or test
failure, and the shipped security policy type is dead code on the production path (its only
`Sources` callers are the CLI conformance scenarios). This is precisely the
"cross-module constant that must agree" class in scope.

**Evidence (quoted code):**

```swift
// WebTransportInteroperableNetworkRuntime.swift:1600
QUIC(alpn: ["h3"]) { UDP() }
// WebTransportSecurityPolicy.swift:1-11
public enum WebTransportALPNPolicy {
    public static let requiredHTTP3Protocol = "h3"
    public static func validateNegotiatedProtocol(_ protocolName: String?) throws { ... }
```

`grep -rn 'WebTransportALPNPolicy' Swift/Sources` → declaration plus
`WebTransportCLIConformance.swift:719` only.

**What correct looks like.** One exported constant used by both the QUIC configuration and
the policy, so a change cannot silently desynchronise offer and validation.

**Smallest correct fix.** `QUIC(alpn: [WebTransportALPNPolicy.requiredHTTP3Protocol]) { UDP() }`
(the runtime already imports `WebTransportHTTP3Core`); if the framework-level negotiation
makes the validator redundant, say so in the policy type and remove the unused public
surface rather than leaving two sources of truth.

---

## F-swift-architecture-10 — S2 — docs — the shipped DocC promises a unidirectional-stream API the product does not have, and claims the protocol helpers are not public

**File:** `Swift/Sources/WebTransport/WebTransport.docc/WebTransport.md:10` (also 13–16);
manifests `Package.swift:18-41`, `Swift/Package.swift:18-41`

**What is wrong.** The DocC overview says the `WebTransport` module exposes "the public
Swift concurrency API for opening WebTransport sessions, bidirectional streams,
**unidirectional streams**, datagrams, and graceful close/drain flows", and that the package
"keeps deterministic protocol helpers out of the public release surface". Neither is true of
the shipped product: `WebTransportSession` has `openBidirectionalStream`/
`acceptBidirectionalStream` only — no unidirectional API anywhere in
`Swift/Sources/WebTransport` — while the root manifest publishes `WebTransportQUICCore`,
`WebTransportTLSCore`, `WebTransportHTTP3Core`, `WebTransportUDPApple` and
`WebTransportCryptoApple` as library products. A customer reading the docs will look for a
capability that does not exist, and a reviewer reading "helpers are not public" will not
expect the whole deterministic protocol stack to be a product.

**Evidence (quoted doc, and the product surface):**

```
WebTransport.md:10  opening WebTransport sessions, bidirectional streams, unidirectional streams,
WebTransport.md:15  network I/O through the WebTransport Network.framework runtime and keeps
WebTransport.md:16  deterministic protocol helpers out of the public release surface.
```

`grep -rn -i unidirectional Swift/Sources/WebTransport/` → only the doc sentence.
`grep -n 'public func openBidirectionalStream\|public func acceptBidirectionalStream'
Swift/Sources/WebTransport/WebTransport.swift` → 314, 318 (no unidirectional equivalent).
`Package.swift:18-41` → `.library(name: "WebTransportQUICCore" ...)`, `"WebTransportTLSCore"`,
`"WebTransportHTTP3Core"`, `"WebTransportUDPApple"`, `"WebTransportCryptoApple"`.

**What correct looks like.** Documentation and product surface agree. Either the
unidirectional API is added to the shipped `WebTransport` product (the manager already
supports it: `WebTransportSessionManager.openUnidirectionalStream` /
`acceptUnidirectionalStream`), or the docs stop claiming it; and the "helpers are not
public" sentence is removed or the products are narrowed.

**Smallest correct fix.** Add `openUnidirectionalStream()`/`acceptUnidirectionalStream()` to
the public `WebTransportSession` (wrapping the existing manager calls) and correct
WebTransport.md:15-16; or correct both doc claims in the same edit.

---

## F-swift-architecture-11 — S2 — logic — `close()` and `drain()` are not idempotent: a second call throws `sessionGone`

**File:** `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift:705`
(`makeCloseSessionCapsuleResult`; `sessionForIngress` 1470–1482; public wrapper
`Swift/Sources/WebTransport/WebTransport.swift:351`)

**What is wrong.** Closing a session sets its state to `.closed`; every later call that must
find the session (`makeCloseSessionCapsuleResult`, therefore the public
`WebTransportSession.close(...)`, and `drain()` through `makeDrainSessionCapsule`) goes
through `sessionForIngress`, which throws `.sessionGone` for `.closed`. An application that
closes a session on the error path and again in a `defer` — a normal Swift pattern, and the
same one the resource-leak hardening elsewhere in this file relies on — gets a spurious
error from the teardown itself. `WebTransportListeningServer.shutdown()` is documented and
tested as idempotent, so the equivalent guarantee is expected one layer down but absent.

**Evidence (quoted code):**

```swift
// 704-705
try validateSettingsReady()
_ = try sessionForIngress(sessionID)          // throws .sessionGone when state == .closed
...
// 1474-1481
switch session.state {
case .requested, .accepted, .draining: return session
case .closed: throw WebTransportDraft16Error(kind: .sessionGone, ...)
case .rejected: throw WebTransportDraft16Error(kind: .sessionGone, ...)
}
```

**What correct looks like.** A close/drain of an already-closed session is a no-op (or
returns the existing close frame); only genuinely wrong states (e.g. a drain before the
session is established) throw.

**Smallest correct fix.** In `makeCloseSessionCapsuleResult` (and the drain path), accept
`case .closed` as success: if `sessionsByID[sessionID]` is already `.closed`, return the
serialised capsule without re-running `markSessionClosed` (or return early from the public
wrapper). Add a test that closes twice and drains after close.

---

## F-swift-architecture-12 — S3 — deps — `WebTransportCLIConformance` declares a dependency it never imports

**File:** `Package.swift:66` (list 64–74); identical in `Swift/Package.swift:72`

**What is wrong.** The target declares `WebTransportCryptoApple` but does not import or use
it. Module boundaries should be exactly the set of modules a target consumes; a stale
declaration keeps an otherwise-unused library in the build graph, defeats the
`check-manifest-sync.sh` spirit, and hides real drift (this is the mirror image of A-0006:
that task covers imports with no declaration, this is a declaration with no import). The
same check would be needed to catch it automatically.

**Evidence.** `grep -rn 'CryptoApple\|QUICInitialKeyDerivation\|QUICPacketProtection'
Swift/Sources/WebTransportCLIConformance/` → no matches; the file's imports are
`Foundation, WebTransport, WebTransportHTTP3Core, WebTransportQUICCore, WebTransportTLSCore,
WebTransportUDPApple` (lines 1–6).

**What correct looks like.** A target's dependency list equals the set of project modules
its sources import.

**Smallest correct fix.** Delete `"WebTransportCryptoApple",` from
`WebTransportCLIConformance.dependencies` in both manifests (and extend the A-0006 check to
fail on unused declarations as well).

---

## F-swift-architecture-13 — S3 — dead — four unused constants, a duplicated private helper, and a vestigial parameter

**File:** `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1571`
(constants 1571–1574; duplicate helpers 106–111 and 1547–1552; parameter 1649–1651)

**What is wrong.** Dead declarations in a 2.5k-line module the size of a small library:

* `InteroperableQUICRuntime.defaultAuthority`, `defaultPath`, `defaultOrigin`,
  `defaultProtocol` have no reader anywhere in `Swift/Sources` (the same literals are
  repeated as default arguments on the public functions and initializers).
* `renderSettings` is defined twice, byte-for-byte identical, once in `WebTransportQUICClient`
  and once in `WebTransportQUICServer`.
* `makeRequestStreamPayload(streamID:requestFrame:)` ignores `streamID` and returns
  `requestFrame.encode()`.

**Evidence.**

```
$ grep -rn 'defaultAuthority\|defaultPath\|defaultOrigin\|defaultProtocol' Swift/Sources
.../WebTransportInteroperableNetworkRuntime.swift:1571-1574   (definitions only)
$ grep -rn 'func renderSettings' Swift/Sources
.../WebTransportInteroperableNetworkRuntime.swift:106
.../WebTransportInteroperableNetworkRuntime.swift:1547
// 1649-1651
static func makeRequestStreamPayload(streamID: UInt64, requestFrame: HTTP3Frame) throws -> Data {
    try requestFrame.encode()
}
```

**What correct looks like.** One definition of each shared literal/helper, and no parameter
that is not used.

**Smallest correct fix.** Use the constants as the defaults (or delete them), hoist
`renderSettings` to `InteroperableQUICRuntime` once, and drop `streamID` from
`makeRequestStreamPayload` (and its call site at 257).

---

## F-swift-architecture-14 — S3 — placeholder — the shipped compliance matrix can only ever report PASS

**File:** `Swift/Sources/WebTransportHTTP3Core/WebTransportComplianceMatrix.swift:2`
(enum 1–3; items 25–79; `allPass` 81–83)

**What is wrong.** `WebTransportDraft16ComplianceStatus` has exactly one case, `pass`, every
one of the six requirement families is hard-coded to `.pass`, and `allPass` merely re-checks
those hard-coded values — so the type is a tautology that can never report a gap, while it
is shipped in the public `WebTransportHTTP3Core` product as the project's definition of done
(and is cited by version metadata as if it were a check). The evidence strings name real test
suites, but nothing ties the claim to their results, and at least one claim (flow control)
is unreachable in production (F-swift-architecture-06). This is the placeholder pattern the
severity rubric names, sitting on a documentation/metadata path rather than a runtime one,
hence S3 rather than S0.

**Evidence (quoted code):**

```swift
public enum WebTransportDraft16ComplianceStatus: String, Equatable, Sendable {
    case pass = "PASS"                       // only case
}
...
status: .pass,                               // every item
public static var allPass: Bool {
    definitionOfDone.allSatisfy { $0.status == .pass && !$0.evidence.isEmpty && !$0.documentedBehavior.isEmpty }
}
```

**What correct looks like.** A compliance status that can express not-implemented/partial/
unknown, or a plain document; if it stays code, `allPass` should be derivable from facts
(tests/CI results) rather than from literals.

**Smallest correct fix.** Either move the matrix to documentation, or add
`case partial`, `case notImplemented`, `case unknown` and set the current values honestly
(e.g. flow control `.partial` while F-06 stands); a one-line honest step is to delete the
`allPass` property so nothing can treat the literal table as a check.

---

## Categories checked and found CLEAN

* **logic / bug — module dependency graph.** The SwiftPM target graph is a DAG; I found no
  circular dependency (`WebTransport` → `NetworkRuntime` → `{HTTP3Core, TLSCore, CryptoApple,
  UDPApple, SecurityShim}` → `QUICCore`; `TLSCore`/`HTTP3Core`/`CryptoApple` → `QUICCore`).
  A per-target comparison of `import`/`@testable import` lines against both manifests'
  dependency lists (all 14 source targets and all 7 test targets) shows **no missing
  declaration and no import of an undeclared module** — the A-0001 defect class is fully
  fixed at this commit. The only mismatch is the unused declaration in
  F-swift-architecture-12.
* **unsafe — crash constructs on production paths.** `grep -rnE 'fatalError\(|preconditionFailure\(|assert\(|precondition\(|try!|as!|unsafeBitCast'`
  over `Swift/Sources` returns no occurrence; the single `unsafeDowncast` (server identity,
  `WebTransportServerIdentity.swift:276`) is guarded by a `CFGetTypeID` check against
  `SecIdentityGetTypeID()` and is sound. Error propagation is `throws`-based throughout;
  `fatalError` is not used at all.
* **unsafe — C shim `WebTransportSecurityShim`.** Ownership and threading reviewed and found
  correct: `outItems` follows the Create Rule, is explicitly NULLed on both the parameter
  error path and the exception path, and is declared `CF_RETURNS_RETAINED` in the header;
  `outStatus`/`outExceptionName` are optional and handled; the exception name is copied into
  a `_Thread_local` buffer before the Objective-C frame unwinds and the header documents the
  "valid until the next call on the same thread" contract, which the Swift caller honours by
  copying immediately (`WebTransportServerIdentity.swift:227-229`); no shared mutable state
  beyond that buffer. Nit, not filed: a >127-byte exception name is truncated by `strlcpy`
  into `nameBuffer[128]`.
* **unsafe — `Sendable` / strict concurrency (compiler-enforced).** CI builds both packages
  with `-strict-concurrency=complete -require-explicit-sendable -warnings-as-errors`
  (`swift-ci.yml:37-44`), so the `@unchecked Sendable` opt-outs are the only unchecked
  surface. I read them all: `WebTransportNetworkBidirectionalStream`, `WebTransportSession`
  (public), `WebTransportNetworkSession`, `WebTransportQUICServer`,
  `InteroperableQUICConnectionBudget/Lease`, `ConnectionRateLimiter`, `PendingTimer`. Each
  confines mutable state to an actor or `Mutex`; the defects found are the specific ones
  filed above (F-02, F-08), not a general isolation break. Actor re-entrancy and
  continuation-exactly-once are handled consistently by `OneShotContinuation`, `RaceCompletion`,
  the waiter-id queues and `PendingTimer`.
* **dead.** No unused file, target, product or public type was found beyond F-13/F-14; the
  `WebTransportALPNPolicy` and `TLSPinnedCertificateTrustPolicy` types are unused by the
  runtime (folded into F-09/F-10 as contract/documentation issues rather than re-filed).
* **perf.** Nothing material filed. Noted only: `WebTransportSessionManager.bufferedIngressSessionCount`
  and `buffer()` are O(sessions)/O(streams) per call, and the manager is copied by value
  into the session at construction; both are bounded by the configured limits and are not on
  a hot per-byte path (the per-chunk path goes through the actors).
* **style.** Out of the functional remit; the repo's `swift format lint --strict` gate covers
  `Swift/Sources` and `Swift/Tests` (the manifests' formatting is A-0007). No style finding
  is filed here.
* **secrets.** No credential, key, token or `.env` content was read, printed or copied. No
  live-looking credential was encountered in the audited files.
* **test.** The runtime has real regression coverage for accept-waiter starvation, graceful
  shutdown, establishment-failure naming, stream-chunk classification and server identity
  (7 test targets, 308 tests). I did not file a separate "missing test" finding; instead each
  defect above names the regression test it implies. The one weak assertion I found is
  `WebTransportPublicAPITests.swift:178-179`, which asserts the hard-coded
  `datagramsAvailable == true`; it is cited inside F-swift-architecture-03 rather than filed
  twice.
