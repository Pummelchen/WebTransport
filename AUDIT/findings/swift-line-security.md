# swift-line-security — L3 function/line + L4 security (Swift + the C shim)

Scope: `/Users/node3/Downloads/WebTransport/Swift/Sources/**`, including
`WebTransportSecurityShim`'s C code. Branch `audit/2026-09-15`, base `196324e`.
Phase B — enumeration only. Nothing was modified, no server was started, no state-changing git
command was run. All findings are read from committed source; the only commands executed were
read-only greps, the SDK header read, and two throwaway Swift probes in `/tmp` used as evidence.

**Counts: S0 0 · S1 3 · S2 7 · S3 2 (12 findings).**

The shipped runtime (`WebTransportNetworkRuntime`, `WebTransport`) performs QUIC/TLS through
Network.framework; `WebTransportQUICCore`, `WebTransportHTTP3Core`, `WebTransportTLSCore` and
`WebTransportCryptoApple` are nonetheless separately vended library products, so a defect in them
ships to customers as an API even when the top-level runtime does not exercise it. Every finding
below says which path is affected.

---

## F-swift-line-security-01 — S1 — bug — `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift:1440`

**Session teardown resets and stops every associated stream regardless of which half this endpoint owns.**

### What is wrong

`terminateAssociatedStreams(for:requestStreamID:)` walks `streamIDsBySessionID[sessionID]`,
`bufferedStreamIDsBySessionID[sessionID]` and emits **both** a RESET_STREAM_AT and a STOP_SENDING
frame for every stream id it finds:

```swift
// WebTransportSession.swift:1435-1441
let activeStreamIDs = (streamIDsBySessionID[sessionID] ?? []).sorted()
for streamID in activeStreamIDs {
    guard var stream = streamsByID[streamID] else { continue }
    streamResetFrames.append(stream.reset(applicationErrorCode: wtSessionGone))
    streamStopSendingFrames.append(stream.stopSending(applicationErrorCode: wtSessionGone))
```

The set is not restricted to streams whose send half (for RESET_STREAM) or receive half (for
STOP_SENDING) this endpoint owns. Peer-initiated **unidirectional** streams reach
`streamsByID` through `acceptUnidirectionalStreamWithActions` (`WebTransportSession.swift:985-987`
calls `register(stream)`), and locally initiated unidirectional streams reach it through
`openUnidirectionalStream` (`WebTransportSession.swift:865`). For a peer-initiated unidirectional
stream this endpoint is the *receiver only*: it cannot send RESET_STREAM. For a locally initiated
unidirectional stream it is the *sender only*: it cannot send STOP_SENDING.

The direction rule is implemented one layer down but is bypassed by `reset()`/`stopSending()`:

```swift
// QUICCoreState.swift:718-733
private func ensureCanSend() throws {
    ...
    if direction == .unidirectional && localRole != endpointRole(for: initiator) {
        throw QUICStateError.streamStateViolation("cannot send on peer-initiated unidirectional stream")
    }
}
private func ensureCanReceive() throws {
    ...
    if direction == .unidirectional && localRole == endpointRole(for: initiator) {
        throw QUICStateError.streamStateViolation("cannot receive on locally initiated unidirectional stream")
    }
}
```

`QUICStreamState.reset` (`QUICCoreState.swift:706-710`) and `QUICStreamState.stopSending`
(`QUICCoreState.swift:712-716`) never call either guard, and
`WebTransportStreamState.reset`/`stopSending` (`WebTransportStreams.swift:186-198`) do not either.

### Evidence

- The code above. RFC 9000 §19.4: "An endpoint that receives a RESET_STREAM frame for a send-only
  stream MUST terminate the connection with error STREAM_STATE_ERROR." RFC 9000 §19.5 has the
  mirror rule for a STOP_SENDING frame on a receive-only stream. The peer therefore kills the
  connection on the teardown path that exists to end a session gracefully.
- The sibling C99 implementation of the same draft guards exactly this, which is the
  copy-paste-divergence proof (the two implementations share no files but do share the contract):

```
C99/src/http3/driver.c:917-929
static int has_send_half(const wt_quic_connection_t *connection, uint64_t stream_id) {
  if (wt_quic_stream_id_is_bidirectional(stream_id) != 0) return 1;
  return wt_quic_stream_id_from_client(stream_id) == (connection->config.role == WT_QUIC_ROLE_CLIENT);
}
static int has_receive_half(const wt_quic_connection_t *connection, uint64_t stream_id) { ... }

C99/src/http3/driver.c:979-998
status = (skip_reset != 0 || has_send_half(driver->connection, stream_id) == 0)
             ? WT_OK
             : wt_quic_connection_reset_stream_at(...);
...
if (has_receive_half(driver->connection, stream_id) != 0) {
  (void)wt_quic_connection_stop_sending(...);
}
```

- Reachability: the shipped `WebTransportNetworkRuntime` discards the frames returned by
  `makeCloseSessionCapsule` (it calls the non-`Result` variant,
  `WebTransportInteroperableNetworkRuntime.swift:763-769`), so this is latent for the top-level
  binary. It is live for consumers of the `WebTransportHTTP3Core` library product, which exposes
  `makeCloseSessionCapsuleResult`, `resetStream`, `stopSendingStream`, and
  `terminateAssociatedStreams`' callers.

### What correct looks like

Each frame is emitted only on a half this endpoint owns: RESET_STREAM when
`hasSendHalf(streamID)`, STOP_SENDING when `hasReceiveHalf(streamID)`, for both header forms
(bidirectional streams own both halves). Nothing is emitted for the other half.

### Smallest correct fix

In `terminateAssociatedStreams`, gate the two appends on the stream's direction/initiator — or,
better, have `WebTransportStreamState.reset`/`stopSending` call the existing `ensureCanSend` /
`ensureCanReceive` (made `internal` instead of `private`) and skip the frame on
`streamStateViolation`, mirroring `has_send_half`/`has_receive_half`.

---

## F-swift-line-security-02 — S1 — incomplete — `Swift/Sources/WebTransportQUICCore/QUICPacket.swift:310`

**Short-header reserved bits are never validated, although the long-header and Retry decoders do validate them.**

### What is wrong

The long-header decoder rejects non-zero reserved bits (`first & 0x0c`, RFC 9001 §5.4), and the
Retry decoder does the same:

```swift
// QUICPacket.swift:90-94 (long header)
// RFC 9001 section 5.4: the two reserved bits must be zero after header
// protection is removed; a non-zero value is a PROTOCOL_VIOLATION.
guard (first & 0x0c) == 0 else {
    throw QUICCodecError.malformed("long header reserved bits are not zero")
}
// QUICPacket.swift:214-216 (Retry)
guard (first & 0x0c) == 0 else { throw QUICCodecError.malformed("Retry packet reserved bits are not zero") }
```

`QUICShortHeaderPacket.decode` checks only the header-form bit (0x80) and the Fixed Bit (0x40),
then goes straight to the packet number:

```swift
// QUICPacket.swift:303-310
guard (first & 0x80) == 0 else { throw QUICCodecError.malformed("not a short header packet") }
guard (first & 0x40) != 0 else { throw QUICCodecError.malformed("short header fixed bit is not set") }

let packetNumberLength = Int(first & 0x03) + 1
let keyPhase = (first & 0x04) != 0
```

The short header's reserved bits are `0x18`, and are not tested anywhere in the file (grep for
`0x18` in `QUICPacket.swift` returns nothing).

### Evidence

- The quoted code; `grep -n "0x18" WebTransportQUICCore/QUICPacket.swift` → no match.
- RFC 9001 §5.4: an endpoint "MUST treat receipt of a packet that has a non-zero value for these
  bits, after removing both packet and header protection, as a connection error of type
  PROTOCOL_VIOLATION."
- The sibling C99 implementation checks both forms, so the omission is Swift-only:

```
C99/src/quic/packet.c:286   out->reserved_bits_set = (first & 0x0cU) != 0U ? 1 : 0;   /* long header */
C99/src/quic/packet.c:404-406
  /* RFC 9000 section 17.3's reserved bits, reported for the same reason the long header's are ... */
  out->reserved_bits_set = (first & 0x18U) != 0U ? 1 : 0;                             /* short header */
C99/src/quic/packet_io.c:218-221  if (reserved_bits_set != 0) return WT_ERR_PROTOCOL;
```

- This decoder is public API of the shipped `WebTransportQUICCore` product; the top-level runtime
  gets QUIC from Network.framework, so the peer-input path that reaches it is a library consumer's.

### What correct looks like

`QUICShortHeaderPacket.decode` rejects `(first & 0x18) != 0` with the same
`QUICCodecError.malformed("short header reserved bits are not zero")` the long-header path uses
(after header protection removal, which is the caller's step, as the long-header comment states).

### Smallest correct fix

Add, immediately after the Fixed-Bit guard at `QUICPacket.swift:307`:

```swift
guard (first & 0x18) == 0 else {
    throw QUICCodecError.malformed("short header reserved bits are not zero")
}
```

---

## F-swift-line-security-03 — S1 — unsafe — `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:2390`

**The per-connection inbound-stream queue has no bound, and post-establishment unidirectional streams have no consumer at all.**

### What is wrong

Every inbound QUIC stream is appended to `queued[direction]` and only removed by a waiter:

```swift
// WebTransportInteroperableNetworkRuntime.swift:2330, 2390
private var queued: [Int: [Element]] = [:]
...
queued[direction, default: []].append(stream)
```

There is no cap on `queued`, no age-out, and no path that drops a queued stream when nobody asks
for it. The only consumers in the whole runtime are:

```
601-602  acceptBidirectionalStream  → inboundStreams.next(direction: .bidirectional)
1447     server's own CONNECT request stream → next(direction: .bidirectional)
1890     readPeerControlStream (establishment only, looks for type 0x00/0x02/0x03)
```

`WebTransportSessionManager.acceptUnidirectionalStream` exists
(`WebTransportHTTP3Core/WebTransportSession.swift:949`) but has **no caller** in
`WebTransportNetworkRuntime` or `WebTransport` (grep: no match). The public
`WebTransportSession` API only offers `openBidirectionalStream()` and
`acceptBidirectionalStream()` (`WebTransport/WebTransport.swift:314-320`). So every
peer-initiated unidirectional stream is enqueued and retained for the life of the connection; the
same is true of peer-initiated bidirectional streams whenever the application does not accept
them. The collector is per connection, is handed the `QUIC.Stream` object itself (holding its
buffers), and the connection is admitted before anything is authenticated.

### Evidence

- The quoted enqueue and the four call sites above; `grep -rn "acceptUnidirectionalStream"
  WebTransportNetworkRuntime/ WebTransport/` → no matches.
- The queue is never cleared: `fail(_:)` (`:2441-2450`) only resumes waiters; `queued` is left in
  place.
- QUIC's own stream limit does not bound this over time: RFC 9000 §4.6 counts a stream against
  `initial_max_streams_*` until it is closed, and a stream the peer FINs reaches the closed state
  independent of whether the application reads it, so a peer can retire streams and open more
  indefinitely. Even in the conservative reading (streams never retire) the queue retains the
  full concurrent-stream allowance of `QUIC.Stream` objects per connection forever.
- Confidence: the absence of any bound and the absence of a unidirectional consumer are certain
  from the code; the exact growth rate depends on Network.framework's stream accounting, so the
  remote-growth consequence is marked SUSPECTED in the JSON.

### What correct looks like

A bounded queue: a cap on queued streams per direction (and a reset of excess streams, e.g.
`WT_BUFFERED_STREAM_REJECTED`/`H3_EXCESSIVE_LOAD`), plus a consumer for unidirectional streams (or
an explicit refusal at accept time). At minimum the queue must not retain streams the endpoint has
decided it will never hand out.

### Smallest correct fix

Add a `maxQueuedStreams` (default e.g. 16, the advertised stream limit) to
`InteroperableQUICStreamQueue`; in `enqueue`, when `queued[direction]?.count >= maxQueuedStreams`,
stop the stream with an application error instead of appending it.

---

## F-swift-line-security-04 — S2 — dead — `Swift/Sources/WebTransportQUICCore/QUICCoreState.swift:679`

**Both final-size checks in `QUICStreamState.receive` are unreachable, so FINAL_SIZE_ERROR is never produced by this type.**

### What is wrong

```swift
// QUICCoreState.swift:662-692
public mutating func receive(_ frame: QUICFrame) throws -> Data {
    try ensureCanReceive()                      // throws when receiveClosed || stopSendingSent
    ...
    if let finalReceiveSize, attempted > finalReceiveSize {          // 679: always nil here
        throw QUICStateError.streamStateViolation("STREAM data exceeds final size")
    }
    receiveOffset = attempted
    if fin {
        if let finalReceiveSize, finalReceiveSize != attempted {     // 685: always nil here
            throw QUICStateError.streamStateViolation("inconsistent final stream size")
        }
        finalReceiveSize = attempted                                 // 688: only assignment
        receiveClosed = true
    }
```

`finalReceiveSize` is `private(set)` and is assigned exactly once in the file, at line 688,
together with `receiveClosed = true`. `ensureCanReceive()` (`:727-734`) throws whenever
`receiveClosed` is set, so by the time control reaches line 679 `finalReceiveSize` is necessarily
`nil`, and by the time control reaches line 685 `receiveClosed` was false a moment ago, so
`finalReceiveSize` is still `nil`. Both `if let` bodies are dead.

### Evidence

- The quoted code; `grep -n "finalReceiveSize" QUICCoreState.swift` → declaration (`:614`),
  read at `:679`, `:685`, assignment only at `:688`.
- Consequence: the RFC 9000 §4.5 checks this type is supposed to perform ("STREAM data exceeds
  final size" and "inconsistent final stream size") never fire. A peer that sends data past the
  final size after a FIN is rejected with the generic "receive side is closed", not
  FINAL_SIZE_ERROR. `TLSQUICConnectionState` works around this with its own pre-check
  (`TLSQUICConnectionState.swift:338-361`), which is itself evidence that the intended check does
  not live where it is written.
- The related `closeDueToStreamError` dispatch also depends on the messages these dead branches
  would have produced — see F-swift-line-security-11.

### What correct looks like

The final size is compared against every incoming STREAM frame *before* the receive-closed gate:
an offset+length beyond a known final size is FINAL_SIZE_ERROR, a FIN whose offset differs from an
already-recorded final size is FINAL_SIZE_ERROR, and `finalReceiveSize` must also be recorded from
a RESET_STREAM frame (RFC 9000 §19.4 carries Final Size), which this type never does.

### Smallest correct fix

Move the `finalReceiveSize` comparison above `ensureCanReceive()` and add a `finalSizeRecorded`
state (or move the receive-closed test after the final-size test) so the two branches can execute;
record `finalReceiveSize` from `resetStream` as well.

---

## F-swift-line-security-05 — S2 — incomplete — `Swift/Sources/WebTransportHTTP3Core/QPACK.swift:876`

**HTTP field values from the peer are never validated: CR, LF and NUL are accepted, and `:status` accepts non-3DIGIT forms.**

### What is wrong

`HTTPFieldLine.init` validates only the *name* (lowercase, token bytes). The value is stored
verbatim:

```swift
// QPACK.swift:8-25
public init(name: String, value: String) throws {
    let lowercasedName = name.lowercased()
    ... // empty / lowercase / token-byte checks on the name only
    self.name = name
    self.value = value            // no validation at all
}
```

Decoding likewise stops at UTF-8 validity:

```swift
// QPACK.swift:866-880
private func decodeStringLiteral(...) throws -> String {
    ...
    let decodedBytes = huffmanFlag ? try QPACKHuffman.decode(bytes) : bytes
    guard let value = String(data: decodedBytes, encoding: .utf8) else {
        throw QUICCodecError.malformed("QPACK string literal is not UTF-8")
    }
    return value
}
```

`"\r\n"`, `"\u{0}"` and every other C0 control are valid UTF-8, so
`QPACK.decodeFieldSection` / `decodeHeadersFrame` hand them to callers as ordinary field values.
RFC 9110 §5.5 forbids CR, LF and NUL in field values; RFC 9114 §4.1.2 makes a field section whose
values are not valid field values a malformed message, and §4.1.2 additionally requires
connection-specific fields to be rejected. Nothing in `WebTransportHTTP3Headers`,
`WebTransportSessionHeaders` or `QPACK.decodeFieldLine` closes this.

Separately, the status parser accepts forms RFC 9110 §15 does not allow:

```swift
// WebTransportSession.swift:1727-1735
guard let statusValue = try optionalUniqueField(":status", from: fields),
    let status = UInt16(statusValue),
    (100...599).contains(status)
```

`UInt16("+200")` and `UInt16("0200")` both succeed (proof below), so `:status: +200` is treated as
a 200 response; `WebTransportHTTP3Headers.validateSuccessfulResponse`
(`WebTransportHeaders.swift:59-64`) has the same shape via `Int(status)`.

### Evidence

```
$ swift -e 'print(UInt16("+200") as Any, UInt16("0200") as Any, UInt16(" 200") as Any)'
Optional(200) Optional(200) nil
```

No in-repo consumer currently re-emits or logs a field value, so this is a validation defect in a
shipped library (`WebTransportHTTP3Core`) rather than a demonstrated exploit here; it becomes a
header/log-injection vector for any consumer that forwards or prints a decoded value.

### What correct looks like

`HTTPFieldLine` rejects values containing C0 controls, DEL, CR, LF and NUL (RFC 9110 §5.5), and
`:status` is matched as exactly three DIGITs before conversion.

### Smallest correct fix

In `HTTPFieldLine.init`, add
`guard !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f })` and throw;
in `WebTransportSessionHeaders.status`, require `statusValue.count == 3 &&
statusValue.allSatisfy(\.isASCII && $0.isNumber)` before `UInt16(statusValue)`.

---

## F-swift-line-security-06 — S2 — logic — `Swift/Sources/WebTransportCryptoApple/QUICInitialKeyDerivation.swift:62`

**The CryptoApple HKDF-Expand-Label silently wraps the RFC 5869 block counter, while the TLSCore copy of the same function is guarded against exactly that.**

### What is wrong

```swift
// QUICInitialKeyDerivation.swift:61-79
static func hkdfExpandLabel(secret: Data, label: String, outputByteCount: Int) throws -> Data {
    guard outputByteCount <= UInt16.max else {          // 65535, not 255*32
        throw QUICCodecError.valueOutOfRange("HKDF output too large")
    }
    ...
    return hkdfExpand(pseudoRandomKey: secret, info: info, outputByteCount: outputByteCount)
}

// QUICInitialKeyDerivation.swift:81-102
var counter: UInt8 = 1
while output.count < outputByteCount {
    ...
    input.append(counter)
    ...
    counter &+= 1        // wraps 255 -> 0, no block-count guard
}
```

Contrast the deliberately guarded twin, whose comment names this exact hazard:

```swift
// TLS13KeySchedule.swift:36-44
// RFC 5869 section 2.3 caps L at 255 * HashLen. ... anything above 8160 bytes cannot be produced
// by the defined construction: the block counter would wrap to zero and the output would silently
// stop being the RFC's HKDF stream while still looking well-formed to a caller.
guard outputByteCount >= 0, outputByteCount <= 255 * sha256Length else {
    throw QUICCodecError.valueOutOfRange(...)
}
```

`QUICPacketProtection.deriveKeys(trafficSecret:keyByteCount:ivByteCount:headerProtectionKeyByteCount:)`
(`WebTransportCryptoApple/QUICPacketProtection.swift:19-42`) is public and forwards caller-supplied
byte counts into this function, so a count above 8160 produces a byte string that is not the RFC's
HKDF output while every guard passes.

### Evidence

Standalone probe of the copied function (algorithm copied verbatim from `:81-102`):

```
$ swift /tmp/hkdf_probe.swift
blocks=255 (RFC 5869 max for SHA-256 = 255) counter wrapped to 0: false
blocks=256 (RFC 5869 max for SHA-256 = 255) counter wrapped to 0: true
```

Not peer-controlled on the shipped runtime path (all production call sites use fixed 16/12/32-byte
lengths); it is a silent-wrong-result hazard on the public `WebTransportCryptoApple` API and a
copy-paste divergence from `TLS13KeySchedule`.

### What correct looks like

`hkdfExpandLabel` rejects any `outputByteCount > 255 * 32` (the SHA-256 RFC 5869 limit), exactly as
`TLS13KeySchedule.hkdfExpandLabel` does.

### Smallest correct fix

Change the guard at `QUICInitialKeyDerivation.swift:62` to
`guard outputByteCount >= 0, outputByteCount <= 255 * 32 else { ... }`.

---

## F-swift-line-security-07 — S2 — dead — `Swift/Sources/WebTransportTLSCore/TLSIdentityTrust.swift:138`

**The pinned-certificate trust policy and the CertificateVerify verifier are not reachable from any shipped client path.**

### What is wrong

`TLSPinnedCertificateTrustPolicy.evaluate(certificateChainDER:)` (`TLSIdentityTrust.swift:138-152`)
and `TLSCertificateVerifier.verify(_:role:transcriptHash:publicKey:)`
(`TLSCertificateVerification.swift:39-66`, i.e. the CertificateVerify signature check) exist and
are tested, but nothing in `Sources` calls them:

```
$ grep -rn "TLSPinnedCertificateTrustPolicy\|TLSCertificateVerifier\|evaluate(certificateChainDER" Swift/Sources
.../TLSIdentityTrust.swift:123:public struct TLSPinnedCertificateTrustPolicy ...
.../TLSIdentityTrust.swift:138:    public func evaluate(certificateChainDER: [Data]) throws {
.../TLSIdentityTrust.swift:154:    public static func sha256Fingerprint ...
.../TLSCertificateVerification.swift:19:public enum TLSCertificateVerifier {
.../WebTransportCLIConformance/WebTransportCLIConformance.swift:732-733:  (conformance harness only)
```

The runtime's public trust surface offers no way to use them:
`WebTransportQUICPeerTrustPolicy` has exactly `.systemTrust` and `.localDevelopmentSelfSigned`
(`WebTransportInteroperableNetworkRuntime.swift:48-85`), and certificate/signature validation is
delegated wholesale to Network.framework's TLS. So a customer cannot pin a leaf certificate, and
the only "pinned trust" evidence for the shipped product is the conformance harness. The shipped
compliance matrix nevertheless lists "pinned trust" as implemented
(`WebTransportComplianceMatrix.swift:67-78`).

### Evidence

- The grep output above (only the definition files and one conformance call site).
- Default path is sound (`.systemTrust` → platform validation,
  `WebTransportInteroperableNetworkRuntime.swift:1613-1619`), so this is not a trust bypass; it is
  an unreachable control plus an overstated compliance claim.

### What correct looks like

Either the pinning policy is a supported configuration of the client
(`WebTransportQUICPeerTrustPolicy.pinned(SHA256Fingerprints)`, wired into the Network.framework
verify path), or the API/compliance text states that pinning is available to direct users of
`WebTransportTLSCore` only and is not integrated with the runtime.

### Smallest correct fix

Add a `.pinned(Set<Data>)` case to `WebTransportQUICPeerTrustPolicy` and install a
`sec_protocol_options_set_verify_block` that calls
`TLSPinnedCertificateTrustPolicy.evaluate(certificateChainDER:)`; if that is out of scope for this
release, correct the compliance-matrix item.

---

## F-swift-line-security-08 — S2 — perf — `Swift/Sources/WebTransportTLSCore/TLSHandshakeFlight.swift:96`

**CRYPTO-stream reassembly is quadratic in the buffered byte count and retains every consumed byte forever.**

### What is wrong

`append` (pre-authentication peer input) recomputes a full scan of the byte map once per frame:

```swift
// TLSHandshakeFlight.swift:127-150
public mutating func append(offset: UInt64, data: Data) throws {
    ...
    var pendingBytes = pendingByteCount            // 132: O(n) scan
    ...
}

// TLSHandshakeFlight.swift:106-116
private func recomputePendingByteCount() -> Int {
    guard consumedByteCount > 0 else { return bytesByOffset.count }
    guard let lowestLive = bytesByOffset.keys.filter({ $0 >= consumedByteCount }).min() else { return 0 }
    return bytesByOffset.count - bytesByOffset.keys.count(where: { $0 < lowestLive })
}
```

Once the watermark has moved (`consumedByteCount > 0`) every `append` costs two passes over the
whole map. A peer can drive the map to its 64 KiB ceiling (`defaultMaximumBufferedBytes`,
`:61`) one byte per frame — each small CRYPTO frame costs O(n), so the total is O(n²) ≈ 2×10⁹ map
probes per connection, all before authentication, on a structure whose comment claims append is
"linear rather than quadratic" (`:103-105`). Byte-granular keys make the constant worse:
`bytesByOffset: [UInt64: UInt8]` is one dictionary entry per byte (`:63`, `:147`).

Independently, consumed bytes are never removed — deliberately, for overlap-conflict detection
(`:66-73`) — and the transcript is appended unconditionally for every decoded message
(`:218`, `TLS13KeySchedule.swift:141-143`). The decoder accepts the six handshake types
(`TLSHandshakeMessage.swift:4-11`) with no state machine forbidding repeats, and
`TLSQUICConnectionState.receiveHandshakeFrames` (`TLSQUICConnectionState.swift:132-140`) does not
reject a second ClientHello/Finished, so a peer that keeps sending well-formed handshake messages
grows `bytesByOffset` and the transcript without bound for the connection's lifetime. (Message
types outside the enum, e.g. NewSessionTicket, are rejected, which is why the pending-bytes ceiling
does bound *undecodable* data.)

### Evidence

- The quoted code and the reachability of `append` from `TLSHandshakeFlightDecoder.receive(frame:)`
  (`:177-184`) for any CRYPTO frame a caller feeds it.
- Not on the shipped runtime path (Network.framework terminates TLS), so impact is on consumers of
  the shipped `WebTransportTLSCore` product.

### What correct looks like

Maintain the pending count incrementally (increment on insert, decrement on `markConsumed`, both
O(1)), or compute it only when a frame actually crosses the ceiling; and bound total retained CRYPTO
bytes / transcript bytes (e.g. drop conflict-detection rows below the watermark after a grace
window).

### Smallest correct fix

Replace the `pendingByteCount` call inside `append` with a stored counter updated by `append` and
`markConsumed`.

---

## F-swift-line-security-09 — S2 — unsafe — `Swift/Sources/WebTransportServer/main.swift:52`

**Peer-controlled echo text is printed into operator logs without escaping (log injection).**

### What is wrong

The served-session summary interpolates peer bytes inside quotes with no escaping:

```swift
// WebTransportServer/main.swift:51-53
print(
    "network \(result.transport.rawValue) session served: remote=\(result.remoteEndpoint.commandLineValue)\(session) message=\"\(result.message)\""
)
```

`result.message` is the peer's payload decoded as UTF-8:
`serveOne` returns `message: echoedMessage` from `echoOneStream`, which returns the bytes it
received (`WebTransportInteroperableNetworkRuntime.swift:1321-1327`, `1349-1358`). The client CLI
does the same with the server's response text:

```swift
// WebTransportClient/main.swift:34-36
print(
    "network \(result.transport.rawValue) session connected: ... message=\"\(result.message)\""
)
```

A peer that sends `x"\nsession served: admin=true` forges additional log lines and closes the
quoted field early. `WebTransportLogEvent` is properly redacted and count-only
(`WebTransport/WebTransport.swift:119-147`); these two CLI printfs are the paths that bypass it.

### Evidence

- The quoted code plus the echo-source lines. (Contrast: `WebTransportErrorSurface` exists precisely
  to keep peer text out of user-visible output, `WebTransport/WebTransport.swift:167-215`.)
- Same class as the brief's log-injection item; no privileged action depends on the text.

### What correct looks like

Peer-derived text is never printed raw: escape/percent-encode it, replace control characters, or
log only its byte count (as `WebTransportLogEvent.sessionClosed(reasonByteCount:)` already does).

### Smallest correct fix

In both CLIs, print `message_bytes=\(Data(result.message.utf8).count)` instead of the raw string, or
sanitize with a control-character filter before interpolation.

---

## F-swift-line-security-10 — S2 — bug — `Swift/Sources/WebTransportTestSupport/Phase11Identity.swift:97`

**`parseKeyType` maps the Ed25519 key type name to `kSecAttrKeyTypeECSECPrimeRandom`.**

### What is wrong

```swift
// Phase11Identity.swift:92-101
switch value {
case "rsa":            return kSecAttrKeyTypeRSA
case "ec", "ecsecprimerandom", "prime", "p256":
                       return kSecAttrKeyTypeECSECPrimeRandom
case "ed25519":        return kSecAttrKeyTypeECSECPrimeRandom   // wrong: not an EC-prime key
default:               throw Phase11IdentityError.invalidArgument("unsupported key type: \(value)")
}
```

An operator or fixture script that asks for `--key-type ed25519` gets a P-256 `SecKeyCreateWithData`
attempt and a confusing `OSStatus -50`, or, worse for a caller that also supplies a P-256 key blob,
a silently mislabelled identity. The name should either map to an Ed25519 key type or be rejected as
unsupported, exactly as the `default` branch does for any other unknown name.

### Evidence

- The quoted switch. `WebTransportTestSupport` is a target used by executable/test consumers
  (`LibrarySmokeServer/main.swift:4` imports it), so this is reachable from a shipped executable's
  identity-loading path.

### What correct looks like

`"ed25519"` is either rejected (no Ed25519 support in `SecKeyCreateWithData` on this platform) or
mapped to the correct key type; it must not silently return the EC-prime type.

### Smallest correct fix

Delete the `case "ed25519"` line (it then falls to `default` and throws
`"unsupported key type: ed25519"`).

---

## F-swift-line-security-11 — S3 — style — `Swift/Sources/WebTransportTLSCore/TLSQUICConnectionState.swift:329`

**Error-code selection is decided by substring-matching a human-readable message.**

### What is wrong

```swift
// TLSQUICConnectionState.swift:325-335
private mutating func closeDueToStreamError(_ error: QUICStateError) {
    switch error {
    case .flowControlViolation: _ = closeTransport(error: .flowControlError, ...)
    case .streamStateViolation(let message) where message.contains("final size"):
        _ = closeTransport(error: .finalSizeError, ...)
    case .streamStateViolation: _ = closeTransport(error: .streamStateError, ...)
    default: _ = closeTransport(error: .protocolViolation, ...)
    }
}
```

Two `QUICStateError.streamStateViolation` cases are distinguishable only by prose ("STREAM data
exceeds final size" vs "inconsistent final stream size", `QUICCoreState.swift:680`, `:686`). Any
edit to those strings silently reclassifies a FINAL_SIZE_ERROR as STREAM_STATE_ERROR. The branch is
also doubly dead: per F-swift-line-security-04 neither message can be produced.

### Evidence

- The quoted code and the message strings it keys on.
- Category is style by impact (both outcomes close the connection), but the coupling is a real
  maintenance hazard in a wire-visible decision.

### What correct looks like

A dedicated `QUICStateError` case (e.g. `.finalSizeExceeded` / `.inconsistentFinalSize`) that the
caller switches on structurally.

### Smallest correct fix

Add a `case finalSizeViolation(String)` to `QUICStateError`, throw it from the two final-size
checks, and match that case here.

---

## F-swift-line-security-12 — S3 — bug — `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift:62`

**`setsockopt` failure is ignored.**

### What is wrong

```swift
// QUICUDPPort.swift:59-62
var reuse: Int32 = 1
// SAFETY: The pointer references one initialized Int32 ...
unsafe setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
```

The return value is discarded, unlike every other syscall in the file (`bind`, `getsockname`,
`sendto`, `poll`, `recvmsg` all check and throw `QUICUDPError.posix`). The practical consequence is
small (SO_REUSEADDR failure usually means the bind that follows fails visibly), but the
inconsistency means the error surfaces later and with the wrong operation name.

### Evidence

- The quoted line; the neighbouring calls at `:70-77`, `:85-92`, `:115-125`, `:149-155`,
  `:184-187`.

### What correct looks like

The status is checked and a `.posix(operation: "setsockopt", code: errno)` error is thrown (with
`close(fd)` before throwing, as the bind/getsockname paths do).

### Smallest correct fix

```swift
guard unsafe setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
    let code = errno; close(fd); throw QUICUDPError.posix(operation: "setsockopt", code: code)
}
```

---

## Categories checked, and what was found CLEAN

| category | result in `Swift/Sources/**` |
| --- | --- |
| `logic` | 4 findings (F-01, F-04, F-06, F-11). Arithmetic/varint/ACK-range/stream-ID logic re-derived against RFC 9000 (packet-number truncation matches Appendix A.3 exactly; ACK range expansion guards every subtraction; `QUICVarInt`, QPACK prefixed integers and Required-Insert-Count reconstruction match RFC 9000 §16 / RFC 9204 §4.1.1/§4.5.1.1; WebTransport app-error↔H3-error mapping matches draft-ietf-webtrans-http3-16 §4.4 including the `0x1f*N+0x21` skips). **CLEAN** for the codecs' numeric edge cases. |
| `dead` | 2 findings (F-04, F-07). Also reviewed and found CLEAN except those: `QUICConnectionIDStore`, `QUICAckTracker`, `HTTP3RequestStream`, `WebTransportSessionManager` tombstone eviction — every private helper has a live caller. |
| `unsafe` | 3 findings (F-03, F-08, F-09, plus F-12's unchecked call). **CLEAN** for pointer/bounds use: the C shim (`WebTransportSecurityShim.m`) and every `unsafe` Swift site (`QUICUDPPort`, `QUICPacketProtection.headerProtectionMask`, `TLS13KeyAgreement`, `sec_protocol_metadata_create_secret_with_context` in the runtime, `WebTransportServerIdentity`'s out-parameter calls) were checked against the SDK header `SecProtocolMetadata.h:419-423` — the exporter argument order and lengths are correct, no `as!`/`try!`/`fatalError` exists anywhere in `Sources`, and no out-of-bounds index was found. |
| `bug` | 3 findings (F-01, F-10, F-12). |
| `incomplete` | 2 findings (F-02, F-05). |
| `placeholder` | **CLEAN as a new finding.** The only placeholder-shaped code is the single-case compliance status (`WebTransportComplianceMatrix.swift:1-3`, `allPass` tautology) and that is already `F-swift-architecture-14`; the DocC single-stream promise is `F-swift-architecture-10`. Both are left to the architecture examiner rather than double-reported. |
| `style` | 1 finding (F-11). |
| `perf` | 1 finding (F-08). |
| `test` | **CLEAN (out of scope by design).** `Swift/Sources/**` contains no XCTest target; the shipped conformance harness lives in `WebTransportCLIConformance` and its assertions (`require`, `expectThrows`, `:1132-1145`) do assert observable outcomes, so no "test that asserts nothing" was found inside the scope path. Test targets under `Swift/Tests/**` are outside this area's scope. |
| `deps` | **CLEAN as a new finding.** No dependency problem is visible from `Sources/**` alone (manifest-level issues — the unused `WebTransportCryptoApple` dependency, manifest sync — are `F-swift-architecture-12` and the ledger's A-0006). |
| `docs` | **CLEAN as a new finding** in `Sources/**`; the DocC inaccuracy is `F-swift-architecture-10`. |

Additional security-specific sweeps that came back CLEAN and are worth recording:

- **Weak randomness** — none. The only CSPRNG use is `SecRandomCopyBytes` with the status checked
  and a refusal to degrade (`WebTransportServerIdentity.swift:597-618`); no `arc4random`,
  `Int.random`, `UUID()` or time-derived token exists in `Sources`.
- **Non-constant-time secret/tag comparison** — none. AEAD verification is CryptoKit
  (`QUICPacketProtection.open`); the only byte-set comparison is the pinned SHA-256 fingerprint,
  which is a public value.
- **Trust-validation bypass** — none beyond the documented, host-checked loopback development mode:
  `localDevelopmentSelfSigned` requires `endpoint.host ∈ {localhost, 127.0.0.1, ::1}` before it
  selects `peerAuthentication(.none)` (`WebTransportInteroperableNetworkRuntime.swift:68-85`,
  `1613-1619`), and the self-signed identity is refused on any non-loopback bind
  (`WebTransportServerIdentity.swift:163-173`). Loopback checks fail closed for unrecognised forms
  (`127.0.0.01`, `::ffff:127.0.0.1`, `127.1` are all rejected by `IPv4.parse`/`LoopbackHost`).
- **Format strings / secret leakage in logs** — no `String(format:)`, no `%@`, no secret, key or
  `.env` material is logged. The opt-in interop debug channel announces itself and emits identifiers
  only (`WebTransportInteroperableNetworkRuntime.swift:12-46`); the `WEBTRANSPORT_INTEROP_DEBUG`
  env var is the only environment read.
- **Live-looking credentials** — none found in `Swift/Sources/**`; no finding of the form
  "`file:line` contains a live-looking credential".
