## 1. Identity and integrity

```
$ git -C /Users/node3/Downloads/WebTransport rev-parse HEAD
46937e29eb734887ca7b739abfedaf68ae565de2

$ git -C /Users/node3/Downloads/WebTransport status --porcelain
                    <- literal output: empty (no lines)
```

**No source file was changed. There is no sha256 to report, because the set is empty.**

Note on HEAD movement: I began and read the tree at `6be4315`. Mid-session the checkout moved to `46937e2` (two commits by another process: `49e2b68`, `46937e2`, both AUDIT-only). `git diff --stat 6be4315..46937e2 -- Swift/ Package.swift` is **empty** — the Swift sources and both manifests are byte-identical between the two, and the two changed files are `AUDIT/ledger.json` and `AUDIT/ledger.md`. Every file:line anchor below was re-verified against `46937e2`. All probes/builds live in `/tmp/sa-probe`, `/tmp/sa-copy`, `/tmp/sa-repo-build`, `/tmp/sa-copy-build`; the repository was only ever read.

## 2. Coverage

| Area | Checks actually executed | Result |
|---|---|---|
| Whole Swift package | `swift test --package-path /Users/node3/Downloads/WebTransport --scratch-path /tmp/sa-repo-build` | exit 0; every target passed (HTTP3CoreTests 140, CryptoAppleTests 7, …); no build dir written into the repo |
| Path-dependency build | `/tmp/sa-probe` with `.package(path: …)`, `swift build --build-tests` | Build complete, exit 0 |
| Version lockstep | `./Swift/check-version-sync.sh` | `version 1.4.0 agrees across VERSION, C99/include/webtransport/version.h and Swift/…/WebTransportVersion.swift`, exit 0 |
| Manifest/import gates | `./Swift/check-manifest-sync.sh`, `./Swift/check-target-imports.sh` | `19 shared targets agree`, `42 targets agree … (202 imports)`, exit 0 |
| QPACK static Huffman | extracted all entries from `QPACKHuffman.swift`, diffed against RFC 7541 App. B | 257/257 exact match (script-verified) |
| QPACK dynamic table | `/tmp/sa-copy` probe: 4 table states × ~4000 random inputs to `decodeFieldSection(dynamicTable:)` and `applyEncoderStream(to:)`; encode/decode round-trip for capacities 0/1/32/33/64/512/4096 | no trap, exact round-trips (`probeDynamicQPACKNeverTraps`, `probeDynamicQPACKEncodeDecodeRoundTrip` pass) |
| Inbound queue ceiling | `/tmp/sa-copy` `probeRetainCriticalHasNoCeilingWhileEnqueueDoes` | `enqueue accepted=16 refused=1584 limit=16`; `retainCritical accepted=100000 retainedCount=100000` |
| Live loopback unidirectional accept (real QUIC) | `/tmp/sa-copy` `ProbeUniClassificationTests`, `ProbeCriticalRetentionLiveTests` (additive test-only producer; shipped code unmodified) | see findings 1, 3, 4 |
| CONNECT-stream capsule flow control | `/tmp/sa-copy` `probeOverLimitMaxStreamsClosesTheSession` | see finding 2 |
| Full code read | `QUICCoreState.swift`, `QUICPacket.swift`, `QUICFrame.swift`, `QUICByteCursor/VarInt/TransportParameters`, `HTTP3{Connection,Frame,Settings,Stream,Constants}`, `QPACK{,.Huffman}`, `WebTransport{Session,Streams,FlowControl,Datagrams,Headers}`, `TLS{HandshakeFlight,13KeySchedule,QUICConnectionState,Extension,…}`, `QUICUDPPort`, `WebTransportInteroperableNetworkRuntime` (all 3381 lines), `WebTransportServerPolicy`, `WebTransport.swift` | read |
| **Not covered** | ASan/TSan runs (**unfinished** — I did not run them); CLI executables and `LibrarySmoke{Client,Server}` mains; `WebTransportServerIdentity` PKCS#12 path; `WebTransportCLIConformance`; third-party interop (no external peers on this host); Linux; C99 (out of scope); clang-tidy (C only). The Swift-side branch-coverage claim of ~67% from the prior audit was not re-measured. | |

## 3. Findings

### SWAUD-1 [P1] An unknown/reserved unidirectional stream type is reported as a session error instead of being ignored
`Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:819-828` (accept path, `throw WebTransportNetworkRuntimeError.unexpectedFrame` at `:827`), same defect during establishment at `:2547-2561` (`default: throw` at `:2560`).
spec basis: RFC 9114 §6.2 — "Recipients of unknown stream types MUST either abort reading of the stream or discard incoming data without further processing … The recipient **MUST NOT consider unknown stream types to be a connection error of any kind**"; §6.2.3 reserves `0x1f*N+0x21` precisely so peers may send them.
evidence (before): scratch test `probeReservedUnidirectionalStreamTypeIsReportedAsAnError` (real loopback QUIC session; peer opens a unidirectional stream with bytes `21 de ad be ef`, i.e. reserved type `0x21`):
```
PROBE reserved-type: threw unexpected frame in WebTransport network packet
```
expected vs actual: expected the runtime to discard/abort that one stream and keep waiting (so the call would end in `.timeout`); actual is an immediate session-level error naming the peer's *ignorable* stream.
suggested fix: in the `guard … hasStreamPrefix(firstChunk) else` branch, when `HTTP3StreamTypeParser` yields a type that is neither control/QPACK (retain) nor WebTransport, drop the handle and `continue`; do the same in `readPeerControlStream`'s `default` case when waiting for the control stream.
confidence: **verified (execution)**

### SWAUD-2 [P1] An over-limit WT_MAX_STREAMS capsule on the CONNECT stream never closes the session, and the local state stays `accepted`
`Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift:826-836` — the outer `WebTransportFlowCapsuleCodec.parse` at `:828` throws before `receiveFlowControlCapsuleWithActions` is reached, and the surrounding `catch where capsuleType == wtCloseSessionCapsule` (`:836`) matches only WT_CLOSE_SESSION. The close path that *is* correct lives at `:649-655`.
spec basis: draft-ietf-webtrans-http3-16 §5.6.2 — "Recipients of a capsule with a Maximum Streams value larger than this limit **MUST close the WebTransport session with a WT_FLOW_CONTROL_ERROR** error code."
evidence (before): scratch test `probeOverLimitMaxStreamsClosesTheSession`, same session and same capsule through the two entry points:
```
PROBE connect-stream over-limit threw: WebTransportDraft16Error(kind: .flowControl, message: "wt-max-streams-uni exceeds the draft-16 2^60 maximum")
PROBE connect-stream over-limit state after: Optional(WebTransportSessionState.accepted)
PROBE direct over-limit   threw: WebTransportDraft16Error(kind: .flowControl, message: "wt-max-streams-uni exceeds the draft-16 2^60 maximum")
PROBE direct over-limit   state after: Optional(WebTransportSessionState.closed(applicationErrorCode: 73221255 /* 0x045D4487 = WT_FLOW_CONTROL_ERROR */, …))
```
`receiveConnectStreamCapsulesWithActions` is the entry point the shipped runtime uses (`WebTransportInteroperableNetworkRuntime.swift:1145-1150`), and its caller then resets the CONNECT stream with `H3_MESSAGE_ERROR` (`:1174-1177`), so the peer is told the wrong code *and* the local manager keeps believing the session is live.
expected vs actual: session closed with `WT_FLOW_CONTROL_ERROR` on both entry points; actual is "throw, session still `.accepted`" from the CONNECT-stream path.
suggested fix: parse once (or route the parse failure for *any* flow-control capsule type through `closeForFlowControlViolation`), and make `receiveConnectStreamCapsulesWithActions` catch `WebTransportDraft16Error(kind: .flowControl)` and close the session before propagating.
confidence: **verified (execution)**

### SWAUD-3 [P2] A second HTTP/3 control stream (and duplicate QPACK streams) is silently retained instead of raising H3_STREAM_CREATION_ERROR
`Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:2507-2513` (`case control, qpackEncoder, qpackDecoder → retainCritical`, no occurrence count).
spec basis: RFC 9114 §6.2.1 — a second control stream "MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR"; RFC 9204 §4.2 the same for a second encoder/decoder stream.
evidence (before): scratch test `probeSecondControlStreamIsSilentlyRetained`, peer writes `00 04 00` (control type + empty SETTINGS) on a new unidirectional stream:
```
PROBE second-control: threw network runtime operation timed out after 2000ms
```
expected vs actual: expected the connection error; actual is a silent retain (the stream is parked in `retainedCriticalStreams`) and the accept simply times out.
suggested fix: track whether a control stream and each QPACK stream has already been seen (the establishment path already sets `receivedPeerControlStream`) and raise `H3_STREAM_CREATION_ERROR` for a second one, rather than retaining it.
confidence: **verified (execution)**

### SWAUD-4 [P2] The accept path's critical-stream retention has no ceiling, and it permanently consumes the peer's unidirectional-stream credit
`Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:3037-3041` (`private var retainedCriticalStreams: [Element] = []`, `retainCritical` appends with no bound), reached from `:2499-2517`; contrast `:3076-3113`, where `enqueue` refuses past `ceiling(for:)` and returns `refusedQueueFull`.
spec basis: RFC 9114 §10.5 ("Implementations SHOULD track the use of these features and set limits on their use"); draft-ietf-webtrans-http3-16 §4.6 ("endpoints MUST limit the number of buffered streams and datagrams").
evidence (before):
```
probeRetainCriticalHasNoCeilingWhileEnqueueDoes:
  PROBE enqueue accepted=16 refused=1584 limit=16
  PROBE retainCritical accepted=100000 retainedCount=100000

probeRetainedCriticalStreamsGrowWithPeerStreams (live loopback session, peer sends 4 control-typed uni streams per round):
  PROBE initial retained=1
  PROBE round 0 retained=7
  PROBE round 1 retained=11
  PROBE round 2 retained=15
  then the peer's next openStream timed out after 15000ms
```
expected vs actual: the F-03 ceiling bounds the *queue* but nothing bounds what the acceptor pulls out of it; every retained handle is held until the session ends, and the observed run shows the peer's `initialMaxUnidirectionalStreams` capacity is not returned.
Honest scope: in the observed run the growth stopped at the QUIC concurrent-stream advertisement because credit never came back (so the *memory* growth per connection is bounded by that advertisement); the array itself has no bound, and the verified second-order effect is that a peer can permanently strand its own unidirectional-stream slots. Marking the "unbounded memory" form **unfinished — needs a run long enough to show whether Network.framework ever returns the credit**.
suggested fix: give `retainCritical` the same per-direction ceiling as `enqueue`, refusing (and counting) anything beyond the two QPACK streams and one control stream the connection is entitled to; the conformance fix in SWAUD-3 removes the peer's ability to manufacture critical streams at all.
confidence: **verified (execution) for growth, ceiling absence, and credit consumption**

### SWAUD-5 [P3] `acceptUnidirectionalStream` can wait twice its own deadline
`Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:800-812` — `remaining` is computed once before `inboundStreams.next(…)` and then reused for `readFirstChunk(…)`, so one loop iteration may block up to `2 × remaining`; the loop repeats that per critical stream encountered.
spec basis: none (API contract).
expected vs actual: the caller's `timeoutMilliseconds` is documented as the wait budget; actual is up to 2× per iteration.
suggested fix: recompute `remaining` between the two awaits, and again after each retained critical stream.
confidence: **verified by reading only (unfinished — no timing probe run)**

### SWAUD-6 [P3] SUSPECTED: CONNECT-stream capsules are read and written as raw stream bytes rather than as DATA-frame payloads
`Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1082-1084, 1135-1217` and `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift:806-864`.
spec basis: RFC 9297 §3.1 — "In HTTP/2 and HTTP/3, the data stream … consists of all bytes sent in DATA frames"; RFC 9114 §4.4 — "Once the CONNECT method has completed, **only DATA frames are permitted** to be sent on the stream."
evidence (before): none obtainable here. **SUSPECTED (unverified): no external implementation was reachable from this host to settle it.** The C99 library does the same (`C99/src/http3/driver.c:375-403`), and the repository's recorded interop evidence (F-repo-ops-09, 7/7 across five implementations) suggests deployed peers accept the raw form, which is why I am not calling it a defect.
suggested fix (if confirmed): unwrap/emit DATA frames on the CONNECT stream, or cite the interop result in the code so the deviation is deliberate and documented.
confidence: **suspected (unverified)**

### SWAUD-7 [P3] `QUICTransportParameters.validated()` omits RFC 9000 §18.2's 2^60 cap, and no shipped path calls it on peer parameters
`Swift/Sources/WebTransportQUICCore/QUICTransportParameters.swift:30-79` — checks `max_udp_payload_size`, `ack_delay_exponent`, `max_ack_delay`, `active_connection_id_limit`, reset-token length and connection-ID lengths, but nothing for `initial_max_streams_bidi`(0x08)/`initial_max_streams_uni`(0x09), which §18.2 caps at 2^60.
spec basis: RFC 9000 §18.2 ("Values above 2^60 … are invalid"; `TRANSPORT_PARAMETER_ERROR`). This is the same missing rule the ledger recorded for C99 as **F-05** (`C99/src/quic/transport_parameters.c:214`), so the Swift twin is unaudited.
evidence (before): `grep -rn "\.validated()" Swift/Sources/` shows only `admission.validated()` and `transportLimits.validated()` (local policy types); the only `.validated()` on a `QUICTransportParameters` anywhere is none. The runtime delegates the QUIC handshake to Network.framework, so peer parameters never reach this API.
expected vs actual: the public validator should reject the values it claims to enforce.
suggested fix: add the two 2^60 guards (and note in the doc that the runtime does not call this on peer input).
confidence: **verified by reading (no shipped caller reaches it)**

## 4. Investigated and rejected (not real)

| Candidate | Why rejected |
|---|---|
| QPACK dynamic-table index arithmetic / Required-Insert-Count wrapping / Base sign | 4 table states × ~4000 random inputs into both dynamic entry points: no trap, no bad return; encode→decode round-trips exactly for capacities 0…4096 including eviction (`probeDynamicQPACKNeverTraps`, `probeDynamicQPACKEncodeDecodeRoundTrip` pass) |
| QPACK Huffman table or padding/termination bug | All 257 entries extracted and diffed against RFC 7541 App. B — exact; `EOS` symbol is at index 256 and is refused; adversarial padding corpus passes |
| `QPACKDynamicTable.insert` throwing when an entry exceeds capacity | Correct per RFC 9204 §3.2.2; the initial probe failure was my own test inserting oversized fields |
| ACK range bookkeeping (`insertReceivedRange` / `makeAckFrame` gap arithmetic) | Read line-by-line: ranges stay descending and non-adjacent, `gap = previousLow - upper - 2` cannot underflow, and `low - 1` is only reached under `low > 0`; the committed `QUICCoreStateTests` cost/regression tests pass. (Unfinished: I did not write an independent randomised invariant test.) |
| Unbounded ACK-range allocation in `QUICFrame.decode` (`for _ in 0..<rangeCount`) | Each iteration consumes ≥2 bytes or throws `truncated`, so the loop is bounded by the datagram length; not a peer-declared-length allocation |
| Reserved/fixed-bit validation in the packet codecs | Already fixed (F-swift-line-security-02); the current `QUICShortHeaderPacket.decode:315` rejects `0x18`. No regression found |
| Receive-only enforcement on the new unidirectional stream | `QUICStreamState.ensureCanSend` (`QUICCoreState.swift:921-928`) refuses `sendStreamPayload`; `resetStream` is guarded at `WebTransportSession.swift:1143`. No defect |
| Datagram dropped when the per-session buffer/queue is full (`WebTransportSession.swift:564-577`) | Draft §4.6 says an over-limit datagram "MUST be dropped"; by design |
| `enqueueInboundStream` refusals (F-03's fix) | Matches draft §4.6's `WT_BUFFERED_STREAM_REJECTED` requirement; no regression |

## 5. Where the maintainers' own words disagree with the code

1. `WebTransportInteroperableNetworkRuntime.swift:469-472` says the send half is refused "see `WebTransportSessionManager.sendStreamPayload`". That method has **no** half-ownership guard (`WebTransportSession.swift:1110-1123`); the refusal happens one layer down in `QUICStreamState.ensureCanSend` (`QUICCoreState.swift:921-928`). Behaviour is right, the pointer is wrong.
2. `:785-792` presents the per-direction inbound ceiling as the bound on retention, while the structure the accept path actually feeds (`:3037 retainedCriticalStreams`) has no ceiling and no reader — the exact gap SWAUD-4 measures.
3. `:2184-2186` says a foreign-session stream "must be reset rather than silently dropped". For a peer-initiated **unidirectional** stream this endpoint owns only the receive half, so a RESET_STREAM is a STREAM_STATE_ERROR (RFC 9000 §19.4) and the only correct signal is STOP_SENDING; the code sets the same `streamApplicationErrorCode` and drops the handle without distinguishing the two forms.
4. `:2133-2143` states the refusal code for streams refused at the transport without noting that the RESET_STREAM half of that refusal is illegal for a peer-initiated unidirectional stream (same point as 3).
5. `WebTransportUnidirectionalStream`'s DocC (`WebTransport.swift:325-335`) and the runtime doc both assert receive-only-ness "by construction"; that is true only because `sendStreamPayload` happens to reach `ensureCanSend` — the manager-level API itself would accept the call.

Two findings (SWAUD-1, SWAUD-2) are wire-visible MUST violations, both reachable by an unauthenticated peer through the new unidirectional accept path and the CONNECT-stream capsule path respectively; SWAUD-3/SWAUD-4 are the same two paths' resource/conformance consequences. Nothing here duplicates a ledger row: `F-swift-line-security-05b` covered *having* a consumer for peer-initiated unidirectional streams, not how the consumer classifies what it receives.
