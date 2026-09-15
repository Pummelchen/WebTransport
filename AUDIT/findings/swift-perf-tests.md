# L5 performance + L6 tests — Swift (`swift-perf-tests`)

Examiner area: **swift-perf-tests**. Scope: `Swift/Sources/**` for performance, `Swift/Tests/**` for tests.
Branch `audit/2026-09-15`. Read-only pass; nothing was changed except this file and its JSON twin.

Method: static reading of the hot paths (QUIC state machine, QPACK, HTTP-3 connection, session manager,
Network.framework runtime) plus targeted test-file review, then read-only commands for evidence
(`grep`, `ls`, and two `swift test --filter` runs of the specific tests named below). Two micro-benchmarks
were run with `swift -e` (no repository files written) to settle whether `Data.removeFirst` and
`Array.removeFirst` are O(1) or O(n); the results are quoted where they matter.

Baseline claims taken as given: `swift build --build-tests` / `swift test` green at 308 tests; the C99 tree
is out of scope here (shares no files).

---

## Severity summary

| id | sev | category | one-line |
| --- | --- | --- | --- |
| F-swift-perf-tests-01 | S2 | perf | Per-payload struct copy + `[Data].removeFirst()` makes draining a buffered stream O(n²) |
| F-swift-perf-tests-02 | S2 | perf | `QUICLossRecovery.processAck` sorts twice and linearly scans peer ACK ranges per sent packet |
| F-swift-perf-tests-03 | S2 | perf | `makeAckFrame` sorts the whole 16K packet-number set on every call; the doc claims otherwise and the test only checks size |
| F-swift-perf-tests-04 | S2 | perf | Fixed 4096-entry bookkeeping arrays shifted with `firstIndex`/`removeFirst` on every stream close/delivery |
| F-swift-perf-tests-05 | S3 | perf | `QUICUDPPort.receive` allocates and zeroes a 64 KiB buffer per datagram and blocks in `poll` |
| F-swift-perf-tests-06 | S3 | perf | `waitForPeerClosure` busy-polls the manager actor every 5 ms |
| F-swift-perf-tests-07 | S1 | test | The peer-input "does not exhaust memory" fuzz test asserts nothing |
| F-swift-perf-tests-08 | S1 | test | No test covers the bounded-read contract (`receive(maximumBytes:)`) of the shipped stream API |
| F-swift-perf-tests-09 | S2 | test | UDP cancellation test asserts only `Task.isCancelled`; every `receive` error is swallowed |
| F-swift-perf-tests-10 | S2 | test | Cross-process test lock is a fixed `/tmp` dir with a 180 s wait and no stale-owner detection |
| F-swift-perf-tests-11 | S2 | test | The concurrency-limit precedence test never asserts the limit was applied |
| F-swift-perf-tests-12 | S3 | test | Unconditional 2 s sleeps on the success path of the public-API exchange helpers |

12 findings: 0 × S0, 2 × S1, 7 × S2, 3 × S3. No S0, and no S0/S1 in the performance half.

---

## Categories checked and found CLEAN

- **Per-packet Array/Data copies in the production packet path** — CLEAN. `QUICByteCursor.readBytes`
  (`Sources/WebTransportQUICCore/QUICByteCursor.swift:58`) does `Data(bytes)`, which copies the slice, but
  the runtime never calls it: the shipped runtime uses Network.framework's QUIC and only decodes HTTP/3
  frame prefixes/capsules (`Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:282,1478`).
  No production per-packet copy was found.
- **`Data.removeFirst` in the capsule loop** — CLEAN (and explicitly *not* filed). Both `popCompleteCapsule`
  (`...NetworkRuntime.swift:872`) and `receiveConnectStreamCapsulesWithActions`
  (`WebTransportSession.swift:772`) call `Data.removeFirst`. Benchmarked: cost is constant per call
  (`removeFirst(2)` over an 8 KiB→128 KiB `Data` scales linearly with the number of *bytes*, not with
  `n²`), so these are not quadratic. Only the per-capsule `Data(prefix)` allocation remains, which is one
  small allocation for a value that must be materialized anyway.
- **Unbounded collections reachable from a peer** — deferred to other examiners where already filed
  (`F-swift-line-security-03`, `F-swift-architecture-01`). In this area I confirmed `QUICDatagramQueue`
  (`QUICCoreState.swift:737`) has no cap, but it is not wired into any production path (grep: only tests),
  so it is not re-filed. `HTTP3RequestStream.dataChunks` (`HTTP3Connection.swift:220`) is unbounded only
  under `.buffer`, which no production call site selects (default is `.reject`); not re-filed.
- **Blocking calls inside async production paths** — CLEAN. No `Thread.sleep`, `usleep`, synchronous file
  I/O or blocking sockets inside async code in `Sources/` outside the test-only `QUICUDPPort` (filed as
  F-swift-perf-tests-05). The `Task.sleep` sites in the runtime are timeout/poll implementations, not
  blocking waits (`...NetworkRuntime.swift:593,797,1561,1979,2432`). `WebTransportServer/main.swift:287`
  reads a PKCS#12 file once in argument parsing, before serving.
- **O(n²) or worse on peer-controlled sizes in the runtime data path** — CLEAN apart from the fixed-4096
  bookkeeping (F-04). The CONNECT-capsule buffer, stream read loop and datagram path were walked; no
  growth-proportional nested scan was found in the runtime itself (the quadratic in the TLS CRYPTO
  reassembler is already filed as `F-swift-line-security-08`, and `TLSHandshakeFlight` is not in this area).
- **Missing caching where correctness allows** — CLEAN. The repeated QPACK static-table lookups
  (`QPACK.swift:137-147,551,562`) are linear scans over a 99-entry constant table; the dynamic-table
  lookups (`QPACK.swift:264,304`) scan an eviction-bounded table. Both are small and hot only for
  library consumers; noted, not filed.
- **Tests: missing failure-path and boundary coverage generally** — mostly CLEAN. The suite is unusually
  strong on error paths (specific error kinds checked in `WebTransportEstablishmentFailureTests`,
  `WebTransportHardeningTests`, `WebTransportDraft16Tests`, the TLS negative-vector tests, and the
  deterministic fuzz corpora). Only the two gaps in F-07/F-08 are filed.
- **Tests: assertion helpers** — CLEAN. `expectThrowing` (`Tests/WebTransportTLSCoreTests/TLSCoreTests.swift:889`)
  and the `#require(...)`/`Issue.record` patterns are correct; no helper swallows a failure.
- **Tests: fixed ports** — CLEAN. All listener tests bind port 0 and read the assigned port back; the
  `4433` literals are only endpoint-parsing fixtures, not binds.

---

## Findings

### F-swift-perf-tests-01 — S2 / perf — Draining a buffered WebTransport stream is quadratic (struct copy + `[Data].removeFirst()`)

**file:line** `Sources/WebTransportHTTP3Core/WebTransportSession.swift:1034` (and `:997`, and
`Sources/WebTransportHTTP3Core/WebTransportStreams.swift:181`)

**What is wrong.** `WebTransportSessionManager` stores `WebTransportStreamState` by value in
`streamsByID: [UInt64: WebTransportStreamState]`. Every payload operation copies the whole stream struct
out of the dictionary, mutates it, and writes it back. Because `bufferedPayloads` is an `[Data]`, the
mutation is a copy-on-write copy of the entire array:

```swift
public mutating func receiveStreamPayload(streamID: UInt64, payload: Data) throws {
    guard var stream = streamsByID[streamID] else { ... }
    ...
    try stream.receivePayload(payload)      // bufferedPayloads.append(data)  -> CoW copy of [Data]
    streamsByID[streamID] = stream
}
public mutating func popStreamPayload(streamID: UInt64) -> Data? {
    guard var stream = streamsByID[streamID] else { return nil }
    let payload = stream.popPayload()       // bufferedPayloads.removeFirst() -> O(n) shift + CoW copy
    streamsByID[streamID] = stream
    return payload
}
```

`WebTransportStreamState.popPayload()` (`WebTransportStreams.swift:177-184`) uses
`bufferedPayloads.removeFirst()`. `Array.removeFirst` is O(n), and because the dictionary still holds a
reference when `removeFirst` runs, it also forces a CoW copy of the remaining elements. A stream may hold
up to `maxBufferedBytes` = 64 KiB (`WebTransportSession.swift:288`); 1-byte stream frames therefore allow
up to 65,536 buffered entries, and draining them is O(n²).

The runtime's own read path (`WebTransportInteroperableNetworkRuntime.swift:459-463`) appends a payload
and immediately pops it, so the array stays shallow there — but that path still pays two CoW allocations
and two actor-isolated dictionary mutations for every `receive()` call to accomplish nothing net.
The public manager API *is* used with real buffering: `Sources/WebTransportHTTP3Core/WebTransportLibrarySmoke.swift:228-231`
receives three payloads before popping at `:257`, and `Sources/LibrarySmokeServer/main.swift:222-223` and
`Sources/LibrarySmokeClient/main.swift:1025-1026` round-trip through it.

**Evidence.** Code quoted above. Micro-benchmark of the exact pattern (`swift -e`, array of `Int`,
`n/2` pops):

```
array 1024:  0.000155 s
array 8192:  0.002585 s      # 8x n -> 16.7x time
array 32768: 0.038075 s      # 32x n -> 245x time   (quadratic)
cow 8192:    0.005741 s      # dictionary copy-in/copy-out variant, ~2x
cow 32768:   0.080259 s
```

**What correct looks like.** Draining a stream should cost O(total bytes), not O(entries²); a payload read
that is immediately returned should not be copied through a value-typed dictionary twice.

**Smallest correct fix.** Keep a head index alongside `bufferedPayloads` (advance it in `popPayload`
instead of `removeFirst`) and compact only when the head passes a threshold. Independently, have
`WebTransportNetworkBidirectionalStream.receive` return the read payload directly instead of calling
`receiveStreamPayload` followed by `popStreamPayload` (`...NetworkRuntime.swift:459-463`).

---

### F-swift-perf-tests-02 — S2 / perf — `QUICLossRecovery.processAck` sorts twice and linearly scans every ACK range per sent packet

**file:line** `Sources/WebTransportQUICCore/QUICCoreState.swift:469` (and `:475`, `:455`)

**What is wrong.** For every ACK received:

```swift
for packetNumber in packets.keys.sorted() where acknowledgedRanges.contains(where: { packetNumber >= $0.low && packetNumber <= $0.high }) { ... }
...
for packetNumber in packets.keys.sorted() where isPacketThresholdLost(...) { ... }
```

- `packets.keys.sorted()` is built twice per ACK — O(n log n) each, n = packets outstanding in that
  number space.
- The first loop scans **all** peer-supplied ranges for every outstanding packet — O(n·m), where m is the
  peer's ACK range count. m is bounded only by `maximumExpandedAckedPacketNumbers = 16_384`
  (`QUICCoreState.swift:228`), i.e. a peer can hand the receiver ~16K ranges in one frame.
- The range scan also does not early-exit on the first match; it re-tests the same ranges for every packet.

**Evidence.**

```swift
453: public mutating func processAck(
459:     let acknowledgedRanges = try QUICAckTracker.acknowledgedPacketNumberRanges(from: ackFrame)
469:     for packetNumber in packets.keys.sorted() where acknowledgedRanges.contains(where: { packetNumber >= $0.low && packetNumber <= $0.high }) {
475:     for packetNumber in packets.keys.sorted()
228:     public static let maximumExpandedAckedPacketNumbers = 16_384
```

The public method is library API; the shipped runtime does not call it (grep: no `processAck` call site
outside tests), so this is a library-consumer cost, not a runtime hot path today.

**What correct looks like.** Ranges are sorted by construction (descending); iterate packets in descending
order with two cursors, or bisect into the range list, so the classification pass is O(n log m) at worst
and the keys are sorted once.

**Smallest correct fix.** Sort `packets.keys` once into a local array, reuse it for both loops, and replace
`contains(where:)` with a cursor walk over `acknowledgedRanges` (they are already ordered high→low).

---

### F-swift-perf-tests-03 — S2 / perf — `makeAckFrame` sorts the whole tracked packet-number set on every call; the cited test checks set size, not cost

**file:line** `Sources/WebTransportQUICCore/QUICCoreState.swift:328`

**What is wrong.** `makeAckFrame` is the per-packet "how do I acknowledge what I have" operation:

```swift
328: let ranges = contiguousRangesDescending(Array(receivedPacketNumbers).sorted(by: >))
```

`receivedPacketNumbers` is capped at `maximumTrackedReceivedPacketNumbers * 2` (`:243`, `:299`), i.e. up
to 16,384 numbers, and the whole set is copied into an array and sorted on **every** call. An ACK is built
per received packet (or per ACK-eliciting packet) in any normal use of this tracker. The doc comment at
`:230-243` argues the window exists because "retaining every number seen ... made each `makeAckFrame` sort
the entire history"; the window bounds n but does not remove the per-call O(n log n) sort, so the stated
cost profile is only partially delivered.

**Evidence.** Code at `:328`; window at `:243` and `:299` (`guard receivedPacketNumbers.count >
Self.maximumTrackedReceivedPacketNumbers * 2`). The regression test named for this property,
`Tests/WebTransportQUICCoreTests/QUICCoreStateTests.swift:324-336`, only asserts
`receivedPacketNumbers.count <= window * 2`, `largestReceived`, and `discardedBelow > 0` — it never measures
or bounds the cost of `makeAckFrame`, so the comment's claim is not covered by any test.

**What correct looks like.** ACK generation should cost roughly what is being acknowledged. Maintaining the
received set in a structure that yields contiguous ranges descending without a full sort (e.g. keep the
sorted array incrementally, or track only the recent window already sorted) makes it O(ranges).

**Smallest correct fix.** Keep `receivedPacketNumbers` as a sorted structure updated on insert, or cache the
last computed ranges and invalidate on insert; do not allocate + sort 16 K elements per call.

---

### F-swift-perf-tests-04 — S2 / perf — Fixed 4096-entry bookkeeping arrays are shifted on every stream close and every inbound delivery

**file:line** `Sources/WebTransportHTTP3Core/WebTransportSession.swift:1131` and
`Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:2378`

**What is wrong.** Two separate "recently seen stream" caches are plain arrays mutated at the front, so once
they reach their window every subsequent stream event costs O(window):

```swift
// WebTransportSession.swift:1130-1139  (maxRetainedClosedStreams = 4_096, line 296)
private mutating func recordClosedStream(_ streamID: UInt64) {
    if let existing = closedStreamOrder.firstIndex(of: streamID) { closedStreamOrder.remove(at: existing) }
    closedStreamOrder.append(streamID)
    while closedStreamOrder.count > maxRetainedClosedStreams { ... closedStreamOrder.removeFirst() ... }
}
// ...NetworkRuntime.swift:2376-2379  (maxRememberedDeliveries = 4_096, line 2333)
deliveredKeys.insert(key)
deliveryOrder.append(key)
if deliveryOrder.count > maxRememberedDeliveries { deliveredKeys.remove(deliveryOrder.removeFirst()) }
```

Once each array is at its cap — which a long-lived connection reaches after 4,096 streams — every peer
stream close (server side) and every peer stream delivery (client side) does a linear `firstIndex(of:)`
scan and/or a 4,096-element front removal. Both operations are peer-driven and unbounded in count over the
life of a connection (`F-swift-line-security-03` documents that the delivery queue itself is unbounded).

**Evidence.** Code quoted; constants at `WebTransportSession.swift:296` and
`...NetworkRuntime.swift:2333`. `Array.removeFirst` is O(n) — benchmark above (F-01): 32,768 elements over
16,384 pops = 38 ms versus 2.6 ms for 8,192.

**What correct looks like.** An insertion/eviction-ordered cache (a ring buffer, an index cursor, or
`isKnownUniquelyReferenced`-free head index) makes both the membership test and the eviction O(1), keeping
the per-stream cost constant.

**Smallest correct fix.** Replace `closedStreamOrder` / `deliveryOrder` with a fixed-size ring buffer (or
track a head index and compact occasionally); keep the `Set`/dictionary for membership.

---

### F-swift-perf-tests-05 — S3 / perf — `QUICUDPPort.receive` allocates and zeroes a full-size buffer per datagram and blocks in `poll`

**file:line** `Sources/WebTransportUDPApple/QUICUDPPort.swift:158`

**What is wrong.** Every receive allocates and zeroes a fresh `[UInt8]`:

```swift
136: public func receive(maximumBytes: Int = 65_535, timeoutMilliseconds: Int32 = 1_000) throws -> ...
158:     var buffer = [UInt8](repeating: 0, count: maximumBytes)
...
200:     return (Data(buffer.prefix(received)), endpoint)
```

The default `maximumBytes` is 65,535, so a caller that loops (as the probe client and the cancellation test
do) pays a 64 KiB zero-fill plus a `Data` copy per datagram. The whole call is synchronous and blocks in
`poll` (`:149`) and `recvmsg` (`:184`); it is invoked from async test bodies, where it blocks a cooperative
thread. The type's own doc comment scopes it to "QUIC runtime tests and local packet probes"
(`:39-41`), so this is not on the produced server's packet path — hence S3 rather than S2.

**Evidence.** Code quoted; default at `:136`; doc comment at `:39-41`; `receiveLock` serializes receives
(`:49`, `:144`).

**What correct looks like.** A reusable buffer (owned by the port, guarded by `receiveLock`) sized once, or
an allocation sized to the actual datagram where the platform allows.

**Smallest correct fix.** Hoist `var buffer = [UInt8](repeating: 0, count: maximumBytes)` into a lazily
grown stored property under `receiveLock`, reusing it across calls when `maximumBytes` does not increase.

---

### F-swift-perf-tests-06 — S3 / perf — `waitForPeerClosure` polls the session actor every 5 ms

**file:line** `Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:775`

**What is wrong.** After an echo exchange, `serveOne` waits (up to 250 ms) for the peer's session to reach
`.closed` by waking every 5 ms and taking the manager actor to read the state:

```swift
775: fileprivate func waitForPeerClosure(timeoutMilliseconds: Int32) async {
777:     while InteroperableQUICHelpers.remainingTimeout(...) > 0 {
781:         let isClosed = await manager.withManager { manager in ... }
797:         try await Task.sleep(for: .milliseconds(5))
```

Each iteration is an actor hop plus a dictionary lookup, up to 50 per call. This is a busy-wait where a
continuation resumed by the close path (or a longer, adaptive interval) would do.

**Evidence.** Code quoted; call site `...NetworkRuntime.swift:1320`
(`await session.waitForPeerClosure(timeoutMilliseconds: min(timeoutMilliseconds, 250))`).

**What correct looks like.** The close path signals the wait instead of the wait polling the state.

**Smallest correct fix.** Replace the poll with `Task.sleep` backoff (e.g. 1→20 ms) or have the manager's
close path resume a stored continuation for this session.

---

### F-swift-perf-tests-07 — S1 / test — The peer-input "does not exhaust memory" fuzz test asserts nothing

**file:line** `Swift/Tests/WebTransportHTTP3CoreTests/PeerInputFuzzTests.swift:186`

**What is wrong.** `peerFacingParsersRejectOversizedInputWithoutExhaustingMemory` names a memory-safety
property for the peer-facing parsers (a peer claims a 2^62 length in a few bytes; the parser must not
pre-allocate against the claim). The body has **zero** assertions:

```swift
186: @Test
187: func peerFacingParsersRejectOversizedInputWithoutExhaustingMemory() throws {
...
194:     for parser in peerInputParsers {
195:         do { try parser.run(oversized) } catch { /* Expected. */ }
...
207:     for parser in peerInputParsers {
208:         do { try parser.run(headerOnly) } catch { /* Expected. */ }
```

Both loops swallow every outcome. The test cannot fail for the property it is named after: a parser that
returned early, or that allocated a 4 GB buffer and (on this machine, under this allocator) survived, passes
identically. It is a regression guard only against traps/aborts, which the sibling test
`peerFacingParsersNeverTrapOnArbitraryInput` already covers with a much larger corpus. The only explicit
assertion in this file, `#expect(inputs.count > iterations)` (`:182`), is a tautology about the local corpus
(`inputs.count == 12 + 6*iterations`); it says nothing about the parsers.

**Evidence.** Command (read-only):

```
$ swift test --filter 'peerFacingParsersRejectOversizedInputWithoutExhaustingMemory'
✔ Test peerFacingParsersRejectOversizedInputWithoutExhaustingMemory() passed after 0.002 seconds.
```

0.002 s for 22 parsers × 2 inputs confirms the test performs no meaningful work.

**What correct looks like.** The test should assert the observable contract: for an absurd declared length,
each throwing parser throws (and none returns a value carrying the absurd length), or the run is executed
under a bounded allocator/`--sanitize=address` with a recorded allocation ceiling. Either way the pass/fail
must depend on parser behaviour.

**Smallest correct fix.** Replace the swallowing loops with per-parser `#expect(throws:)` for the entries
that must reject, and either drop the misleading "WithoutExhaustingMemory" name or add an assertion that
the declared length is not honoured (e.g. `#expect(decodedByteCount <= available)`); delete the tautological
`#expect(inputs.count > iterations)`.

---

### F-swift-perf-tests-08 — S1 / test — No test covers the bounded-read contract of the shipped stream API

**file:line** `Swift/Tests/WebTransportNetworkRuntimeTests/WebTransportNetworkRuntimeTests.swift:28` (the
file that exercises the runtime's stream/session API end-to-end) — absence of a test for
`Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:442`
(`receive(maximumBytes:)`)

**What is wrong.** The public stream read takes a bound:

```swift
442: public func receive(maximumBytes: Int = 64 * 1024, ...) async throws -> Data {
446:     if let initialPayload = await state.consumeInitialPayload(), !initialPayload.isEmpty {
452:         return initialPayload          // <-- returns up to 64 KiB regardless of maximumBytes
```

That bound is documented and, when an initial payload was buffered at accept time, ignored. No test in
`Swift/Tests/**` calls it: the only `maximumBytes` uses in the whole test tree are for `QUICUDPPort`
(`grep -rn "maximumBytes" Tests/` returns only `Tests/WebTransportUDPAppleTests/QUICUDPPortTests.swift:55,58,61,64,109,115`).
The absence of this boundary test is why the defect survived to audit
(`F-swift-architecture-04`: `receive(maximumBytes: 1)` can return ~64 KiB).

**Evidence.**

```
$ grep -rn "maximumBytes" Tests/ | grep -v QUICUDPPort
(no output)
$ grep -rn "\.receive(" Tests/          # only port.receive / decoder.receive frames
```

The runtime-level stream API is otherwise exercised only indirectly through CLI subprocess runs
(`WebTransportProcessTests`), which pass small messages and never check a read bound.

**What correct looks like.** A test that accepts a stream whose first chunk is larger than k, then asserts
`receive(maximumBytes: k)` returns at most k bytes and that the unread remainder is preserved for the next
read — i.e. the contract the signature advertises.

**Smallest correct fix.** Add one test to `WebTransportNetworkRuntimeTests` that drives
`WebTransportNetworkBidirectionalStream.receive(maximumBytes:)` with an oversized initial payload and
asserts `payload.count <= k` plus a successful second read of the remainder.

---

### F-swift-perf-tests-09 — S2 / test — UDP cancellation test asserts only `Task.isCancelled`; every `receive` error is swallowed

**file:line** `Swift/Tests/WebTransportUDPAppleTests/QUICUDPPortTests.swift:69`

**What is wrong.** The test spins a loop around `port.receive(timeoutMilliseconds: 10)`, catches and ignores
**all** errors, sets `looped = true` purely from `Task.isCancelled`, and asserts that flag:

```swift
72:     let task = Task { () -> Bool in
73:         var looped = false
74:         while true {
75:             do { _ = try port.receive(timeoutMilliseconds: 10) } catch { /* expected for timeout */ }
80:             if Task.isCancelled { looped = true; break }
84:         }
85:         return looped
86:     }
88:     try await Task.sleep(for: .milliseconds(60))
89:     task.cancel()
90:     let observedCancellation = await task.value
91:     #expect(observedCancellation)
```

`Task.isCancelled` becomes true as soon as `task.cancel()` is called, whatever `QUICUDPPort.receive` does,
and the `catch` hides the only observable output. The test passes if `receive` is stubbed to
`throw QUICUDPError.timeout` immediately (`looped` is still set on the next poll), and it also cannot detect
the failure it was written for — a cancelled call that keeps blocking for its full timeout — because there
is no timing assertion.

**Evidence.** Code quoted. Command (read-only):

```
$ swift test --filter 'udpPortCancellationObservedWithShortReceiveTimeout'
✔ Test udpPortCancellationObservedWithShortReceiveTimeout() passed after 0.073 seconds.
```

0.073 s ≈ the 60 ms sleep: the assertion depends on the sleep, not on the port.

**What correct looks like.** The assertion must be about the port: either record that a call returned with
`QUICUDPError.timeout` before cancellation and stopped doing so after (with an elapsed-time bound), or assert
the post-cancel latency is small. As written the test name overstates what it checks.

**Smallest correct fix.** Capture `Date()` around the loop and assert the time between `task.cancel()` and
task completion is bounded (e.g. `< 200 ms`), and count at least one thrown `QUICUDPError.timeout`, so a
no-op or permanently-blocking `receive` fails.

---

### F-swift-perf-tests-10 — S2 / test — Cross-process test lock is a fixed `/tmp` directory with a 180 s wait and no stale-owner detection

**file:line** `Swift/Tests/WebTransportNetworkRuntimeTests/WebTransportNetworkRuntimeTests.swift:474`
(duplicate implementation: `Swift/Tests/WebTransportTests/WebTransportProcessTests.swift:945`)

**What is wrong.** All loopback tests in two test targets serialize on one hard-coded path via `mkdir`,
with `maximumWait = 180` seconds:

```swift
474: private static let lockPath = "/tmp/webtransport-loopback-tests.dirlock"
476: private static let maximumWait: TimeInterval = 180
499: private static func acquireBlocking(label: String) throws {
500:     let deadline = Date().addingTimeInterval(maximumWait)
504:         if unsafe Darwin.mkdir(lockPath, S_IRWXU) == 0 { try writeOwner(label); return }
508:         guard errno == EEXIST else { ... }
511:         if Date() >= deadline { throw ... "Timed out waiting for loopback lock held by \(readOwner())" }
518:         usleep(10_000)
535: private static func release() { _ = unlink(...); _ = rmdir(lockPath) }
```

There is no liveness check on the recorded owner PID and no age check. If any test process is killed while
holding the lock (CI timeout, `Ctrl-C`, crash in a test body), the directory persists and **every** gated
test in both targets blocks for 180 s and then fails — with the whole `swift test` run appearing to hang.
The `owner.txt` is written for diagnostics only; nothing ever reclaims the lock. Two independently written
copies of the same protocol also exist (one async-only, one with both overloads), so a fix must be applied
twice. `ls -ld /tmp/webtransport-loopback-tests.dirlock` currently reports "No such file or directory", so
the failure mode is latent, not active, on this host.

**Evidence.** Code quoted; two definitions confirmed by
`grep -rn "webtransport-loopback-tests.dirlock" Swift/Tests` (lines 474 and 945). `release()` is only
reached through `defer` on a normal return.

**What correct looks like.** A lock the kernel releases when the holder dies (or a stale check that reclaims
when the recorded PID is gone), and one shared implementation.

**Smallest correct fix.** Take an `flock`/`F_SETLK` exclusive lock on a lock file (released automatically on
process death) instead of `mkdir`, and have `WebTransportProcessTests` call the same helper; if `mkdir` is
kept, read `owner.txt`, parse the PID, and `mkdir` a replacement when `kill(pid, 0)` reports `ESRCH`.

---

### F-swift-perf-tests-11 — S2 / test — The concurrency-limit precedence test never asserts the limit was applied

**file:line** `Swift/Tests/WebTransportNetworkRuntimeTests/WebTransportServerPolicyTests.swift:146`

**What is wrong.** `explicitConcurrencyLimitOverridesANonDefaultPolicy` is the regression test for the
precedence rule (an explicit limit must beat the admission policy). Its body constructs a listener with
`maxConcurrentConnections: 1` and `.publicFacing`, calls `shutdown()`, and asserts nothing about the
result — the comment "the limit is applied" is not checked anywhere:

```swift
150:     let overriding = try WebTransportQUICServer(
151:         endpoint: endpoint,
152:         maxConcurrentConnections: 1,
153:         authority: "localhost", localOnly: false, admission: .publicFacing)
157:     overriding.shutdown()
```

The only `#expect` in the body is the `#expect(throws:)` for the invalid `0`/`-1` cases (`:160-170`). The
test therefore passes for the exact defect it was written to guard: the magic value `16` still means "argument
not supplied" (`F-swift-architecture-05`), because the test only uses `1`, which is not the sentinel. It
would also pass with the limit silently dropped, since nothing observes it.

**Evidence.** Code quoted (`:146-180`); `grep` shows no other test reads back an effective
`maxConcurrentConnections`. Compare `F-swift-architecture-05`, which cites this same test as covering "only
1 and 0/-1".

**What correct looks like.** The test must observe the effective limit. Cheapest reliable form: with
`maxConcurrentConnections: 16` and `.publicFacing`, establish 16 sessions and assert the 17th is refused
(the sentinel case), and/or expose the applied limit on the listener so the precedence is assertable without
behavioural setup.

**Smallest correct fix.** Add `maxConcurrentConnections: 16` with a non-default policy plus an assertion on
an observable effect (a refused 17th session, or a read-back accessor), and keep the 1/0/-1 cases.

---

### F-swift-perf-tests-12 — S3 / test — Unconditional 2 s sleeps on the success path of the public-API exchange helpers

**file:line** `Swift/Tests/WebTransportTests/WebTransportPublicAPITests.swift:154` (also `:208`, `:212`)

**What is wrong.**

```swift
139:     for _ in 0..<5 {
140:         do {
...
151:             let result = try await client.echo(to: listener.localEndpoint, message: message)
152:             let serverResult = try await served
153:             listener.shutdown()
154:             try await Task.sleep(for: .seconds(2))
155:             return (result, serverResult)          // success path
...
164: private func runLoopbackPublicAPISessionCloseExchange() async throws {
166:     for _ in 0..<8 {
...
208:             try await Task.sleep(for: .seconds(2))  # success path
209:             return
210:         } catch {
212:             try await Task.sleep(for: .seconds(2))  # failure path
```

The success path sleeps 2 s after the exchange has already completed and the listener has been shut down,
with no assertion or later step depending on the delay (ports are ephemeral, `port: 0`). The close-lifecycle
helper can sleep 2 s × 8 attempts plus 2 s on success ≈ 18 s. This is a fixed wall-clock delay used as
implicit synchronisation: it slows the suite and, worse, hides whether any real ordering dependency exists.

**Evidence.** Code quoted; `makeLoopbackPublicAPIPair` binds `port: 0` (`:127`), so no port-reuse wait is
required.

**What correct looks like.** Wait on the condition that actually needs to hold (e.g. `listener.shutdown()`
completing, or the retry budget), not a constant sleep; drop the success-path sleep entirely.

**Smallest correct fix.** Delete the `Task.sleep(for: .seconds(2))` on the success path (`:154`, `:208`); if
a teardown must complete, await it explicitly (shutdown already returns after it stops accepting).

---

## Notes on things deliberately not filed

- `WebTransportSessionManager.bufferedIngressSessionCount` (`WebTransportSession.swift:1236-1245`) rebuilds a
  `Set` over all sessions on every buffered-ingress acceptance. It is bounded by `maxBufferedSessions = 64`
  and only runs on the ingress-buffering path; not filed.
- `WebTransportSession.enqueueBlockedFlowCapsule` uses `queue.contains(capsule)` (`:1310`) — O(n) per
  enqueue, but the queue holds monotonic-limit capsules and stays small; not filed.
- `QPACKDynamicTable.entries.insert(field, at: 0)` (`QPACK.swift:226`) is O(n) per insert into an
  eviction-bounded table; not filed.
- The Swift suite is otherwise green and the tests I ran (`peerFacingParsersRejectOversizedInput…`,
  `udpPortCancellationObservedWithShortReceiveTimeout`) pass, which is the evidence for F-07 and F-09.
