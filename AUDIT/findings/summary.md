# Phase B Findings Summary

Consolidated merge of `AUDIT/findings/*.json` into `AUDIT/ledger.json` (Phase B, 2026-09-15; branch `audit/2026-09-15`, base `196324e`).

| | Count |
|---|---|
| Phase B findings merged | 91 |
| Area files merged | 5 |
| Pre-existing Phase A ledger rows kept | 7 |
| **Total ledger tasks** | **98** |

## Counts by severity

| Severity | Phase B findings | Ledger total |
|---|---:|---:|
| S0 | 4 | 5 |
| S1 | 16 | 18 |
| S2 | 45 | 46 |
| S3 | 26 | 29 |
| **Total** | **91** | **98** |

## Counts by area (Phase B)

| Area | S0 | S1 | S2 | S3 | Total |
|---|---:|---:|---:|---:|---:|
| c99-deep | 3 | 6 | 18 | 8 | 35 |
| repo-ops | 0 | 1 | 7 | 10 | 18 |
| swift-architecture | 1 | 4 | 6 | 3 | 14 |
| swift-line-security | 0 | 3 | 7 | 2 | 12 |
| swift-perf-tests | 0 | 2 | 7 | 3 | 12 |
| **Total** | **4** | **16** | **45** | **26** | **91** |

## Every S0 finding

- **A-0001** — Swift test bundle fails to LINK on Swift 6.4: the test target uses WebTransportTLSCore without declaring it  
  `Swift/Package.swift:217, Package.swift:196` · Phase A (swift:WebTransportHTTP3CoreTests) · bug
- **F-01** — Ten QPACK static-table entries are truncated at the RFC's line wrap, and the --check that exists to prevent this re-derives the same wrong table  
  `C99/src/http3/qpack_static_table.h:60` · c99-deep · bug
- **F-02** — The draft-16 :protocol token is defined as the HTTP/2 capsule token, and the 'legacy' constant is the same string, so webtransport-h3 can neither be sent nor accepted  
  `C99/include/webtransport/webtransport/session_request.h:38` · c99-deep · bug
- **F-03** — The stream-table reclaim decrements the opened-stream counters, so a session reuses stream IDs and then fails to open streams at all  
  `C99/src/quic/stream.c:463` · c99-deep · bug
- **F-swift-architecture-01** — CONNECT-stream capsule reader hides an unbounded, peer-controlled buffer: remote memory exhaustion  
  `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:831` · swift-architecture · unsafe

## Every S1 finding

- **A-0004** — 25 Swift warnings in the baseline; §1 mandates warnings-as-errors  
  `Swift/Sources/WebTransportUDPApple/QUICUDPPort.swift (+2)` · Phase A (swift:all) · style
- **A-0006** — No check that a target's imports are covered by its declared dependencies (the A-0001 defect class)  
  `.github/workflows/swift-ci.yml:26` · Phase A (swift:ci) · test
- **F-04** — The reset_stream_at transport-parameter codepoint is wrong, so the extension draft-16 requires is never negotiated  
  `C99/include/webtransport/quic/transport_parameters.h:64` · c99-deep · bug
- **F-05** — Two RFC 9000 18.2 MUSTs are missing from the transport-parameter value check: initial_max_streams above 2^60, and a client-sent stateless_reset_token  
  `C99/src/quic/transport_parameters.c:214` · c99-deep · logic
- **F-06** — A peer's initial_source_connection_id is adopted as the destination connection ID without ever being compared with the Source Connection ID of the packet it arrived in  
  `C99/src/quic/connection.c:185` · c99-deep · logic
- **F-07** — A WebTransport unidirectional prefix split between the type and the session ID aborts the connection with INTERNAL_ERROR after the stream is already marked classified  
  `C99/src/http3/driver.c:228` · c99-deep · bug
- **F-08** — Pseudo-header values are never checked for the field-content grammar, so :method/:scheme/:path/:authority/:protocol may carry CR, LF or NUL  
  `C99/src/http3/headers.c:128` · c99-deep · bug
- **F-28** — On Windows the monotonic clock wraps after about 21 days of uptime because ticks are multiplied by 10^6 before the division  
  `C99/src/core/time.c:35` · c99-deep · bug
- **F-repo-ops-01** — CI never builds or tests on the mandated Swift 6.4 / Xcode 27 toolchain  
  `.github/workflows/swift-ci.yml:18` · repo-ops · test
- **F-swift-architecture-02** — waitForReady leaks its checked continuation and connection observer when the handshake times out  
  `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1752` · swift-architecture · unsafe
- **F-swift-architecture-03** — datagramsUsable returns a constant true, so the public datagramsAvailable flag and echo() report a capability that was never negotiated  
  `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1804` · swift-architecture · bug
- **F-swift-architecture-04** — receive(maximumBytes:) ignores its bound when the stream has a buffered initial payload  
  `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:446` · swift-architecture · logic
- **F-swift-architecture-05** — The magic value 16 means 'argument not supplied', so an explicit maxConcurrentConnections: 16 is silently overridden by the admission policy  
  `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:1046` · swift-architecture · logic
- **F-swift-line-security-01** — Session teardown resets and stops every associated stream regardless of which half this endpoint owns  
  `Swift/Sources/WebTransportHTTP3Core/WebTransportSession.swift:1440` · swift-line-security · bug
- **F-swift-line-security-02** — Short-header reserved bits are never validated, although the long-header and Retry decoders do validate them  
  `Swift/Sources/WebTransportQUICCore/QUICPacket.swift:310` · swift-line-security · incomplete
- **F-swift-line-security-03** — Per-connection inbound-stream queue has no bound and post-establishment unidirectional streams have no consumer  
  `Swift/Sources/WebTransportNetworkRuntime/WebTransportInteroperableNetworkRuntime.swift:2390` · swift-line-security · unsafe
- **F-swift-perf-tests-07** — The peer-input test named 'RejectOversizedInputWithoutExhaustingMemory' contains zero assertions and swallows every parser outcome  
  `Swift/Tests/WebTransportHTTP3CoreTests/PeerInputFuzzTests.swift:186` · swift-perf-tests · test
- **F-swift-perf-tests-08** — No test covers the bounded-read contract of the shipped stream API, which is why receive(maximumBytes:) returning the whole buffered initial payload survived  
  `Swift/Tests/WebTransportNetworkRuntimeTests/WebTransportNetworkRuntimeTests.swift:28` · swift-perf-tests · test

_S0/S1 entries not prefixed `F-` are pre-existing Phase A ledger rows, preserved unchanged by this merge._
