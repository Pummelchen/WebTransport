# Swift Production Readiness Audit

Audit date: 2026-06-19

Protocol reference: latest official WebTransport over HTTP/3 draft on the IETF
Datatracker, `draft-ietf-webtrans-http3-15` dated 2026-03-02:
<https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>

## Current Verdict

The Swift draft-15 core compliance matrix builds and passes, but the Swift
package is not yet a production go-live SDK. It has strong protocol-layer test
coverage and in-memory smoke coverage, but it still lacks the published
client/server facade, complete authoritative TLS handshake gating, full RFC 9204
QPACK dynamic-base coverage, and several flow-control/reset semantics needed
before external production handoff.

## Fixes Landed From This Audit

- QUIC ACK processing no longer expands attacker-controlled ACK ranges during
  loss recovery; public ACK set expansion is capped.
- UDP receive rejects invalid buffer and timeout inputs and serializes blocking
  `poll`/`recvfrom` calls.
- TLS extension-list decoding rejects duplicate extension types.
- HTTP/3 WebTransport SETTINGS validation is role-sensitive: servers do not
  require clients to send `SETTINGS_ENABLE_CONNECT_PROTOCOL`; clients still
  require it from servers.
- WebTransport DATAGRAM prefixes now encode/decode the HTTP Datagram Quarter
  Stream ID instead of the raw CONNECT stream ID.
- `WT_CLOSE_SESSION` message length now allows the draft-15 8192-byte maximum.
- `WT_MAX_STREAMS_BIDI` and `WT_MAX_STREAMS_UNI` reject values above `2^60`.

## Remaining Go-Live Blockers

| Priority | Area | Blocker |
| --- | --- | --- |
| P0 | Public API | No production `WebTransport` client/server package product or Swift concurrency facade is published. Current products are low-level libraries and spike executables. |
| P0 | TLS handshake authority | `TLSQUICConnectionState` can derive application keys as a primitive without enforcing certificate trust, CertificateVerify, Finished, ALPN `h3`, and QUIC transport-parameter milestones. Either gate those milestones or document/rename it as a non-authoritative key-schedule state. |
| P0 | Flow control | Disabled, zero, and unlimited flow-control states need explicit modeling; receive-side advertised limit violations must close the session with `WT_FLOW_CONTROL_ERROR` rather than using sender-side blocked behavior. |
| P1 | Stream reset semantics | WebTransport stream resets need complete 32-bit application error remapping and `RESET_STREAM_AT` use for data-stream resets. |
| P1 | QPACK | WebTransport HEADERS coverage passes, but full RFC 9204 dynamic Base/post-Base field-line semantics and vectors need a dedicated closure pass before calling QPACK production-complete. |
| P1 | Protocol negotiation fields | `WT-Protocol` and `WT-Available-Protocols` need strict Structured Fields parsing/serialization, including parameter handling and optional malformed-field ignore semantics. |
| P1 | Buffered ingress | Excess buffered datagrams should be dropped, and excess buffered streams should produce the required stream close/reset action. |
| P2 | Release surface | Spike executables should not be shipped as production products, and the release script should clean or reject stale binaries before packaging. |
| P2 | Error typing | The code rejects `WT_MAX_STREAMS` above `2^60`, but the HTTP/3 `H3_DATAGRAM_ERROR` outcome is not yet represented as a typed application error. |

## Verification

- `swift test --package-path Swift`: passed, 135 tests.
- `swift build -c release --package-path Swift`: passed.

## Next Audit Execution Plan

1. Add the public `WebTransport` package product with client, server, session,
   stream, datagram, close, and backpressure APIs.
2. Split TLS primitives from the authoritative QUIC/TLS connection state and add
   tests that prove application traffic cannot start before all authentication,
   ALPN, Finished, and transport-parameter milestones are satisfied.
3. Refactor WebTransport flow-control state to distinguish disabled, zero, and
   unlimited limits, and add receive-side close tests for advertised-limit
   violations.
4. Complete stream reset mapping and `RESET_STREAM_AT` behavior across the
   WebTransport stream layer.
5. Finish QPACK RFC 9204 base/post-base semantics with draft/RFC vectors.
6. Replace ad hoc WebTransport protocol negotiation parsing with Structured
   Fields parsing and serialization.
7. Harden buffered ingress behavior and release packaging.
