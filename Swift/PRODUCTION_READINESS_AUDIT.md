# Swift Production Readiness Audit

Audit date: 2026-06-19

Protocol reference: latest official WebTransport over HTTP/3 draft on the IETF
Datatracker, `draft-ietf-webtrans-http3-15` dated 2026-03-02:
<https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>

## Current Verdict

The Swift draft-15 core compliance matrix builds and passes, and the follow-up
closure pass has resolved the go-live blockers found in this audit. The Swift
package now publishes a `WebTransport` library product plus app-style
`WebTransportClient` and `WebTransportServer` CLI products over the native core.

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

## Go-Live Blocker Closure

| Priority | Area | Closure |
| --- | --- | --- |
| P0 | Public API | Added the public `WebTransport` package product, Swift concurrency facade, and `WebTransportClient` / `WebTransportServer` CLI products. |
| P0 | TLS handshake authority | Documented `TLSQUICConnectionState` as a deterministic TLS-for-QUIC primitive, not an authoritative production peer-authentication gate. Production callers must gate application traffic on certificate trust, CertificateVerify, Finished, ALPN `h3`, and QUIC transport parameters. |
| P0 | Flow control | Refactored flow-control state to distinguish disabled, explicit zero, and unlimited limits; receive-side advertised-limit violations now close the session with `WT_FLOW_CONTROL_ERROR`. |
| P1 | Stream reset semantics | Completed 32-bit WebTransport application-error remapping and `RESET_STREAM_AT` emission for stream reset paths. |
| P1 | QPACK | Completed RFC 9204 dynamic Base/post-Base decoding semantics and added dedicated vectors. |
| P1 | Protocol negotiation fields | Replaced ad hoc `WT-Protocol` / `WT-Available-Protocols` parsing with Structured Fields string/list parsing and serialization, including optional malformed-field ignore behavior. |
| P1 | Buffered ingress | Excess buffered datagrams are dropped; excess buffered streams report the required reset action with `WT_BUFFERED_STREAM_REJECTED`. |
| P2 | Release surface | Removed spike executables from production package products and hardened the release script to clean release output and reject stale spike binaries. |
| P2 | Error typing | Kept `H3_DATAGRAM_ERROR` represented through typed HTTP/3 application-error constants while retaining the `WT_MAX_STREAMS` `2^60` guard. |

## Verification

- `swift test --package-path Swift`: passing.
- `swift run --package-path Swift WebTransportClient`: passing.
- `swift run --package-path Swift WebTransportServer`: passing.
- `swift build -c release --package-path Swift`: passing.
- `Swift/build-release-apple-silicon.sh`: passing.

## Follow-Up Production Monitoring

1. Re-run this audit whenever the IETF WebTransport draft advances beyond
   draft-15 or becomes an RFC.
2. Keep the CLI facade, smoke matrix, and protocol tests in lockstep when adding
   externally interoperable network transport behavior.
3. Keep spike targets out of production products and release artifacts.
