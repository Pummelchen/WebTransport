# Swift Implementation

This directory contains the active native Swift implementation of HTTP/3
WebTransport protocol layers.

Current Phase 1 through Phase 13 status: the draft-15 core compliance matrix
builds and passes. A 2026-06-19 production-readiness audit is recorded in
`PRODUCTION_READINESS_AUDIT.md`; the follow-up closure pass added the public
`WebTransport` product, app-style client/server CLI products, and targeted
correctness fixes for the remaining go-live blockers found in that audit.

- `AppleQUICSpike` proves prompt-free localhost QUIC listener/client startup,
  HTTP/3 ALPN negotiation, client-initiated bidirectional streams,
  client-initiated unidirectional streams, and server inbound stream acceptance
  using only Apple SDK frameworks.
- The runtime identity is generated in memory from a non-persistent `SecKey` and a
  generated self-signed certificate. It does not create, import, search, or modify
  keychains.
- QUIC datagrams are currently blocked: `NetworkConnection<QUIC>` negotiates
  `usableDatagramFrameSize == 0` on both peers even when both sides configure
  `.maxDatagramFrameSize(1_200)`.
- Full Network.framework QUIC datagram and runtime reset mutation support remains
  blocked in the Apple adapter audit. This does not block the project because the
  production transport path is the native Swift QUIC core over Apple UDP.
- `WebTransportQUICCore` now contains native QUIC byte, varint, packet-number,
  transport-parameter, long-header packet, and frame codecs.
- `WebTransportQUICCore` includes `RESET_STREAM_AT` and the draft reset-stream-at
  transport parameter required by `draft-ietf-webtrans-http3-15`.
- `WebTransportQUICCore` also contains reusable Phase 2 QUIC state-machine
  primitives for connection ID lifecycle and retirement, version policy, packet
  number spaces, ACK generation and decoding, packet-threshold loss recovery,
  retransmission frame selection, baseline congestion accounting, stream send and
  receive state, stream and connection flow control, DATAGRAM size enforcement,
  connection close, and idle timeout behavior.
- `WebTransportCryptoApple` derives QUIC v1 Initial secrets with Apple CryptoKit
  and is tested against RFC 9001 sample vectors.
- `WebTransportCryptoApple` also proves Handshake/1-RTT style packet protection
  mechanics with AEAD seal/open, tamper rejection, nonce construction, and AES
  header-protection mask generation.
- `WebTransportUDPApple` provides prompt-free loopback UDP I/O for native packet
  tests.
- `NativeQUICCoreSpike` proves native STREAM, DATAGRAM, RESET_STREAM,
  STOP_SENDING, and CONNECTION_CLOSE frame exchange over Apple UDP without using
  Network.framework QUIC, proves the Phase 2 QUIC state-machine primitives, then
  proves packet-protection seal/open and header-mask generation.
- `WebTransportTLSCore` now contains TLS 1.3 transcript hashing, HKDF label/key
  schedule helpers, Finished verify-data generation, ALPN `h3` extension encoding,
  QUIC transport-parameter extension encoding, typed ClientHello/ServerHello/
  EncryptedExtensions/Certificate/CertificateVerify/Finished bodies, TLS 1.3
  supported_versions, key_share, and signature_algorithms extension helpers,
  X25519 handshake secret derivation, application traffic secret progression,
  prompt-free identity/trust input models, and CertificateVerify verification
  primitives.
- `WebTransportTLSCore` also provides a CRYPTO-frame handshake flight encoder and
  decoder that fragments typed TLS messages into QUIC CRYPTO frames, reassembles
  out-of-order CRYPTO data, emits complete handshake messages, and updates the
  TLS transcript.
- `WebTransportHTTP3Core` contains HTTP/3 frame header codecs, SETTINGS payload
  encoding/decoding, unidirectional stream type parsing, the draft-15
  `webtransport-h3` upgrade token, WebTransport-required SETTINGS constants, and
  a versioned WebTransport-over-HTTP/3 draft-15 constants table.
- `WebTransportHTTP3Core` also contains the Phase 6 HTTP/3 base connection layer:
  client/server control stream generation, SETTINGS receive validation, request
  stream lifecycle, HEADERS handling through QPACK, DATA frame policy handling,
  GOAWAY state, and HTTP/3 application-error mapping.
- `WebTransportHTTP3Core` now contains the Phase 7 WebTransport session
  establishment layer: client extended CONNECT generation, server accept/reject
  decisions, session ID derivation from request stream IDs, draft/settings
  validation, protocol negotiation headers, and request-stream-to-session mapping.
- `WebTransportHTTP3Core` now contains the Phase 8 stream layer: WebTransport
  stream prefix serialization/parsing, bidirectional/unidirectional stream open and
  accept path with session ownership registration, session-scoped stream registry,
  backpressure-limited receive buffering, and reset/stop-sending frame emission.
- `WebTransportHTTP3Core` now contains the Phase 9 datagram layer: QUIC datagram
  framing for WebTransport sessions using the HTTP Datagram Quarter Stream ID,
  with per-session receive buffering, session routing, frame-size validation, and
  loss-tolerant queue pop APIs.
- `WebTransportHTTP3Core` now contains the Phase 10 flow-control layer:
  per-session flow-control settings from SETTINGS, capsule codec and parsing for
  max-*/blocked WebTransport capsules, stream-open and stream/send-path data
  limit enforcement, and flow-control capsule queueing for blocked senders.
- `WebTransportHTTP3Core` also contains the QPACK support needed for
  WebTransport session establishment and Phase 13 draft-15 hardening: static table
  lookup, dynamic table context lifetime and indexed references, Huffman string
  encoding/decoding from RFC 7541, encoder-stream instructions, decoder-stream
  instructions, RFC 9204 Base and post-Base field-line decoding, literal
  field-line encoding/decoding, required extended CONNECT request and response
  pseudo-header validation, decoder limits, malformed-input rejection, and QPACK
  HEADERS frame helpers.
- `WebTransportHTTP3Core` now includes Phase 13 draft-15 session and shutdown
  behavior for deterministic tests: `WT_DRAIN_SESSION`, `WT_CLOSE_SESSION`,
  CONNECT stream finish-as-close, close-result FIN/STOP_SENDING actions,
  `WT_SESSION_GONE` post-close stream/datagram cleanup, additional CONNECT stream
  data reset with `H3_MESSAGE_ERROR` after received close, bounded 8192-byte close-message
  validation, client and server buffered stream/datagram ingress before session
  acceptance, per-session and connection-level buffered ingress exhaustion,
  rejected-session buffer cleanup, explicit draft error mapping and QUIC frame
  helpers, 0-RTT CONNECT rejection, remembered-settings compatibility checks for
  future accepted 0-RTT paths, malformed CONNECT data-ordering rejection,
  protocol-policy rejection metadata, GOAWAY-driven draining, monotonic
  WebTransport flow-control limit updates, non-mutating failed capacity attempts,
  and deduplicated blocked-flow capsule queues under repeated blocked sends.
- `WebTransportHTTP3Core` also provides `LibrarySmokeClient`/
  `LibrarySmokeServer` in-memory smoke drivers and a strict pass/fail smoke matrix
  for close/drain, rejection, backpressure, early-ingress ordering promotion, and
  multi-session isolation scenarios. `NativeQUICCoreSpike` runs this matrix.
- `WebTransportHTTP3Core` also provides an executable
  `WebTransportDraft15ComplianceMatrix` covering the Phase 13J definition of done:
  establishment/negotiation, streams/datagrams, close/drain, flow-control/errors,
  H3 stream constraints, and prompt-free security/identity handling.
- The 2026-06-19 audit also hardened QUIC ACK handling, UDP receive validation,
  TLS extension-list decoding, role-sensitive HTTP/3 WebTransport SETTINGS
  validation, WebTransport datagram prefixing, `WT_CLOSE_SESSION` message bounds,
  and `WT_MAX_STREAMS` bounds.
- The public `WebTransport` product exposes async `WebTransportClient`,
  `WebTransportServer`, and `WebTransportSession` types. The
  `WebTransportClient` and `WebTransportServer` executables are app-style
  deterministic CLI demos over the native core; they are intended for packaging,
  smoke validation, and API exercise rather than external network interop.
- `AppleQUICSpike` and `NativeQUICCoreSpike` remain internal executable targets
  for protocol development, but they are not shipped as production products and
  the release script rejects stale spike binaries in release output.

Commands:

```sh
swift build
swift test
swift run WebTransportServer
swift run WebTransportClient
./build-release-apple-silicon.sh
```

Internal spike commands:

```sh
swift run AppleQUICSpike --loopback
swift run NativeQUICCoreSpike
```

Constraints:

- No external libraries.
- Keep protocol behavior aligned with the C99 and C++ implementations.
- Keep platform-specific networking and cryptographic primitives isolated behind
  internal interfaces.
