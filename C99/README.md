# C99 WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-16`, dated 2026-07-06.

Draft-16 score: **0%** — the protocol is not implemented yet. What exists is the
foundation the protocol is built on, and it is real, tested code rather than
scaffolding.

## Current Status

**Phases 0 to 4 of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) are complete, and
Phase 5 (HTTP/3) and Phase 7 (the draft-16 session layer) have their message-level pieces in, and
Phase 8's public API has begun: one umbrella header exposes every layer and states the rules that hold
across them.** Phase 3 finishes the TLS 1.3 handshake end to end, and Phase 4
is the QUIC connection runtime: packet number spaces with ACK generation, loss detection
and probe timeouts, NewReno congestion control, the stream state machines and flow
control, QUIC DATAGRAM, the close paths, connection IDs (issued, retired and received),
the packet build/read seam, and the IPv4/IPv6 UDP runtime, with two connections completing
a whole handshake and exchanging protected, acknowledged packets over IPv6 and IPv4
loopback in the tests. Phase 4's completion criteria are met: those loopback tests pass on
macOS and Linux in CI, the loss, probe-timeout and close-path suites pass, and every suite
runs again under AddressSanitizer and UndefinedBehaviorSanitizer.
The rest of Phase 5, and Phases 6 to 14, are not started: no WebTransport protocol is
implemented yet, so the draft-16 score is 0%.

What is here:

- The CMake build: a static library, a shared library, three CLI executables, an
  install tree with a CMake package a consumer can `find_package`, and
  warnings-as-errors on this project's own sources with `-Wconversion` among
  them.
- Core utilities, one file each, with the reason for each written down:
  - `status.h` — the status and error model every public call returns.
  - `checked.h` — checked integer arithmetic, so a length from the wire cannot
    wrap into an allocation of the wrong size.
  - `endian.h` — big-endian load and store, including the 24-bit forms QUIC and
    TLS both use.
  - `cursor.h` — a bounds-checked read cursor with a sticky failure.
  - `writer.h` — a two-pass write cursor, so a length-prefixed message is built
    once and measured by the same code that writes it.
  - `buffer.h` — a growable buffer with an explicit capacity bound.
  - `allocator.h` — the allocator interface, taking a size on free and realloc so
    a counting allocator can be exact.
  - `log.h` — a callback logging surface with no formatted output, because the
    plan forbids peer data in logs and a printf-shaped surface makes that a rule
    to remember at every call site.
  - `time.h` — a monotonic clock and deadline arithmetic that cannot wrap.
  - `version.h` — library identity.
- 70 unit test files and 79,589 checks, run by `ctest` and again under
  AddressSanitizer and UndefinedBehaviorSanitizer. Most of that count is the
  malformed-input corpus, which drives every parser with a fixed pseudo-random
  byte stream: a random buffer is a better generator of the case nobody thought
  of than a list of cases somebody did, and under the sanitizers an out-of-bounds
  read is a failure rather than a plausible value. Two more of the large counts
  are loops rather than hand-written cases: 4,160 checks in `test_buffer`, 4,096
  of them from appending a byte at a time to prove buffer growth is logarithmic,
  and 1,013 in `test_time` from stepping a monotonic clock and checking the
  deadline arithmetic does not wrap near the counter's top. Note that Darwin has
  no LeakSanitizer, so a leak in the tests is found by the Linux CI leg and not by
  a local run on this machine; that is how the first one was found.
- **The public API** (Phase 8), which is what a consumer outside this repository
  builds against; `docs/PUBLIC-API.md` is its contract, and
  `apps/wt-api-sample/main.c` is a consumer that includes only the umbrella header
  and is built and run by CTest on every platform, so the document is checked rather
  than described:
  - `webtransport.h` — the one header a consumer includes, carrying the three rules
    that hold across every layer: a bound is this endpoint's and the code says so
    rather than blaming the peer, incomplete is not malformed on a stream (a
    datagram is the deliberate exception, because a datagram is the unit), and a
    refusal keeps the peer's code.
  - `api/session.h` — the opaque session handle: `wt_session_create`/`wt_session_destroy`
    take the allocator the object was made with, so a session created from a pool
    returns to that pool; the state a consumer reads is this header's own enum,
    mapped member by member rather than cast, so a renumbering of the internal
    machine is a compile error and not a silent contract change; and
    `wt_session_last_error` reports a stable status NAME and the peer's CODE, never
    a peer's text. The two bounds the API owns are the session's own: an authority
    too long for the handle's copy is refused rather than truncated (a truncated
    authority names a different session) and a capsule value over
    `max_capsule_bytes` is refused as excessive load rather than buffered.
  - `api/events.h` — the event-loop seam: a callback table with a context and
    nothing else, so a caller needs no synchronization it did not already have for
    the call it made. The contract is written down where a caller can see it: the
    library never calls a callback from a thread of its own and never re-enters
    itself, a pointer passed to a callback is a view valid for the call only, and
    no callback for an event means the event is accepted and discarded rather than
    turned into a connection error. Peer streams live in a fixed table sized by
    `max_streams` (the peer runs into the bound; the table never grows for one), and
    a stream or datagram naming another session is refused with HTTP/3's identifier
    error instead of being delivered to the wrong session or dropped silently.
    `wt_session_config_default()` returns every bound at its default, because a C
    caller that forgot a field would otherwise pass whatever its stack held into a
    bound.
  - `http3/driver.h` — the seam between a connection and the endpoint: it turns a
    stream's opening bytes into a classified stream, and it exists because a stream's
    type prefix is a varint that a peer may SPLIT across frames. Deciding a type from
    half a varint is how an implementation reads someone else's stream, so the driver
    holds at most the first eight bytes of each opening stream until they add up to a
    prefix — in a fixed table, because a buffer that grows with a peer's stream count
    is a heap exhaustion path with the peer's name on it. A prefix that does not start
    at offset zero, or a stream resumed out of order, is the caller's accounting rather
    than the peer's, and the payload after the prefix is a view into the frame that
    completed it, so nothing is copied. The same header starts this endpoint's OWN
    streams: the control stream is its `0x00` prefix followed by a SETTINGS frame built
    from the caller's settings, measured into scratch before the frame is written — the
    same measure-then-write rule as everywhere else — and the QPACK streams are their
    prefixes alone, with the endpoint's once-per-connection rule refusing a second one
    before any bytes go out. The same header reassembles a stream's HTTP/3 FRAME
    boundaries, where a frame's own varints can be split the same way — and it
    deliberately does not buffer a frame's payload: it reports pieces to a sink with a
    `last` flag, because how much of a HEADERS section to hold is a bound, and a bound
    belongs to whoever owns the memory. The one number the driver does bound is the
    frame's declared length, refused as excessive load before the sink allocates for
    it. A frame whose header or payload is cut off by the stream's end is
    `WT_ERR_TRUNCATED` — one byte of a two-varint header is exactly as incomplete as
    one byte of a payload, which is the case a naive reassembler misses. The same header
    carries the routing that makes the driver installable as a QUIC connection's frame
    handler: a STREAM frame on a peer's unidirectional stream has its prefix
    reassembled and its bytes then sent either to the frame sink (HTTP/3's own streams)
    or to the session (the draft's stream type, whose bytes are not frames at all), a
    peer's bidirectional stream becomes a request stream, a DATAGRAM's payload goes to
    the session uninterpreted, and a frame on a stream this endpoint OPENED is not
    routed at all — the peer's answer belongs to the connection's own stream state. The
    outbound half goes through a three-call transport table (`open_stream`,
    `send_stream`, `send_datagram`) rather than naming a QUIC connection, so the HTTP/3
    layer stays independent of the connection implementation and its bytes are checked
    against a recording transport instead of a live handshake. Each stream is BUILT
    before it is opened, which puts the once-per-connection rules ahead of the open and
    means a refused start cannot orphan a stream the peer would see and this endpoint
    could not explain. `wt_http3_driver_quic_transport` binds that table to a real
    connection, and it reads the send offset from the CONNECTION's own stream state
    (`stream->send_offset`) rather than keeping its own — an adapter with its own counter
    would be a second opinion about a number the connection already owns, which is how two
    layers come to disagree about where a stream is. A stream the connection does not know
    is refused by this layer as the caller's error, and everything else is passed through
    unchanged: congestion and connection state are the connection's to report.
  - `http3/endpoint.h` — the HTTP/3 endpoint's own streams, which is the lifecycle a
    consumer never sees: our control stream (`0x00`) and QPACK streams (`0x02`/`0x03`)
    exist once each, the peer's unidirectional streams are classified by their type
    prefix, an UNKNOWN type is ignored rather than failed (section 6.2.1) while a
    second control stream, a second QPACK stream and an unrequested push stream each
    commit the connection to the error the RFC names, and the draft's WebTransport
    stream (`0x54`) is recognised as the session layer's rather than mistaken for an
    unknown one -- which would lose a session's streams one at a time. The peer-stream
    table is fixed, so running into it is `WT_ERR_LIMIT` with no error code: this
    endpoint's bound, not the peer's mistake.
  - the same header's request-stream lifecycle, which is the session's own stream: only
    a client opens one (HTTP/3 has no server-initiated request, and section 6.1 makes a
    client that receives a server-initiated bidirectional stream a
    `H3_STREAM_CREATION_ERROR`), a complete request keeps its state until the stream
    ends, and the request-ordering rules stay in `request.h` rather than being
    re-implemented. The request table is bounded too, at
    `WT_HTTP3_ENDPOINT_REQUESTS_MAX` sessions per connection, and a duplicate is found
    before the bound so a caller's mistake is never reported as a limit.
  - the same header's QPACK decode path, which is what turns a HEADERS frame into a
    request: the endpoint owns the decoder state (the dynamic table its peer's encoder
    stream fills, and the insertion count), a capacity below 32 makes `MaxEntries` zero
    so no section may reference a dynamic table this endpoint never advertised, and the
    draft-16 layer then decides whether the decoded pseudo-headers are a WebTransport
    request — the endpoint deliberately does not know what one is. The RFC's "trailers
    MUST NOT contain pseudo-header fields" is enforced here, because the message
    decoder has one request shape and one response shape and cannot tell a trailer from
    a request on its own.
  - the encode side of that same header: `wt_http3_message_encode` writes a field
    section for a request or a response, and
    `wt_http3_endpoint_write_headers` writes the HEADERS frame around it. The section
    is encoded into the caller's scratch FIRST because a frame's length prefix is a
    varint whose width depends on the length — the frame can only be written once the
    section has been measured, which is the rule this library follows everywhere a
    length is written. The lines are literal (always valid, never needing a dynamic
    table, larger on the wire than a static-table reference would be), and the round
    trip is the test: what a client writes is fed to a server's decode path and then to
    the draft-16 validator, so the two directions cannot disagree without a test
    failing.
  - `api/endpoint.h` — which side this program is, the name the peer's certificate
    must be valid for, and how it is judged, so a trust misconfiguration is a return
    value before any packet rather than a handshake failure afterwards. The
    development bypass is tied to a loopback name through the trust layer's own
    `wt_tls_trust_host_is_loopback`, which is exported precisely so the configuration
    check and the handshake cannot disagree about the rule; a server must carry no
    trust policy, because this draft has no client authentication and a policy there
    would be a promise the library cannot keep.
  - `api/flow.h` — the session's send-side flow control, which is what backpressure
    means when there is no socket to block on. The draft's rules are the
    implementation: flow control is off until both endpoints' SETTINGS say otherwise
    (and a capsule arriving while it is off is ignored, not refused, because the
    draft makes it conditional); limits strictly increase, so a repeat and a decrease
    are both the draft's flow-control error; a stream count above the draft's
    `2^60` ceiling is that error too; and the allowance functions answer "may I send
    this" before the refusal rather than after it. The initial limits come from the
    peer's SETTINGS through `wt_session_flow_advertised`, so a setting the peer
    omitted is zero rather than unlimited -- which is what it means on the wire.
- **The QUIC wire core** (Phase 1), which is everything QUIC needs before there
  is a connection:
  - `quic/varint.h` — variable-length integers, encoding shortest and decoding
    any form, with the RFC's four examples in the test.
  - `quic/packet_number.h` — packet number encoding from the reconstruction
    window and decoding by RFC 9000 appendix A.2, including its overflow guard
    near the top of the 62-bit range.
  - `quic/frame.h` — every RFC 9000 frame, the RFC 9221 DATAGRAM pair and
    `RESET_STREAM_AT`, parsed into a tagged union whose payloads are views, so
    parsing a packet allocates nothing. Each field rule the RFC states is a
    refusal with the transport error code the peer must be told.
  - `quic/packet.h` — long, short and Retry headers, with the Length field
    computed on encode so a caller cannot disagree with itself, and the consumed
    size reported so a coalesced datagram can be walked.
  - `quic/transport_parameters.h` — the parameter codec, with framing and
    duplicates refused here and the section 18.2 value rules a separate opt-in
    check, because the same bytes are parsed as a TLS extension by a layer that
    must not refuse them itself.
  - `quic/connection_id.h` — connection ID storage and retirement, enforcing the
    peer's `active_connection_id_limit`, `retire_prior_to` and the
    `CONNECTION_ID_LIMIT_ERROR` of RFC 9000 section 5.1.1.
- **Crypto and packet protection** (Phase 2), which turns bytes into a QUIC
  packet an observer cannot read:
  - `crypto/crypto.h` — one interface, one backend. SHA-256, HMAC, HKDF extract,
    expand and expand-label, AES-128-GCM and ChaCha20-Poly1305, the AES block and
    ChaCha20 keystream header protection is built from, a constant-time comparison
    and a secure zero. `wt_aead_open` verifies the tag itself and clears the
    plaintext when it does not, so there is no way for a caller to act on
    unauthenticated bytes by forgetting a comparison.
  - `quic/protection.h` — the Initial secret and packet keys, the traffic-secret
    and key-update derivations, the packet nonce, and the four header protection
    operations. The order is the documented part: a sample of the payload masks the
    header, and the unmasked header carries the packet number the payload's nonce
    needs, so the receive path cannot be reordered.
- **The TLS 1.3 key schedule** (Phase 3, first part), which is what turns a
  handshake into the secrets QUIC protects with:
  - `tls/keyschedule.h` — RFC 8446 section 7.1's two chains: the extracts that build
    the Early, Handshake and Master secrets from the PSK and the ECDHE shared
    secret, and the derivations that turn them into both directions' handshake and
    application traffic secrets, the exporter and resumption secrets, the record
    traffic keys, the Finished keys and verify data, and the key update secret. An
    all-zero shared secret is refused where it enters, per RFC 8446 section 7.4.2.
  - The handshake transcript lives here too. It absorbs whole handshake messages
    into a running SHA-256 and reads the hash at each point without consuming it, so
    a transcript is a few hundred bytes whatever the peer's certificate chain
    weighs; a message whose framing disagrees with its length is refused rather than
    hashed.
- **The TLS handshake messages and extensions** (Phase 3, second part):
  - `tls/handshake.h` — the four-byte handshake framing and the ClientHello and
    ServerHello, parsed into views, re-encoded byte for byte and built from
    parameters. A parsed message keeps extensions this implementation does not
    implement, which is what lets a server answer a shape it does not interpret.
  - `tls/extension.h` — the extension list codec and the typed readers and writers for
    the extensions a QUIC handshake uses: `server_name`, `supported_groups`,
    `signature_algorithms`, `supported_versions`, `key_share`,
    `psk_key_exchange_modes`, ALPN and `quic_transport_parameters`. Every list a peer
    can grow is bounded by a capacity and refused rather than written past.
- **The X25519 key agreement** (Phase 3, third part): `tls/keyshare.h` carries RFC 7748's
  primitive, key generation, the public key a private key produces, and the shared secret,
  and refuses an all-zero secret where it is computed, because RFC 8446 section 7.4.2
  makes a point of small order a handshake failure. X25519 is the only group the
  implementation can complete, so it is the only one a client should advertise: a group
  offered without a key share invites a HelloRetryRequest, which this implementation
  refuses.
- **The certificate messages** (Phase 3, fourth part): Certificate and CertificateVerify
  are parsed as framing -- a chain of DER views and a scheme with a signature -- and
  Finished is exactly Hash.length bytes. Nothing here validates anything, which is what
  lets the codec be pinned to RFC 8448's own certificate message byte for byte; the trust
  layer is a separate question that this layer deliberately does not answer.
- **Peer authentication** (Phase 3, fifth part): `tls/trust.h` validates a certificate
  chain through OpenSSL and verifies a CertificateVerify signature, with a prompt-free
  policy that mirrors the Swift library -- system trust, a caller-supplied store, pinned
  leaf fingerprints, and a development bypass that is restricted to loopback names because
  the restriction is part of the mode. The chain is parsed, validated and discarded inside
  one call, so no X.509 object outlives it and no OpenSSL type appears in a public header.
- **The client handshake** (Phase 3, sixth part): `tls/session.h` sequences the whole
  handshake -- the ClientHello as bytes, the ServerHello's version, ciphersuite, session id
  echo and key share, ALPN and the transport parameters QUIC requires, the certificate chain
  through the trust policy, CertificateVerify over the transcript through the Certificate,
  the server's Finished over the transcript through CertificateVerify, and the client's
  Finished over the transcript through the server's. The application secrets exist in no
  state before the last of those, so every security condition is a precondition for them.
  The machine is driven end to end by RFC 8448's recorded flight: it is started with the
  RFC's ClientHello and client key and must produce the RFC's own secrets and Finished.
- **The server handshake** (Phase 3, seventh part): `tls/session.h` also carries the server --
  the ClientHello's version, ciphersuite, key share, ALPN and transport parameters checked, the
  flight built in the order the client's checks expect, the signature over the transcript
  through the Certificate, and the client's Finished gating the application secrets. The flight
  is two calls because QUIC has two encryption levels. `tests/unit/test_tls13_server.c` runs a
  whole handshake between the two halves and requires that they agree, including that each end's
  application secret is the other's in the opposite direction.
- **The QUIC packet number space** (Phase 4, first part): `quic/pn_space.h` holds the received
  set as a bounded list of ranges, the ACK frame it produces, the acknowledgement debt that
  decides prompt or delayed, and RFC 9002 section 5's round trip estimator with its probe
  timeout. No I/O, no policy -- which is why the ranges are checked for order-independence and
  the RTT arithmetic against section 5.3 worked out by hand.
- **Loss detection and probe timeouts** (Phase 4, second part): `quic/loss.h` holds the sent-packet
  list, RFC 9002 section 6's packet and time thresholds, the loss timer they imply, the bytes in
  flight the congestion controller will read, and the probe timeout with its backoff. The list is
  bounded and being at the bound is an error rather than a drop, because a forgotten packet is one
  that is never retransmitted.
- **Congestion control** (Phase 4, third part): `quic/congestion.h` is RFC 9002 section 7's NewReno
  -- the initial window with its 14720-byte bound, slow start, congestion avoidance's fractional
  increment, the recovery epoch that makes a burst of losses cost one halving, the two-datagram
  floor, and persistent congestion. It reads the bytes in flight from the loss module rather than
  counting them, so the two cannot disagree after a retransmission.
- **Stream state machines and flow control** (Phase 4, fourth part): `quic/stream.h` carries RFC 9000
  sections 2, 3 and 4 -- both halves' state machines, the final size as the boundary that stops a
  peer appending to an ended stream, RESET_STREAM and STOP_SENDING, and flow control at the
  connection's level and the stream's. Flow control counts *offsets* rather than delivered bytes,
  which is the RFC's model: a gap cannot be used to escape the accounting.
- **QUIC DATAGRAM and the close paths** (Phase 4, fifth part): `quic/datagram.h` is RFC 9221's
  unreliable messages -- the size rule against both the peer's frame limit and the path's packet size,
  and a bounded receive queue whose discard policy is the newest rather than the oldest.
  `quic/close.h` is the two forms of CONNECTION_CLOSE, which are different messages, and the draining
  period of three probe timeouts.
- **The wire seam** (Phase 4, sixth part): `quic/packet_io.h` is where frames become a datagram and a
  datagram becomes frames. `wt_quic_packet_build` writes the header, seals the frames with the header
  through the packet number as associated data, appends the tag, and applies header protection last;
  `wt_quic_packet_read` removes header protection first, reconstructs the packet number against the
  largest this endpoint has seen, and only then authenticates and decrypts -- because the header
  protection sample is ciphertext and the packet number's own length is behind the mask. Two codec
  additions came out of it: `wt_quic_long_header_encode_prefix` writes a long header for a payload the
  caller has not produced yet, and `wt_quic_protected_pn_offset` walks a header that is *still
  protected* by its layout alone, which no decoder can do because the masked first byte hides both the
  packet number length and the two reserved bits. Because a round trip would let a shared mistake pass,
  the test flips every byte of a packet and requires that the frames never come back.
- **The UDP socket layer** (Phase 4, seventh part): `runtime/udp.h` moves whole datagrams between two
  addresses on IPv4 and IPv6 and knows nothing about QUIC. It is the only POSIX file in the tree
  (WT-13), so it is also the only place a syscall failure is classified -- one `map_errno`, with
  `WT_ERR_IO` for what it cannot classify rather than a guess. IPv6 sockets set `IPV6_V6ONLY`
  explicitly because Linux and the BSDs disagree, and a datagram larger than the buffer is
  `WT_ERR_TRUNCATED` with no length reported rather than a short read that would let QUIC parse the
  prefix of a packet (WT-36). A link-local address carries its scope id, because dropping it is the
  difference between reaching the peer and reaching nobody.
- **The connection runtime** (Phase 4, eighth part): `quic/connection.h` is one connection over one
  borrowed socket -- its three packet number spaces and their keys, the received sets and the
  acknowledgements they owe, the sent-packet list with loss detection and probe timeouts, NewReno, the
  close paths and the acknowledgement-delay timer. The frames it does not own (CRYPTO, STREAM, the
  limits, DATAGRAM) go to a caller-installed handler, which is the seam the handshake and the stream
  layer plug into. `now` is a parameter and the event loop is the caller's, so the timers are tested by
  moving a number rather than by sleeping. `tests/unit/test_quic_connection.c` runs two connections over
  two real loopback sockets on IPv4 and on IPv6 with Initial keys both ends derive from one connection
  ID, so a packet travels the whole path -- build, protect, send, receive, unprotect, walk, acknowledge,
  account -- without a handshake.
- **The CRYPTO stream** (Phase 4, ninth part): `quic/crypto_stream.h` is the handshake bytes, which
  arrive by offset rather than in order. The receive half is a window with a bitmap of what has
  arrived, delivering only up to the first hole, so a ClientHello split across two packets reads
  correctly; the send half keeps what was sent, because a packet can be declared lost after a later one
  was acknowledged and its bytes are the peer's only copy. Both are bounded and a frame that does not
  fit is refused whole, which is what lets the connection answer with the transport error code
  RFC 9000 gives this case.
- **The TLS 1.3 handshake over CRYPTO** (Phase 4, tenth part): `quic/handshake.h` joins the TLS machine to
  the packet layer -- reassembling each level's CRYPTO stream, walking it into whole handshake messages,
  feeding them to TLS in order, installing the keys each step makes available, and sending a lost flight
  again from the bytes it kept. `tests/unit/test_quic_handshake.c` runs a whole handshake between two
  connections over real loopback sockets on IPv4 and IPv6, with a real certificate and trust check, then a
  1-RTT frame -- the phase's completion criterion in one test.
- **The peer's limits** (Phase 4, eleventh part): the connection parses the transport parameters the
  handshake carried into `wt_quic_peer_limits_t` -- the flow control limits at both levels, the stream
  counts, the connection ID limit, the datagram size -- with RFC 9000 section 18.2's own defaults, where
  an absent parameter and a zero one are different facts. The effective idle timeout becomes the smaller
  of the two ends', because RFC 9000 section 10.1 makes it the minimum. This is the other half of every
  resource limit the stream and datagram work will enforce.
- **QUIC DATAGRAM over the connection** (Phase 4, twelfth part): `wt_quic_connection_send_datagram`
  sends an RFC 9221 frame bounded by both the peer's `max_datagram_frame_size` and what the path carries,
  with no retransmission descriptor -- that is what makes it unreliable -- and the receive half is a
  bounded queue whose newest datagram is discarded when it is full. The receive path is a function a
  composed frame handler calls, which is the layering the handshake, the stream layer and the session
  layer all use.
- **The key lifecycle** (Phase 4, thirteenth part): `wt_quic_connection_discard_keys` zeroes a space's
  keys and marks it gone, and the connection calls it where RFC 9001 section 4.9 says to -- the Initial
  keys when the first Handshake packet is processed, the Handshake keys when the handshake is confirmed.
  Both are a MUST, not a tidy-up: the Initial keys come from a connection ID either end can see, so
  keeping them leaves the connection readable to anyone who saw its first packet.
- **The STREAM send path** (Phase 4, fourteenth part): `wt_quic_connection_send_stream` encodes and sends
  an RFC 9000 section 19.8 frame with the stream number checked against the peer's grant -- and a stream
  number is four fields in one, so whether a limit applies depends on who opened the stream. It is
  deliberately not the stream layer: nothing remembers the bytes, so nothing retransmits them, which is
  what the stream layer adds.
- **The connection-level limit this endpoint grants** (Phase 4, fifteenth part):
  `wt_quic_connection_send_max_data` sends an RFC 9000 section 19.9 MAX_DATA frame and the connection
  seeds and reads the value -- the other direction from the peer limits, and one that may only ever rise,
  because section 4.1 makes a limit that decreases a protocol error.
- **The stream counts this endpoint grants** (Phase 4, sixteenth part):
  `wt_quic_connection_send_max_streams` sends an RFC 9000 section 19.11 MAX_STREAMS frame, with the same
  only-ever-rising rule as MAX_DATA and a count per direction, since a bidirectional stream costs the peer
  one of its own and a unidirectional one only ours.
- **The peer's limits are acted on** (Phase 4, seventeenth part): a received MAX_DATA or MAX_STREAMS is
  applied by the connection itself -- what the peer grants is what this endpoint may send -- and a limit
  that falls is the PROTOCOL_VIOLATION RFC 9000 sections 4.1 and 4.6 make it, with the frame type named.
- **A closed connection stops processing frames** (Phase 4, eighteenth part): RFC 9000 section 10.2.1
  allows only PADDING, the close's own frames and the probes once a connection is closed, and the frame
  walk now enforces it -- through `wt_quic_close_accepts_frame_type`, so the rule is stated once, in the
  module that owns it.
- **HANDSHAKE_DONE only reaches a client** (Phase 4, nineteenth part): RFC 9000 section 19.20 makes a
  server that receives one refuse the connection with a PROTOCOL_VIOLATION, which the connection now does
  while a client still has the frame handed on to the handshake layer.
- **Frames are refused in the wrong packet type** (Phase 4, twentieth part): RFC 9000 section 12.4 makes a
  frame that may not appear where it arrived a PROTOCOL_VIOLATION, and the connection now enforces section
  12.5's table -- including that a CRYPTO frame at the application level is refused, which is what stops a
  peer injecting handshake data into a finished connection.
- **The four fields in a stream number** (Phase 4, twenty-first part): `quic/stream.h` reads and writes
  RFC 9000 section 2.1's initiator bit, directionality bit and index in one place, and the connection's
  stream-number check uses them instead of shifting at the call site. The first piece of the stream layer.
- **The stream table** (Phase 4, twenty-second part): `quic/stream.h` holds a bounded table of stream state
  machines -- the resource limit the plan names -- with per-class counts, a full table refusing a new
  stream rather than dropping a live one, and a stream forgotten only when both halves are done
  (RFC 9000 section 3.3). The limit is the opener's, so a peer's stream costs the peer's allowance.
- **Opening a stream** (Phase 4, twenty-third part): the connection owns a stream table and
  `wt_quic_connection_open_stream` derives the number from the table's counts, bounds it by the peer's
  `initial_max_streams_*`, and starts the stream with the two directions' flow control limits -- this
  endpoint's own for receiving, the peer's for sending.
- **A stream is created by its first frame** (Phase 4, twenty-fourth part): a received frame for a
  peer-initiated stream this endpoint has never seen opens it (RFC 9000 section 3.2), bounded by the count
  it granted -- beyond which is STREAM_LIMIT_ERROR, and a frame for an unopened number of its own is
  STREAM_STATE_ERROR. MAX_STREAM_DATA raises one stream's send allowance.
- **RESET_STREAM and STOP_SENDING reach their state machines** (Phase 4, twenty-fifth part): the two
  frames that change a stream's lifecycle rather than carrying data are applied by the connection as they
  arrive, before the caller's handler sees them, with FINAL_SIZE_ERROR and STREAM_STATE_ERROR for the
  states RFC 9000 sections 4.5 and 19.5 make errors.
- **Received stream data is accounted against both limits** (Phase 4, twenty-sixth part): the connection
  keeps the connection-level flow control and charges every STREAM frame's data against it and the
  stream's, with the RFC's code chosen by asking each limit in turn -- because the stream module reports a
  per-stream overrun and a final-size contradiction with the same status.
- **The receive limits are raised as data arrives** (Phase 4, twenty-seventh part): when the connection's
  received total reaches the limit it granted it sends MAX_DATA for the next window and moves the limit,
  and the same for a stream's MAX_STREAM_DATA -- RFC 9000 section 4.1's rule, applied where arrival is
  consumption because this runtime hands each frame's bytes to the caller immediately.
- **A sender can cancel a stream** (Phase 4, twenty-eighth part): `wt_quic_connection_reset_stream` sends
  RESET_STREAM (RFC 9000 section 19.4) with the final size computed from what was sent, moves the send half
  to Reset Sent, and refuses a stream that is not this endpoint's to send on or one already finished --
  with the receive side already handling an arriving reset, both directions of the cancellation path exist.
- **A lost stream packet names what to send again** (Phase 4, twenty-ninth part): a STREAM send carries a
  retransmission descriptor -- the stream, the offset and the length -- which the connection hands to the
  owner when loss detection declares its packet lost, so the layer that keeps the bytes can send them
  again. The same shape the CRYPTO stream uses, with the stream id added to `wt_quic_tx_frame_t`.
- **STOP_SENDING, the other half of cancellation** (Phase 4, thirtieth part): the receiver of a stream's
  data asks the peer to stop, once and only on a stream it receives on -- so with RESET_STREAM the
  cancellation path exists in both roles, and a frame that could not be sent leaves the stream unchanged
  for a caller that retries.
- **The Retry integrity tag** (Phase 4, thirty-first part): RFC 9001 section 5.8's AES-128-GCM tag over
  `ODCID Length || ODCID || Retry packet`, with the version's own key and nonce, so a client can tell a
  Retry the server sent from an injected one before any handshake. Its value is not asserted yet -- RFC
  9001 A.4's Retry packet still has to be extracted, and vectors here are extracted, never transcribed.
- **Issuing connection IDs** (Phase 4, thirty-second part): `wt_quic_connection_issue_connection_id` sends
  NEW_CONNECTION_ID (RFC 9000 section 19.15) and keeps what it issued, bounded by both its own table and
  the peer's `active_connection_id_limit` less the handshake's ID (section 5.1.1), with the stateless reset
  token taken from the caller because section 10.3 requires it to be unguessable.
- **The peer's connection IDs are stored** (Phase 4, thirty-third part): a received NEW_CONNECTION_ID is
  kept with its reset token, with RFC 9000's FRAME_ENCODING_ERROR for a bad length or a `retire_prior_to`
  above the sequence, PROTOCOL_VIOLATION for a sequence whose connection ID or token changes, and
  CONNECTION_ID_LIMIT_ERROR beyond what this endpoint advertised it would store (section 5.1.1).
- **A short packet is padded until it can be sampled** (Phase 4, thirty-fourth part): RFC 9001 section
  5.4.2 samples header protection from four bytes past the packet number, so a packet too short to hold
  sixteen bytes from there cannot be protected at all -- which made a two-byte frame such as
  RETIRE_CONNECTION_ID or PING impossible to send, and the builder refused it with a truncation error. It
  now fills the plaintext with PADDING frames (RFC 9000 section 19.1), which carry nothing and are ignored
  by every receiver. The header's length cancels out of the requirement, so the shortfall is at most three
  bytes and no caller has to know the rule.
- **RETIRE_CONNECTION_ID retires an issued ID** (Phase 4, thirty-fifth part): the frame gives the ID back,
  freeing both the table slot and the peer's `active_connection_id_limit` budget, with PROTOCOL_VIOLATION
  for a sequence that was never issued and for the sequence the carrying packet was addressed to
  (section 19.16) -- which this endpoint numbers 0, because it receives only on the ID the handshake used
  (section 5.1.1). A repeat of a retirement already made is tolerated, since the frame is retransmitted
  when it is lost, and issued sequences now start at 1 instead of colliding with the handshake's own.
- **A client's Initial datagram is expanded to the minimum** (Phase 4, thirty-sixth part): RFC 9000
  section 14.1 requires every UDP datagram carrying an Initial packet to be at least 1200 bytes, because a
  server discards one that is smaller -- an unpadded Initial cannot start a connection against a
  conformant server at all. The client now expands the packet with PADDING frames and the server discards
  a short Initial datagram before reading it. The expansion is applied by rebuilding rather than
  computed ahead of the build, because the long header's Length varint widens with the value it carries;
  a pass that lands a byte over trims padding instead of putting a datagram above the path's limit.
- **The Retry integrity tag is checked against the RFC** (Phase 4, thirty-seventh part): RFC 9001
  appendix A.4's Retry packet and the tag it prints are extracted by
  `tests/vectors/extract_rfc9001_retry.py`, which refuses to write a block that does not parse as a
  version-1 Retry whose original destination connection ID agrees with A.2's client Initial packet. The
  tag was computed but never asserted against the document before this -- the test that existed proved it
  was computed consistently, which a wrong constant would also satisfy. Now the RFC's own tag is the
  expectation, and the same packet with one changed byte, or with another original connection ID, is
  refused.
- **A frame the decoder refuses closes the connection** (Phase 4, thirty-eighth part): RFC 9000 section
  12.4 makes an undecodable frame a connection error, and the decoder reports the code -- but the error
  was returned to the caller instead of being sent, so a peer that sent a malformed frame was never told
  and the connection stayed open with the failure visible only to whoever called
  `wt_quic_connection_receive`. A decode failure now closes the connection with the code the frame's own
  rule names, or FRAME_ENCODING_ERROR for a truncated frame. Found by the test WT-83 asked for: a
  hand-written NEW_CONNECTION_ID whose `retire_prior_to` is above its sequence, which the encoder cannot
  produce because this library refuses to encode what it would refuse to decode.
- **Packets addressed to an issued connection ID are accepted** (Phase 4, thirty-ninth part): the receive
  path compared every packet's Destination Connection ID with the handshake's alone, so the IDs this
  endpoint issued with NEW_CONNECTION_ID were write-only -- a peer that used one, which is exactly what
  they are for, had its packets discarded as somebody else's. The handshake's ID and every issued ID that
  has not been retired are now recognised, and which sequence a packet used travels with its frames so
  RFC 9000 section 19.16's "cannot retire the ID the packet was addressed to" is applied to the ID that was
  actually addressed rather than to sequence 0. A packet addressed to a retired ID is discarded, and
  `wt_quic_connection_issue_connection_id` now refuses an ID whose length is not this endpoint's own,
  because a short header carries no length and such an ID could never be received.
- **The HTTP/3 frame codec** (Phase 5, first part): `http3/frame.h` is RFC 9114's varint type, varint
  length and payload, with the registered frame types, the section 8.1 error codes, the stream type
  prefixes of section 6.2.1 and the section 7.2.8 test for the frame types HTTP/2 reserved. It is a codec
  and nothing more -- what a SETTINGS identifier or a GOAWAY identifier means belongs to the stream layer
  -- so a length that does not fit `size_t` or does not fit the bytes present is refused as a frame error,
  a refusal leaves the caller's cursor where it was so the caller can name the frame that failed, and an
  unknown frame type is a frame like any other rather than an error the codec invents.
- **HTTP/3 SETTINGS** (Phase 5, second part): `http3/settings.h` parses and encodes the identifier/value
  pairs of RFC 9114 section 7.2.4 into a fixed table, so duplicate detection covers the settings this build
  does not understand as well as the ones it does. A reserved HTTP/2 identifier (`0x02` to `0x05`) and a
  non-boolean `ENABLE_CONNECT_PROTOCOL` are H3_SETTINGS_ERROR, a payload that ends between an identifier and
  its value is one too, more identifiers than the table holds is H3_EXCESSIVE_LOAD, and the exercise
  identifiers of the `0x1f * N + 0x21` range are ignored rather than refused -- refusing them would break
  the one rule they exist to exercise. The encoder writes ascending identifier order, so the same set is
  always the same bytes.
- **The control stream's lifecycle** (Phase 5, third part): `http3/control.h` is RFC 9114 section 6.2.1's
  state machine for the peer's control stream, where all four rules are connection errors -- a first frame
  that is not SETTINGS (H3_MISSING_SETTINGS), a second control stream (H3_STREAM_CREATION_ERROR), the
  stream closing at any point (H3_CLOSED_CRITICAL_STREAM), and a frame the section does not allow there,
  including a second SETTINGS and the types section 7.2.8 reserved for HTTP/2 (H3_FRAME_UNEXPECTED). It
  decides permission only: what a SETTINGS, GOAWAY or MAX_PUSH_ID frame says is parsed by whoever owns it.
- **GOAWAY** (Phase 5, fourth part): `http3/goaway.h` carries RFC 9114 sections 7.2.6 and 5.2 -- the
  identifier is a client-initiated bidirectional stream ID from a server (anything else is H3_ID_ERROR)
  and a push ID from a client, it may not grow between frames (H3_ID_ERROR), requests at or above it are
  rejected, no new request may be started after it arrives, and the graceful-shutdown maximum is `2^62 - 4`
  for a server and `2^62 - 1` for a client. The payload is exactly one varint: a second field or a trailing
  byte is a frame error rather than a frame read partially.
- **Which frame belongs on which stream** (Phase 5, fifth part): `http3/streams.h` is RFC 9114 section
  7.2's table -- DATA and HEADERS on request and push streams, the connection-management frames on the
  control stream, PUSH_PROMISE from a server to a client on a request stream, no HTTP/3 frame at all on a
  QPACK stream (section 4.2), and the section 7.2.8 reserved types refused everywhere. The role decides two
  of the rules, so the receiver's role is a parameter: MAX_PUSH_ID is a client's frame (section 7.2.7) and
  PUSH_PROMISE a server's (section 7.2.5), and receiving one's own frame is H3_FRAME_UNEXPECTED. Unknown
  frame types stay allowed, because HTTP/3 grows by extension frames.
- **The request stream's frame order** (Phase 5, sixth part): `http3/request.h` is RFC 9114 section 4.1's
  shape for the request direction -- one HEADERS frame, optional DATA, one optional trailing HEADERS -- with
  anything else, and anything after the trailer, H3_FRAME_UNEXPECTED. A stream that ends before the
  request's HEADERS is an incomplete request instead: H3_REQUEST_INCOMPLETE, which section 4.1 defines as
  the code a server aborts its own RESPONSE stream with, so it is reported as a stream error rather than a
  connection error. The response direction is deliberately not here: whether a HEADERS frame is an
  informational 1xx response is only known from the decoded `:status`, so that machine lands with QPACK.
- **QPACK's static table** (Phase 6, first part): `http3/qpack.h` exposes RFC 9204 appendix A's 99
  name/value pairs with the exact-pair and by-name lookups a field line needs, and the section 8 error
  codes. The table is generated from the RFC by `tests/vectors/extract_rfc9204_static_table.py` and checked
  by `check-vectors.sh`, because an encoder and a decoder that disagree on one entry produce two different
  header sections with nothing in the exchange to say so.
- **Prefixed integers and strings** (Phase 6, second part): QPACK's two primitives (RFC 9204 section 4.1)
  -- an integer behind an N-bit prefix, and a string whose length is one behind a seven-bit prefix with the
  H bit above it. The section's 62-bit bound is enforced, a continuation that runs past it or never ends is
  refused, and a string's Huffman flag is RETURNED rather than ignored: this build does not decode Huffman
  yet, and a caller that treated coded bytes as field content would produce a header section the peer
  cannot parse.
- **Huffman decoding** (Phase 6, third part): `qpack_huffman.c` decodes RFC 7541 appendix B's code, which
  RFC 9204 adopts, against a table generated from the RFC by `tests/vectors/extract_rfc7541_huffman.py` --
  the script checks the code is symbol-ordered, prefix-free and canonical (and derives the decode index from
  that) and extracts C.4.1's worked example as the one vector the decoder is checked against. EOS in a
  string, padding that is not all ones or is longer than seven bits, and a decoded size larger than the
  caller's buffer are all refused, because accepting a string the peer could not have encoded is how two
  implementations come to disagree silently.
- **Huffman encoding** (Phase 6, fourth part): the encoder side of the same table, with the section 5.2
  padding rule (one-bits, the EOS prefix) and a size helper so a caller can bound its buffer without
  guessing. It is checked against the RFC's own appendix C.4.1 bytes rather than only against a round trip
  through this implementation -- an encoder and decoder that share a wrong table round-trip happily -- and
  then over all 256 symbols, which is what says the bit packing survives both the five-bit codes and the
  thirty-bit ones.
- **The field line representations** (Phase 6, fifth part): `qpack_field.c` reads and writes all seven of
  RFC 9204 section 4.5's forms, and the TYPE says which table a line needs -- static, dynamic or post-base
  -- so a decoder cannot resolve a dynamic index against the static table by accident, which is the mistake
  that silently produces a different header section. The static forms resolve to a name; the dynamic and
  post-base ones report that they need the dynamic table, which is the next part's work.
- **The dynamic table** (Phase 6, sixth part): `qpack_dynamic.c` is RFC 9204 section 3.2's FIFO with the
  section's size rule (name and value plus 32), eviction from the oldest end, and absolute indices that never
  change meaning, so a reference to an evicted entry is reported as such rather than resolved to whatever now
  occupies its place. It is bounded like every other peer-driven table here: 32 entries, a 4 KiB arena, and an
  entry larger than the capacity refused rather than truncated.
- **The encoder stream instructions** (Phase 5/6, seventh part): `qpack_encoder_stream.c` applies RFC 9204
  section 4.3's four instructions -- the capacity, a name from a table, a name written out, a duplication --
  to the dynamic table, and writes them from this implementation's own encoder. Both errors only visible at
  this layer are enforced: a capacity above what SETTINGS granted this peer, and an index naming an entry the
  table has already evicted, are QPACK_ENCODER_STREAM_ERROR rather than a clamp or a guess.
- **The decoder stream instructions** (Phase 6, eighth part): `qpack_decoder_stream.c` applies RFC 9204
  section 4.4's three instructions -- section acknowledgement, stream cancellation, insert count increment --
  and writes them, with the section's own errors: a zero increment and one that would pass the number of
  insertions are QPACK_DECODER_STREAM_ERROR. An instruction whose bytes have not all arrived is treated as
  INCOMPLETE rather than malformed, in both stream modules: QPACK delivers instructions in pieces, so the
  caller waits for more, and only a malformed instruction is the peer's error.
- **The field section prefix** (Phase 6, ninth part): `qpack_header_prefix.c` is RFC 9204 section 4.5.1's
  Required Insert Count and Base -- the count is sent modulo twice the table's size in entries so it stays
  inside the window the decoder knows, the Base is a signed delta from it, and both of the section's error
  exits are enforced. `wt_qpack_max_entries` derives the window from the capacity, which is why the prefix
  cannot be read without knowing what this endpoint advertised.
- **The field section decoder** (Phase 6, tenth part): `qpack_field_section.c` resolves one line at a time
  against the static table, the dynamic table and the section's prefix -- the index arithmetic is where
  QPACK's dynamic references live, `Base - Index - 1` for a dynamic reference and `Base + Index` for a
  post-base one -- and decodes an inline Huffman name or value into the caller's scratch, because a resolved
  field has to be plain bytes. A reference the table cannot resolve is QPACK_DECOMPRESSION_FAILED; a scratch
  buffer too small is the caller's limit, not the peer's error, and the two are reported apart.
- **Huffman strings on the way out** (Phase 6, eleventh part): `wt_qpack_string_encode_coded` writes a string
  with the H bit set, coding it into the caller's scratch (the coded length has to be known before the
  length byte that precedes it), and `wt_qpack_field_line_encode_coded` does the same for a line's name and
  value. The plain `wt_qpack_field_line_encode` now REFUSES a line whose flags ask for coding rather than
  writing it plainly: the flags are part of the representation, so a plain string with the H bit clear is a
  different line.
- **Whole field sections** (Phase 6, twelfth part): `qpack_field_section_codec.c` writes a section -- prefix,
  then lines -- and reads one back, with the section's BLOCKED case kept apart from a decompression failure:
  RFC 9204 section 2.1.2 lets a decoder wait for the encoder stream when a section needs insertions that have
  not arrived, so that is `WT_ERR_AGAIN` with no error code rather than a connection error over an
  instruction still in flight.
- **The encoder's eviction bookkeeping** (Phase 6, thirteenth part): `qpack_encoder_state.c` remembers what
  each outstanding section was written with, because RFC 9204 section 2.1.1 forbids evicting an entry an
  unacknowledged section might reference -- `wt_qpack_encoder_state_evictable_below` is the SMALLEST required
  insert count among them, and a section that references nothing holds nothing back. Section
  acknowledgements, stream cancellations and the decoder's insert count increments are what move it.
- **HTTP/3 message header rules** (Phase 5, seventh part): `http3/headers.h` validates a decoded field section
  as a request or a response -- pseudo-headers first and at most once, only the ones the message type defines,
  :method/:scheme/:path required except for CONNECT (which requires :authority), lowercase names, the
  connection-specific fields forbidden and `te` only for `trailers`. Every breach is H3_MESSAGE_ERROR, and the
  validator consumes fields one at a time because the rules are about ORDER.
- **HTTP/3 messages** (Phase 5, eighth part): `http3/message.h` is the join between the two phases -- a
  QPACK field section in, a validated request or response out, with the method, scheme, path, authority and
  status kept where a caller can read them instead of walking the fields again. It adds the two rules that
  live at this layer: a `:status` must be three digits in 100..599, and the values that must be present must
  also be non-empty. A blocked section is WT_ERR_AGAIN, and QPACK's own failure codes travel through
  unchanged -- they are HTTP/3 application errors, so they belong in the same place.
- **The WebTransport session request** (Phase 7, first part): `webtransport/session_request.h` decides what a
  decoded request is -- an ordinary request, an extended CONNECT for another protocol, or a WebTransport
  session request this server accepts or refuses with a status. It is a DECISION rather than an error, because
  "not mine" and "mine, but refused" are ordinary answers. Two rules are easy to get backwards and are tested
  both ways: the CONNECT exception does NOT excuse a WebTransport request from carrying :scheme and :path
  (it applies to the plain CONNECT), and a server that never advertised `WT_ENABLED` refuses rather than
  serving a session the client could not have known about. `:protocol` is now a recognised request
  pseudo-header in the HTTP/3 layer, which is what makes any of this reachable.
- **WebTransport capsules** (Phase 7, second part): `webtransport/capsule.h` reads and writes the CONNECT
  stream's control messages -- a varint type, a varint length and that many bytes -- with the draft's capsule
  types, `DRAIN_WEBTRANSPORT_SESSION` (no value) and `CLOSE_WEBTRANSPORT_SESSION` (a four-byte code and a
  reason no longer than 1024 bytes). An incomplete capsule is `WT_ERR_TRUNCATED` rather than malformed, an
  unknown type is handed on rather than refused, and a value longer than the caller will buffer is
  `H3_EXCESSIVE_LOAD` -- the same three rules the QPACK instruction parsers and the frame codec follow.
- **The session lifecycle** (Phase 7, third part): `webtransport/session.h` is the draft's three rules about
  what a session may DO -- after a drain in either direction no new stream may start (existing ones may
  finish), after a close nothing at all, and the FIRST close's code is the one the session reports however
  many more arrive. A stream that simply ends has no application code, which the state records separately
  from a close whose code happens to be zero.
- **The session's flow control** (Phase 7, fourth part): the draft's flow-control capsules -- MAX_DATA,
  MAX_STREAM_DATA, MAX_STREAMS in both directions, and the blocked signals -- each carrying one or two
  varints, with a value that is not exactly that being a message error rather than a bigger number. The
  connection-level limits may only grow: a limit below one already granted would invalidate data sent against
  the old one, so it is `WT_FLOW_CONTROL_ERROR` rather than a new limit.
- **Stream and datagram framing** (Phase 7, fifth part): `webtransport/framing.h` is the draft's stream prefix
  (type 0x41 or 0x54, then the session ID) and its datagram frame (a quarter stream ID, then the data), with
  the identifier SHAPE checked: a session ID must be the CONNECT stream's -- client-initiated and
  bidirectional -- and a prefix naming anything else describes a session that cannot exist. An incomplete
  prefix is `WT_ERR_TRUNCATED`; a datagram without its quarter ID is malformed, because a datagram is the
  unit.
- **The umbrella header** (Phase 8, first part): `include/webtransport/webtransport.h` is the one header a
  consumer includes, and it states the three rules that hold across every layer -- nothing is allocated for a
  peer, incomplete is not malformed on a stream (a datagram is the exception), and a refusal keeps the peer's
  code. A test including ONLY that header uses a piece of every layer, so a module missing from it, or a header
  that does not include what it uses, fails here rather than in a consumer's build.
- The vectors are RFC 9001 appendix A and RFC 8448 section 3, extracted from the RFC
  text rather than
  transcribed: `tests/vectors/extract_rfc9001_keys.py` re-derives every value it
  writes -- the Initial secret from the version-1 salt and the connection ID, each
  key from its traffic secret, each header protection sample as the packet's bytes
  at `pn_offset + 4`, each mask by turning the printed unprotected header into the
  printed protected one, and the short header's nonce from the IV and the packet
  number -- and refuses to write one that does not check. The tests then take each
  protected packet apart and put it back together, so a mistake that was symmetric
  between the two directions fails the second one.
- The TLS vectors are RFC 8448's own key schedule trace, including the handshake
  messages it prints: `tests/vectors/extract_rfc8448_keyschedule.py` recomputes every
  secret, key and Finished value from the RFC's inputs, checks the schedule as a
  chain, and checks the trace's three transcript hashes against the messages it
  extracted -- so a message read from the wrong place in a 3,800-line document fails
  generation rather than becoming a vector a wrong implementation would pass.
- A package consumer test: the library is installed and a separate CMake project
  links it, which is the only way to know the install tree works. It found that the
  installed config did not declare its OpenSSL dependency, which no build inside
  this tree could have noticed.

What is not here: TLS, HTTP/3, QPACK and WebTransport, the QUIC connection
runtime, the CLI tools' actual behavior, external interoperability evidence, and
the platform runtimes. The wire core parses and builds QUIC messages and the crypto
layer protects them; nothing yet decides what to send.

## Building

```sh
C99/scripts/build-and-test.sh              # Debug, build and test
C99/scripts/build-and-test.sh --release    # Release
C99/scripts/build-and-test.sh --sanitize   # Debug with ASan and UBSan
C99/scripts/build-and-test.sh --all        # all three
C99/scripts/check-package.sh               # install and build a consumer
C99/scripts/check-vectors.sh               # re-extract the RFC vectors and compare
```

Output goes under `C99/out/<platform>/`, which is gitignored; see
[out/README.md](out/README.md). The packaging entry points under
[platform/](platform/) are wrappers around the same CMake project.

## Layout

```text
include/webtransport/   public headers, installed
src/core/               the Phase 0 utilities
src/crypto/             the OpenSSL-backed crypto provider
src/quic/               the QUIC wire core and packet protection
src/tls/                the TLS 1.3 key schedule and transcript
tests/vectors/          generated RFC vectors and the scripts that extract them
apps/                   wt-client-c99, wt-server-c99, wt-conformance-c99
tests/unit/             one file per module, registered with CTest
tests/package/          a consumer of the installed package
scripts/                the development loop
platform/               per-OS packaging entry points
```

The remaining protocol phases add `src/tls`, `src/http3` and `src/runtime` beside
`src/core`, `src/crypto` and `src/quic`, and their headers under the matching
`include/webtransport/` directories, which already exist.
