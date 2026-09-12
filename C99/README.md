# C99 WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-16`, dated 2026-07-06.

Draft-16 score: **0%** — the protocol is not implemented yet. What exists is the
foundation the protocol is built on, and it is real, tested code rather than
scaffolding.

## Current Status

**Phases 0, 1 and 2 of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) are
complete, and Phase 3 is under way: its key schedule, transcript, handshake message
codecs (Hellos and certificates), X25519 key agreement, peer authentication and both halves of
the handshake are done, and Phase 4 has its packet number space, loss detection, congestion control, the stream machines,
DATAGRAM and the close paths.**
The rest of Phase 3, and Phases 4 to 14, are not started.

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
- 38 unit test files and 75,522 checks, run by `ctest` and again under
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
