# C99 WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-16`, dated 2026-07-06.

Draft-16 score: **0%** — the protocol is not implemented yet. What exists is the
foundation the protocol is built on, and it is real, tested code rather than
scaffolding.

## Current Status

**Phases 0, 1 and 2 of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) are
complete, and Phase 3 is under way: its key schedule, transcript and handshake
message codecs are done.**
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
- 22 unit test files and 73,519 checks, run by `ctest` and again under
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
