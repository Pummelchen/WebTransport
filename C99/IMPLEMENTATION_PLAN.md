# C99 WebTransport Implementation Plan

**Phase status is recorded in the wiki project tracker**, as `WT-54` to `WT-67`
under "C99 implementation phases", which is the only task list for this
repository. A phase is marked complete there when its completion criteria below
are met, and the status line in each phase says which commit did it.

This plan describes how to build a portable C99 implementation from the completed Swift implementation.

Target protocol: `draft-ietf-webtrans-http3-16`
Language standard: ISO C99
Supported platforms: macOS 26, Debian Linux, FreeBSD, Windows 11
Build system: CMake
License: MIT

## Goal

Build a pure C99 WebTransport over HTTP/3 implementation that reaches the same draft-16 behavior and external interoperability evidence as the Swift implementation.

Required outputs:

- Production C library with stable ABI.
- Public C headers.
- `wt-client-c99` CLI.
- `wt-server-c99` CLI.
- `wt-conformance-c99` CLI.
- Unit, integration, fuzz/property, process, IPv4/IPv6, and external interop tests.
- Cross-platform CI and release artifacts for all supported OS targets.

## Design Constraints

C99 has no RAII, exceptions, templates, coroutines, or standard async runtime. The implementation must therefore make ownership and error handling explicit.

Required conventions:

- Every public object has `create`/`destroy` functions.
- Every public operation returns `wt_status_t` or a documented result enum.
- Output values are passed through out-parameters.
- All buffers use pointer plus length pairs.
- No ownership transfer occurs unless the function name or documentation says so.
- No global mutable protocol state.
- No hidden thread creation in the core protocol library.
- No unbounded peer-controlled allocation.
- No interactive certificate or trust prompts.
- No sensitive TLS, packet, datagram, connection ID, session ID, or close-message data in production logs.

## Architecture Map

| Swift module | C99 equivalent |
| --- | --- |
| `WebTransportQUICCore` | `wt_quic` |
| `WebTransportTLSCore` | `wt_tls` |
| `WebTransportCryptoApple` | `wt_crypto` |
| `WebTransportHTTP3Core` | `wt_http3` |
| `WebTransportNetworkRuntime` | `wt_runtime` |
| `WebTransport` | `wt_api` |
| `WebTransportClient` / `WebTransportServer` | `wt-client-c99` / `wt-server-c99` |
| Swift conformance harness | `wt-conformance-c99` |

## Repository Layout

```text
C99/
  CMakeLists.txt
  cmake/
  include/webtransport/
    api/
    quic/
    tls/
    crypto/
    http3/
    runtime/
  src/
    api/
    quic/
    tls/
    crypto/
    http3/
    runtime/
  apps/
    wt-client-c99/
    wt-server-c99/
    wt-conformance-c99/
  tests/
    unit/
    integration/
    interop/
    fuzz/
  docs/
  scripts/
  platform/
    macos26/
    debian/
    freebsd/
    windows11/
  third_party/
  out/
  Experiments/
```

## Public ABI Shape

Use opaque handles for public objects:

```c
typedef struct wt_client wt_client_t;
typedef struct wt_session wt_session_t;
typedef struct wt_stream wt_stream_t;

typedef enum wt_status {
    WT_OK = 0,
    WT_ERR_INVALID_ARGUMENT,
    WT_ERR_OUT_OF_MEMORY,
    WT_ERR_TIMEOUT,
    WT_ERR_PROTOCOL,
    WT_ERR_TLS,
    WT_ERR_CLOSED
} wt_status_t;
```

Expected API style:

```c
wt_client_config_t config;
wt_client_config_init(&config);
config.authority = "example.com";
config.path = "/wt";
config.origin = "https://example.com";

wt_client_t *client = NULL;
wt_status_t status = wt_client_create(&config, &client);
```

No public header may expose internal struct layouts.

## Dependency Policy

Production dependencies:

- CMake 3.28 or newer.
- OpenSSL 3.x for crypto primitives, X.509 parsing, certificate validation, HKDF, AEAD, and signature verification.
- Native socket backends behind one C runtime abstraction.

Do not use an existing QUIC, HTTP/3, QPACK, or WebTransport implementation for the production core. Those projects remain external interoperability targets only.

Platform runtime targets:

- macOS 26: BSD sockets or a portable UDP backend, OpenSSL via Homebrew or bundled release build.
- Debian Linux: epoll-capable UDP runtime, system OpenSSL.
- FreeBSD: kqueue-capable UDP runtime, OpenSSL/LibreSSL compatibility reviewed early.
- Windows 11: WSA/IOCP UDP runtime, OpenSSL through vcpkg or bundled release build.

## Memory and Resource Policy

Requirements:

- All allocations go through a configurable allocator interface.
- Every parser accepts explicit maximum lengths.
- Dynamic tables, streams, datagram buffers, packet queues, and malformed-peer buffers are bounded.
- Integer arithmetic uses checked helpers for length/capacity calculations.
- Reference-counting is allowed only where ownership is clear and tested.
- Shutdown must free every owned resource deterministically.

## Phase 0: Foundation

**Status: complete**, on `main` at `a922521` and `fe70487`. The build is CMake
with static and shared libraries, the three CLI executables and a `find_package`
config; the core utilities are `status`, `checked`, `endian`, `cursor`, `writer`,
`buffer`, `allocator`, `log`, `time` and `version`; 10 test files with 5,392
checks pass under CTest and under AddressSanitizer and UndefinedBehaviorSanitizer,
on macOS and on Linux; `scripts/check-package.sh` builds a consumer against the
installed package; and `C99 CI` runs the matrix. Two things the criteria named
are deliberately part of this status rather than outstanding: the CLI tools are
stubs that exit 3 rather than 0, because a tool with no protocol must not read as
a successful run, and "at least one smoke test" is the ten unit test files rather
than one.

Create the C99 project skeleton.

Tasks:

- Add `C99/CMakeLists.txt`.
- Add static and shared library targets.
- Add executable targets for `wt-client-c99`, `wt-server-c99`, and `wt-conformance-c99`.
- Add compiler matrix support for Clang, GCC, MSVC, and Clang-CL.
- Add warnings-as-errors configuration.
- Add core utilities: byte buffers, byte cursor/writer, endian helpers, checked arithmetic, status/error types, allocator hooks, logging surface, and time abstractions.

Completion criteria:

- Empty library and CLI stubs build on every target compiler.
- CTest runs at least one smoke test.
- CI skeleton exists.

## Phase 1: QUIC Wire Core

**Status: complete** on `main` at `f793d4d` and the commit that follows it. The
codecs are `quic/varint.c`, `quic/packet_number.c`, `quic/frame.c`,
`quic/packet.c`, `quic/transport_parameters.c` and `quic/connection_id.c`, with
their headers under `include/webtransport/quic/`. The vectors include RFC 9000's
varint and packet number examples and RFC 9001 appendix A.2's client Initial --
both its header and the CRYPTO frame inside it, extracted from the RFC text by
`tests/vectors/extract_rfc9001_client_initial.py` rather than transcribed. The
malformed-input corpus in `tests/unit/test_quic_malformed.c` drives every parser
with a fixed pseudo-random stream and is run under the sanitizers. Four defects
were found while building this phase and each is recorded in the commit that
fixed it; the one worth naming here is that the long header's reported size
excluded the packet number, which would have made phase 2's AEAD authenticate the
wrong bytes.

Port Swift QUIC primitives first.

Tasks:

- Implement QUIC varints.
- Implement byte cursor/writer.
- Implement packet number encoding and reconstruction.
- Implement long and short packet headers.
- Implement Initial, Handshake, and 1-RTT packet forms.
- Implement ACK, CRYPTO, STREAM, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAMS, DATAGRAM, and CONNECTION_CLOSE frame codecs.
- Implement transport parameter codec.
- Implement connection ID storage and retirement state.

Tests:

- Mirror Swift QUIC tests.
- Add RFC 9000/RFC 9001 packet and frame vectors.
- Add malformed/truncated frame corpus.

Completion criteria:

- QUIC packet/frame corpus round-trips.
- Malformed wire input fails deterministically without undefined behavior.

## Phase 2: Crypto and Packet Protection

**Status: complete.** The crypto provider is `src/crypto/crypto_openssl.c` behind
`include/webtransport/crypto/crypto.h` -- SHA-256 (streaming and one-shot), HMAC,
HKDF extract, expand and expand-label, AES-128-GCM and ChaCha20-Poly1305 with the
tag verified inside the AEAD, the AES block and ChaCha20 keystream that header
protection is built on, a constant-time comparison and a secure zero -- and
`src/quic/protection.c` turns those into QUIC's two protections: the Initial
secret and packet keys, the traffic-secret and key-update derivations, the packet
nonce, the header protection sample, mask, protect and unprotect, and the payload
seal and open. Handshake and 1-RTT keys are the same function as Initial keys,
differing only in where the secret comes from, which is why this phase has no
separate 1-RTT code path to test: `wt_quic_packet_keys_from_secret` is what phases
3 and 4 will call.

The vectors are RFC 9001 appendix A, all five parts: the Initial secrets and keys
(A.1), the client Initial (A.2), the server Initial (A.3) and the
ChaCha20-Poly1305 short header packet (A.5), including their header protection
samples, masks, packet numbers and the short header's nonce. They are extracted
from the RFC text by `tests/vectors/extract_rfc9001_keys.py`, which refuses to
write a value that does not re-derive: the Initial secret is recomputed from the
version-1 salt and the connection ID, every key from its traffic secret, each
sample is checked to be the packet's bytes at `pn_offset + 4`, each mask is
checked to turn the printed unprotected header into the printed protected one,
and the nonce is recomputed from the IV and the packet number. The mask itself is
the one value taken on the RFC's word, because checking it would mean a second
implementation of AES inside the extractor.

`tests/unit/test_crypto.c` (249 checks) pins the primitives to published vectors
rather than to round trips: NIST's SHA-256 and GCM cases, RFC 4231's HMAC-SHA256
including the 131-byte key, RFC 5869's HKDF, RFC 8439's ChaCha20 keystream and
ChaCha20-Poly1305, and FIPS 197's AES block. `tests/unit/test_quic_protection.c`
(170 checks) takes each RFC 9001 packet apart and puts it back together, so a
wrong nonce, AAD or sample offset that was symmetric between seal and open would
fail the second direction; it also checks that a damaged tag, a damaged
ciphertext, a changed AAD, the wrong packet number and the other direction's keys
are all refused with `WT_ERR_PROTOCOL` *and* that the plaintext buffer is cleared
when they are. One test exists only because the RFC's vectors cannot catch the
defect it covers: both published AES masks have a zero in the bit that separates a
four-bit mask from a five-bit one, so it builds packets whose masks set that bit
and checks the long and short header widths separately.

Four defects were found while building this phase, all of them in code that had
never been executed because this phase added the first tests that call it:

- `wt_aead_open` was designed to return the computed tag for the caller to
  compare, which OpenSSL 3 cannot do: its provider GCM produces a tag only from a
  finalisation that already succeeded, which needs the expected tag. Measured, not
  assumed, and the API was changed to an authenticated open returning
  `WT_ERR_AUTHENTICATION`, which clears the plaintext -- so the caller that could
  forget to compare no longer exists.
- HKDF-Expand was built on `EVP_KDF` with its mode passed as a four-byte string,
  which that parameter rejects; every derivation in the library returned
  `WT_ERR_UNSUPPORTED`. It is now the RFC 5869 HMAC chain, which is what the
  extract half already used, and both halves are checked against RFC 5869.
- The streaming SHA-256 context had no initialised marker, so update or final on a
  context that had never been initialised dereferenced whatever was in the
  caller's array and crashed inside libcrypto. It now carries a marker and answers
  `WT_ERR_STATE`.
- The installed CMake package did not declare its OpenSSL dependency, so
  `find_package(webtransport_c99)` failed for a consumer of the static library
  with an error inside a generated file. `scripts/check-package.sh` caught it.

Two test vectors were also written wrong in the way this project treats as the
worst kind: RFC 4231's cases 6 and 7 were given invented message bytes beside the
RFC's published digests, and NIST's GCM case 5 was given 64-byte buffers for a
60-byte plaintext. Both would have passed a round trip and failed the published
value, which is exactly what they did.

Implement the crypto provider layer.

Tasks:

- Add OpenSSL-backed HKDF.
- Add AES-GCM packet protection.
- Add ChaCha20-Poly1305 support when available.
- Implement QUIC header protection.
- Implement Initial secret derivation.
- Implement Handshake and 1-RTT packet protection.
- Implement key update lifecycle.

Tests:

- RFC 9001 Initial secret vectors.
- Protected packet seal/open vectors.
- Tamper rejection.
- Packet number reconstruction under protection.

Completion criteria:

- Protected Initial and 1-RTT packets round-trip.
- Tampered packets fail without exposing packet bytes or secrets in logs.

## Phase 3: TLS 1.3 for QUIC

**First part done: the key schedule and the transcript.**
`include/webtransport/tls/keyschedule.h` and `src/tls/keyschedule.c` carry RFC 8446
section 7.1's two chains -- the extracts that build Early, Handshake and Master
secrets out of the PSK and the ECDHE, and the derivations that turn those into the
two directions' handshake and application traffic secrets, the exporter and
resumption secrets, the record traffic keys, the Finished keys and verify data, and
the key update secret -- plus the handshake transcript they consume. The transcript
absorbs whole handshake messages into a running SHA-256 and reads the hash at each
point without consuming it, which is what `wt_sha256_snapshot` was added to the
crypto interface for: a handshake hashes on the order of a hundred bytes of state
rather than buffering a peer's certificate chain. A message whose framing disagrees
with its length is refused, because a transcript that absorbed one would hash bytes
the peer never hashed and every secret after it would be wrong with nothing to point
at. An all-zero ECDHE shared secret is refused here rather than in a caller, per
RFC 8446 section 7.4.2.

The vectors are RFC 8448 section 3, extracted by
`tests/vectors/extract_rfc8448_keyschedule.py`, which recomputes every value before
writing it: each extract as HMAC(salt, IKM), each derivation as
HKDF-Expand-Label(PRK, label, hash), each traffic and Finished key from the secret
its own step names, the schedule as a chain (each extract's salt is the previous
"derived" step's output), and the three transcript hashes against the handshake
messages it extracts beside them. 33 values, and `tests/unit/test_tls13_keyschedule.c`
(361 checks) drives the implementation through them: the extract chain, the
transcript through each checkpoint, both directions' secrets, all four traffic key
sets, both Finished keys and verify data, and the negative cases the trace cannot
cover -- an all-zero shared secret, a Finished with one bit of one byte changed
(tried for every bit of every byte), a message whose framing lies, a transcript used
before it was initialised or after it was cleared.

**Second part done: the handshake messages and extensions.**
`tls/extension.h` and `tls/handshake.h` carry the four-byte handshake framing, the
extension list codec and the typed readers and writers for the extensions a QUIC
handshake uses (`server_name`, `supported_groups`, `signature_algorithms`,
`supported_versions`, `key_share`, `psk_key_exchange_modes`, ALPN and
`quic_transport_parameters`), and the ClientHello and ServerHello in both directions:
parse into views, re-encode byte for byte, and build from parameters.

Parsing is view-based and building is parameter-based, and that asymmetry is the
design rather than an accident: a peer's message is read once and used, while what we
send is built from values we chose. Both directions run the same body function through
the two-pass writer, so a built message and a parsed message have the same layout by
construction rather than by having been written out twice -- the encoder measures the
body with the same code that writes it, so a length field cannot disagree with what
follows it. Every list a peer can grow is bounded by a capacity argument and refused
with `WT_ERR_LIMIT` rather than written past, and every field TLS 1.3 gives exactly one
legal value (`legacy_version`, `legacy_compression_methods`) is refused when it is
anything else.

The vectors are RFC 8448's own ClientHello and ServerHello, parsed and re-encoded byte
for byte -- including the two extensions this implementation does not implement, which
is what makes "unknown extensions survive a round trip" a check rather than a claim.
`tests/unit/test_tls13_handshake.c` (131 checks) also drives each typed reader with the
RFC's real extension bodies, checks the builder by parsing back what it built, and
refuses what the vectors cannot contain: a duplicated extension, an extension block
with trailing bytes, an extension longer than its block, more extensions than the list
holds, a two-method compression list, a zero-length key share, and an odd-length value
list.

**Third part done: the X25519 key agreement.**
`tls/keyshare.h` and `tls/keyshare.c` carry RFC 7748's primitive, key generation, the
public key a private key produces, and the shared secret, and refuse an all-zero secret
at the point it is computed -- RFC 8446 section 7.4.2 makes a point of small order a
handshake failure, and OpenSSL's X25519 refuses it by failing the derivation rather than
by returning zeroes, which is reported as the same failure. X25519 is the only group
this implementation can complete, so it should be the only one a client advertises:
offering a group without a key share invites a HelloRetryRequest, and this implementation
refuses HelloRetryRequest rather than handling it.

The vectors are RFC 7748's, extracted by `tests/vectors/extract_rfc7748_x25519.py`,
which carries a ladder implemented from section 5 of the same document as an oracle: the
oracle must reproduce both of section 5.2's scalar-multiplication vectors (where the
u-coordinate is not the base point) and all five values of section 6.1's Diffie-Hellman
example before anything is written, so a vector read from the wrong place -- the
identical labels of the X448 block sit directly below the Curve25519 one -- fails
generation. `tests/unit/test_tls13_keyshare.c` (50 checks) drives the implementation
through those values and adds the one that ties two documents together: X25519(client
private, server public) must equal the ECDHE value RFC 8448's key schedule consumes, and
both public keys must be X25519(private, 9), so the key agreement and the schedule cannot
disagree without a test saying so.

**Fourth part done: the certificate messages.**
`tls/handshake.h` now carries Certificate, CertificateVerify and Finished: a parsed chain
is a list of DER views with the per-entry extension block RFC 8446 section 4.4.2 defines,
CertificateVerify is a scheme and a signature, and Finished is exactly Hash.length bytes
and nothing else. Nothing here validates anything -- framing is this layer's question and
trust is the layer above -- which is what lets the codec be tested against RFC 8448's own
444-byte Certificate and 136-byte CertificateVerify, both re-encoded byte for byte. A
client with no certificate to offer builds an empty chain rather than omitting the
message, which is what section 4.4.2 requires.

Building this part settled an error-semantics question the earlier parts had left
inconsistent: a read past the end of a region whose length has already been validated is
WT_ERR_PROTOCOL, not WT_ERR_TRUNCATED. Every parser here is handed a complete message --
its outer framing is checked first -- so an inner length that overruns is a length that
lies rather than bytes that have not arrived, and the difference decides whether a
receiver gives up on the connection or waits for more. Truncation is now what it says:
the buffer is shorter than the framing itself.

**Fifth part done: peer authentication.**
`tls/trust.h` and `tls/trust.c` validate a chain and verify a CertificateVerify signature,
with a policy that mirrors the Swift library's: `WT_TLS_TRUST_SYSTEM` is `systemTrust`,
`WT_TLS_TRUST_PINNED_CERTIFICATE` is `TLSPinnedCertificateTrustPolicy` (SHA-256 fingerprints
of the leaf), `WT_TLS_TRUST_STORE` is the same policy against certificates the caller
supplies rather than a platform store a portable library cannot assume, and
`WT_TLS_TRUST_LOCAL_DEVELOPMENT` is `localDevelopmentSelfSigned` -- including its
restriction, because the loopback requirement travels with the mode rather than sitting
beside it as advice. There is no callback and no interaction: every failure is a status and
the same inputs give the same answer, which is what the phase's completion criterion asks
for.

The chain is parsed, validated and discarded inside one call, so no X.509 object outlives
the function that needed it and the public header mentions no OpenSSL type. The signature
check takes the scheme's digest from the scheme rather than from a second parameter, and it
sets RSA-PSS's salt length and MGF1 digest explicitly because OpenSSL's defaults are not
RFC 8446's.

The test that matters most uses one document end to end: it rebuilds RFC 8448's transcript
through the Certificate, constructs the content a CertificateVerify signs from that hash,
extracts the public key from the RFC's own certificate DER, and verifies the RFC's
signature with it -- so the transcript, the content construction, the key extraction and the
signature arithmetic all have to be right, and the expected answer is a document rather than
this code. Chain validation is tested against certificates generated by
`tests/vectors/trust/make-fixtures.sh`: a valid chain, a name mismatch, an unknown issuer,
and an expired certificate, which is RFC 8448's own rather than a fixture. Two defects were
found while writing it, both in this part: a failure path freed a certificate stack the
caller also freed (a double free that segfaulted the test), and the SubjectPublicKeyInfo was
written into a caller's buffer before its length was checked.

**Sixth part done: the client state machine, and with it Phase 3's completion criteria.**
`tls/session.h` and `src/tls/session.c` sequence the handshake: the ClientHello is absorbed
as the bytes that were sent, the ServerHello is checked for the version, the ciphersuite, the
session id echo and the key share, the EncryptedExtensions are checked for the ALPN the
caller asked for and the transport parameters a QUIC handshake requires, the Certificate goes
through the trust policy, the CertificateVerify is checked over the transcript through the
Certificate, the server's Finished is verified over the transcript through CertificateVerify,
and the client's Finished is produced over the transcript through the server's. The
application secrets are derived at the last of those steps and are available in no earlier
state, which is the phase's first completion criterion; every failure is a status and the
policy is the one from the previous part, which is the second.

The machine takes the ClientHello as bytes rather than building one and assuming it was sent,
because the transcript is over the bytes the server saw and nothing else. That is what makes
RFC 8448's recorded flight usable as evidence: `tests/unit/test_tls13_session.c` (79 checks)
starts the machine with the RFC's ClientHello and the RFC's client private key, feeds it the
RFC's server messages in order, and requires the handshake secrets, the application secrets
and the client's Finished to be the RFC's own. A mistake shared by the transcript, the
schedule, the signature check and the Finished construction would be invisible; a mistake in
any one of them cannot pass.

That test found three real defects, all of them one message out of step and all of them
invisible without a recorded flight: the Early Secret was never derived (the handshake
secret was computed from its own output buffer), the handshake traffic secrets were read from
a transcript that did not yet include the ServerHello, and the client's Finished was over a
transcript that did not yet include the server's Finished. Each produces secrets that are
well formed and verify against nothing.

**Seventh part done, and Phase 3 with it: the server handshake.**
`wt_tls_server_*` mirrors the client's checks and order: the ClientHello is checked for the
version, the ciphersuite, an x25519 key share, the ALPN the server speaks and the transport
parameters QUIC requires; the ServerHello is answered with the handshake secrets derived from
the transcript through it; the rest of the flight (EncryptedExtensions, Certificate,
CertificateVerify, Finished) is built in the order the client's checks expect, with the
signature over the transcript through the Certificate; and the client's Finished gates the
application secrets exactly as the server's does on the client. The flight is two calls because
QUIC has two encryption levels -- the ServerHello goes under Initial keys and the rest under
handshake keys -- and it is buildable once, because an RSA-PSS signature is randomised and a
second flight would not match the transcript the first one signed.

The signer is `wt_tls_signature_sign`, the mirror of the verifier in the trust layer, and the
reason the two halves here cannot disagree about what a scheme means: both take the digest from
the scheme and both set RSA-PSS's parameters the same way.

`tests/unit/test_tls13_server.c` (88 checks) runs a whole handshake between the two halves and
requires that they agree: the ALPN and the transport parameters survive both directions, the
certificate validates against the generated CA, and the application secrets each end derives are
the other end's in the opposite direction -- the property neither half can check alone. The
server's own gates are tested as refusals, and a client that will not accept the server's chain
stops at the Certificate.

Two defects came out of that test, both in the server and both invisible to a single half: the
ALPN extension was written as a bare name where RFC 7301 defines a ProtocolNameList, so the
client's parser refused it; and the test itself walked a concatenation of handshake messages
with the header parser, which refuses a buffer longer than the message it describes -- which is
why `wt_tls_handshake_message_len` now exists for walking a CRYPTO stream, as the QUIC runtime
will have to.

Port the Swift TLS behavior into portable C99 state machines.

Tasks:

- Implement ClientHello and ServerHello parsing/generation.
- Implement TLS extensions for ALPN `h3`, supported groups, key share, signature algorithms, and QUIC transport parameters.
- Implement Certificate, CertificateVerify, and Finished handling.
- Implement transcript hash and TLS 1.3 key schedule.
- Implement certificate chain validation through OpenSSL.
- Implement prompt-free trust policy and explicit test-only trust modes.
- Gate QUIC application-key readiness on certificate trust, CertificateVerify, Finished, ALPN `h3`, and QUIC transport parameters.
- Enforce 0-RTT policy and immutable settings requirements.

Tests:

- Mirror Swift TLS tests.
- Wrong ALPN negative test.
- Bad certificate negative test.
- Bad transport parameter negative test.
- CertificateVerify failure test.
- Finished failure test.

Completion criteria:

- Application keys are unavailable until every required security condition is satisfied.
- All trust failures are deterministic and non-interactive.

## Phase 4: QUIC Connection Runtime

**First part done: the packet number space.** `quic/pn_space.h` and `src/quic/pn_space.c` are what
one packet number space remembers: the received set as a bounded list of ranges (so a peer cannot
choose this endpoint's memory by sending packets), the ACK frame that set produces, the
acknowledgement debt that decides whether to send promptly or wait, and RFC 9002 section 5's round
trip estimator with the probe timeout that comes from it. There is no I/O and no policy in it,
which is why it can be tested exhaustively: the ranges are checked for the property that matters
most -- the same packets inserted in any order produce the same set -- the ACK frame is checked by
decoding it back with the Phase 1 frame codec, and the RTT arithmetic is checked against values
worked out by hand from section 5.3.

Two defects came out of that test, both in the merging logic: a packet that bridged a gap extended
the range above it without joining the range below, leaving two ranges where the set has one (an
ACK that describes a gap that does not exist); and the bound dropped the *newest* range rather than
the oldest, because the list is kept largest-first and "the last one" is the oldest. A third
finding was in the test: the ACK gap field is RFC 9000 section 19.3.1's "contiguous unacknowledged
packets preceding the packet number one lower than the smallest in the preceding range", which is
one less than the number of missing packets -- the round trip through the decoder is what settles
it.

**Second part done: loss detection and probe timeouts.** `quic/loss.h` and `src/quic/loss.c` hold
RFC 9002 section 6: the sent-packet list with the caller's own tag on each packet, the packet
threshold (three numbers higher acknowledged) and the time threshold (9/8 of the larger of the
smoothed and latest round trip times), the loss timer that comes from the time threshold, bytes in
flight for the congestion controller to read, and the probe timeout with its exponential backoff.
The list is bounded and being at the bound is WT_ERR_LIMIT rather than a silent drop: a forgotten
packet is one that is never retransmitted, and the stall it causes names nothing. What has to be
retransmitted is frames, and frames belong to the connection -- this file hands back a lost
packet's number and the caller's tag rather than keeping a second copy of the send state.

`tests/unit/test_quic_loss.c` (169 checks) pins both thresholds at their boundaries: three numbers
higher is lost and two is not, and a packet sent one microsecond inside 9/8 of the round trip time
is not yet lost while one at the threshold is. It also checks the two things the probe timeout is
easy to get wrong -- it exists only while something ack-eliciting is in flight, and its backoff is
reset by acknowledging an ack-eliciting packet rather than by any acknowledgement at all. One
finding was in the tests: the packet threshold's boundary and the time threshold's clock are both
inclusive comparisons, so an off-by-one in either direction is a test that passes for the wrong
reason.

**A contract defect fixed on the way to the runtime: a failed tag is an authentication failure.** The
Phase 2 protection layer returned `WT_ERR_PROTOCOL` from `wt_quic_unprotect_frames` when the AEAD's tag
did not verify, and `status.h` says the opposite in the status's own definition: `WT_ERR_AUTHENTICATION`
exists for exactly this case and is "deliberately not `WT_ERR_PROTOCOL`", because the packet is well
formed and simply was not produced by the holder of the key -- forged or corrupted in transit, which is
the ordinary case on a hostile network rather than a violation. The two could not both be right, and
the connection runtime is where it would have bitten: a caller cannot decide whether to discard a
datagram or to close a connection if both are reported as the same protocol error. `unprotect_frames`
now returns `WT_ERR_AUTHENTICATION`, its header states that the choice of remedy belongs to the caller,
and `wt_quic_packet_read` passes it through unchanged. The five expectations in the Phase 2 test that
pinned the old value were the thing that was wrong, which is the one case where a test is worth less
than nothing: it was holding a defect in place.

**Third part done: congestion control.** `quic/congestion.h` and `src/quic/congestion.c` are RFC
9002 section 7's NewReno: the initial window's formula with its 14720-byte bound, slow start,
congestion avoidance's `mds * acked / cwnd` increment, the recovery epoch that makes a burst of
losses cost one halving rather than one per packet, the two-datagram floor, and persistent
congestion as an effect the caller asks for. What is not here is stated rather than implied: the
pacing rate and HyStart++ are optional in the RFC, and the application-limited rule is something the
caller knows and this file does not.

The epoch is the part the tests are mostly about, because both ways of getting it wrong are quiet: a
controller that halves once per packet of a burst collapses to the floor and looks like a dead path,
and one that lets an acknowledgement from before the period grow the window grows it during the
recovery it is recovering from. `tests/unit/test_quic_congestion.c` (88 checks) sends the burst and
checks that the window moved exactly once, then checks that a later loss does reduce it again. Three
findings were in the tests and one in a comment: the increment is `mds * acked / cwnd` with integer
division, so a small acknowledgement adds nothing while a large one adds a *fraction* of a datagram
rather than a whole one, and repeated losses only collapse the window if each is a new event.

**Fourth part done: the stream state machines and flow control.** `quic/stream.h` and
`src/quic/stream.c` carry RFC 9000 sections 2, 3 and 4: the send half's five states and the receive
half's five, the final size that bounds everything after it is known, RESET_STREAM and STOP_SENDING
in both directions, and flow control at both levels -- the connection's and the stream's -- in both
directions. The two halves are independent, because a stream that is reset one way stays usable the
other, and the final size is treated as the security boundary it is: data at or beyond it is
FINAL_SIZE_ERROR, and so is a FIN that contradicts it, which is what stops a peer appending to a
stream it has already ended.

Flow control counts **offsets rather than delivered bytes**, which is the RFC's model and the reason
the code says "credit" rather than "new bytes": a peer that writes ten bytes at offset one million
has spent a million bytes of the connection's credit even though ten arrived, so a gap cannot be used
to escape the accounting. The limits in the sending direction are checked before a frame is written
rather than after, because a frame that is written and then refused has already counted.

`tests/unit/test_quic_stream.c` (109 checks) walks both state machines through their legal moves and
refuses the illegal ones -- writing after a FIN, a second FIN, reading a reset stream as if it were
data -- and checks the flow control cases where only one of the two levels is exhausted. One finding
was a gap in the API rather than a bug: a reset receive half had no way to become *read*, so a stream
whose reset had arrived could never be forgotten; `wt_quic_stream_on_reset_read` is the transition
RFC 9000 section 3.2 puts between them.

**Fifth part done: QUIC DATAGRAM and the close paths.** `quic/datagram.h` carries RFC 9221's
datagrams: the size rule in both directions (the peer's `max_datagram_frame_size` bounds the frame and
the path's packet size bounds the packet, and the answer is the smaller of the two, including the
frame's own length field whose width follows the value it describes), and a bounded receive queue
whose policy is stated rather than implied -- when it is full the NEWEST datagram is discarded, because
the application has already been told about everything in the queue and for the traffic this carries
the freshest message is the one that matters least. `quic/close.h` carries RFC 9000 sections 10.2 and
19.19: the two forms of CONNECTION_CLOSE, which are different messages and must not be confused (the
transport form names the frame that caused the error and the application form cannot), and the
draining period of three probe timeouts, with no deadline at all when there is no probe timeout to
multiply -- which is not the same as a deadline that has already passed.

`tests/unit/test_quic_datagram.c` (103 checks) and `tests/unit/test_quic_close.c` (53 checks) check
those rules at their boundaries: a limit that cannot hold an empty datagram, a byte that changes the
length field's width, a queue that wraps, and the narrow list of frames that may still be processed
once the connection has closed. Two findings were in the tests: a ring test that pushed every
iteration and popped every other one was checking the queue's depth rather than its order, and a block
that reused a queue the previous block had left entries in.

**Sixth part done: the wire seam.** `quic/packet_io.h` and `src/quic/packet_io.c` are the one place
where frames become a datagram and a datagram becomes frames, and the order of the two protections is
what they exist to fix. `wt_quic_packet_build` writes the header, seals the frames with that header
through the packet number as associated data, appends the tag, and applies header protection last;
`wt_quic_packet_read` removes header protection first, reconstructs the packet number against the
largest this endpoint has seen, and only then authenticates and decrypts -- because the header
protection sample is ciphertext (RFC 9001 section 5.4.2) and the packet number's own length is behind
the mask. A round trip is therefore not enough to test this: a builder and a reader that shared one
mistake would agree with each other, so the tests here also flip every byte of a packet and check that
the frames never come back, which is what makes the order a checked property rather than a convention.

Making the read possible needed two additions to the packet codec. `wt_quic_long_header_encode_prefix`
writes a long header and its Length field for a payload the caller has not produced yet, because the
AEAD's associated data has to exist before the payload can be sealed and the payload's length has to be
known before the header can be written; the two forms share one body so they cannot disagree about the
Length field. And `wt_quic_protected_pn_offset` walks a
header that is *still protected* by its layout alone -- first byte, version, both connection IDs, the
Initial token, the Length field -- because no decoder can. The packet number length lives in the low
two bits of the first byte and so do the two reserved bits the decoders rightly refuse, both of which
the mask owns, so a decode before unprotection is a decode of the mask. It lives in `packet.c` beside
the decoders it mirrors, so the layout is written once, and it yields both the sample's offset and the
packet's own end inside a datagram that may hold several coalesced packets.

`tests/unit/test_quic_packet_io.c` (148 checks) covers the round trip for both header forms, an Initial
with a token (where the packet number's offset is not a fixed distance from the start), the packet
number reconstruction across the cases where the truncated bytes differ from the number itself, the
tamper sweep, the wrong local connection ID length, and the refusals: a datagram cut short at every
length, a Version Negotiation, a Retry (neither is protected by these keys, and both have their own
parsers), and a build with no room. Three findings were in the tests: a failed tag is reported as
WT_ERR_PROTOCOL by the protection layer, not WT_ERR_AUTHENTICATION, and the read's contract now says
so; a wrong local connection ID length is refused by whichever check the wrong sample offset breaks,
which is a protocol error either way; and an empty payload cannot be protected at all with a one-byte
packet number -- with an eight-byte connection ID the sample needs the full four bytes -- which is a
real minimum and one of the reasons a QUIC datagram has a size floor.

**Seventh part done: the UDP socket layer.** `runtime/udp.h` and `src/runtime/udp.c` are the platform,
and they are deliberately the only file in the tree that is POSIX rather than ISO C99 (WT-13): C99 has
no sockets, so this is where the syscall enters and it is the reason the build sets a feature-test
macro at all. It moves whole datagrams between two addresses on IPv4 and IPv6 and knows nothing about
QUIC -- the connection runtime drives it, which is why a failure is a status rather than a closed
socket and why nothing blocks an event loop longer than the caller asked. Every classification of a
platform failure is in one place, `map_errno`, so that a caller can act on WT_ERR_AGAIN or WT_ERR_LIMIT
without knowing which kernel refused it; the failures this layer cannot classify are reported as a
status added for the purpose, `WT_ERR_IO`, because a caller that reads "limit" or "closed" acts on it
and inventing a diagnosis is worse than admitting the layer does not have one.

Two decisions are stated in the header rather than left to the platform. IPv6 sockets set `IPV6_V6ONLY`
explicitly, because Linux and the BSDs disagree about the default and a socket that is sometimes
dual-stack would make "which family is this connection" depend on the host -- so an IPv4 address needs
an IPv4 socket, and a mismatched send is a caller error rather than a second way to reach the same
peer. And **truncation is reported, not hidden** (WT-36): a datagram larger than the caller's buffer is
`WT_ERR_TRUNCATED` with the length zeroed, because a QUIC packet cut in half is a different packet and
a caller that parsed the prefix of one would turn a truncation into a parsing bug. The peer's address
is filled in even then, because "who sent what I could not receive" is the useful half of the report;
`WT_UDP_MAX_DATAGRAM` is the buffer size that cannot truncate. The scope id of a link-local address is
part of the address type, since two interfaces can carry the same `fe80::` address and dropping the
scope is the difference between reaching the peer and reaching nobody.

`tests/unit/test_runtime_udp.c` (177 checks) is the one test that uses the real network, and it is a
unit test because the subject is a syscall wrapper: a fake socket would test the fake. It runs on the
loopback interface only, opens two real sockets per case, and lets the kernel choose every port, so it
needs no network, no privileges and no free port. Both families are checked through a round trip, a
zero-length datagram, two datagrams that must not merge, a datagram too large for the buffer in both
directions, and every refusal -- an unopened socket, a closed one, a mismatched family, a datagram
above the UDP maximum, and the arguments. One defect came out of it and it is exactly the kind a
synthetic test would have hidden: `wt_udp_address_loopback` wrote 127.0.0.0 for IPv4 because the IPv6
case needed only its last byte set, and binding a network address fails with EADDRNOTAVAIL -- which a
fake socket would have accepted.

**Eighth part done: the connection runtime over the socket.** `quic/connection.h` and
`src/quic/connection.c` are one connection: its three packet number spaces and the keys of each, the
received sets and the acknowledgements they owe, the sent-packet list with loss detection and probe
timeouts, the congestion controller, the close paths, and the UDP socket it borrows. The frames it does
not own -- CRYPTO, STREAM, the flow control limits, NEW_CONNECTION_ID, DATAGRAM -- go to a
caller-installed handler, which is the seam the handshake and the stream layer plug into. That seam is
what let this part be tested against a real socket without a handshake, and it is what keeps a peer's
frame types out of the packet layer.

`now` is a parameter everywhere and the event loop is the caller's: `receive` reads one datagram,
`flush` sends what is owed, `next_timeout` says how long the caller may wait and `on_timeout` does what
the deadline was for. Nothing sleeps and nothing owns a thread, which is what makes the timers
testable: a probe timeout, a time-threshold loss and an idle timeout are all checked by moving a number
rather than by sleeping, and a test that slept would be asserting on the machine's load.

Three rules came out of the work that are worth naming. **A connection with no round trip sample must
still arm a probe timeout**: RFC 9002 section 6.2.1 uses a fixed initial round trip until the estimator
has a sample, and a client whose first Initial is lost has no sample by definition -- an implementation
that waited for one would never retransmit the very packet that would produce it, so `wt_quic_loss_pto`
refusing before the first sample is answered by the runtime's own fallback. **An acknowledgement is
owed by an ack-eliciting packet and not by any packet**: answering an ACK-only packet with an ACK-only
packet is the storm RFC 9000 section 13.2.1 exists to prevent, so such a packet is recorded, arms no
timer, and is covered by the next acknowledgement. And **an acknowledgement may be delayed** by up to
this endpoint's own `max_ack_delay`, which is a deadline like any other -- zero in the Initial and
Handshake spaces, and separate in the configuration from the peer's delay, because RFC 9002's round
trip arithmetic uses the peer's number and RFC 9000's timer uses this endpoint's.

`tests/unit/test_quic_connection.c` (291 checks) runs two connections over two loopback sockets, on
IPv4 and on IPv6, with the Initial keys both ends derive from one connection ID (RFC 9001 section 5.2).
The whole path is therefore exercised without a handshake: a CRYPTO payload is built, protected, sent,
received, unprotected, walked frame by frame, acknowledged and accounted for; the round trip sample is
checked against the clock the test chose; the congestion window grows in slow start; the packet
threshold declares a loss and the descriptor names the bytes to send again; a probe is padded to what
header protection needs (WT-72) and arrives; a close goes out in the highest space that has keys, ends
the peer's connection and starts its draining period; an acknowledgement of a packet that was never
sent is the protocol violation RFC 9000 section 13.1 makes it; and a datagram from an unknown address,
one carrying another connection ID, one for a key this endpoint does not have, and an empty one are all
discarded with nothing owed. Two findings were the runtime's rather than the test's: the peer's
connection ID has to be the one the peer answers to and not the one it sends, and the wire's ACK Range
Count counts only the ADDITIONAL ranges -- the first range is in Largest Acknowledged and First ACK
Range -- which is worth knowing before writing a chain walk, because the frame codec's range accessor
indexes the additional ranges and not the first one.

What is not here yet, and what the phase still needs: the TLS handshake driven over CRYPTO frames, the
stream frames and their flow control (both of which plug into the handler), the resource limits the
task list names, cancellation, and the server's connection-ID issuance and Retry. The completion
criterion -- local IPv4 and IPv6 loopback -- is now met at the packet level, which is what this part
was for.

**Ninth part done: the CRYPTO stream.** `quic/crypto_stream.h` and `src/quic/crypto_stream.c` are the
handshake bytes, which do not arrive in order. A CRYPTO frame names its own offset and its own length
(RFC 9000 section 19.6), so the receive half is a window of bytes with a bitmap saying which have
arrived, delivering only up to the first hole -- which is what makes a ClientHello split across two
packets readable -- and the send half keeps what was sent so a lost packet can be sent again. The
bitmap is what avoids an allocation per gap, and the window slides when the consumer takes bytes, so
the bound is a subtraction rather than a growing index.

Both halves are bounded, and the bound is the point: a peer chooses the offsets, so a frame that does
not fit the buffer is refused WHOLE -- nothing is stored, which is what lets the caller close the
connection with `WT_QUIC_CRYPTO_BUFFER_EXCEEDED`, the transport error code RFC 9000 section 20.1 gives
this case -- and an offset beyond the protocol's own bound is refused as the overflow it is. The send
half deliberately keeps bytes after they are first sent: RFC 9002 section 6.1 can declare a packet lost
by a time threshold after a later one was acknowledged, and those bytes are still the peer's only copy.

`tests/unit/test_quic_crypto_stream.c` (97 checks) checks the two ways a receiver is attacked: an
out-of-order split that must deliver nothing until the hole is filled, and offsets a peer picks
arbitrarily, including one that would need memory beyond the buffer (refused, with the state
unchanged), one that ends exactly at the buffer's end (accepted), and one past RFC 9000's bound
(refused as an overflow). It also checks the property that makes the bound workable -- after the
consumer takes bytes, the peer may send more at the offset it reached, which is the sliding window a
fixed buffer needs -- and that a duplicate, an overlapping retransmission and a repeat of what was
already delivered are all ordinary rather than errors.

**Tenth part done: the TLS 1.3 handshake over CRYPTO, and a whole handshake over loopback.** `quic/handshake.h`
and `src/quic/handshake.c` are the join between the message-at-a-time TLS machine and the packet layer:
they reassemble each encryption level's CRYPTO stream, walk it into whole handshake messages, feed them to
the TLS machine in order, take what it produces, install the keys each step makes available, and send a
lost flight again from the bytes they kept. Three rules are worth naming. A message boundary is the
transport's and not TLS's, so a partial message is held rather than parsed. The keys appear AS the
handshake makes them -- the Initial keys are the caller's, the handshake keys arrive with the ServerHello
(client) or the ClientHello (server), and the application keys only when the handshake is confirmed --
and a driver that installed them early would protect a packet with a key the peer does not have. And a
lost flight is retransmitted from here, because TLS is asked for a flight once: an RSA-PSS signature is
randomised, so a second flight would not match the transcript the first one signed.

`tests/unit/test_quic_handshake.c` (108 checks) runs a whole handshake between two connections over two
real loopback sockets, on IPv4 and on IPv6: a real certificate, a real signature and a real trust check,
with the ClientHello in an Initial packet, the ServerHello in another, the rest of the server's flight
under the handshake keys the ServerHello derived, the client's Finished under the same, the server's
HANDSHAKE_DONE under the application keys, and then a 1-RTT frame the server reads -- which is this
phase's completion criterion, in one test.

**Three defects came out of it, and they are the reason it was worth writing.** The loss list keyed a
packet on its number alone, and packet numbers are per space (RFC 9000 section 12.3): the server's first
Handshake packet number zero was refused as a duplicate of its Initial packet number zero. The fix is
RFC 9002 appendix A's own shape -- the space is part of the key, and loss detection, the loss timer and
the probe timeout are per space (WT-75). The connection's send path set the source connection ID and the
token unconditionally, so every SHORT header packet was refused by the builder and the first 1-RTT frame a
connection ever sent was `WT_ERR_INVALID_ARGUMENT` (WT-76). And the TLS machine's views of the ALPN and the
peer's transport parameters point into the CRYPTO window, which slides as the handshake proceeds, so a
driver that read them after the handshake read bytes that had been consumed: the driver now copies them
the first time they are reported, which is also what the connection needs, since both outlive the
handshake (WT-77).

Two small additions came with it: `wt_quic_connection_send_frame`, the general path for a frame this
layer does not produce (HANDSHAKE_DONE today, the stream frames next, which is why it exists), and a
close-code hint a frame handler may set before refusing a frame, so that a failed handshake goes out as
RFC 9000 section 20.1's CRYPTO_ERROR with the TLS alert in its low byte rather than as a generic internal
error.

**Eleventh part done: the peer's transport parameters as the limits this endpoint obeys.** A connection
now parses the parameters the handshake carried (`wt_quic_connection_set_peer_parameters`) and keeps what
they say about what the peer will accept: the flow control limits at both levels, the stream counts, the
connection ID limit, the datagram size, the payload size. THIS IS THE OTHER HALF OF EVERY LIMIT the
resource limit task names, and the reason the stream and datagram work comes after it: a sender that does
not know the peer's `initial_max_data` cannot know when to stop, and one that ignores
`max_datagram_frame_size` sends a frame the peer must reject.

The parser is where RFC 9000 section 18.2's defaults live, and getting them right is not the same as
zeroing a struct: an absent parameter and a zero one are different facts, and the RFC gives three
parameters defaults that are not zero (`max_udp_payload_size` is 65527, `active_connection_id_limit` is 2,
and the flow control limits are zero, which means "nothing granted"). A list that breaks the section's
rules -- a payload size below 1200, a stream limit above 2^60 -- is a connection error rather than
something to clamp, and the codec's own check reports the offender.

The effective idle timeout becomes the SMALLER of this endpoint's and the peer's, because RFC 9000
section 10.1 makes it the minimum of the two nonzero values: a connection that enforced only its own
would stay open after the peer had forgotten it, and one that enforced only the peer's would outlive its
own configuration. `tests/unit/test_quic_peer_limits.c` (57 checks) checks every limit through a real
codec round trip, the defaults for an empty list, both directions of the idle timeout minimum (through
the connection's own timer rather than a field), and the refusals: a too-small payload size, a truncated
list, and the arguments.

**Twelfth part done: QUIC DATAGRAM over the connection.** `wt_quic_connection_send_datagram` sends an
RFC 9221 DATAGRAM frame in the Application space, and the payload is bounded by BOTH the peer's
`max_datagram_frame_size`, which the previous part put on the connection, and what the path will carry;
`wt_quic_connection_max_datagram_payload` answers which bound applies. A peer that never offered
DATAGRAM gets `WT_ERR_UNSUPPORTED` rather than a limit error, because the difference matters: one means
"smaller", the other means "it does not speak this". A datagram carries NO retransmission descriptor,
which is what makes it unreliable -- a caller that needs the bytes uses a stream -- and the receive half
is a bounded queue (`wt_quic_connection_on_datagram`) whose policy is the module's: when it is full the
newest is discarded and counted, because a datagram that was never guaranteed to arrive is not an error
when it does not.

The receive half is a function rather than something the connection does by itself, and that is the
layering decision this part makes concrete: a frame handler composed of several consumers -- the
handshake, the datagram queue, and later the stream layer and the WebTransport session -- decides what a
frame is for. `tests/unit/test_quic_handshake.c` now installs such a handler (handshake first, then the
datagram queue) and carries a real handshake followed by a datagram exchange and an oversized refusal,
which is also what proves the two halves compose.

**Thirteenth part done: the key lifecycle RFC 9001 section 4.9 makes a MUST.** `wt_quic_connection_discard_keys`
zeroes a space's two key sets and marks the space gone, and the connection calls it at the two moments
the RFC names: the Initial keys go when the first Handshake packet is successfully processed -- not when
the Handshake keys were installed, because both ends can derive the Initial keys from a connection ID
either of them can see, and the proof that the peer has the handshake is the Handshake packet itself --
and the Handshake keys go when the handshake is confirmed, which for a client is the server's
HANDSHAKE_DONE and for a server is the client's verified Finished. What is left is the application
level, which is the only one an attacker who saw the first packet cannot derive.

The receive path already discarded a packet for a space without keys (RFC 9001 section 4.9.3), so the
observable effect is that a late Initial packet is dropped rather than read, and the tests now say so:
`tests/unit/test_quic_handshake.c` requires the Initial and Handshake keys to be gone on both ends after
a real handshake with the application keys kept, and `tests/unit/test_quic_connection.c` checks the
discard itself -- idempotent, a send in a discarded space refused with WT_ERR_STATE, a space that never
had keys not an error, and the arguments.

**Fourteenth part done: the STREAM frame send path.** `wt_quic_connection_send_stream` encodes an
RFC 9000 section 19.8 STREAM frame -- id, offset (omitted when it is zero, which is what a sender does for
a stream's first bytes), length, FIN and data -- and sends it, with the stream number checked against what
the peer granted. That check is the interesting half: a stream number is four fields in one (section 2.1),
so whether a limit applies at all depends on WHO opened the stream -- sending on a stream the peer opened
is always allowed, because it is theirs, and only a stream this endpoint opens is bounded by the count the
peer's `initial_max_streams_bidi`/`_uni` grants.

It is deliberately NOT the stream layer, and the header says so: nothing here remembers the bytes, so a
STREAM frame is not retransmitted and nothing counts the flow control credit spent. It exists because the
send path and the wire format are worth having and testing on their own, and because the stream layer's
first part is exactly this plus the state that remembers. `tests/unit/test_quic_handshake.c` (194 checks)
now carries a handshake, a datagram and a STREAM frame over loopback, checks the frame's fields and bytes
as the peer's composed handler sees them, that a stream beyond the peer's grant is refused, and that a
peer-initiated stream is sendable.

**Fifteenth part done: the connection-level limit this endpoint grants.** `wt_quic_connection_send_max_data`
sends an RFC 9000 section 19.9 MAX_DATA frame, and `wt_quic_connection_set_max_data`/`_max_data` seed and
read it. This is the OTHER DIRECTION from the peer limits: what the peer granted this endpoint is parsed
from its transport parameters, and what this endpoint grants the peer has to be advertised and raised as
the application reads. RFC 9000 section 4.1 makes a limit that only ever decreases a protocol error, so a
sender must never lower one; the function refuses a limit below the last one it sent for exactly that
reason, and it refuses to send at all before the caller has seeded the value this endpoint advertised in
its own transport parameters -- a MAX_DATA frame that contradicted that parameter would be the same
protocol error arriving from the other side.

`tests/unit/test_quic_handshake.c` (214 checks) now carries a handshake, a datagram, a STREAM frame and a
MAX_DATA frame over loopback, with the peer's composed handler recording what each carried.

**Sixteenth part done: the stream counts this endpoint grants.** `wt_quic_connection_send_max_streams`
sends an RFC 9000 section 19.11 MAX_STREAMS frame, with the same shape and the same rule as the
connection-level limit: it may only rise, because section 4.6 makes a count that decreases a protocol
error -- the peer has already been told it may open that many. The two directions are counted separately,
since a bidirectional stream costs the peer one of its own and one of ours while a unidirectional one
costs only ours, and the frame carries the direction it is about.

With this the advertisable half of the limits is complete: the connection knows what the peer granted
(parsed from its transport parameters), what it grants the peer in bytes, and what it grants in streams,
in both directions. What is not here is the accounting that decides WHEN to raise them, which is the
stream layer's: it is the layer that knows a stream was closed and that its slot is free again.

`tests/unit/test_quic_handshake.c` (240 checks) now carries a handshake, a datagram, a STREAM frame, a
MAX_DATA frame and a MAX_STREAMS frame over loopback.

**Seventeenth part done: the peer's limits are acted on, not just parsed.** The connection now handles a
received MAX_DATA and MAX_STREAMS itself rather than handing them to a handler: what the peer grants is
what this endpoint may send, so raising it is a fact about the connection and not about the application
above it. Both are checked against RFC 9000 section 4.1's and section 4.6's rule that a limit may only
ever rise -- a peer that sends a lower one has contradicted an earlier promise, which is a
PROTOCOL_VIOLATION and closes the connection with the frame type named -- and a MAX_STREAMS moves only
the direction it names, which is why the frame carries one.

This closes the loop the previous parts opened: the limits the peer granted are parsed from its transport
parameters, its raising of them is applied as it arrives, and what this endpoint grants is advertised and
raised with `wt_quic_connection_send_max_data` and `wt_quic_connection_send_max_streams`. What is still
missing is the accounting that decides WHEN to raise them, which is the stream layer's.

**Eighteenth part done: a closed connection stops processing frames.** RFC 9000 section 10.2.1 says that
once a connection is closed, only PADDING, the close's own frames and the frames a probe needs may still
be processed. The connection now enforces that in its frame walk: a decoded kind is mapped onto the wire
type the close rule asks about, `wt_quic_close_accepts_frame_type` answers -- ONE statement of the rule,
in the module that owns it, rather than a second list here that could drift -- and anything refused STOPS
the walk rather than failing it, because a peer's late frame is not this endpoint's error and the
connection is already closed. Before this, a MAX_DATA or a STREAM frame that arrived after a close was
still applied, which is exactly the "MUST NOT process" the section names.

`tests/unit/test_quic_connection.c` proves it with a packet built for the occasion: a peer-closed server
is sent a readable packet carrying a larger MAX_DATA than the peer had granted, and the limit it may send
does not move -- while the packet itself is still read, because a closed connection still reads PADDING
and closes.

**Nineteenth part done: HANDSHAKE_DONE only reaches a client.** RFC 9000 section 19.20 says a server that
receives a HANDSHAKE_DONE frame must treat it as a PROTOCOL_VIOLATION: the frame is what tells a client
its handshake is confirmed, so a client that sends one is confused about which end of the connection it
is. The connection refuses it there, naming the frame, and a client that receives one still has it handed
on, because whether the handshake is now confirmed is the handshake layer's business. The frame dispatch
that the handler path used is now one function (`deliver_to_handler`), so the "hand the rest to the
caller" branch and the HANDSHAKE_DONE case share one statement of what a handler's refusal means.

THE TEST THAT PROVES IT TOOK THREE ATTEMPTS, AND THE REASON IS WORTH RECORDING: a HANDSHAKE_DONE frame is
one byte, and a packet whose payload is shorter than three bytes cannot be header-protected with a
one-byte packet number (WT-72's minimum). The first two attempts built a packet that was refused as
truncated, so nothing was sent, the server was never closed by the rule, and the assertions read the
zeros of a connection that had been closed by something else -- an idle timeout -- instead. The fix is
three PADDING bytes in the test's payload, and the lesson is that a test whose packet cannot be built
proves nothing while looking like a failure of the thing under test.

**Twentieth part done: a frame that arrives in the wrong packet type is refused.** RFC 9000 section 12.4
makes a frame that may not appear in the packet type it arrived in a PROTOCOL_VIOLATION, and section
12.5's table is what says which may. The runtime can tell the two facts that table turns on: the frames
allowed in every space (PADDING, PING, ACK and the two CONNECTION_CLOSE forms), and the frames allowed
only where the application level is -- STREAM, the flow control limits, NEW_TOKEN, the connection ID
frames, the path frames, HANDSHAKE_DONE and DATAGRAM. CRYPTO is the one frame the other way round: it
belongs to the handshake's own spaces, so a CRYPTO frame arriving at the application level is refused,
which is what stops a peer from injecting handshake data into a connection that has finished
handshaking. The refused frame's own type is named in the close, so the peer can see which one.

One map now answers "what wire type is this kind" for both rules that speak in wire terms -- this one and
the close rule -- because a second copy is a second thing to keep in step with the codec.
`tests/unit/test_quic_connection.c` proves the rule with a STREAM frame in an Initial packet, the case the
table rules out most plainly, and the connection closes naming STREAM.

**Twenty-first part done: the four fields in a stream number.** RFC 9000 section 2.1 packs four things into
one number -- who opened the stream, whether it is bidirectional, and an index within that class -- and
every rule about streams turns on them: whether a count limit applies at all, whether a stream may be
reset, which end owns it. `quic/stream.h` now reads and writes those fields in one place
(`wt_quic_stream_id_index`, `_from_client`, `_is_bidirectional`, `_make`) instead of every call site
shifting bits itself, and the connection's own stream-number check -- written before the helpers existed,
with its arithmetic inline -- now uses them. The test checks the four classes, the inverse round trip for
the first sixteen numbers, and the two accessors that are easy to get backwards (the initiator bit is the
LOW one and the directionality is the next). It is a small part on purpose: it is the first piece of the
stream layer, and the layer's table will read these fields for every rule it enforces.

**Twenty-second part done: the stream table.** `quic/stream.h` carries a bounded table of stream state
machines, which is the resource limit the plan names: a peer chooses how many streams it opens, so a
receiver that allocated a structure per stream number would let the peer choose its memory. A full table
refuses a new stream rather than dropping an old one -- a stream that is silently forgotten is data the
application never sees -- the per-class counts are kept so a MAX_STREAMS can be raised from them, and a
stream is only forgotten when BOTH halves are done, which is what RFC 9000 section 3.3 requires before its
number is never seen again. One rule is worth naming because it is easy to invert: the limit is the
OPENER's, so a peer-initiated stream costs the peer one of its allowance and not this endpoint one of its
own (section 4.6). The table owns the state and nothing else -- no frames, no bytes, no policy about when
to send -- so what it answers is which stream a frame is about, whether one more may be opened, and which
streams are still alive, which is what the receive path needs before it can hand a frame to a state
machine. Its first attempt did not link because the stream-number helpers it reads had been lost from the
header; landed again after those were restored, it passes.

**Twenty-third part done: the connection owns the table, and a stream can be opened.** The connection now
holds a stream table and `wt_quic_connection_open_stream` derives the number from the counts the table
keeps -- a client's bidirectional streams are 0, 4, 8, so a number is never reused or chosen by the caller
(RFC 9000 section 2.1) -- checks it against the peer's `initial_max_streams_*`, and starts the stream with
the two flow control limits that are the two directions': this endpoint's own for what it will receive and
the peer's `initial_max_stream_data_*` for what it may send. Those are different numbers from different
places, which is why they are set together in one place here rather than by each caller.

The receive side is not wired yet, and that is the next piece: RFC 9000 section 3.2 makes a received frame
for an unseen stream OPEN it, with the granted counts as the bound -- a peer that opens more than this
endpoint's MAX_STREAMS allows is the STREAM_LIMIT_ERROR of section 4.6 -- and MAX_STREAM_DATA then raises
the one stream's allowance.

**Twenty-fourth part done: a stream is created by its first frame, and the limits that bound it.** RFC 9000
section 3.2 makes a received frame for a peer-initiated stream this endpoint has never seen OPEN it -- no
separate message announces a stream -- and the connection now does that, with the two rules that decide
whether it is allowed, both of them the peer's fault when they are not: a frame for one of this endpoint's
OWN numbers that was never opened is the STREAM_STATE_ERROR of section 19.8, and a peer-initiated stream
beyond the count this endpoint granted is the STREAM_LIMIT_ERROR of section 4.6. A full table is neither,
because it is this endpoint's own bound. MAX_STREAM_DATA then raises the one stream's send allowance, which
is the per-stream counterpart of MAX_DATA and the first piece of flow control that the receive path
applies rather than merely checks.

`tests/unit/test_quic_connection.c` (475 checks) covers all four: the stream appearing in the table as the
peer's and bidirectional, the limit error with the frame named, the state error for an unopened local
number, and the allowance moving.

**Twenty-fifth part done: RESET_STREAM and STOP_SENDING reach their state machines.** The two frames that
change a stream's state rather than carrying its data are now applied by the connection as they arrive: a
RESET_STREAM ends the receive half with the peer's error code and final size, and a STOP_SENDING tells the
send half that the peer wants no more. They are the stream's own facts rather than the application's, which
is why the connection applies them before the caller's handler sees the frame -- the handler observes the
data, the state machine owns the lifecycle. A reset whose final size contradicts what already arrived is
the FINAL_SIZE_ERROR of RFC 9000 section 4.5, and a STOP_SENDING for a stream in the wrong state is the
STREAM_STATE_ERROR of section 19.5; both close the connection naming the frame.

**Twenty-sixth part done: received stream data is accounted against both flow control limits.** The
connection keeps the CONNECTION-level flow control -- what it granted and has received, and what the peer
granted -- and every STREAM frame's data is charged against both that limit and the stream's. RFC 9000
section 4.1 makes data beyond a limit a FLOW_CONTROL_ERROR, and deciding WHICH limit was broken needed a
careful reading of the stream module: it reports a per-stream overrun, a connection overrun and a
final-size contradiction with two statuses between them, so the status alone cannot choose the code. The
caller therefore recomputes the credit the module would have charged and asks each limit in turn -- the
stream's, then the connection's, then the final size -- which is what makes the error the peer receives
the right one rather than whichever branch happened to be first.

Three findings came out of landing it, all of them about the tests rather than the rule. A stream's
receive limit and the connection's are seeded by DIFFERENT calls (`local_max_stream_data` at connection
setup, `set_max_data` for the connection), so a test that grants one and not the other gets a refusal that
looks like a rule failure. The `-Wshadow` rule caught a credit variable redeclared in the same block. And
two existing test blocks assert about the PRE-SEED state of a limit, so seeding a limit before them
invalidates their expectations -- the MAX_STREAMS block in the twenty-second part and the MAX_DATA block
here, whose "a limit before the seed is a state error" is no longer true once the receive path needs room
earlier. Both blocks now test the rule that matters (a limit may only rise) rather than the state they
used to start in.

**Twenty-seventh part done: the receive limits are raised as the data arrives.** RFC 9000 section 4.1 asks a
receiver to extend a limit as it consumes, so that a sender is never blocked by accounting it cannot see.
The connection now does that for both levels: when the connection's received total reaches the limit it
granted, it sends a MAX_DATA frame for the next window and moves the limit; and when a stream's highest
offset reaches that stream's limit, it sends MAX_STREAM_DATA for the next window. This runtime hands each
frame's bytes to the caller's handler immediately -- it does not buffer -- so ARRIVAL IS CONSUMPTION, and
that is why the extension follows the account rather than a separate read call.

`tests/unit/test_quic_connection.c` checks it end to end: a peer sends exactly the four bytes the endpoint
granted, the endpoint raises its own limit past four, and the PEER reads the MAX_DATA frame the connection
sent by itself and moves what it may send to match.

Implement the production network state machine.

Tasks:

- Implement packet number spaces.
- Implement ACK generation and ACK processing.
- Implement loss detection and PTO.
- Implement congestion accounting.
- Implement stream state machines.
- Implement flow control.
- Implement QUIC DATAGRAM support.
- Implement connection close paths.
- Implement IPv4 and IPv6 UDP runtime.
- Implement cancellation and timeout behavior.
- Implement resource limits for packets, streams, datagrams, and buffered peer input.

Runtime backend plan:

- Start with a portable POSIX backend for macOS, Linux, and FreeBSD.
- Add epoll/kqueue optimizations after correctness.
- Add Windows WSA/IOCP backend before Windows release.

Completion criteria:

- Local IPv4 and IPv6 QUIC loopback works on macOS and Linux.
- Loss/PTO and close-path tests pass.
- Runtime shutdown is race-clean under sanitizers where available.

## Phase 5: HTTP/3 Core

Port Swift HTTP/3 behavior.

Tasks:

- Implement HTTP/3 frame codec.
- Implement SETTINGS.
- Implement control stream lifecycle.
- Implement request stream lifecycle.
- Implement GOAWAY.
- Implement H3 error mapping.
- Implement stream type prefixes.
- Enforce request/control stream constraints.
- Reject duplicate SETTINGS and malformed stream ordering.

Completion criteria:

- HTTP/3 control and request stream tests match Swift behavior.

## Phase 6: QPACK

Port the complete Swift QPACK implementation.

Tasks:

- Implement full RFC 9204 static table.
- Implement Huffman encoding and decoding.
- Implement static indexed fields.
- Implement literal field lines.
- Implement dynamic table.
- Implement encoder and decoder streams.
- Implement Base and post-Base dynamic references.
- Enforce table capacity and malformed reference handling.

Completion criteria:

- QPACK static, literal, Huffman, dynamic, Base, and post-Base tests pass.

## Phase 7: WebTransport Draft-16 Core

Port the Swift WebTransport session layer.

Tasks:

- Implement extended CONNECT.
- Enforce `:protocol = webtransport-h3`.
- Implement Structured Fields parsing and serialization for `WT-Protocol` and `WT-Available-Protocols`.
- Implement session ID validation.
- Implement WebTransport stream prefixes.
- Implement WebTransport datagram prefixes.
- Implement buffered ingress before session establishment.
- Implement buffered stream/datagram rejection paths.
- Implement `WT_DRAIN_SESSION`.
- Implement `WT_CLOSE_SESSION` with 32-bit application error code, UTF-8 message, FIN semantics, and stream cleanup.
- Implement CONNECT stream close as session close equivalent.
- Implement flow-control capsules and monotonic update validation.
- Implement GOAWAY interaction.
- Implement 0-RTT CONNECT restrictions.
- Implement complete draft-16 error mapping.

Completion criteria:

- C99 conformance matrix matches the Swift draft-16 matrix.
- All required session, stream, datagram, close, drain, flow-control, and error paths are covered by passing tests.

## Phase 8: Public C API

Design the public API after the protocol core is stable.

API requirements:

- Opaque handles only.
- Explicit `create`/`destroy`.
- Explicit allocator support.
- Callback/event-loop integration for async operations.
- Optional blocking helper wrappers for CLI and simple users.
- Backpressure-aware streams and datagrams.
- Explicit close/drain operations.
- Sanitized error surface.
- No placeholders or in-process facades exposed as production API.

Completion criteria:

- Public sample app compiles on all target platforms.
- Public API documentation covers trust, endpoints, sessions, streams, datagrams, backpressure, close, drain, and ownership.

## Phase 9: CLI Apps

Implement CLI apps that mirror the Swift tools.

Targets:

- `wt-client-c99`
- `wt-server-c99`
- `wt-conformance-c99`

Required flags:

- `--listen`
- `--connect`
- `--transport packet`
- `--trust system`
- `--origin`
- `--protocol`
- `--settings-validation`
- `--exchange stream|datagram`
- `--message`
- `--timeout-ms`
- `--scenario all`
- `--json`

Completion criteria:

- CLI tools run local IPv4 and IPv6 packet sessions.
- CLI tools produce stable machine-readable scenario output.
- Unsupported or unsafe modes are rejected deterministically.

## Phase 10: Test Port

Mirror Swift tests into C99.

Test groups:

- QUIC varints, frames, packets, packet numbers.
- TLS handshake, key schedule, CertificateVerify, Finished.
- Packet protection.
- Transport parameters.
- HTTP/3 frames, SETTINGS, request streams, control streams, GOAWAY.
- QPACK static, Huffman, dynamic, Base, post-Base.
- WebTransport CONNECT.
- Streams and datagrams.
- Close and drain.
- Flow control.
- Malformed input.
- Resource exhaustion.
- IPv4 and IPv6.
- CLI process behavior.
- External interop.

Recommended tools:

- CTest for all test runners.
- Small internal C99 test harness for portability.
- libFuzzer/AFL++ for parser fuzzing where available.

Completion criteria:

- `ctest` passes locally.
- CI passes on macOS, Linux, FreeBSD, and Windows.

## Phase 11: External Interop

Reuse the five independent VPS endpoints already installed under `/var/webtransport`.

Add:

```sh
C99/scripts/run-vps-third-party-interop.sh
```

Required C99 proof matrix:

- `pywebtransport` / `aioquic`: stream.
- `web-transport-quinn`: stream.
- `web-transport-quinn`: datagram.
- `web-transport-quiche`: stream.
- `hyperium/h3-webtransport`: datagram.
- `erlang-webtransport`: stream.
- `erlang-webtransport`: datagram.

Aggregate pass criteria:

- `testedImplementationCount = 5`
- `passedProofCount = 7`
- `requiredProofCount = 7`
- `allPassed = true`

Completion criteria:

- C99 client proves real external interoperability against all five implementations.
- README table includes implementation name, version, URL, third-party OS, test date, and proof.

## Phase 12: Cross-Platform CI

Required matrix:

- macOS 26, Apple Silicon, Clang.
- Debian 13, GCC.
- Debian 13, Clang.
- FreeBSD latest, Clang.
- Windows 11, MSVC.
- Windows 11, Clang-CL.

Checks:

- Configure.
- Debug build.
- Release build.
- Unit tests.
- Integration tests.
- CLI smoke.
- Sanitizers where supported.
- Release artifact reproducibility.

Completion criteria:

- All required jobs are green.
- Artifacts are reproducible and checksumed.

## Phase 13: Production Hardening

Required checks:

- ASan clean.
- UBSan clean.
- MSVC analyzer clean where useful.
- Parser fuzzing for QUIC varints, QUIC frames, transport parameters, HTTP/3 frames, QPACK, capsules, and WebTransport stream prefixes.
- Static analysis with clang-tidy or cppcheck.
- No unchecked integer narrowing.
- No unbounded peer-controlled memory growth.
- No sensitive logs.
- No production insecure trust defaults.
- No exposed test runtime or facade.
- Stable shutdown and cancellation behavior.

Completion criteria:

- Hardening checks are documented and pass.
- Any disabled sanitizer/check has a documented platform reason.

## Phase 14: Release Readiness

Tasks:

- Update `C99/README.md` with actual C99 status.
- Add generated API docs.
- Update root README status table.
- Update `CHANGELOG.md`.
- Generate release artifacts for all supported platforms.
- Publish SHA256 checksums.
- Add external interop proof table.
- Tag/release when C99 reaches the milestone.

Completion criteria:

- C99 can be consumed as a normal CMake package.
- Shared and static libraries are produced.
- Public headers are installable.
- Release artifacts are reproducible.
- Public docs match actual behavior.

## Definition of Done for C99 100%

The C99 implementation can be marked 100% only when all of the following are true:

- Full draft-16 spec matrix is implemented.
- All Swift-equivalent conformance tests pass in C99.
- C99 client/server CLI passes local IPv4 and IPv6.
- C99 passes the five-implementation VPS interop matrix.
- CI is green on macOS 26, Debian, FreeBSD, and Windows 11.
- Sanitizers and static checks are clean.
- Public API is documented.
- No placeholder, facade, deterministic test runtime, or spike source is exposed as production.
- README status is updated from `0%` to the measured final score.

## Suggested Execution Order

1. Build system and project skeleton.
2. Core utilities, allocator, and error/status model.
3. QUIC varints, frames, and packets.
4. Crypto and packet protection.
5. TLS 1.3 QUIC handshake.
6. QUIC connection runtime.
7. HTTP/3.
8. QPACK.
9. WebTransport session logic.
10. Public C API.
11. CLI apps.
12. Local conformance tests.
13. VPS third-party interop.
14. CI and platform hardening.
15. Documentation and release polish.
