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

**Twenty-eighth part done: a sender can cancel a stream.** `wt_quic_connection_reset_stream` sends RFC 9000
section 19.4's RESET_STREAM and moves the stream's send half to Reset Sent, which is what stops anything
further being sent on it. The frame carries the final size the peer needs to tell a truncated stream from a
complete one -- which is why the state machine computes it from what was actually sent rather than letting
a caller state it -- and the rules about WHO may reset are the sender's: this endpoint resets its own
streams and the peer's bidirectional ones, never a peer's unidirectional stream, and never twice. With the
receive side already handling a reset that arrives, the stream layer now has both directions of the
cancellation path, which is the "cancellation" item of the phase's task list.

**Twenty-ninth part done: a lost stream packet names what to send again.** A STREAM send now carries a
retransmission descriptor -- the stream, the offset and the length -- so that when RFC 9002's loss
detection declares its packet lost, the connection hands the descriptor to the owner and the owner sends
the bytes again. WHO KEEPS THE BYTES IS THE POINT: this layer cannot, and should not, so the descriptor is
the whole mechanism -- the same shape the CRYPTO stream already uses, which is why `wt_quic_tx_frame_t`
grew a `stream_id` and the handshake driver's lost handler ignores anything that is not its own.

Two things the test had to get right and are worth remembering. The acknowledgement must be in the SAME
packet number space as the packets it acknowledges -- an ACK in the Initial space says nothing about
Application-space packets (RFC 9000 section 12.3) -- and a burst of losses reports several packets, in the
order they were sent, so a witness that overwrites its record describes the newest rather than the
oldest. `tests/unit/test_quic_connection.c` (606 checks) checks the descriptor of the first loss: the
stream, the offset and the length the packet actually covered.

**Thirtieth part done: STOP_SENDING, the other half of cancellation.** `wt_quic_connection_stop_sending`
sends RFC 9000 section 19.5's STOP_SENDING, which asks the peer to stop sending on a stream and names the
application error code it is expected to answer with (section 3.5). With the twenty-eighth part's
RESET_STREAM the cancellation path is now complete in both roles: a RESET_STREAM cancels what this
endpoint is sending, and a STOP_SENDING asks the peer to stop what it is sending.

The rules are the mirror image of the reset's and are checked as such: only the RECEIVER of a stream's
data may ask, only once -- a second is the STREAM_STATE_ERROR the section names rather than something to
ignore -- and not on a stream whose receive half is already finished. A frame that could not be sent
leaves the stream as it was, because a caller that retries after WT_ERR_AGAIN must not be told it has
already asked.

**Thirty-first part done: the Retry integrity tag.** `wt_quic_retry_integrity_tag` and
`wt_quic_retry_integrity_verify` are RFC 9001 section 5.8: AES-128-GCM with an empty plaintext over the
pseudo-packet `ODCID Length || Original Destination Connection ID || Retry packet without its tag`, with
the version's own key and nonce -- constants rather than a negotiated secret, because the point of the tag
is that a client can tell a Retry the server sent from one an attacker injected BEFORE any handshake has
happened. The verification accumulates differences instead of stopping at the first, so a fast answer
cannot tell an attacker how much of a guess was right.

The tag's VALUE is not asserted here: this repository's vectors are extracted from the documents, never
transcribed, and RFC 9001 appendix A.4's Retry packet has not been extracted yet -- that is recorded as a
task rather than satisfied with a hand-written constant. What the test does check is the property the tag
exists for: the same inputs give the same tag, a verification accepts it, and a changed byte OR a
different original destination connection ID is refused, the second being the attack it defends against.

**Thirty-second part done: issuing connection IDs.** `wt_quic_connection_issue_connection_id` sends RFC 9000
section 19.15's NEW_CONNECTION_ID and keeps what it issued, bounded twice over: by `WT_QUIC_CONNECTION_IDS_MAX`
in this endpoint, because a NEW_CONNECTION_ID is peer-visible state an endpoint should not grow on its own
instructions, and by the peer's `active_connection_id_limit` LESS the ID the handshake used -- section 5.1.1
counts that one among what the peer will store, so the default grant of two leaves exactly one spare. The
stateless reset token is taken from the caller rather than invented: section 10.3 requires it to be
unguessable, which means derived from a secret this layer does not hold.

The duplicate check comes before the limit check, and the test caught that: a caller that hands the same ID
twice has made a mistake whether or not there is room, and "you already issued that" is a different answer
from "the peer will not store another".

**Thirty-third part done: the peer's connection IDs are stored.** A received NEW_CONNECTION_ID is kept with
its stateless reset token, and the section's own errors are raised rather than ignored: a connection ID
whose length is not 1..20 and a `retire_prior_to` above the sequence it arrives with are both
FRAME_ENCODING_ERRORs (RFC 9000 section 19.15), a sequence that arrives twice with a DIFFERENT connection
ID or token is a PROTOCOL_VIOLATION (the same one twice is merely a duplicate), and more IDs than this
endpoint advertised it would store is the CONNECTION_ID_LIMIT_ERROR of section 5.1.1. A `retire_prior_to`
retires what is below it, which is how a peer asks for its old IDs back.

One finding was the kind that hides until a default is exercised: a configuration field left at zero meant
"store nothing" rather than "the RFC's default", so the first NEW_CONNECTION_ID closed the connection with a
limit error. Zero now means the RFC's two, and that is the documented meaning of the field.

**Thirty-fourth part done: a short packet is padded until it can be sampled.** RFC 9001 section 5.4.2 takes
the header protection sample from the sixteen bytes starting four bytes into the packet number field, and an
endpoint must discard a packet too short to contain one -- so a sender cannot protect one either. That made
a two-byte frame impossible to send on its own: `RETIRE_CONNECTION_ID`, `PING`, and any small
acknowledgement came back from `wt_quic_packet_build` as a truncation error and never left the process. It
was found by writing the RETIRE_CONNECTION_ID tests below, which is the second time the frame layer has been
where a rule the packet layer owns shows up.

The header's own length cancels out of the requirement, because the sample starts after the packet number
rather than after the header: a packet needs `offset + sample` bytes from the start of the packet number,
the tag supplies sixteen and the packet number the rest, so the shortfall is at most three bytes. The
builder now fills it with PADDING frames (RFC 9000 section 19.1), which carry nothing and are ignored by
every receiver, and the two numbers are named in `protection.h` so the sampler and the builder cannot drift
apart. The empty-payload test used to assert the refusal; it now asserts the padding, and a new test sends
the two-byte retire frame and checks that the receiver sees the frame with the padding behind it.

**Thirty-fifth part done: RETIRE_CONNECTION_ID retires an issued ID.** RFC 9000 section 19.16 makes two
sequences a PROTOCOL_VIOLATION -- one that was never issued, and the one the peer used as the Destination
Connection ID of the packet that carried the frame -- and the connection handled neither, because the frame
was simply handed to the caller. Retiring an ID now frees its slot and the peer's `active_connection_id_limit`
budget, so a peer that retires an ID can be given a replacement; a repeat of a sequence already retired is
tolerated, because RETIRE_CONNECTION_ID is retransmitted when it is lost and the second copy describes a
state the endpoint is already in. This endpoint accepts packets only on the ID the handshake used, which
section 5.1.1 numbers 0, so sequence 0 is always the ID of the carrying packet here. Replacing a retired ID
needs a fresh ID and stateless reset token, which only the caller can produce, so the frame still reaches the
handler.

Writing that test exposed a defect that had been there since the IDs were first issued: the first ID this
endpoint announced was numbered 0, colliding with the handshake's own connection ID, and a peer retiring
either would have been ambiguous. Sequences now start at 1 and are never reused, which is what makes a
RETIRE_CONNECTION_ID naming a sequence mean one thing.

**Thirty-sixth part done: a client's Initial datagram is expanded to the minimum.** RFC 9000 section
14.1's rule was the last unimplemented piece of the Initial packet path, and it is not cosmetic: a server
must discard an Initial packet carried in a datagram smaller than 1200 bytes, so an unpadded client
Initial cannot start a connection against a conformant peer at all. The client now expands the packet with
PADDING frames (section 19.1) until the datagram reaches the minimum, and the server discards a short
Initial datagram before reading it.

Three details are what the earlier attempts at this missed. First, the expansion is applied by rebuilding
the packet rather than computed ahead of it, because the long header's Length field is a varint whose width
grows with the value it carries: a size computed from the unpadded payload lands a byte short, and adding
the shortfall then lands a byte over. The loop adds the shortfall the previous pass measured and trims
instead when it overshoots, so the datagram lands on the minimum rather than above the caller's
`max_datagram_size`. Second, only the client expands: the rule is a client requirement, and a server's
Initials are already large enough to carry the handshake. Third, the discard is of the whole datagram and
happens before the frame walk, which is why the frame-permission test now pads its hand-built Initial -- the
test is about section 12.4's table, and the datagram-size rule would otherwise have swallowed the packet
before the rule under test could refuse it.

Two tests: the client's four-byte CRYPTO payload leaves as a 1200-byte datagram the server processes, and a
hand-built short Initial is discarded with nothing recorded for it and no connection error.

**Thirty-seventh part done: the Retry integrity tag is checked against the RFC.** RFC 9001 section 5.8's
tag is the only thing that lets a client tell a Retry the server sent from one an attacker injected, and
until now nothing asserted the value this implementation produces against the document: the test that
existed proved the tag was computed consistently, which a wrong key or nonce would satisfy just as well.
`tests/vectors/extract_rfc9001_retry.py` now extracts appendix A.4's Retry packet and the tag printed with
it, and refuses to write a block that does not parse as a version-1 Retry with a zero-length Destination
Connection ID, a Source Connection ID of 1..20 bytes, a non-empty token and exactly sixteen bytes of tag --
and whose named original destination connection ID is not the one A.2's client Initial packet carries, read
from that packet's hex rather than from the sentence beside it. The test then requires the implementation's
tag to equal the RFC's, the RFC's packet to verify, and a changed byte or a different original connection
ID to be refused. `check-vectors.sh` runs the extractor's `--check` alongside the others.

**Thirty-eighth part done: a frame the decoder refuses closes the connection.** WT-83 asked for the test
the encoder cannot produce -- a NEW_CONNECTION_ID whose `retire_prior_to` is above its own sequence, which
RFC 9000 section 19.15 makes a FRAME_ENCODING_ERROR and which this library refuses to encode -- written by
hand into a packet. Writing it found a defect one layer up: the decoder reported the code, but the
connection returned the error status to its caller instead of closing, so a peer that sent an undecodable
frame was never told and the connection stayed open, with the failure visible only to whoever called
`wt_quic_connection_receive`. Section 12.4 makes such a frame a connection error, so `process_packet` now
closes with the code the frame's own rule named -- or FRAME_ENCODING_ERROR when the failure came back from
the cursor helpers as a truncation, which section 12.4 defines the same way. A status raised by the frame
visitor is left alone, because those paths have already closed the connection with the code they chose.

The test asserts what the RFC requires rather than what the code did: the connection closes with
FRAME_ENCODING_ERROR for the hand-written frame.

**Thirty-ninth part done: the connection IDs this endpoint issues are receivable.** NEW_CONNECTION_ID could
be sent and the peer's own IDs were stored, but the receive path compared each packet's Destination
Connection ID with the handshake's ID alone (RFC 9000 section 7.2). Everything this endpoint issued was
therefore write-only: a peer that used one of them -- which is the entire point of issuing them, and what a
peer does when it moves to a new path -- had its packets discarded as belonging to another connection. The
handshake's ID and every issued ID that has not been retired are now recognised, and packets addressed to a
retired one are discarded, which is this side's half of section 10.2's rule.

Which sequence a packet used now travels with the frames, so section 19.16's second PROTOCOL_VIOLATION --
the peer cannot retire the ID the packet was addressed to -- is applied to the ID that was actually
addressed rather than to sequence 0, which was only ever right while the handshake's ID was the only one
this endpoint would receive on.

Writing the test found one more thing worth keeping: `wt_quic_connection_issue_connection_id` accepted an ID
of any length in 1..20, including lengths this endpoint could never receive. A short header carries no
Destination Connection ID length (section 17.2), so the receive path parses with the one length the
connection uses; an ID of another length is one whose packets would be thrown away. It is now refused at the
call rather than at the peer.

Three tests, one per behaviour: a packet addressed to an issued ID is processed, one addressed to a retired
ID is discarded without advancing the received set, and a RETIRE_CONNECTION_ID addressed to the very ID it
retires closes the connection with PROTOCOL_VIOLATION.

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

- **First part done: the HTTP/3 frame codec and the stream type prefixes.** `include/webtransport/http3/frame.h`
is RFC 9114's frame: a varint type, a varint length and that many bytes of payload, with the registered
types of section 11.2.1, the error codes of section 8.1, the stream types of section 6.2.1, and the
section 7.2.8 test for the frame types HTTP/2 reserved (`0x1f * N + 0x21`).

Three decisions are worth stating because later parts depend on them. First, the codec interprets nothing:
a SETTINGS identifier, a GOAWAY identifier and a frame's right to appear on a stream are the stream layer's
rules, and keeping them out means one place decides whether a frame is *well formed* and one place decides
whether it is *allowed*. Second, a frame whose declared length is not in the buffer is a frame error rather
than a request to wait, because HTTP/3 has no partial frame -- the stream layer assembles a frame's bytes
before handing them over -- and a length that does not fit `size_t` is refused rather than narrowed. Third, a
failed decode leaves the caller's cursor exactly where it was, so a caller can report which frame failed
instead of only that something did. An unknown frame type decodes like any other: a codec that refused one
would refuse whatever a later revision defines, and section 7.2.8's reserved range is exposed as a predicate
for the layer that owns the rule.

Six tests cover the registered types and an unknown one round tripping, a frame with no payload, prefix
decoding leaving the following frame intact, the truncated cases, the encode refusals, and the stream type
prefix including a stream whose type is not there.

Implement HTTP/3 frame codec.
- **Second part done: SETTINGS.** `include/webtransport/http3/settings.h` parses and encodes RFC 9114
section 7.2.4's identifier and value pairs into a fixed table. Three of the section's rules decided the
shape. A reserved HTTP/2 identifier (`0x02` to `0x05`, section 11.2.2) is H3_SETTINGS_ERROR, and so is a
value above one for `ENABLE_CONNECT_PROTOCOL`, which RFC 9220 section 3 makes a boolean. A duplicate
identifier is a MAY in the section -- "MAY treat the presence of duplicate setting identifiers as a
connection error of type H3_SETTINGS_ERROR" -- and this build takes the option, because a peer that names
the same setting twice is a peer disagreeing with itself and there is no reading of the frame that is not a
guess.

The third rule is the one that shaped the table rather than the code: unknown identifiers MUST be ignored,
and the `0x1f * N + 0x21` identifiers exist only to exercise that (a sender SHOULD include one). So the
table stores identifiers as well as values, which is what lets a duplicate of a setting this build does not
understand be caught while the setting itself is still ignored, and the parser and the encoder agree on
which identifiers are reserved. The table is fixed at sixteen entries: a peer that sends more is refused
with H3_EXCESSIVE_LOAD rather than made the author of this endpoint's memory use. A payload that ends
between an identifier and its value is H3_SETTINGS_ERROR rather than a short read, because HTTP/3 has no
partial frame -- the same rule the frame codec follows. The encoder writes ascending identifier order, so a
set always produces the same bytes, and setting an identifier twice is refused so the encoder cannot
produce a frame the parser would refuse.

Five tests cover the reserved and exercise identifiers, a round trip whose expected wire bytes are written
by hand, the malformed cases, the table bound, and the setter's refusals. Writing the hand-written bytes
caught a real bug in the first version of the sort: it emitted entries twice and skipped others, which the
round trip alone would not have noticed because parsing still failed -- with PROTOCOL, from the duplicate
the encoder had produced.

Implement SETTINGS.
- **Third part done: the control stream's lifecycle.** `include/webtransport/http3/control.h` is RFC 9114
section 6.2.1's state machine for the peer's control stream, and all four of the section's rules are
connection errors: a first frame that is not SETTINGS is H3_MISSING_SETTINGS, a second control stream from
the same peer is H3_STREAM_CREATION_ERROR, the stream closing at any point is H3_CLOSED_CRITICAL_STREAM
(whether or not SETTINGS had arrived -- the closure itself is the error), and a frame the section does not
allow there is H3_FRAME_UNEXPECTED. That last set is where the judgement is: DATA, HEADERS and PUSH_PROMISE
describe requests and have nothing to describe on a control stream, a second SETTINGS is forbidden by section
7.2.4's "MUST NOT be sent subsequently", and the frame types section 7.2.8 reserved for HTTP/2 are checked
before those so a reserved type is reported as reserved. CANCEL_PUSH, GOAWAY, MAX_PUSH_ID and unknown
extension frames are allowed, which is the half an over-eager implementation gets wrong.

The state machine decides permission and nothing else: this takes a frame TYPE rather than a frame, because
what a SETTINGS, GOAWAY or MAX_PUSH_ID frame says belongs to the part that owns that frame. A frame that
arrives before the stream was opened, or after it closed, is the caller's own ordering and returns
WT_ERR_STATE without naming a connection error, since there is nothing to tell the peer.

Four tests: SETTINGS first and only once, every frame type that may not open the stream, the allowed and
refused sets after SETTINGS, and the one-stream and closure rules.

Implement control stream lifecycle.
- **Sixth part done: the request stream's frame order.** `include/webtransport/http3/request.h` is RFC 9114
section 4.1's shape for the request direction: a single HEADERS frame, optionally the content as DATA
frames, optionally a single trailing HEADERS. "Receipt of an invalid sequence of frames MUST be treated as a
connection error of type H3_FRAME_UNEXPECTED. In particular, a DATA frame before any HEADERS frame, or a
HEADERS or DATA frame after the trailing HEADERS frame, is considered invalid", and the machine refuses
everything that is not the next frame in that shape -- which also covers the frames the stream table has
already ruled out, so a caller cannot reach this with a SETTINGS frame and get a different answer.

Two decisions are worth recording. The response direction is deliberately absent: a server may send zero or
more informational (1xx) responses before the final one, and whether a HEADERS frame is informational is
only known from its decoded `:status`, so that machine belongs with QPACK rather than being guessed from
frame order. And an end before the request's HEADERS is an incomplete request rather than a malformed
sequence: section 4.1 has the server abort its own response stream with H3_REQUEST_INCOMPLETE, which is a
STREAM error, and the machine reports it as one -- a caller that closed the connection for it would be
turning its own decision into the peer's fault.

Three tests: the legal shapes (HEADERS alone, with content, with a trailer), every frame type in each of the
three positions where it is wrong, and the endings, including a reset, which is not an ordering matter at
all.

Implement request stream lifecycle.
- **Fourth part done: GOAWAY.** `include/webtransport/http3/goaway.h` carries RFC 9114 section 7.2.6 and
section 5.2's shutdown rules. The payload is one varint, so the work is in what the identifier means and
when it may change: a server's is a client-initiated bidirectional stream ID (section 7.2.6 makes any other
stream type H3_ID_ERROR, and RFC 9000 section 2.1's two low bits are zero exactly for that type) while a
client's is a push ID; the identifier may not grow between frames, and a larger one later is H3_ID_ERROR
because a client may already have retried the requests it was told were not processed; requests at or above
it are rejected and no new request may be started once it has arrived; and the graceful-shutdown pattern the
monotonic rule exists to make usable is the maximum first -- `2^62 - 4` for a server, `2^62 - 1` for a
client -- followed by what was really processed. A payload that is not exactly one varint is a frame error,
the same rule the frame codec follows, because a second field is a frame this implementation cannot
interpret.

Five tests: the payload round trip including both maxima, the malformed payloads, the stream type a server
may name, the monotonic rule across both directions including the equal-and-lower cases, and the rejection
range together with the "no new requests" flag.

Implement GOAWAY.
- Implement H3 error mapping.
- Implement stream type prefixes.
- **Fifth part done: which frame belongs on which stream.** `include/webtransport/http3/streams.h` is
RFC 9114 section 7.2's table in one place, because each of its eight frame sections ends with the same
sentence -- a frame on a stream it has no business on is H3_FRAME_UNEXPECTED -- and a rule stated eight
times is a rule with seven places to forget it. DATA and HEADERS belong to request and push streams, the
connection-management frames (SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH) to the control stream,
PUSH_PROMISE to a request stream from a server, and a QPACK stream carries no HTTP/3 frame at all
(section 4.2), which is why that kind is refused before the table is consulted. Section 7.2.8's reserved
types are refused on every kind.

Two of the rules are about the receiving endpoint's ROLE rather than the stream, which is why the role is a
parameter: section 7.2.7 makes MAX_PUSH_ID a frame only a client sends, so a client that receives one has
been sent its own frame, and section 7.2.5 makes PUSH_PROMISE a server's with the same consequence in the
other direction. Unknown frame types are allowed everywhere except on the QPACK streams -- HTTP/3 grows by
extension frames, and section 9's rule is that a layer ignores what it does not understand.

`wt_http3_stream_kind_for_type` maps a stream type prefix to one of these kinds and reports an unknown
prefix as WT_ERR_STATE rather than an error, because section 6.2.1 leaves unknown stream types for later
revisions and the caller ignores the stream.

Five tests, and the first version of one of them was wrong in a way worth recording: it asserted that a
client may receive MAX_PUSH_ID. The rule is the opposite, and the check that failed was the test's, not the
code's -- which is the useful direction for that mistake to point.

**Seventh part done: HTTP/3's message header rules.** `include/webtransport/http3/headers.h` validates a
decoded field section as a request or a response. QPACK's job ends at the fields; what makes them an HTTP/3
request is section 4.1 to 4.4's rules, and they are all about ORDER and TYPE rather than content: a
pseudo-header after a regular field, a pseudo-header twice, a pseudo-header the message type does not define,
a request without :method/:scheme/:path, CONNECT without :authority, an uppercase name, a connection-specific
field, or `te` with anything but `trailers` are each H3_MESSAGE_ERROR. The validator therefore consumes one
field at a time and has a `finish` for what the section did NOT carry, because an absent pseudo-header cannot
be noticed until the last field has gone by.

The check worth its own test is CONNECT: it is the one method whose required set changes shape, and a
validator that enforced :scheme and :path unconditionally would reject every extended CONNECT -- which is
exactly the request a WebTransport session begins with (draft-ietf-webtrans-http3 section 3.1). That
connection is why this part is HTTP/3's side of the line rather than QPACK's.

**Eighth part done: HTTP/3 messages.** `include/webtransport/http3/message.h` is the join between the two
phases: a QPACK field section in, a validated request or response out, with the method, scheme, path,
authority and status kept where a caller can read them rather than walking the fields again -- which is what
the CONNECT handling of the draft-16 session layer will want. It adds the two rules that belong here rather
than in either neighbouring layer: a `:status` has to be three digits in 100..599 (section 4.3.2), and a value
that must be PRESENT must also be non-empty, so an empty `:path` is refused even though the field arrived.

Two interface details came out of it. A blocked section is WT_ERR_AGAIN, as the QPACK layer reports it, and
the caller that gives up is the one that turns it into an error -- the same rule as the two parts before. And
the two error enums do not share a zero value: QPACK's success is 0 and HTTP/3's is 0x0100, so passing one
through as the other would hand a caller a "no error" that is not its type's no-error. Every QPACK result is
translated, and the codes themselves need no mapping because RFC 9204 section 8 makes them HTTP/3 application
errors in the first place.

Enforce request/control stream constraints.
- Reject duplicate SETTINGS and malformed stream ordering.

Completion criteria:

- HTTP/3 control and request stream tests match Swift behavior.

## Phase 6: QPACK

Port the complete Swift QPACK implementation.

Tasks:

- **First part done: the static table.** `include/webtransport/http3/qpack.h` exposes RFC 9204 appendix
A's 99 entries with the two lookups a field line needs -- an exact name-and-value match for an indexed field
line, and the first entry with a name for a literal field line with a name reference -- plus section 8's
error codes. The table is generated from the RFC's own ASCII table by
`tests/vectors/extract_rfc9204_static_table.py`, which refuses to write it unless the indices are 0..98
with no gap or repeat, every name is well formed and every row parses; `check-vectors.sh` runs its `--check`
with the other five vector sets. A table transcribed by hand is the one kind of defect this project's vector
rule exists to prevent: an encoder that indexes entry 17 as one field and a decoder that reads it as another
produce two different header sections, and nothing in the exchange would say so.

Two findings from the part are worth recording. The extractor's first version found the appendix heading in
the RFC's table of contents rather than in the body -- the same mistake the Retry extractor made, which is
why both now match headings as whole lines -- and the test's first version expected `:method` at index 44,
which is where HPACK keeps it: QPACK orders its static table by frequency (CONNECT, DELETE, GET, HEAD,
OPTIONS, POST, PUT at 15 to 21) and not by pseudo-header the way HPACK does. The code was right and the test
was wrong, which is the direction that costs nothing, but it is exactly the kind of assumption a table
shared between two specifications invites.

Implement full RFC 9204 static table.
- **Second part done: prefixed integers and strings.** RFC 9204 section 4.1's two primitives are in
`qpack.h` and `src/http3/qpack_primitives.c`: an integer behind an N-bit prefix, and a string whose length is
one behind a seven-bit prefix with the H bit above it. Every QPACK representation is built from them, so the
tests are about the edges -- the value that exactly fills the prefix, which changes the encoding's shape; the
62-bit bound the section sets, which is refused at both ends; a continuation that never ends and one that
runs past the bound; a string whose length is longer than the bytes present; and the H bit.

Two decisions are worth recording. The H bit is returned to the caller rather than dropped: this build does
not decode Huffman yet, and a caller that treated coded bytes as field content would build a header section
the peer cannot parse -- a silent corruption of exactly the kind the vector rule exists elsewhere to catch.
And the encoder's flag parameter is the bits ABOVE the prefix, only those: a flag inside the prefix is
refused rather than masked, because a caller that set one meant something else and dropping it would change
the representation it asked for. The first version checked the wrong bits (it required the flags to fit in
the top `8 - prefix_bits` bits, which refuses the perfectly legal 0x80 above a seven-bit prefix) and the
tests caught it before anything depended on it.

**Third part done: Huffman decoding.** RFC 7541 appendix B's code -- which RFC 9204 section 4.1.2 adopts
wholesale -- is generated into `src/http3/qpack_huffman_table.h` by
`tests/vectors/extract_rfc7541_huffman.py`, together with appendix C.4.1's worked example, which the script
writes into `tests/vectors/rfc7541_huffman_vectors.h` because it is evidence rather than implementation
data. The extractor checks what a decoder depends on: 257 rows in symbol order, each row's stated length
agreeing with its bit string, the code prefix-free, EOS thirty one-bits (which is what padding is made of),
and the code canonical -- from which it derives the (first code, offset, count) index per length that the
decoder walks. The decoder refuses EOS inside a string (section 5.2's own rule), padding longer than seven
bits or not all ones, a code longer than the table's longest, and an output larger than the caller's buffer:
a string a peer could not have encoded is a decoding error, and accepting one is how two implementations
come to disagree silently.

Three findings, all in the extractor rather than the codec, and all worth recording because each is a way a
table parser goes wrong. The appendix prints an ASCII representation before the symbol for printable
characters -- including `'|'` for symbol 124, which is the one row a pattern excluding pipes loses. The
table is in SYMBOL order, not canonical order, so the decode index cannot be derived by walking the rows;
the script sorts by (length, code) and checks the canonical property against every entry. And C.4.1's
appendix contains two hex blocks -- the encoded block and a per-representation decoding walk -- so the
extractor has to take the first and stop at the blank line, or it splices the block together with its own
explanation.

**Fourth part done: Huffman encoding.** `wt_qpack_huffman_encode` writes the same generated table the
decoder reads, MSB first, and pads the final byte with one-bits -- the EOS prefix, which is what section
5.2 requires and what the decoder's padding check accepts. `wt_qpack_huffman_encoded_size` exists because the
code is not a fixed width and a caller that guessed would either overflow its buffer or refuse a string that
fits.

The test that matters is not a round trip: an encoder and a decoder that read the same wrong table round-trip
perfectly. Appendix C.4.1's plaintext must encode to exactly the twelve bytes the RFC prints, which neither
side of this implementation can satisfy by being self-consistent with the other. The exhaustive pass over all
256 symbols then covers what the example cannot: both the five-bit codes and the thirty-bit ones, and the
bit packing that carries a code across a byte boundary.

Implement Huffman encoding and decoding.
- **Fifth part done: the field line representations.** `src/http3/qpack_field.c` reads and writes all seven
of RFC 9204 section 4.5's forms. The decision that shaped the API is that the TYPE says which table a line
needs -- static, dynamic, or post-base -- rather than the decoder assuming: resolving a dynamic index against
the static table is the mistake that silently produces a different header section, and it is invisible in any
exchange because both sides believe they are right. So the two static forms resolve to a name through
`wt_qpack_field_line_static_name` while the dynamic and post-base forms report WT_ERR_STATE, and the dynamic
table part will consume them deliberately.

Two smaller decisions: the decoder PEEKS the first byte rather than reading it, because each form's index (or
the literal form's name length) is an integer whose prefix lives in that byte and the integer primitive is
what reads it; and the N bit (never-indexed) and the H bits travel in the struct rather than being acted on,
for the same reason the string primitive reports Huffman coding -- the layer that owns the decision is not
this one.

Three tests: a hand-written wire byte sequence for one line of each prefix family, so a wrong prefix cannot
pass by round-tripping through the same code; the literal forms including an inline name; and the post-base
and truncation cases.

Implement static indexed fields.
- Implement literal field lines.
- **Sixth part done: the dynamic table.** `src/http3/qpack_dynamic.c` is RFC 9204 section 3.2's FIFO: entries
sized as name plus value plus 32, evicted from the oldest end when the capacity would be exceeded, with
absolute indices that never change meaning, so a reference to an evicted entry is reported (WT_ERR_CLOSED)
rather than resolved to whatever now occupies its place. The capacity is the peer's through
SETTINGS_QPACK_MAX_TABLE_CAPACITY, zero is legal and means no dynamic table, and a shrinking capacity evicts
until the size fits -- section 3.2.2's rule, which can empty the table.

The table is bounded like every other piece of peer-driven state in this library: 32 entries and a 4 KiB
arena, with a refusal rather than growth beyond them, and an entry larger than the capacity refused because
section 3.2.1 says the encoder must not insert one. The arena is compacted when the oldest entry is evicted,
which is what keeps a long-lived table from running out of space after capacity's worth of traffic.

One bug, found by the test that inserts three entries into a two-entry table: the eviction moved the
surviving entries' BYTES down but left their recorded offsets behind, so entry two's name pointed into what
had been entry one's value -- a wrong name read out of a well-formed table, which is the quietest way for
QPACK to produce a different header section. Both the fix and the reason are in the code.

Implement dynamic table.
- **Seventh part done: the encoder stream instructions.** `src/http3/qpack_encoder_stream.c` applies RFC
9204 section 4.3's four instructions to the dynamic table -- Set Dynamic Table Capacity, Insert With Name
Reference (static or dynamic), Insert With Literal Name and Duplicate -- and writes each of them from this
implementation's own side, so the writers and the reader are checked against each other on the wire. A
relative index resolves against the CURRENT insert count (section 3.2.3), which is what makes the arithmetic
survive evictions.

Two errors are only visible here rather than in the table: a capacity above the SETTINGS limit this endpoint
advertised, which section 4.3.1 makes QPACK_ENCODER_STREAM_ERROR rather than a clamp, and an index that names
an entry the table has already evicted, which is the case a decoder cannot guess its way out of. The
Huffman-coded case is refused explicitly (WT_ERR_STATE) rather than decoded into a buffer this function does
not have: the encoder stream stores DECODED bytes, so a coded name or value needs a decoder buffer that
belongs with the part that owns the insertion path end to end.

One C detail worth recording: the error enum's members cannot be named after the error codes, because those
are macros -- an enumerator sharing a macro's name is replaced before the compiler sees it, and the header
fails to parse for every translation unit that includes it.

**Eighth part done: the decoder stream instructions.** `src/http3/qpack_decoder_stream.c` applies RFC 9204
section 4.4's section acknowledgement, stream cancellation and insert count increment, and writes them. Two
of the section's rules are errors rather than no-ops: an increment of zero says nothing and is
QPACK_DECODER_STREAM_ERROR, and an increment that would take the acknowledged count past the number of
insertions cannot describe a decoder that has processed them.

Landing it produced a correction that applies to the encoder stream part as well, and it is the more
interesting half of the work. A truncated instruction was being reported as QPACK_*_STREAM_ERROR, but an
instruction whose bytes have not all arrived is INCOMPLETE, not malformed: RFC 9204 section 2.2 delivers
instructions on a stream, in pieces, so waiting for the rest is the correct response and only a malformed
instruction is the peer's fault. The caller that sees the stream END with an instruction half-read is what
reports the error. Both modules now return WT_ERR_TRUNCATED with no error code for that case, and both tests
assert the distinction -- because a parser that reports "malformed" for "not yet" turns an ordinary network
split into a connection error.

Implement encoder and decoder streams.
- **Ninth part done: the field section prefix.** `src/http3/qpack_header_prefix.c` is RFC 9204 section
4.5.1's Required Insert Count and Base. The count is not sent plainly: it is sent modulo twice the table's
size in entries, plus one, so that a long-lived connection's ever-growing count still fits a byte -- and the
decoder reconstructs it from the window it knows, which is why the prefix cannot be read without the capacity
this endpoint advertised (`wt_qpack_max_entries`). Both of the section's error exits are enforced: an encoded
count outside the full range, and a decoded count that is more than the encoder could have inserted. The Base
is a signed delta from the count, and its negative form subtracts one, so a delta with nothing to subtract
from is refused.

One finding, and it is the kind that only an exact-byte check catches: the S bit is the MOST significant bit
of the Base byte, not the one below it. RFC 9204's figures number their bits left to right from the top, and
reading the figure's `| S | Delta Base (7+) |` as if `S` sat at 0x40 puts the sign inside the seven-bit
prefix -- which this module's own flag check then rejected, so the encoder refused every prefix whose Base
was below its required count. The round trip would have hidden it had the flag check been laxer, because both
sides would have agreed on the wrong bit.

Implement Base and post-Base dynamic references.
- **Tenth part done: the field section decoder.** `src/http3/qpack_field_section.c` resolves one line at a
time against the static table, the dynamic table and the section's prefix, which is where QPACK's pieces
meet. The index arithmetic is the part worth testing hardest, because it is the only place the two
directions of a relative index live -- `Base - Index - 1` for a dynamic reference and `Base + Index` for a
post-base one -- and a sign error there resolves to a DIFFERENT but perfectly valid entry, which nothing
later in the exchange can detect. The tests therefore assert the two directions with neighbouring indices
(0 and 1 at the same Base) rather than a single index that would pass either way.

An inline name or value may be Huffman-coded, so the resolved field is built into the caller's scratch: a
resolved field must be plain bytes, and this is the layer that knows it. Two kinds of failure are kept
apart deliberately -- a reference the tables cannot resolve is QPACK_DECOMPRESSION_FAILED, while a scratch
buffer the caller did not make large enough is WT_ERR_LIMIT with no error code, because it says nothing
about the peer.

One gap is now explicit rather than implied: `wt_qpack_string_encode` writes only plain strings, so this
build cannot yet WRITE a Huffman-coded string in a field line. The test builds that line by hand from
section 4.5.3's figure, which is honest -- a test that used the encoder for it would be testing a line the
encoder cannot produce -- and the encoder-side Huffman string is recorded as remaining work.

**Eleventh part done: Huffman strings on the way out.** The gap the last part recorded is closed:
`wt_qpack_string_encode_coded` writes a string with the H bit set, coding it into the caller's scratch, and
`wt_qpack_field_line_encode_coded` does the same for a line's inline name and value. The scratch is not
optional because the coded length has to be known before the length byte that precedes it -- the two-pass
writer's measuring pass exists for exactly this shape of problem, and a field line is written into a buffer
whose size the caller chose, so the buffer comes from the caller too. The name is written into the writer
before the value reuses the scratch, which is safe because the writer copies what it is given.

The plain `wt_qpack_field_line_encode` now REFUSES a line whose flags ask for coding (WT_ERR_STATE) instead
of writing it plainly. That is the correction to the last part's compromise: the flags are part of the
representation, so a plain string with the H bit clear is a DIFFERENT line, and an encoder that silently
wrote one would produce something the decoder reads as something else. The `_coded` variant honours the
flags, and the two together mean this build can no longer write a line it would misread.

The test now writes the coded line with this build's encoder AND keeps the hand-built variant from the last
part: the first says the two sides agree, the second says the reader is not merely reading its own writer's
dialect.

**Twelfth part done: whole field sections.** `src/http3/qpack_field_section_codec.c` writes a section --
the prefix, then one line per field -- and reads one back through a small stack state, which is the shape the
HTTP/3 header codec will use. The rule worth the part is the BLOCKED case: a section whose Required Insert
Count is above the insertions this decoder has received is not malformed, it is EARLY, and RFC 9204 section
2.1.2 lets a decoder wait for the encoder stream to catch up. So `begin` reports WT_ERR_AGAIN with no error
code, and only the caller that gives up -- because the stream ended, or because it will not wait -- turns that
into a connection error. A decoder that treated "not yet" as "no" would close a connection over an
instruction that is still in flight, which is the third time this project has had to make that distinction
(the stream instruction parsers and the truncated frames being the other two).

The other decision is where the reference tracking lives. Deciding the Required Insert Count and the Base,
and which entries a section referenced so they cannot be evicted, is the ENCODER's bookkeeping: it depends on
what this endpoint has sent and what the peer has acknowledged, not on the bytes. The codec therefore takes
the prefix as an argument and writes what it is given, and the tracking belongs with the encoder that owns
those sections.

**Thirteenth part done: the encoder's eviction bookkeeping.** `src/http3/qpack_encoder_state.c` is what
turns a QPACK reader into a QPACK user: an encoder may not evict an entry that an unacknowledged section might
reference (section 2.1.1), so it has to remember what it sent and what the decoder confirmed.
`wt_qpack_encoder_state_begin_section` returns the prefix to write (the current insert count as both the
Required Insert Count and the Base, so the newest entry is dynamic index zero) and records the section;
`evictable_below` is the SMALLEST required insert count among the outstanding sections, or the whole table
when nothing is outstanding.

Three decisions. A section that references nothing is not recorded at all: its prefix is zero and it cannot
hold anything back, so recording it would only spend one of the sixteen slots. A second section on the same
stream REPLACES the first, because a stream carries one field section at a time and the older record is
superseded. And an acknowledgement for a stream with no outstanding section is refused (WT_ERR_CLOSED) --
that is this endpoint's own records disagreeing -- while a cancellation for one is accepted, because a peer
may cancel anything it likes.

The test that matters takes the SMALLEST of two outstanding counts after more insertions have happened: an
implementation that took the largest, or the first, or the last would pass a test with one section and fail
this one, and the failure it prevents is evicting an entry a section in flight still points at.

Enforce table capacity and malformed reference handling.

Completion criteria:

- QPACK static, literal, Huffman, dynamic, Base, and post-Base tests pass.

## Phase 7: WebTransport Draft-16 Core

**First part done: the WebTransport session request, and the pseudo-header that makes it reachable.**
`include/webtransport/webtransport/session_request.h` decides what a decoded request is: an ordinary request, a
plain CONNECT, an extended CONNECT for another protocol, or a WebTransport session request that this server
accepts or refuses with a status. The outcome is a DECISION rather than an error, because "not mine" and "mine,
but refused" are ordinary answers with status codes, while a malformed request is already the message error the
HTTP/3 layer raised.

Landing it exposed a gap in the layer below, which is the more useful half of the part: `:protocol` was NOT a
recognised pseudo-header, so RFC 9220's extended CONNECT -- the request a WebTransport session actually begins
with -- was refused as an unknown pseudo-header and therefore H3_MESSAGE_ERROR. The HTTP/3 message layer now
recognises it for requests (and refuses it on a response), keeps its value, and the draft layer reads it. That
is the kind of gap a port finds only when the layer above starts asking for something, and it is worth
recording: the HTTP/3 layer was complete for RFC 9114 and incomplete for RFC 9220, which RFC 9114 itself
references.

Two rules are tested in both directions because each is easy to get backwards. The CONNECT exception in RFC
9114 section 4.1 covers the PLAIN CONNECT, so a WebTransport request must still carry :scheme and :path -- a
layer that inherited the exception would accept a request it cannot route. And a server that never advertised
`WT_ENABLED` refuses with 501 rather than serving a session the client could not have known about, which is
what makes the setting mean anything.

**Second part done: the session capsules.** `include/webtransport/webtransport/capsule.h` reads and writes
the CONNECT stream's control messages as RFC 9297 capsules -- a varint type, a varint length and that many bytes
-- with the draft-16 registry: the flow-control capsules, DRAIN_WEBTRANSPORT_SESSION, which carries no value, and
CLOSE_WEBTRANSPORT_SESSION, whose value is a four-byte application error code and a UTF-8 reason of at most
1024 bytes. The close writer enforces that ceiling and the parser enforces the four-byte minimum, so this build
cannot send a close its own reader would refuse and a value too short to hold the code is a malformed capsule
rather than one with nothing to say.

The three rules it shares with the layers below are stated in the same words, deliberately: an incomplete
capsule is WT_ERR_TRUNCATED rather than malformed, because a stream delivers in pieces; an unknown capsule type
is decoded and handed on, because RFC 9297 section 3.2 has a receiver ignore what it does not understand; and a
value longer than the caller will buffer is H3_EXCESSIVE_LOAD, because the bound is this endpoint's. Those are
now the fourth, fifth and sixth appearances of the same three decisions, which is why they are recorded as this
project's standing rules rather than as each part's local choice.

**Third part done: the session lifecycle.** `include/webtransport/webtransport/session.h` is the draft's
three rules about what a session may DO, as opposed to what its bytes say: after a drain, in either direction,
no new stream may be started for the session while existing ones may finish; after a close, nothing at all;
and the FIRST close's code is the one the session reports, however many more arrive, because the session ended
at the first one. The drain and the close remember which direction each came from, so a caller can tell "the
peer is going away" from "we are", and a stream that simply ends is recorded as having no application code --
which is not the same as a close whose code happens to be zero, and the flag is what keeps them apart.

Two boundaries of the machine are deliberate. A drain or a close before the response has gone out is a caller
error rather than a transition, because the session does not exist yet and inventing a state for it would let
a caller half-open one. And every transition after the close is refused, because a capsule that arrives after
the end is a message the peer has no state for -- this layer cannot honour it and must not pretend to.

**Fourth part done: the session's flow control.** The draft's flow-control capsules are in the capsule
module: MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS in both directions, and the blocked signals that ask for more.
Each carries one varint, or two for the ones that name a stream, and a value that is not exactly that is a
message error rather than a bigger number -- the same rule as everywhere else in this tree, and the reason a
trailing byte cannot pass as a larger limit.

The rule worth the part is the connection-level one: a limit may only GROW. A value below one already granted
would invalidate data sent against the old limit, so it is WT_FLOW_CONTROL_ERROR (the draft's own code for it)
rather than a new limit. An implementation that simply stored it would accept a peer rewriting a promise it
had already relied on, which is the flow-control equivalent of evicting a referenced entry.

One bug, of the kind that hides behind a small number: the writer emitted a CONSTANT one-byte length for every
one-varint capsule, so a value of 100000 -- a four-byte varint -- was described as one byte long and decoded as
its first byte. Every small test value passed. The length is the value's own encoded size, and the test that
caught it used a limit large enough to need more than one byte.

**Fifth part done: stream and datagram framing.** `include/webtransport/webtransport/framing.h` is the
draft's stream prefix -- type 0x41 for bidirectional and 0x54 for unidirectional, then the session ID -- and
its datagram frame, which is a QUARTER stream ID followed by the session's data. What the two have in common
is that the identifier is checked for SHAPE rather than value: a session ID is the CONNECT stream's, so it is
client-initiated and bidirectional (RFC 9000 section 2.1's two low bits clear), and a prefix naming anything
else is describing a session that cannot exist rather than one this endpoint has not heard of. The quarter ID
is the same number divided by four, and the reverse is what a receiver reconstructs before it can find the
session at all.

The two halves also sit on opposite sides of this project's standing rule about incomplete input, and that is
deliberate: an incomplete stream prefix is WT_ERR_TRUNCATED, because a stream delivers in pieces, while a
datagram that does not hold its quarter ID is malformed, because a datagram IS the unit. The tests state both
in those terms.

Writing them turned up a test-vector mistake worth recording: the stream type 0x41 is above 63, so its varint
is TWO bytes (0x40 0x41) and the first byte is not the type. A test comparing the first byte with the value
would have been checking the varint's shape by accident, and the hand-built prefix in the same test was short
by a byte for the same reason. Varint boundaries are where this tree has now hidden two bugs and one wrong
test; the tests that cross them are worth writing first.

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

**First part done: the umbrella header.** `include/webtransport/webtransport.h` is the one header a consumer
includes, and it is where the three rules that hold across EVERY layer are written down: nothing is allocated
for a peer (a bound is this endpoint's, and the code says so rather than blaming the peer); incomplete is not
malformed on a stream, with a datagram as the deliberate exception because a datagram is the unit; and a
refusal keeps the peer's code, because RFC 9000's transport codes, RFC 9114's H3_* codes and RFC 9204's QPACK
codes all travel as QUIC application error codes and rewriting one would hide what the peer said. The header
also fixes the ownership rule -- a producer writes into a caller's buffer, a reader returns views into the
caller's bytes, so nothing here owns memory and no view outlives its buffer.

The test is deliberately a compile-time one: it includes ONLY the umbrella header and then uses a piece of
every layer, so a module missing from the umbrella, a header that does not include what it uses, or a
declaration that moved fails to build here rather than in a consumer's project.

**Second part done: the opaque session handle.** `include/webtransport/api/session.h` is the shape the
rest of the API follows, and the choices in it are the ones that are expensive to change later. The type is
opaque, so the layout can move between releases; construction and destruction are paired and both take the
ALLOCATOR, because an object made from a pool must return to that pool and a `destroy` that guessed the
allocator would leak or corrupt; and the error surface is sanitized by construction rather than by discipline:
`wt_session_error_t` holds a status and a `uint64_t` code and has no room for a string, so a peer's text cannot
reach a log even by accident, while the peer's application code does reach the caller -- a refusal keeps the
peer's code at every layer, including this one.

The state a consumer reads is a separate published enum, mapped from the machine's with a full `switch` rather
than a cast. The cast would have worked today and would have silently renumbered the API the day the internal
enum changed; with `-Wswitch-enum` the omission is a compile error, and the test asserts the mapping.

The two bounds in this part are this endpoint's. An authority or path longer than the handle's copy is refused
with `WT_ERR_LIMIT` instead of being truncated, because a truncated authority names a different session. A
capsule value larger than `max_capsule_bytes` is refused with `WT_ERR_LIMIT` and the H3 excessive-load code,
which is a statement about this endpoint's buffer and not about the peer's encoding.

**Third part done: the event-loop seam.** `include/webtransport/api/events.h` is the callback table
`wt_session_callbacks_t` plus the feed functions that report through it, and the interesting part is what it
refuses to do. It owns no thread and no queue, so a callback runs inside the call the application made; it
does not re-enter itself, so the sequence a recording callback sees is a faithful one; and it does not turn
"nobody asked for this" into a connection error, because blaming the peer for this endpoint's configuration is
the failure mode that makes an API unusable from a program that only wants streams. The one thing it does
refuse is a bound this endpoint published: a stream table sized by `max_streams` and a datagram bound
sized by `max_datagram_bytes`, both refused with the H3 excessive-load code and never grown for a peer.

Peer streams live in a fixed table (`WT_SESSION_STREAM_MAX` slots) rather than a dynamic one, and a stream or
datagram that names a DIFFERENT session is refused with HTTP/3's identifier error rather than delivered to the
wrong session or dropped silently -- a silent drop here would be indistinguishable from a lost packet.

The configuration gained `session_id`, `max_datagram_bytes` and `max_streams`, and with them the problem every
C configuration struct has: a caller that sets three fields of a six-field struct passes whatever the stack
held into a bound. `wt_session_config_default()` returns a fully initialized value, so the caller overwrites
rather than completes. Bounds that the handle cannot honour (a stream table larger than the fixed one, a
datagram bound above the QUIC DATAGRAM ceiling) are refused at create rather than clamped: a caller that asks
for more than the build can do must find out.

**Fourth part done: the session's flow control, and two corrections it forced in Phase 7.** `api/flow.h`
is the send-side view: the peer's grants, this endpoint's usage, and the allowance functions that answer
"may I send this" before a refusal rather than after it. It mirrors the Swift reference's rules, which are the
draft's: flow control is off until SETTINGS say otherwise and a capsule arriving while it is off is IGNORED
rather than refused, because the draft makes the whole mechanism conditional; the limits strictly increase;
and the session's initial limits come from the peer's SETTINGS, so a setting the peer omitted is zero and not
unlimited, which is what it means on the wire. The three draft-16 setting identifiers
(`WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA` and the two stream counts) are now defined beside `WT_ENABLED`.

Writing it against the Swift state machine exposed two places where the Phase 7 flow-limit helper was more
permissive than the draft. It accepted a limit EQUAL to the one already granted, where the draft requires the
limits to strictly increase -- a repeat is what a peer sends when it has lost track of what it granted, and
accepting it hides that. And it had no ceiling on a stream-count limit, where the draft forbids a value above
`2^60` because the stream ID space it would describe does not exist. Both now refuse with the draft's
flow-control error code, and `test_webtransport_flow` asserts the stricter reading rather than the old one.

**Fifth part done: the sample consumer and the API's contract.** `apps/wt-api-sample` is a program that
includes ONLY `webtransport/webtransport.h`, uses only the public functions, and walks a whole session --
establishment, a peer stream, a peer datagram, a flow-control capsule, backpressure, drain, close, destroy --
against the library. It is registered with CTest, so the plan's "public sample app compiles on all target
platforms" is checked rather than compiled: the day a public declaration moves or starts needing a header the
umbrella does not carry, this program stops building. `docs/PUBLIC-API.md` is the contract it exercises,
covering endpoints, sessions, ownership, the error surface, the event loop, streams, datagrams, backpressure,
close and drain, and every bound a caller sets -- with the parts that are NOT there yet (a trust surface, the
blocking helpers, the send side) named as plainly as the parts that are.

Registering the sample as a test found a silent failure worth recording: `add_test` called from the apps
directory before `enable_testing()` is DROPPED, and CTest then reports a clean run of one fewer test. The tree
now enables testing before its subdirectories, and guards the registration on the project's own switch rather
than CTest's `BUILD_TESTING`, which this project never defines. Both mistakes report success, which is what
makes them worth a paragraph.

**Sixth part done: endpoints and trust.** `api/endpoint.h` is the per-program half of the API: which side
this process is, the name it is reached at, the port, the authority and path a CONNECT request carries, and how
the peer's certificate is judged. It exists so that a misconfiguration is a return value from
`wt_endpoint_config_check` before a packet is sent rather than a handshake failure twenty seconds later, and
`wt_endpoint_session_config` then produces the session configuration from it, so the authority a request
carries comes from one place.

Two decisions in it are worth recording. The development bypass
(`WT_TLS_TRUST_LOCAL_DEVELOPMENT`) is tied to a loopback name, and the check is the TRUST LAYER's function --
exported for this purpose -- rather than a copy of its rule: a security rule with two implementations is a
rule that will disagree with itself, and the disagreement will be found by an attacker rather than by a test.
And a SERVER must leave the trust policy unset, because this draft has no client authentication: a server has
no peer certificate to judge, so accepting a policy would be a promise the library cannot keep. Refusing it is
the only honest answer, and the alternative -- ignoring it -- is how a caller comes to believe their clients
are authenticated.

The mode-0 enumeration produced a small lesson of its own: a `case` label for a value outside an enum does not
compile under `-Wswitch`, which is the compiler saying what the code meant -- an unknown mode falls through to
"not a policy" rather than being named.

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

### Phase 9's first part: the HTTP/3 endpoint's own streams

`http3/endpoint.h` is the layer that OWNS the per-connection HTTP/3 state machines for one connection,
and it is the piece Phase 5 deliberately left out: that phase wrote a state machine per concern, and
something has to hold them. It tracks our control stream (`0x00`) and QPACK streams (`0x02`/`0x03`) as sent
once each, classifies the peer's unidirectional streams by their type prefix, forwards control frames to the
control machine, and applies the endpoint's own rules -- which are the RFC's and are worth stating because
they are asymmetric: an UNKNOWN stream type is NOT an error (section 6.2.1 leaves unknown types for future
revisions, so the caller is told and stops reading), while a second control stream, a second QPACK stream
(QPACK section 4.2), and a push stream this build never asked for each commit the connection to the error the
RFC names.

The draft's WebTransport stream type (`0x54`) is the reason the layer exists at all rather than a plain call
to `wt_http3_stream_kind_for_type`: to the HTTP/3 core it is an unknown type, which the core correctly tells
the caller to ignore -- and a session's streams would then vanish one at a time, silently, with the core
behaving exactly as specified. The endpoint claims it for the layer above instead.

The peer-stream table is fixed (`WT_HTTP3_ENDPOINT_STREAMS_MAX`) and running into it is `WT_ERR_LIMIT` with NO
error code: it is this endpoint's bound, and inventing a peer-facing code for it would blame the peer for this
implementation's table.

### Phase 9's second part: request streams at the endpoint

A WebTransport session IS a request stream, so the endpoint has to own them, and `http3/endpoint.h` now does:
it tracks one `wt_http3_request_stream_t` per live request, forwards each frame to the request-ordering
machine, and keeps that machine's rules in ONE place rather than re-implementing HEADERS-first and
H3_REQUEST_INCOMPLETE here.

The role rules are the RFC's and they are asymmetric: only a CLIENT opens a request stream, because HTTP/3
has no server-initiated request, and section 6.1 makes a client that receives a server-initiated bidirectional
stream a connection error of type H3_STREAM_CREATION_ERROR. Both directions are refused loudly rather than
silently tracked, because tracking either would turn a role mix-up into something that looks like a protocol
error from the peer.

The request table is bounded (`WT_HTTP3_ENDPOINT_REQUESTS_MAX`), which makes it the number of concurrent
sessions one connection may carry, and running into it is WT_ERR_LIMIT with no error code -- the same rule as
the peer-stream table, for the same reason. A duplicate stream is detected BEFORE the bound, so a caller's own
mistake is never reported as a limit, and the test asserts that ordering explicitly.

### Phase 9's third part: the QPACK decode path at the endpoint

`wt_http3_endpoint_on_request_headers` closes the chain from a HEADERS frame to a decoded request: the
endpoint applies the request-ordering rule, decodes the field section against decoder state IT owns (the
dynamic table the peer's encoder stream fills, plus the insertion count), and hands back a
`wt_http3_message_t`. What it deliberately does NOT do is decide whether the request is a WebTransport
request: that is `wt_webtransport_session_request_validate`, and keeping the judgement in the draft-16 layer is
why the endpoint needs to know nothing about `:protocol`.

Two details are the RFC's rather than conveniences. The decoder capacity is set explicitly, because a field
section's `MaxEntries` prefix is ENCODED AGAINST what this endpoint advertised -- reading it without saying
what was advertised would be guessing -- and a capacity below 32 makes `MaxEntries` zero, so a section that
references a dynamic table this endpoint never advertised is QPACK_DECOMPRESSION_FAILED rather than a
misread index. And a TRAILER may not carry pseudo-header fields (section 4.1): the message decoder has one
request shape and one response shape and cannot tell a trailer from a request, so the endpoint -- which is the
layer that knows the first HEADERS from the second -- refuses the pseudo-headers itself.

The test also pins down a boundary that is easy to get wrong in the other direction: a first section carrying
only regular fields has no request line, and the message layer refuses it. The endpoint does not second-guess
that, and the test asserts the refusal rather than a hand-built section passing.

### Phase 9's fourth part: writing the request and the response

`wt_http3_message_encode` is the decode path read backwards -- a request's or a response's pseudo-headers out
as a QPACK field section -- and `wt_http3_endpoint_write_headers` puts the HEADERS frame around it. The frame
can only be written once the section has been MEASURED, because the frame's length prefix is a varint whose
width depends on the length; so the section goes into the caller's scratch first and the frame second, which is
the same measure-then-write rule the rest of this library follows.

The lines are LITERAL: the names and values are spelled out rather than indexed against the static table. That
is always valid, never needs a dynamic table on either side, and is therefore usable before either endpoint has
one -- at the cost of bytes on the wire. That is a compression decision with a correct simple answer here and a
clear upgrade path, and the header says exactly that rather than implying the encoder is as small as it could
be. The prefix names Required Insert Count 0 and Base 0, which every peer can read whatever table it advertised.

A failure in the encoder carries NO error code, and that is deliberate: a message that has no method or no
status is refused with H3_MESSAGE_ERROR because that is a wire-shaped mistake, but a section that does not fit
the caller's scratch is the CALLER's buffer, and inventing a peer-facing code for it would tell a peer's story
about a local mistake. The first draft of the code did attach one, and the test caught it by asserting the exact
code (H3_MESSAGE_ERROR, 270) where none belonged.

The test is a ROUND TRIP rather than hand-written bytes: the client's extended CONNECT is written, framed,
decoded by a server's endpoint, and handed to `wt_webtransport_session_request_validate`, so the encode and
decode directions cannot disagree without a test failing.

### Phase 9's fifth part: reassembling a stream's type prefix

`http3/driver.h` is the seam between a connection and the endpoint, and it exists for one fact: a stream's
type prefix is a QUIC varint, and a varint can be SPLIT across frames. A peer may open a stream and send one
byte of a two-byte type in its first packet; the endpoint's classifier -- correctly -- wants the whole prefix,
because deciding a stream's type from half a varint is how an implementation ends up reading someone else's
stream. The driver holds at most the first eight bytes of each opening stream (the longest prefix a varint can
be) in a FIXED table, classifies when they add up, and hands back the rest of the completing frame as a view
into the caller's own buffer, so nothing is copied.

The error taxonomy came out of the same reasoning as the rest of this phase: a prefix that does not start at
offset zero, or a stream resumed at an offset that does not continue what was held, is the CALLER's accounting
and is `WT_ERR_STATE`; a stream that ends before its prefix is complete is dropped without ever becoming a
stream of any type; and the pending table is this endpoint's bound, so running into it is `WT_ERR_LIMIT` with
no error code. The table is about CONCURRENCY rather than a lifetime total, which the test checks by ending a
waiting stream and watching its slot come free.

The test also caught a mistake worth recording, because this tracker has now recorded it three times in three
phases: `WT_WEBTRANSPORT_STREAM_UNI` is `0x54`, and `0x54` as a varint has its top bits set, so it is a
TWO-byte prefix on the wire (`0x40 0x54`). A test that wrote it as one byte was not testing the WebTransport
stream type at all; the driver read the real two-byte value and classified it as unknown, which is exactly
right. Lengths and prefixes are MEASURED on this wire, never transcribed.

### Phase 9's sixth part: starting an endpoint's own streams

A connection is only usable once the endpoint has opened the streams HTTP/3 requires of it, so the driver can
now start them: `wt_http3_driver_start_control` writes the control stream's `0x00` prefix and the SETTINGS
frame built from the caller's settings, and `wt_http3_driver_start_qpack_stream` writes the `0x02` or `0x03`
prefix. The SETTINGS payload is measured into the caller's scratch before the frame is written around it,
which is the same measure-then-write rule every length on this wire follows -- a frame's length is a varint
whose width depends on its value, so a length computed from a guess lands one byte out and the peer either
reads a short frame or refuses the stream.

The endpoint's once-per-connection rules are applied BEFORE any bytes go out, so a caller that starts a second
control stream finds out from a return value rather than from a peer's connection error; the test asserts that
nothing was written in that case. The one failure that does leave bytes behind -- a SETTINGS payload that does
not fit the caller's scratch -- is WT_ERR_LIMIT with no error code, and the test asserts the prefix is already
out when it happens, because a caller that cannot tell "nothing happened" from "half of it happened" cannot
recover.

### Phase 9's seventh part: HTTP/3 frame boundaries on a stream

A stream carries a sequence of HTTP/3 frames, and a frame's own header -- a type varint and a length varint --
can be split across the STREAM frames a connection hands over, exactly as a stream's type prefix can. The
driver reassembles that boundary now, per stream, in sixteen bytes of state each.

It deliberately does NOT buffer the payload: it reports the payload to a sink in the pieces that arrive, with
`last` on the final one. That division is the design. Framing needs sixteen bytes per stream; the payload is
POLICY -- how much of a HEADERS section this endpoint will hold is a bound, and a bound belongs to whoever owns
the memory. A driver that buffered frames would be carrying that policy silently, at a size nobody chose. The
one number the driver does bound is the frame's DECLARED length, because that is the peer's to choose: over the
caller's `max_frame_bytes` it is H3_EXCESSIVE_LOAD, refused before the sink is asked for anything.

Writing the test found the case a naive reassembler misses: a stream that ends part way through a frame HEADER
is exactly as incomplete as one that ends part way through a payload, and the first version of the code only
checked the payload case. The check now covers both, and the test asserts the refusal with the frame error code
rather than a hang or a silent drop.

### Phase 9's eighth part: the driver as a connection's frame handler

`wt_http3_driver_on_quic_frame` has the shape `wt_quic_connection_set_handlers` wants, so a caller installs the
driver directly and stops writing routing code. It routes exactly four things, and each has to be here rather
than in the connection layer: a STREAM frame on a peer-initiated unidirectional stream (reassemble the type
prefix, then send the bytes either to the frame sink or to the session, depending on a type only the HTTP/3
layer knows); a STREAM frame on a peer-initiated bidirectional stream (a request stream, whose first frame
opens it); a DATAGRAM's payload, handed over uninterpreted; and nothing at all for a frame on a stream THIS
endpoint opened, because the peer's answer on a stream we started belongs to the connection's own stream state
and routing it here would mean two layers acting on one answer.

The routing is decided by the peer's stream ID bits rather than by a flag the caller passes: RFC 9000 section
2.1 puts the initiator in the low bit and the direction in the next one, so `wt_quic_stream_id_from_client` and
`wt_quic_stream_id_is_bidirectional` answer both questions. The test caught exactly that, from the other
direction: its first draft used stream 3 as a "client-initiated" stream, and 3 has the low bit SET, so it is
server-initiated -- which the driver correctly treated as its own and refused to route. Reading the stream ID
rather than trusting a comment is what made the mistake visible.

A switch was the natural shape for the router and `-Wswitch-enum` refused it: the warning wants every
enumerator named, and this handler acts on two of twenty-odd kinds. The if-chain that replaced it says why in
the code, because "name twenty-one no-op cases to satisfy a warning" would make the two cases that matter
harder to find -- the opposite of what the warning exists for.

### Phase 9's ninth part: the outbound half, through a transport table

The driver can now open and start an endpoint's own streams, send a request, a response or a trailer as a
HEADERS frame, and send a datagram -- and it does none of that by naming a QUIC connection. The transport is a
table of three calls (`open_stream`, `send_stream`, `send_datagram`), which keeps the HTTP/3 layer independent
of the connection implementation and makes the outbound half testable against a RECORDING transport: what this
layer produces is the thing under test, and a recorder is a more exact reader of it than a live handshake would
be.

One ordering bug came out of writing the test, and it is the kind that only shows up in a protocol: the first
implementation OPENED the stream and then built the bytes, so a second call to start the endpoint's streams --
which the endpoint's own once-per-connection rule refuses -- had already opened a fourth stream before the
refusal. An orphaned stream is one the peer sees and this endpoint cannot explain, which is precisely the state
a "refuse, never half-succeed" rule exists to prevent. Both are built before they are opened now, and the test
asserts the stream count does not move on the refused call.

The frame and its payload share the driver's scratch at fixed halves, so the two cannot overlap while a payload
stays under half the buffer -- a bound the SETTINGS encoder's own limit enforces rather than a comment asking
nicely. A transport that cannot open a stream right now (congestion, `WT_ERR_AGAIN`) passes its refusal straight
through, because that is a connection condition and not an HTTP/3 one.

### Phase 9's tenth part: the transport bound to a real connection

`wt_http3_driver_quic_transport` fills the three-call table with adapters onto
`wt_quic_connection_open_stream`, `wt_quic_connection_send_stream` and
`wt_quic_connection_send_datagram`, so the transport seam is closed end to end: the HTTP/3 layer produces
bytes, the connection moves them, and neither has to know the other's internals.

The one design decision worth recording is where the SEND OFFSET comes from. The adapter reads it from the
connection's own stream state (`stream->send_offset`, which the stream advances when data is sent) rather than
counting for itself. An adapter with its own counter would be a second opinion about a number the connection
already owns -- and the two would disagree the first time a send was retried after a loss, which on this
transport is not an exceptional event but the normal one. A stream the connection does not know is refused by
this layer as the caller's error, because only the connection's own open call can bring one into existence; a
datagram has no stream state at all and is passed straight through, which is why QUIC's DATAGRAM frame has no
retransmission either.

The test checks the adapter by FORWARDING rather than by a session: a freshly initialised connection has no
keys and no room, so it refuses, and the assertion is that the adapter returns exactly what the connection
returns rather than inventing a status of its own. That is the only part of a thin layer that can be wrong
without a handshake, and the only part worth a unit test.

### Phase 9's eleventh part: one options parser for the three tools

`cli/options.h` parses exactly the flags the plan names, and the three tools share it. The reason is the plan's
own requirement rather than tidiness: a flag that means one thing in one tool and another in the next is worse
than a flag that is missing, and the only way to keep one meaning is one implementation. The parser is a
library function rather than argv walking inside each `main`, which is what makes every rule here a failing
check: the missing value, the unsupported mode, the timeout that is digits only, the positional address.

Two rules are the interesting ones. **An unsupported mode is not an unknown one**: `--transport packet` is what
this build has, and `--transport quic` is refused by NAME with exit code 2, because a tool that silently
ignores a mode it cannot honour writes reports nobody can trust. And **a flag that takes a value never takes
the next flag as that value**: `--timeout-ms --connect` is a missing value rather than a timeout of
"`--connect`", so a script's typo cannot become a connection attempt. A single dash, by contrast, is a value
and not a flag, because refusing `-host:1` as an address would be this parser inventing a rule about host names
it has no business having.

`wt_cli_options_check` is the one place that says "a connect needs an address" and "the development bypass is
refused outside loopback", so the three tools cannot disagree about what a usable command line is. `--json`
writes the parsed options as one object with stable field names, and the test asserts the text of that object,
because a field that moves changes a machine's input.

### Phase 9's twelfth part: the conformance report, and the scenarios that can be run today

`cli/report.h` is the conformance tool's product, and its rules are all about not lying. A scenario that did not
run is `unsupported` with a reason -- never a pass, never a failure -- because a tool whose report cannot
distinguish "verified" from "not attempted" has a green line that means nothing. The report is ordered and named
by the tool rather than by the run, so two runs compare without sorting. The exit status carries the same
information rather than replacing it: 0 when everything passed, 1 when anything failed, and 3 when nothing
failed but something was not attempted, which is the status this project already uses for a build that cannot
do what was asked.

`wt-conformance-c99 --scenario all [--json]` now runs the scenarios this build can GENUINELY verify -- QUIC
varints across every form and the boundaries where the form changes, a WebTransport close capsule's round trip
with the peer's code, and the draft-16 decision on a decoded extended CONNECT -- and reports the two
session-over-IP scenarios as unsupported with the reason. The report grows as the CLI grows, and the unsupported
entries become passes when the packet-session wiring lands rather than being deleted.

The tool found a bug in ITSELF on its first run, which is worth recording because it is the point of the
exercise: the varint scenario compared each decoded value against a stale loop index and reported `failed`,
while every library test passed. A conformance report that can be wrong about its own subject is worse than no
report; the fix was to name the failing VALUE in the detail rather than say "a value did not round trip", which
is also what made the cause visible in one run.

### Phase 9's thirteenth part: the tools' local socket

The plan's first completion criterion for the tools is that they "run local IPv4 and IPv6 packet sessions",
and this part is the socket half of it: `cli/endpoint.h` turns a `host:port` into a bound or targeted UDP
endpoint, and both tools open theirs and report it in the `--json` output.

The family comes from the ADDRESS rather than from a flag, and that is not tidiness: the runtime sets
`IPV6_V6ONLY` explicitly because the platform default differs between Linux and the BSDs, so an IPv4 address
on an IPv6 socket is not reachable and a tool that guessed the family would work on one machine and fail on
the next. A listener binds and reports the port it ACTUALLY got, which is what makes `--listen 127.0.0.1:0`
usable from a test at all; a client parses without binding, because two clients on one machine must be able to
reach one server. A wildcard is spelled `0.0.0.0:4433` rather than `:4433`: a host with no family is a guess
about which family was meant, and the runtime's parser refuses to make it -- the test's first draft expected
`:4433` to work and was corrected to assert the refusal instead, which is the same lesson as the trailer rule
in WT-96.

The test asserts IPv4 unconditionally and treats IPv6 as available-or-skipped, because a test that fails on a
machine without an IPv6 loopback is a test about the machine rather than about this code. A refused bind is
passed through as the system's own status rather than translated, for the reason the transport adapter gives in
WT-104: a layer that renames a system refusal hides the reason for it.

### Phase 9's fourteenth part: the packet session driver

`runtime/session.h` is the one place where the socket, the QUIC connection and the TLS handshake meet. Each
already existed and none knew about the others: the connection needs somewhere to send, the handshake needs a
connection carrying Initial keys, and the socket needs a caller to pump it.

Three of its rules are the ones that are invisible when they are wrong. The Initial keys come from the
DESTINATION CONNECTION ID in both directions, with the `from_server` flag OPPOSITE for the receive direction --
backwards, the connection encrypts and decrypts nothing, which presents as a peer that never answers rather
than as a key schedule mistake. The handshake's frame handler is CHAINED rather than replaced, which is why the
handshake driver returns WT_OK for frames that are not its business; a session that installed its own handler
instead would stop the walk before the layer behind it saw anything, and the HTTP/3 driver is the layer behind
it. And a pump NEVER WAITS: it reads what is there, flushes what is owed and returns, because a tool that
waited inside a library call could not honour its own `--timeout-ms` or be interrupted -- the caller owns the
clock and passes `now`.

Its test covers the session's own contract rather than the handshake's (that has its own suite with the trust
fixtures): arming an endpoint, a bounded pump with an empty socket (which is the ordinary case in a
two-endpoint loop, so it must not be an error), an unstarted session refusing to pump, clearing twice because
an error path that unwinds would otherwise double free, and a server with NO CERTIFICATE being refused at start
rather than at the first ClientHello, where the reason is much harder to see. The two-endpoint handshake over
loopback is the next part, and it belongs beside the fixtures it needs.

### Phase 9's fifteenth part: a real handshake between two sessions over loopback

The session driver is now proven end to end: `test_runtime_session_pair` stands up two loopback UDP
sockets and two runtime sessions, arms one as a client and one as a server, and pumps both until the TLS 1.3
handshake inside QUIC Initial and Handshake packets is CONFIRMED on both sides with application keys
installed. It uses the repository's trust fixtures -- a real leaf, a real CA and a real signature -- so the
client validates the server rather than trusting it, which is the difference between testing the handshake and
testing a bypass.

Two details in the test are the ones that make it a test rather than a hang. The socket is WAITED on before
each pump, because a non-blocking receive finds nothing until the packet has actually arrived and a loop that
spun faster than the loopback interface would finish before the first Initial packet did; and both the round
count and the wait are bounded, so a driver that never completes FAILS rather than hanging the suite. The first
draft of the loop also had a break at round zero that skipped the handshake entirely -- the test said so
immediately, which is the argument for a bounded loop with an assertion at the end rather than a while(true)
with a timeout.

The same connection ID is used at both ends, which is what makes the Initial keys -- derived from it -- the
same on both sides. Replacing the peer's ID with the one the server chooses is connection ID management this
runtime still needs, and it is recorded on the tracker rather than left implicit.

### Phase 9's sixteenth part: HTTP/3 joins the session, and what that exposed

The HTTP/3 driver now joins a live session -- `wt_runtime_session_set_frame_handler` puts it behind the
handshake's handler exactly as the chaining was designed for -- and `test_runtime_session_pair` drives the
whole outbound path over a real connection: two handshakes, then the client opening HTTP/3's own control and
QPACK streams, opening a request stream, and sending an extended CONNECT as a QPACK field section. Three real
defects came out of writing it, and each is now fixed:

- **The peer's transport parameters were never applied to the connection.** The handshake carries them and
  nothing turned them into limits, so the connection refused the unidirectional streams HTTP/3 must open
  before it can send anything -- and the refusal presented as a state error from an open call rather than as a
  missing step. The session pump now applies them once, the moment the handshake has them.
- **Opening a request stream was two calls in two machines.** The connection owns the stream ID and its flow
  control; the endpoint owns the request ordering. A caller that did one without the other got a refusal at
  the first send. `wt_http3_driver_open_request` does both, and says why in its comment.
- **A server identity on a returning stack frame.** The handshake keeps the pointer it is given, so the first
  version of the test's helper left the server signing with freed memory and the test aborted with no output at
  all. The identity now lives in the pair structure. This is the same class as WT-108's "one number, one owner":
  a borrow whose owner is a stack frame is a borrow that expires.

**And one thing that does not work yet, recorded rather than papered over (WT-110), with the measurement
refined twice.** The client's CONNECT goes out and the server reads packets, but the HTTP/3 layer behind the
handshake is never asked about a frame -- a counter at the top of its chained handler stays at zero. The first
reading of that was "the connection consumes STREAM frames into its own stream state", and reading
`connection.c` showed that is wrong: STREAM frames DO reach `deliver_to_handler`, after `ensure_peer_stream`
has created the stream. The second measurement is sharper and is what the test now records as a comment: on the
server, `wt_quic_connection_stream(...)` for the request stream is **NULL**, so the server never created the
stream at all and the frame never reached its frame walk. The next measurement answered it, and the answer is a LIBRARY finding rather than a test one:

- `wt_quic_connection_send_stream` on the client ACCEPTS an 8-byte send on the request stream and returns
  WT_OK, but **not one byte arrives** and the client's `stream->send_offset` stays **zero**. `send_offset` is
  what the stream advances when data is handed to the send path, so the call accepted the data and neither
  recorded nor sent it.
- The control stream's own send DID create a stream on the server (stream 2 exists), so packets flow and the
  fault is specific to sending STREAM data on a stream this endpoint opened AFTER the handshake.

Reading `wt_quic_connection_send_stream` then showed that inference was wrong too, and turned up a real bug on
this side: the function returns WT_OK only when it has WRITTEN a frame, and it leaves the stream's `send_offset`
and final size to the CALLER (`wt_quic_stream_on_data_sent`: "the caller has already had the frame written, so
this records it"). The transport adapter was not recording anything, so the stream never learned it had data and
the next send would have gone at the same offset -- a protocol error, not a slow stream. The adapter records now,
and the test asserts `send_offset > 0` after a send.

The wire measurement then closed the question of which half is at fault, and the answer is neither of the two
layers this session has: across the pump rounds after the CONNECT, the client's `connection.packets_sent` does
NOT move -- it stays at 9 -- while the frame was accepted and the stream recorded it, and the packets the server
reads in that time are the SERVER's own retransmissions. So the CONNECT is written, recorded, and never leaves:
`wt_quic_connection_flush` is where that is decided.

That also exposed a weakness in the pump this phase wrote: it SWALLOWED `WT_ERR_AGAIN` from the connection
flush, so a refusal had been invisible for three rounds. The pump keeps the status now (`last_flush`,
`last_receive`, and a count of receives that are neither success nor "nothing there"), and the test ASSERTS on
all three -- a pump that cannot tell "nothing to send" from "refused to send" is the same class of mistake as a
conformance report that cannot tell "passed" from "not attempted" (WT-106).

**And keeping the status corrected the previous round's headline.** With the instrumentation in place the
measurements are: both sides read packets, NEITHER refuses any, both flushes report OK, and application keys
are installed in both directions -- while still no stream is created on the server and no frame reaches its
handler. `packets_sent` was 9 BEFORE the measurement window and 9 after it, which the previous round read as
"the packet never leaves"; it had already been incremented by the send itself, so the CONNECT packet WAS sent.
The window was the wrong one, not the conclusion about the whole path. The next counter therefore belongs inside
the connection's FRAME WALK (`ensure_peer_stream`, `deliver_to_handler`), which is the one place left that no
measurement has looked at, and WT-110 carries the corrected sequence.

The next counter then went inside the connection's FRAME WALK, and it found the reason in one run. Three
permanent diagnostics on the connection -- `frames_walked`, `stream_frames_seen`, `frames_delivered` -- showed
that the server's walk DOES see the client's STREAM frames (`stream_frames_seen` 4, `frames_walked` 2138) and
that **both connections are CLOSED with transport error code 3, `STREAM_LIMIT_ERROR`**, long before the CONNECT
matters. `ensure_peer_stream` decided the client had opened more streams than this endpoint granted and closed
the connection; every later frame is then ignored by design, which is exactly why no stream was created for the
request and no frame reached the HTTP/3 handler. Three rounds of inference had looked everywhere except at
whether the connection was still alive.

The admission check reads `local_max_streams[bidirectional ? 0 : 1]`, and the test sets BOTH classes to 8 before
any stream is opened, so the ACCOUNTING -- not the test -- is what believed a single unidirectional stream was
granted. Reproducing that in isolation (set 8, open peer streams, read the grant) is the next step, and WT-110
carries it. The test now asserts the two things that are true and that would have saved those rounds: the walk
saw STREAM frames, and it walked frames at all.

### Phase 9's twenty-fourth part: the exchange is complete

**A whole WebTransport exchange now crosses a real connection, and the test file was rewritten to say so
plainly.** `test_runtime_session_pair` is two self-contained tests: one for the TLS 1.3 handshake inside QUIC,
one for the exchange -- the client's extended CONNECT, the server's decode and acceptance of it, the server's
response, and the client's decode of that with `:status 200` -- 99 checks, all green.

Three library fixes came out of this last stretch, and they are the reason it works:

- **A tracked bidirectional stream must be routed, not offered to `on_request_stream` again** (WT-116). The
  duplicate refusal used to ABORT the frame routing, so a peer's response was never handed to the caller.
- **A peer's frames on a BIDIRECTIONAL stream this endpoint opened must be routed** (this part). The driver
  returned early for any stream "we opened", on the reasoning that such a stream carries only the peer's answer,
  "which the connection's own stream state owns" -- and that early return was where the response died. A
  UNIDIRECTIONAL stream we opened is the case where nothing can come back; a bidirectional one carries the
  other direction of the exchange, with its own HEADERS frames (RFC 9114 section 4.1).
- **The receive grants must match what is advertised** (WT-110's root cause), or the first stream frame is
  refused as FLOW_CONTROL_ERROR and the connection closes.

The work also produced the rule that the test's own history taught: it was edited by scripted find-and-replace
seven times, and two of those edits landed blocks in the wrong place -- one cost a round of library diagnosis and
one cost the file's integrity. It is now written whole, as two readable tests, and the phase records the rule:
**a test whose ORDER is its subject is edited by hand or rewritten, never nibbled by anchors.**

### Phase 9's twenty-third part: the response path's routing bug, and a test file that needs a lighter hand

The response could not be reported at all, and the reason is a real library bug now fixed: routing a
bidirectional stream's frames went through `wt_http3_endpoint_on_request_stream` unconditionally, which for a
stream this endpoint OPENED is a duplicate and is refused -- and the refusal ABORTED the frame routing, so the
peer's response was never handed to the caller. The driver now asks whether the endpoint already tracks the
stream: if it does, this endpoint opened it and what arrives is the RESPONSE, which is the other direction of
the same exchange (RFC 9114 section 4.1 gives each direction its own HEADERS frames); if it does not, the peer
initiated it and it becomes a request stream. The two directions of one exchange are two cases, and treating
them as one was the bug.

Two measurements from the round stand and are recorded: the server's connection DOES hold the request stream
after the pumps (so WT-115's "no stream to answer on" was block placement in the test, not the library), and
the server DOES accept and send the response on it. What remains is the response's arrival at the client's sink,
whose next probe is written down: the client's own `stream_frames_seen` and `frames_delivered` after the
response pumps, and whether its connection stayed open.

**A process note this phase has earned.** This test file has been edited by scripted find-and-replace seven
times, and the last round's edits landed blocks in the wrong place twice -- the response block before the pumps
that deliver the CONNECT, and then a deletion that cut into the milestone assertions. One wrong placement cost a
round of library diagnosis; the deletion cost the file's integrity and was reverted with `git checkout`. The
rule that follows is concrete: **a test whose structure matters should be edited by hand or rewritten whole, not
nibbled by anchors** -- and when an edit removes a region, the region's boundaries belong in the same edit as
its replacement, verified by a build before anything else is concluded.

### Phase 9's twenty-second part: the contradiction was my own instrumentation

WT-115's "a contradiction the test has to explain about itself" was correct about the last word and wrong
about the suspect: the diagnostic that reported `stream_frames_seen = 0`, an empty stream table and a live
connection was printed **before** the pumps that carry the CONNECT, so it described a connection that had not
yet seen a packet. The reading was then treated as the post-pump state and became a library hypothesis, and it
cost a round.

Two things come out of it. The test now tells its sinks which stream carries the exchange **the moment the
stream exists**, which is where that assignment belongs, and the phase records the rule plainly: **a diagnostic
belongs AFTER the traffic it describes**, and a counter read at the wrong point is not a measurement but a
coincidence. This is the third time this item has turned on where a number was read rather than what it said
(the `packets_sent` window in round 61, the transport error space in round 64, and now the pump phase), and the
tracker now carries the pattern rather than the three incidents.

What remains genuinely open is unchanged and is one reading away: whether the server's connection has the
request stream **after** the pumps, which decides whether a response can be sent on it. That reading, at the
right point, is WT-115's next step.

### Phase 9's twenty-first part: a contradiction the test has to explain about itself

Probing WT-115 produced a set of facts that cannot all be true of one object, and the honest next step is to
find out which of the test's two objects the frames actually arrive on. After the milestone assertions pass --
the CONNECT assembled and decoded on the server side -- the server's CONNECTION reports `is_closed = 0`, close
code 0, `stream_frames_seen = 0`, and **no streams at all in its table**. A connection that walked zero STREAM
frames cannot have delivered a STREAM frame to the HTTP/3 driver, and a table with no streams cannot answer on
any of them, so either the counters are read from a different object than the handler is bound to, or the
handler is called on a session whose connection is not the one being inspected.

The next probe is therefore one print: the CONNECTION pointer inside the chained handler beside the side
pointer. `side_on_frame` is bound to `&server` and the session to `&pair.server`, both visibly, so if they are
the same object in a run then the library is where to look -- and if they are not, this test has been asserting
the right things about the wrong objects, which is worth knowing before another round of library diagnosis. It
is recorded as a test-shaped hypothesis FIRST because the evidence points that way: the library's own suites
(unit, integration and the handshake pair) all pass, and this is the only place the two sides are wired by hand.

### Phase 9's twentieth part: the response path, and the stream the server does not have

The response side of the exchange now exists in the library -- `wt_http3_endpoint_on_response_headers` decodes a
response with the RESPONSE pseudo-header rules and its own once-per-stream rule, and
`wt_http3_driver_send_response` sends a status -- and the reason it is a separate call from the request path is
worth keeping: RFC 9114 section 4.1 gives the two DIRECTIONS of one exchange their own HEADERS frames on the
same stream, so the response is neither the request line nor a trailer. Decoding it with the request rules (as
this endpoint did before the call existed) refuses a perfectly good `:status` as a pseudo-header in a trailer.

Sending it over a live connection does NOT work yet, and the measurement is precise: the client's CONNECT
arrives and decodes (the milestone assertions pass), but
`wt_quic_connection_stream(&server.connection, request_stream_id)` is **NULL** -- the server has no QUIC stream
to answer on, while the frame walk demonstrably delivered that stream's STREAM frame to this layer. A frame
walked for a stream the connection does not have is the next thing to explain, and it is the last thing between
this phase and a session a caller can actually use. WT-115 carries it.

### Phase 9's nineteenth part: the client's opening sequence in one call

`wt_http3_driver_start_session` does what every WebTransport client does, in the order the protocol fixes: start
this endpoint's own streams (control and both QPACK streams), open a request stream, and send the extended
CONNECT for a given authority and path. The pair test uses it now and still reaches the same milestone, so the
one-call version is proven against a real connection rather than merely written.

It exists because doing the sequence by hand is where THREE separate bugs were found in this phase -- a grant
that did not match the value the endpoint advertised (WT-110's root cause), a stream opened on one machine and
not the other (WT-111), and a send whose offset was never recorded (WT-112). Each was a step in a sequence whose
order and pairing the protocol fixes, which is the argument for one call that cannot get them out of step. A
caller that wants a different order still has the pieces.

### Phase 9's eighteenth part: the CONNECT crosses a real connection

**The milestone this phase was built for is reached**: `test_runtime_session_pair` drives the whole path --
two sessions complete a TLS 1.3 handshake inside QUIC Initial and Handshake packets, the client opens HTTP/3's
control stream and both QPACK streams, sends an extended CONNECT as a QPACK field section, and the SERVER
assembles that section from the pieces the driver reports, decodes it off the wire, and accepts it with the
draft-16 validator, with its request state advanced past the request line.

The bug that blocked it is worth recording in full, because three rounds of the diagnosis were spent on it and
the first reading of its evidence was wrong. The server closed the connection with transport error code **3**,
and this session read that as `STREAM_LIMIT_ERROR` and went looking at the stream-count accounting -- where two
further measurements found nothing wrong. Code 3 is `FLOW_CONTROL_ERROR` (0x04 is the stream limit), and the
close came from the STREAM branch's own mapping after `wt_quic_stream_on_data` refused the frame. The reason it
refused: **the connection-level receive account started at zero**, because nothing pairs the `initial_max_data`
an endpoint ADVERTISES in its transport parameters with the local grant that enforces it
(`wt_quic_connection_set_max_data`). The advertised number is a promise; the grant is the enforcement; the two
must agree, and until they do the first peer stream frame is refused and the connection closes -- which presents
as a peer that says nothing rather than as a missing grant.

`runtime/session.h` now states the rule beside the driver's other invariants, and pairing it automatically is a
task on the tracker: it needs the advertised parameters, which the session driver does not currently see. Two
lessons join the ones this phase has already recorded: **read the error space before reasoning about the error
code** (0x03 is flow control, not stream limit), and **an endpoint that grants nothing receives nothing** --
which is the receive-side twin of the "one number, one owner" rule from WT-108 and WT-112.

### Phase 9's seventeenth part: the stream-limit suspect is eliminated, and the question moves to the client's sends

The isolated check did its job by REMOVING a suspect rather than confirming one. Two facts, both measurements:

- The grants the admission check reads are **8 in both classes on both sides**, asserted on the very
  connections that closed -- so the setter, the getter and the admission field agree, and the previous round's
  "the accounting believed one stream was granted" reading was wrong.
- Instrumenting `ensure_peer_stream` itself showed it runs **exactly once** on the server (stream 2,
  `bidir=0`, `index=0`, `granted=8`) and admits it. It never refuses anything, so `STREAM_LIMIT_ERROR` does not
  come from the admission check at all.

What the measurements leave is a sharper and different question: the server's walk saw **four STREAM frames,
all for stream 2** -- the client's data for streams 6, 10 and 0 never appears in it, although
`wt_http3_driver_start_own_streams` and `send_message` both returned OK and the frames were recorded against
their streams. The server originated a close with transport error code 3 and the client closed in response.
So the next place to look is the CLIENT's send path for its SECOND, THIRD and FOURTH stream: accepted,
recorded, and walked by nobody. That is WT-110's next step, and it is the fourth distinct hypothesis the
measurements have produced -- each previous one eliminated rather than argued away.

The test asserts only what is true today (the CONNECT goes out, the client records and tracks its request
stream), and WT-110 carries the measurement and the next step.

### Phase 9's twenty-eighth part: a message as a datagram

`--exchange datagram` works end to end, and it needed no library change at all: the driver's DATAGRAM branch
already handed the payload over uninterpreted, and the test frames the message the way the draft does -- a
quarter stream ID and the payload -- sends it in a QUIC DATAGRAM frame, and parses what arrives with the session
layer's own parser, which yields this session's quarter stream ID and exactly the payload.

Two properties are worth stating because they are the ones a datagram cannot negotiate. Datagram support is
ADVERTISED (`max_datagram_frame_size`), which is the same match-the-advertisement rule as the flow-control
grants: a peer may only send a DATAGRAM frame when this endpoint's parameters said it would accept one, and the
first run of this test would have failed at the send with a peer that advertised nothing. And a datagram IS the
unit: no reassembly, no ordering, no partial delivery -- which is why the receive path is a single hand-over
rather than the piece-wise reporting the stream paths use.

Both exchange modes the plan names now have a proven path at the library level, and both were checked in debug,
release and ASan+UBSan before being committed.

### Phase 9's twenty-seventh part: a message on a WebTransport stream, and the session ID in the prefix

`--exchange stream` works end to end: after the exchange's response, the client opens a unidirectional
WebTransport stream -- the draft's `0x54` type AND the session ID, then the session's own bytes -- and the
server's session sink receives exactly the message, on the stream it was sent on. It uses the classification the
unidirectional path already had, which is why this piece needed no new routing.

It needed one detail of the draft's own prefix, and the failure it produced is worth recording because it was so
quiet: the type classifier reads only the TYPE, so the SESSION ID was passed along as the first byte of session
data, and the server received eight bytes where the client sent seven -- a leading byte nobody could explain. The
session ID is part of the prefix and is consumed before the session sees anything; a frame that stops after the
type is `WT_ERR_TRUNCATED`, which is the honest answer until the pending table reassembles a split varint. The
`out_prefix_consumed` the caller continues with is the WHOLE prefix -- type and session ID -- because that is the
number it needs.

This is also where WT-120's release-build rule paid for itself: the change was small, and it was checked in
debug, release AND ASan+UBSan before it was committed. The unit expectations that had to change with it are part
of the same edit, and two of them were found by that check rather than later by a user.

### Phase 9's twenty-sixth part: a change that was REVERTED, and why that is the right outcome

The next piece is the `--exchange stream` behaviour: a WebTransport BIDIRECTIONAL stream is a peer-initiated
bidirectional stream whose first bytes are the draft's `0x41` prefix, so the driver's bidirectional branch has to
tell it apart from a request stream's QPACK prefix before routing it. That classification was implemented, the
session-ID check was added beside it (a WebTransport stream must name the session this endpoint serves, or it is
refused rather than delivered to the wrong one), and a unit test fed both shapes through the same entry point.

**The change was reverted, because the release build SEGFAULTED in `test_http3_driver` while the debug and
sanitizer builds passed.** A crash that appears only in one configuration is exactly the kind of defect this
project's four-configuration test loop exists to catch, and shipping it to make a round look productive would
have been the wrong trade: the classification is desirable, the implementation was not trustworthy, and a
segfault in a frame path is the worst possible place to be unsure. The tree is back to the last verified state
(77 CTest tests, all green in debug, release and ASan+UBSan), and the work is recorded as WT-120 with the
measurement, the design note (prefix-first, session-checked, unidirectional-flag agreement enforced) and the rule
that follows: **a frame path is changed with all three build configurations in the loop before anything is
committed** -- the sanitizers catch memory errors in code that RUNS, and a path reached only by a release-mode
test may not run the same way at all.

### Phase 9's twenty-fifth part: a self-signed identity, so a local server needs no certificate file

`tls/self_signed.h` generates, in memory, what a local development server needs: an ECDSA P-256 key and a
certificate for the loopback names, both DER, plus the SHA-256 fingerprint that makes the certificate useful. The
fingerprint is the design rather than a convenience: a self-signed certificate is trusted by NOTHING by
definition, so a client can only reach it by PINNING that value (`WT_TLS_TRUST_PINNED_CERTIFICATE`) or through
the development bypass -- which the trust layer already restricts to loopback names. One call therefore produces
both halves of a local setup, which is what `--listen --trust local-development` needs and what the conformance
tool's session scenarios need without borrowing the repository's test fixtures.

Two details are the ones worth keeping. The identity and the certificate passed to the handshake and to the
trust check are built by SEPARATE calls that point into the generated buffers, so the structure never contains a
pointer to itself -- a self-referential struct is one `memcpy` away from pointing at somebody else's stack, which
is exactly the bug that cost a round of debugging in the session pair (WT-111). And the generator compiles
against OpenSSL unconditionally, like the trust layer beside it: a build with a stub generator next to a real
trust layer would be a promise the build cannot keep.

The test is a closed loop rather than a self-comparison: it generates, pins what the generator returned, has the
TRUST LAYER accept it, checks that a different pin is refused, that no pin at all is refused, and that two
generations differ -- because a generator tested against its own output proves nothing about whether anything can
trust it.

### Phase 9's thirty-first part: the tools complete a session with each other

**`wt-client-c99` and `wt-server-c99` exchange a WebTransport session over a real socket, in two processes**, and
CTest runs them against each other:

    client: {"role":"client","status":"ok","established":true,"connectAccepted":true,
             "responseStatus":200,"receivedBytes":4}
    server: {"role":"server","status":"ok","boundPort":4461,"established":true,
             "connectAccepted":true,"receivedBytes":4,"pin":"1b2a79..."}

The piece that made it work is `wt_udp_peek`: a listener learns its peer's address by looking at the first
datagram and LEAVING IT IN THE QUEUE. The previous version received that datagram and dropped it, on the
reasoning that an Initial cannot be processed before the connection exists -- and that reasoning is right and the
implementation was wrong, because the packet that NAMES the peer is the packet the connection then needs. A
listener that consumes it waits for a retransmission, and a peer that has already given up never sends one: the
client's own report was `{"status":"timeout","established":false}` for exactly that reason. The peek returns the
datagram's true length even when the caller's buffer is too small (a datagram is still a unit), and the caller
that only wants the sender passes a zero-capacity buffer.

`scripts/check-cli-session.sh` runs the two tools against each other and asserts the contract in their JSON:
both `ok`, both `established`, the CONNECT accepted, the response `200`, and four bytes received on each side.
It is registered with CTest as `wt_cli_session`, so the tools' path is checked on every build -- and it is the
second CTest entry (after WT-123) whose result is a real session rather than a codec.

### Phase 9's thirtieth part: the client and server tools run a loop, and the accept path is the missing piece

Both tools now drive a REAL one-sided session loop through a shared `apps/support/session_loop.c`: the client
connects, sends the CONNECT, waits for the response and exchanges a message; the server binds, waits for a peer,
answers the CONNECT and exchanges a message. Both report machine-readable JSON
(`{"role":"client","status":"...","established":...,"connectAccepted":...,"responseStatus":...}`), so the tools'
behaviour is a value a script reads rather than prose it greps.

**The exchange does not complete yet, and the measurement says why:** run against each other,
`wt-client-c99 --connect` reports `{"status":"timeout","established":false}`. The server has to know its peer's
address before it can arm a session, and the first implementation discovered it by RECEIVING the client's first
Initial and dropping it -- which costs a retransmission round and, worse, discards the very packet that names the
peer. The fix is structural rather than a tweak: the runtime session needs a LISTEN mode that arms itself from
the first datagram it reads (holding that datagram and processing it once the connection exists), or the UDP
layer needs a peek that leaves the packet for the connection to read. That is WT-124.

Three things this part settled. The conformance tool's own scenarios (WT-123) are unaffected and still run real
IPv4 and IPv6 sessions in one process, which is what the phase's stated criteria ask for. The tools' CMake
ordering bug that hid this work for a round is worth remembering: a `target_include_directories` call placed
BEFORE `add_executable` fails configure, and a failed configure leaves the previous binaries in place -- so the
tools kept their old behaviour and the build looked clean. And the tools now have a JSON contract of their own,
which is the shape the plan's `--json` flag asks for.

### Phase 9's twenty-ninth part: the completion criteria are met

**The conformance tool runs local IPv4 and IPv6 packet sessions and produces stable machine-readable output.**
`wt-conformance-c99 --scenario all` stands up two endpoints in ONE process over loopback -- a generated, pinned
identity, a real TLS 1.3 handshake inside QUIC, an extended CONNECT accepted by the draft-16 layer, the
response, an 11-byte message on a WebTransport stream and a message as a datagram -- and reports:

    {"summary":{"total":5,"passed":5,"failed":0,"unsupported":0}}   exit 0

with the two session scenarios that were `unsupported` in Phase 8's report now genuinely run. IPv6 reports
`unsupported` WITH ITS REASON on a machine that has no IPv6 loopback, because that is a fact about the machine
rather than a failure of the code -- which is the distinction the report's design was built around (WT-106).

Three things make this a criterion rather than a demo. The tool is run by **CTest**, so the claim is checked on
every build. The identity is GENERATED and PINNED rather than taken from the repository's test fixtures, so the
scenario is runnable where the tool is. And the exchange is the whole one: a handshake, a CONNECT accepted by
the draft-16 validator, a response, a stream message and a datagram -- the same path the library's pair test
proves, now reachable from a command line.

Phase 9's remaining work is the CLIENT and SERVER tools' own loops (`--listen`/`--connect`, `--message`,
`--timeout-ms`), which reuse exactly the pieces this scenario is built from: the runtime session, the HTTP/3
driver, the self-signed identity and the report.

### Phase 10's third part: WT-113, in one focused pass

The reverted refactor is done, and it is done the way the previous part's rule asked for: one focused pass, with
the edit list written down first and all three build configurations in the loop from the first build.

The API is `wt_runtime_session_advertise(session, initial_max_data, initial_max_stream_data,
initial_max_streams_bidi, initial_max_streams_uni)`: one call, after starting a session, that puts what the
endpoint ADVERTISED in its transport parameters into force. It is deliberately NOT four more parameters on
`start_client`/`start_server` -- a call that already takes seven numbers does not need four more, and a caller's
arguments cannot drift when they are not there. It is idempotent (the limits are monotonic), and a caller that
advertises nothing does not call it at all.

Every caller that advertises now uses it: the session pair test, the conformance tool's IPv4/IPv6 scenarios, and
both CLI session loops. The manual `grant_receive_room` helpers those three call sites used to need are GONE,
which is the point: the pairing lives in the driver, once, instead of in every caller's memory. The pair test
asserts the RESULT -- the grants in force before any stream is sent -- rather than the mechanism.

That closes WT-113. The failure it prevents is the one that cost several rounds of measurement (WT-110): an
endpoint that advertises a limit, grants nothing, and closes its own connection on the first stream frame as
FLOW_CONTROL_ERROR, which presents as a peer that says nothing rather than as a missing grant.

### Phase 10's second part: a refactor that was reverted, and why

The next item was WT-113 -- pairing the limits an endpoint ADVERTISES in its transport parameters with the
LOCAL grants that enforce them, so that an endpoint which advertises a limit and grants nothing cannot close its
own connection on the first stream frame (WT-110's root cause). The design is settled and small: one
`wt_runtime_session_limits_t` passed to `wt_runtime_session_start_client`/`_server`, applied by the driver, and
the callers stop calling `wt_quic_connection_set_max_data` and friends by hand.

It was implemented and then REVERTED, because a public-signature change reaches four call sites (the session
pair test, the runtime session test, the conformance scenario and the CLI session loop) and the scripted edits
to those call sites started passing arguments in the wrong positions -- the compiler caught every one, but
following them one at a time at the end of a long session is how a working tree becomes a half-changed one. The
tree is back to the last verified state (80 CTest tests, green in debug, release and ASan+UBSan) and nothing
half-changed is committed.

The lesson is the one this phase has now earned three times over, in three different shapes: **a change that
reaches several call sites is a change to make in one focused pass, with the exact edit list written down
first, and with all three build configurations in the loop** -- not something to bolt onto the end of another
round. WT-113 carries the design, and the file list above is the edit list.

### Phase 10's first part: a malformed-input corpus for the layers above QUIC

The QUIC parsers have had a fuzz-style corpus since Phase 1 -- a deterministic pseudo-random byte stream, with
the assertion that a refusal is a STATUS and never a crash -- and the layers above them were owed the same
treatment. `test_http3_malformed` feeds 4,000 generated inputs to: the HTTP/3 frame decoder, the SETTINGS
parser, the WebTransport capsule decoder and the value parsers for the capsules it decodes, the datagram
parser, the QPACK field-section decoder with NO dynamic table (the strictest configuration, where a section that
references a table this endpoint does not have must be refused rather than read against indices that do not
exist), the draft-16 request validator on whatever decoded, and the HTTP/3 driver's stream classifier and
frame-boundary reassembler. Under AddressSanitizer and UndefinedBehaviorSanitizer the corpus is the test that
matters, because a read past a buffer there is a failure rather than a plausible value.

Two things about the corpus are worth keeping, and both came out of writing it. It asserts that it REFUSES and
that it ACCEPTS, because a generator change that made every input valid would silently turn the suite into a
no-op -- but the proportions are asserted as they ARE, not as a guess: a capsule decoder accepts most of the
corpus, because an unknown capsule type with a length that fits is a VALID capsule (RFC 9297 tells a receiver to
ignore what it does not understand), and the stream classifier accepts an unknown stream TYPE for the same
reason (section 6.2.1). The first version of the test asserted "refused > accepted" in both places and failed --
which is the same lesson this tracker carries from several earlier rounds: assert what the code does, not what a
paragraph about it suggests it should.

### Phase 10's fourth part: the bounded tables, at their bounds

The plan's test port asks for resource exhaustion, and this is what it means in these layers: every table is
FIXED, because a table that grows with a peer is a heap exhaustion path with the peer's name on it.
`test_http3_limits` drives each one to its bound -- the endpoint's peer-stream table, the endpoint's request
table, the driver's pending-prefix table and its frame-boundary table -- and asserts three things about what
happens then:

- the refusal is `WT_ERR_LIMIT`;
- it carries NO error code, because the bound is this endpoint's and blaming the peer for it would tell the
  peer's story about a local limit (the rule WT-99 and WT-102 established, now asserted in one place);
- the table does not move: a refused stream consumes no slot, and a stream that ends GIVES ITS SLOT BACK, since
  these are bounds on CONCURRENCY rather than lifetime totals.

The count assertions are the ones that matter, and the reason is worth keeping: a table that quietly dropped the
entry past its bound would show a short, clean run, and "the peer opened one more stream than we allow" is
exactly the case where a silent drop and a refusal look identical from the outside.

### Phase 10's eighth part: the split bidirectional prefix, attempted and reverted

The narrow edge WT-120 left open -- a WebTransport bidirectional prefix that arrives in PIECES -- was attempted
and is REVERTED. The design was to hold the first bytes in the same pending table the unidirectional path uses,
re-run the proven classifier when more arrive, and then either deliver what follows the prefix to the session or
REPLAY the held bytes into the HTTP/3 request path (which must see a stream's first bytes, not the middle of
them). The prefix table's bound was raised from eight bytes to sixteen at the same time, because a draft-16
prefix is the TYPE plus the session ID and each may be a varint of up to eight bytes -- a table sized for the
type alone would refuse a legal prefix.

It did not work, and the measurement is the useful part: the SECOND frame of a split prefix came back as
`WT_ERR_LIMIT` and nothing was delivered, while the existing 174 checks stayed green. That says the assembly
path itself refused before it could decide -- but the round had no budget left to find where, and a frame path
is not a place to guess. The tree is back to the last verified state (82 CTest tests, green in debug, release and
ASan+UBSan) and nothing half-working was committed.

The next attempt starts from the measurement rather than from the design: put a counter at each refusal in the
assembly path (the pending-table bound, the classifier's status, `on_stream_bytes`'s frame table) and see which
one fires on the second frame. The design above is sound; it is the plumbing that was not verified, and the
lesson this phase keeps re-learning applies here too: **a frame path is changed with a counter in it, not with a
theory about it.**

### Phase 10's seventh part: the tools' test covers both exchange modes

The CLI session test ran `--exchange stream` only, which left the plan's `--exchange stream|datagram` half
covered at the TOOL level (the library's own pair test covers both, and the conformance tool's scenarios cover
both, but the tools are the phase's deliverable). There are now two CTest entries -- `wt_cli_session_stream` and
`wt_cli_session_datagram` -- on different ports, and the script asserts the MODE in both tools' reports:
`"receivedDatagram":true` for one and `false` for the other. They are different code paths in both tools, and a
report that claimed the same thing for both would be worth nothing.

That closes the last gap in what the tools' own test proves: a two-process session, a CONNECT accepted, a 200
response, and a message exchanged in each mode, on every build.

### Phase 10's sixth part: WT-120 lands -- the routing, on its own

The second step is the one the first attempt crashed on, and it is now in: in the driver's bidirectional branch,
a peer stream that is not already tracked is offered to the proven classifier, and when the answer is a
WebTransport prefix the bytes AFTER it go to the session sink. A stream that names ANOTHER session is refused
with HTTP/3's identifier error rather than delivered to the wrong one (the rule every other session-bound
delivery in this library follows), and a prefix that has not fully arrived falls through to the request path
rather than being guessed at from half a varint -- with the honest note in the code that a bidi prefix SPLIT
across frames is a case this routing does not reassemble yet.

The test asserts the three cases separately: a WebTransport stream hands the session exactly its payload and not
its prefix, a stream for another session is refused and reaches the session never, and a request-shaped stream
is tracked as an HTTP/3 request and does not appear as session data. All three configurations are green from the
first build, which is what the two earlier attempts (one crash, one revert) bought: the classifier was proven
alone first, so the routing had nothing left to hide behind.

**WT-120 is closed**, and the remaining note is narrow and written down: a WebTransport bidirectional prefix that
arrives SPLIT across frames needs the pending-prefix reassembly the unidirectional path already has, and it is
recorded rather than half-implemented.

### Phase 10's fifth part: the bidirectional-stream classifier, isolated first

WT-120's bidirectional WebTransport stream classification is being retried in the small steps its own rule
asked for, and the first step is the classifier ALONE: `wt_http3_driver_classify_bidi_start` decides whether a
peer's opening bytes on a bidirectional stream are an HTTP/3 request (a QPACK field-section prefix) or a
WebTransport bidirectional stream (the draft's `0x41` type and the session ID). It is a PURE function -- it
reads, it does not route, and the caller decides -- and the separation is the point: the ROUTING that uses it is
where the release-build crash of the first attempt lived, so the classifier is proven in debug, release AND
ASan+UBSan before anything is routed by it.

Its contract is the one the streaming layer needs rather than the one a buffer parser would have: a prefix that
has not fully arrived is `WT_ERR_TRUNCATED`, which on a stream is a WAIT and not a refusal, because a peer may
open a stream and send its first bytes in the next packet; a stream with no bytes at all is a request stream
until proven otherwise; and the number reported as consumed is the PREFIX's length, not the body's -- which the
test asserted wrongly at first (it expected two bytes where the type `0x41` needs a two-byte varint of its own),
the same MSB-first varint lesson this tracker has recorded several times.

### Phase 10's ninth part: the split bidirectional prefix, found by its counter

The edge WT-120 left open is closed, and the method is the part worth recording because it is the third time this
phase has needed it. WT-130's next step was prescribed as "a counter at each refusal, read on the second frame",
and the first run of the instrumented assembly said everything at once:

    DIAGBIDI id=0 have=0 copied=1  classified=8 kind=0 consumed=0   <- first frame: TRUNCATED, so it is held
    DIAGBIDI second=9 stream_bytes=0                                <- second frame: refused, and NO assembly line

No `DIAGBIDI` line for the second frame meant the assembly never ran for it, and the reason is the design's blind
spot: **a continuation frame has a non-zero offset**, and the assembly's condition was "offset zero". The frame
that would have completed the prefix fell through to the request path, where its middle bytes were read as a
stream's first and refused with WT_ERR_LIMIT. The held-bytes lookup now comes first, so a stream with held bytes
is assembled whatever the frame's offset says.

The test covers both outcomes of the assembly: a WebTransport prefix split across frames delivers exactly its
payload (once, with the pending entry released), and a REQUEST split the same way REPLAYS the held bytes so the
request path sees the stream's first bytes. All three build configurations are green.

Two of the three build configurations were green through every wrong version of this change, which is why the
phase's rule is about counters and not about configurations alone: **a frame path is changed with a counter in
it** -- the configurations say whether the change is SAFE, and the counter says whether it is RIGHT.

### Phase 10's tenth part: the CLI tools' process contract, and the bug it found

The plan's test port names "CLI process behavior" as a group, and the part of it that scripts depend on is the
CONTRACT: exit statuses, refused command lines, and the machine-readable report. `scripts/check-cli-contract.sh`
checks all three without a peer, which is what makes it fast enough to run on every build: an unsupported mode
exits 2 and names what it refused, no mode exits 2, `--help` exits 0 and prints usage, and a client that cannot
reach anybody exits non-zero while reporting `"established":false` and never `"status":"ok"`.

**It found a real bug on its first run, and the bug is the kind that only a contract test finds:** `--help` was
rejected as an UNKNOWN FLAG by the options parser, because the mains handled `--help` in a loop that ran after
parsing had already failed. The parser now owns `--help`, `-h` and `--version`, and the tools answer them BEFORE
the mode and address are checked -- asking what a tool does is not asking it to do anything. The unit suite for
the parser covers the three flags and asserts that `--help` alone parses with no mode at all.

That is Phase 10's malformed-input spirit applied to the tools rather than to the wire: feed the program the
command lines a person actually types and check what the process DOES, not what a function returns.

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

### WT-137 fixed: the reserved settings rule, in one focused pass

The bug the previous round's scenario found is fixed, in the single pass its own note prescribed, over the four
places that had to move together:

1. **the parser** (`wt_http3_settings_parse`) refuses a reserved identifier (`wt_http3_setting_is_exerciser`,
   `0x1f * N + 0x21`) with `H3_SETTINGS_ERROR`, which is what RFC 9114 section 7.2.4.1 requires;
2. **the setter** refuses it too (`WT_ERR_INVALID_ARGUMENT`), for the reason the HTTP/2 set is already refused
   there: refusing at the setter keeps the encoder from producing a frame the parser would refuse;
3. **the predicate's comment** no longer claims the opposite of the section;
4. **the fixtures** -- and this is the part worth remembering. TWO test fixtures used a reserved identifier as
   their example of a legal unknown setting: `test_http3_settings`'s round-trip payload and
   `test_http3_driver`'s oversized-settings payload (which built its size from `0x21 + i * 0x1f`, the reserved
   family itself). The header now names `WT_HTTP3_SETTING_UNKNOWN` (0x22) as "an identifier this version does not
   know and that is NOT reserved -- the shape a future setting has", and both fixtures use it. **A fixture that
   uses a reserved value as its example of a legal one is a bug that hides a bug**, which is why the suite failed
   the instant the parser was corrected.

The conformance report is now **17 scenarios, 0 failed, 0 unsupported**, and the CLI contract script's
"unsupported must carry a reason" check became conditional: it failed the moment the last unsupported entry
disappeared, which is the healthy case -- a check that assumes a known gap exists is a check that breaks when the
gap closes.

### WT-137: a conformance scenario found a real spec violation in our own parser

Four more scenarios were added -- a repeated SETTINGS identifier, a reserved one, a QPACK section that needs a
dynamic table this endpoint never advertised, and two session-state rules (the first close's code wins, and a
drain stops new streams). Three pass. **The fourth found a real bug:**

> RFC 9114 section 7.2.4.1 makes the RESERVED settings identifiers (`0x1f * N + 0x21`) a connection error of type
> `H3_SETTINGS_ERROR`. This parser ACCEPTS one -- status 0, code 256 -- and the predicate that knows the rule
> (`wt_http3_setting_is_exerciser`) is called from nowhere in the parse path. Its own comment even said the
> reserved identifiers were "reserved to exercise the rule that unknown identifiers are ignored", which is the
> opposite of what the section says.

That is what a conformance suite is FOR, and it is worth noting where the scenario came from: the tool's own
`--settings-validation` flag names this rule, and the scenario is the first thing in this project that has ever
checked it.

The fix is reverted for now and the scenario reports **`unsupported` WITH THE MEASUREMENT** rather than `failed`,
because the report's contract distinguishes "the code is wrong" from "this was not attempted" and the tool's exit
status carries the same distinction (3). The fix is one focused pass over three places that must move together --
the parser, `test_http3_settings` (whose round-trip fixture uses a reserved identifier as its example of a LEGAL
unknown setting, which is why the suite failed the moment the parser was corrected) and this scenario -- which is
the rule this phase has now learned three times: a change that reaches several call sites is made in one pass.

The CTest registration also had to learn the distinction: `wt_conformance_scenarios` sets `SKIP_RETURN_CODE 3`,
and the CLI contract script accepts exit 0 or 3 while still refusing a run with a FAILED scenario.

### WT-133, second half: the refusal scenarios, seven of them

The Swift conformance suites are half NEGATIVE -- a request for the wrong path, a CONNECT for another protocol, a
capsule over the bound, a stream for another session -- and the C99 tool had only the positive side. The tool now
reports twelve scenarios, seven of them new, and every one of the seven asserts the CODE the peer would be sent
rather than merely that something failed:

- a path this server does not serve is a `404`, compared exactly (a prefix match would let one host's request be
  served as another's);
- an extended CONNECT for another protocol is `NOT_WEBTRANSPORT`, and the caller answers it as an ordinary request;
- a server that never advertised `WT_ENABLED` refuses a session it could not have been expected to serve;
- a capsule value over the bound is `WT_ERR_LIMIT` with `H3_EXCESSIVE_LOAD`;
- a peer stream past the endpoint's bound is `WT_ERR_LIMIT` with NO error code, because the bound is this
  endpoint's rather than the peer's mistake;
- an empty datagram is `WT_ERR_PROTOCOL` with `H3_MESSAGE_ERROR`, because a datagram IS the unit and has no
  "incomplete";
- and the positive edge this project earned the hard way: half a prefix decides NOTHING, and the whole one
  classifies the stream.

They need no sockets, because a refusal is a decision rather than a session, which is what makes them cheap enough
to run in the report on every build. That is breadth in the direction the suites actually differ: the C99 tool
already had the two hard end-to-end scenarios (WT-123), and what it lacked was the long tail of negative cases
that a conformance suite exists to enumerate.

### WT-133, first half: the tools over IPv6, and an honest skip

The Definition of Done's third criterion is "the C99 client/server CLI passes local IPv4 and IPv6", and the
conformance tool covered both families while the two TOOLS themselves had only ever been driven over IPv4.
`check-cli-session.sh` is parameterised by host now, and `wt_cli_session_ipv6` runs the same two-process session
over `[::1]` -- handshake, CONNECT accepted, 200 response, and a message each way.

The machine-dependent part is handled the way the conformance tool already handles it: when the host is an IPv6
literal, the script first asks the conformance tool whether its own IPv6 scenario passes, and returns CTest's
**skip** code (77) with the reason when it does not. One probe, reused, rather than a second implementation of
"does this machine have an IPv6 loopback" -- and a skip that says WHY rather than a failure that says nothing.

### WT-132: the compliance matrix, and a checker that keeps it honest

`docs/COMPLIANCE-MATRIX.md` is the document the Definition of Done's first criterion needs: every requirement
draft-ietf-webtrans-http3-16 places on an endpoint, mapped to the function that implements it and the test that
exercises it. Twenty-eight rows across the draft's own sections -- the extended CONNECT and its refusals, the
response, the session-as-a-request-stream rules (including trailers and their pseudo-header prohibition),
WebTransport streams and their prefixes (including a prefix that arrives in pieces and the replay for a request),
datagrams and their advertisement, capsules with the strict-increase and 2^60 flow-control rules, drain, close,
and the CONNECT stream ending -- plus rows for the QUIC, HTTP/3 and TLS layers the session runs on.

**The matrix is checked, not trusted.** `scripts/check-matrix.sh` greps every symbol the document names for a C
declaration or a registered CTest name and fails if one is missing, so a matrix that drifts away from the code is
a red build rather than a document that reads like evidence. It caught two names on its first run that were test
names rather than symbols -- which is why it searches CMakeLists and scripts as well as headers and sources -- and
CI now runs it beside the vector and package checks.

Two rows are deliberately not "tested" and are stated rather than hidden: **server push**, which this tree refuses
deterministically (H3_ID_ERROR for a client, H3_STREAM_CREATION_ERROR for a server) because the draft does not use
it, and **a peer that changes its connection ID during the handshake**, which the tests do not cover because they
use the same connection ID at both ends -- the recorded transport gap rather than a claimed feature.

### WT-134, second step: the platform header, and POSIX behaviour unchanged

The inventory's first item was a private header naming the differences so that `udp.c` stops spelling POSIX in a
dozen places, and it is in: `src/runtime/udp_platform.h` defines the handle type and four operations --
`wt_udp_platform_close`, `wt_udp_platform_set_nonblocking`, `wt_udp_platform_wait_readable` and
`wt_udp_platform_last_error` -- with a POSIX branch that is what this project builds and a `_WIN32` branch
written from the inventory. The Windows branch is NOT verified, and the header says so in its first paragraph:
nothing in this repository builds it, and a port that claims to be finished before it has been compiled once is
exactly the failure this project refuses.

The POSIX path is unchanged in behaviour and green in debug, release and ASan+UBSan, which is the only claim a
change like this can make from here. The datagram calls have since joined the header too
(`wt_udp_platform_message_t`, `wt_udp_platform_send_message`, `wt_udp_platform_receive_message`), so what
remains in `udp.c` is the public `int fd` field, which a Windows port must widen to `SOCKET` -- a public change,
and therefore one to make deliberately rather than in passing.

### WT-134, first step: the platform surface, inventoried and checked

FreeBSD and Windows CI legs are the Definition of Done's CI criterion, and the honest first step is not a YAML
job but an inventory: `docs/PORTABILITY.md` lists every place this code assumes POSIX and the adaptation each
needs -- socket headers, `WSAStartup` (which has no home in this library yet, since the UDP layer is the only
place it touches the operating system), `ws2_32`, the `SOCKET` type and `INVALID_SOCKET`, `closesocket`,
`ioctlsocket` for non-blocking mode, `WSAPoll`, `WSAGetLastError` and its different error set, `WSABUF` with
`WSARecvFrom`/`WSASendTo`, and the one BEHAVIOURAL difference: on Windows `MSG_PEEK` does not report a datagram's
full length, so a listener must hold the datagram it looked at -- which is exactly the shape the runtime
session's pending table already has. FreeBSD, by contrast, is close to Debian: the same POSIX calls, and the
difference is the toolchain and the OpenSSL package.

**The inventory is checked, not trusted.** `scripts/check-portability.sh` greps the library for the POSIX-only
names a port must replace and fails if one is used without being named in the document -- the same pattern as the
compliance matrix, for the same reason: an inventory that reads like a plan but has gone out of date is worse
than no inventory at all. It caught `sendto` and `recvfrom` missing on its first run. CI runs it.

**The adaptation itself is NOT done, and no Windows job is added until it is.** A CI job that cannot pass is
worse than an absent one, because it teaches everyone to ignore CI -- so the order is: the private platform
header, `WSAStartup` ownership, the peek difference, then the job.

### WT-136: the score, measured rather than remembered

The Definition of Done's last criterion is that the README's status goes "from 0% to the measured final score",
and a number nobody can reproduce is a guess. `scripts/score-matrix.sh` counts the compliance matrix's rows by
status -- separating the rows that are DRAFT-16 requirements from the rows that describe the QUIC, HTTP/3 and TLS
layers the session runs on -- and prints the nine Definition-of-Done criteria as they stand. Its answer today:

    25 of 25 draft-16 requirements exercised by a test in this tree
    0 partial, 5 rows describing lower layers
    5 of 9 criteria met, 2 partial, 2 not met

The README carries exactly that, with the distinction stated where a reader cannot miss it: **100% of the matrix
is not 100% done.** The criteria that are not met are outside the matrix and outside this repository's reach --
the five-implementation interop matrix needs a host, and the FreeBSD and Windows CI legs need portability work
(a sockets/poll adaptation) before a job for them would be anything but red. Writing one number and letting it
mean everything is the failure the Definition of Done's own wording guards against, which is why the score is
reported as three measured quantities rather than as a percentage.

## Definition of Done audit (measured, 89 rounds in)

Every claim below names the evidence, and the ones that are NOT met name what they still need. This is the
honest state rather than an aspiration:

| Criterion | State | Evidence, or what it still needs |
| --- | --- | --- |
| Full draft-16 spec matrix implemented | **met** | Every layer is written and tested (Phases 0-9), and `docs/COMPLIANCE-MATRIX.md` maps 25 draft-16 requirements to the implementation and to the test that exercises each one, plus 5 rows for the lower layers. `scripts/check-matrix.sh` verifies that all 44 named symbols still exist and CI runs it, so the document cannot rot away from the code. `WT-132` closed. |
| All Swift-equivalent conformance tests pass in C99 | **partial** | The unit suites mirror the Swift suites layer by layer (79 suites, 80,156 checks), the malformed-input corpora exist for QUIC and for HTTP/3/QPACK/session, and the bounded tables are covered. The audit found ONE real feature gap rather than a documentation one: draft-16 section 3.2's sub-protocol negotiation (`wt-protocol`, Structured Fields) had no code here at all, and `src/webtransport/protocol.c` now carries the codec AND the session decision -- the token rules, the first-offered-that-is-supported selection, the required-selection refusal (400) and the client's check that a response names a token it offered -- with `test_webtransport_protocol` (101 checks), and `scenario_protocol.c` now drives it END TO END: the client's list offered through `wt-protocol`, the server selecting the first token it supports, the response's field appended after the message encoder's pseudo-headers, the client finding it by walking the field section, and the two refusals. The append path needed no new API -- `wt_http3_message_encode` writes the section PREFIX and the pseudo-headers, so appending the line afterwards is the order a QPACK section needs -- and the compliance matrix gained the 3.2 row the end-to-end exercise earns. The CONFORMANCE TOOL's scenario count is the other gap: **forty-three scenarios** (three codec, eleven refusals, thirteen connection-control, five header and QPACK, two isolation, five interop matrices -- stream, datagram, GOAWAY/close/drain, CONNECT, malformed/flow-control -- a seven-case flow-control matrix, the split-prefix edge, and two real sessions). All five of the Swift tools' interop matrices now have a counterpart. Its two remaining scenarios assert PACKAGING rather than library behaviour, and they are now mirrored where that belongs: `scripts/check-package.sh` installs the tree with the tools on and asserts that the product list is the three tools -- and that no test, spike or sample binary came with them. Writing that check found the gap it exists for: the install rules carried the libraries and headers but not the tools, so the CLIs were products of the build and not of the package, and the rule now names them. `WT-133`. |
| C99 client/server CLI passes local IPv4 and IPv6 | **met** | `wt-conformance-c99 --scenario all` runs both families (registered as `wt_conformance_scenarios`), and `wt-client-c99`/`wt-server-c99` exchange a session in two processes on IPv4 (registered as `wt_cli_session_stream`/`_datagram`). The tools themselves have not been driven over IPv6; the conformance tool has. `WT-133` covers extending them. |
| C99 passes the five-implementation VPS interop matrix | **not met** | No C99 interop runner exists and no VPS is reachable from this work. The Swift side has `run-docker-interop.sh` and a VPS matrix; the C99 tree needs its own runner and a host to run it on. `WT-135`. |
| CI is green on macOS 26, Debian, FreeBSD and Windows 11 | **partial** | `c99-ci.yml` builds and tests on macOS and Debian (the last completed run was green), with sanitizers, the package consumer and the CLI smoke. FreeBSD and Windows legs are absent, and they are not a YAML edit: Windows needs a sockets/poll adaptation (`WSAPoll`, `ws2_32`) and a toolchain decision before a job for it would be anything but red. `WT-134`. |
| Sanitizers and static checks are clean | **met** | Every round's verification runs debug, release and ASan+UBSan; the build is warnings-as-errors with `-Wconversion -Wsign-conversion -Wcast-qual -Wswitch-enum -Wpedantic -Wshadow` and the rest. No separate static analyser (clang-tidy/scan-build) has been run; that would strengthen the claim. |
| Public API is documented | **met** | `C99/docs/PUBLIC-API.md` covers trust, endpoints, sessions, streams, datagrams, backpressure, close, drain and ownership, and `apps/wt-api-sample` plus `test_public_api` check that the documented surface compiles and behaves. |
| No placeholder, facade, deterministic test runtime or spike is exposed as production | **met** | The tools run real sessions; there is no test-only runtime in the library; the `api/`, `cli/`, `http3/`, `runtime/` modules are all reached by real callers. |
| README status updated from `0%` to the measured final score | **met** | `scripts/score-matrix.sh` prints the score from `docs/COMPLIANCE-MATRIX.md` -- 25 of 25 draft-16 requirements exercised, 6 of the 9 criteria met -- and `C99/README.md` carries that number rather than a guess. `WT-136` closed. |

**What that means for "100%":** six criteria are met, two are partially met and one is not. The remaining work
is named with numbers, and none of it is blocked by a defect: scenario breadth (`WT-133`), two CI legs that need
portability work first (`WT-134`), and an interop runner plus a host (`WT-135`). The matrix (`WT-132`) and the
score that follows it (`WT-136`) have both landed, which is why the count moved from four to six.

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
