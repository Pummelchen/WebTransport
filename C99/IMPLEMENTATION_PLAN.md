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

What remains in this phase: the server side of the same handshake, which needs a certificate
and key to sign with and the flight-building order that mirrors the client's checks.

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
