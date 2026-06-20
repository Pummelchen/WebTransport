# C99 WebTransport Implementation Plan

This plan describes how to build a portable C99 implementation from the completed Swift implementation.

Target protocol: `draft-ietf-webtrans-http3-15`
Language standard: ISO C99
Supported platforms: macOS 26, Debian Linux, FreeBSD, Windows 11
Build system: CMake
License: MIT

## Goal

Build a pure C99 WebTransport over HTTP/3 implementation that reaches the same draft-15 behavior and external interoperability evidence as the Swift implementation.

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

## Phase 7: WebTransport Draft-15 Core

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
- Implement complete draft-15 error mapping.

Completion criteria:

- C99 conformance matrix matches the Swift draft-15 matrix.
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

- Full draft-15 spec matrix is implemented.
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
