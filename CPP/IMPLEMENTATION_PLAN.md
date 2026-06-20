# C++23 WebTransport Implementation Plan

This plan describes how to build the portable C++ implementation from the completed Swift implementation.

Target protocol: `draft-ietf-webtrans-http3-15`  
Language standard: ISO C++23  
Supported platforms: macOS 26, Debian Linux, FreeBSD, Windows 11  
Build system: CMake  
License: MIT

## Goal

Build a pure C++23 WebTransport over HTTP/3 implementation that reaches the same draft-15 behavior and interop evidence as the Swift implementation.

Required outputs:

- Production library with public client/server API.
- `wt-client` CLI.
- `wt-server` CLI.
- `wt-conformance` CLI.
- Unit, integration, fuzz/property, process, IPv4/IPv6, and external interop tests.
- Cross-platform CI and release artifacts.

## Architecture Map

| Swift module | C++ equivalent |
| --- | --- |
| `WebTransportQUICCore` | `webtransport::quic` |
| `WebTransportTLSCore` | `webtransport::tls` |
| `WebTransportCryptoApple` | `webtransport::crypto` |
| `WebTransportHTTP3Core` | `webtransport::http3` |
| `WebTransportNetworkRuntime` | `webtransport::runtime` |
| `WebTransport` | `webtransport::api` |
| `WebTransportClient` / `WebTransportServer` | `wt-client` / `wt-server` |
| Swift conformance harness | `wt-conformance` |

## Repository Layout

```text
CPP/
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
    wt-client/
    wt-server/
    wt-conformance/
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

## Dependency Policy

Use the C++23 standard library wherever possible.

Production dependencies:

- CMake 3.28 or newer.
- OpenSSL 3.x for crypto primitives, X.509 parsing, certificate validation, HKDF, AEAD, and signature verification.
- Standalone Asio or native socket backends behind one runtime abstraction.

Do not use an existing QUIC, HTTP/3, QPACK, or WebTransport library for the production core. Those projects remain external interoperability targets only.

Platform runtime targets:

- macOS 26: BSD sockets or a portable UDP backend, OpenSSL via Homebrew or bundled release build.
- Debian Linux: epoll-capable UDP runtime, system OpenSSL.
- FreeBSD: kqueue-capable UDP runtime, OpenSSL/LibreSSL compatibility reviewed early.
- Windows 11: IOCP/WSA UDP runtime, OpenSSL through vcpkg or bundled release build.

## Error and API Policy

Use explicit result types internally. Prefer `std::expected` when available and a project-local `webtransport::Result<T>` compatibility wrapper otherwise.

Requirements:

- No hidden ownership through raw pointers.
- RAII for sessions, streams, sockets, TLS identities, and packet keys.
- No unbounded peer-controlled allocations.
- No sensitive values in public errors or production logs.
- Prompt-free certificate/trust failures.
- Test-only trust modes must be explicit and loopback-limited.

## Phase 0: Foundation

Create the C++ project skeleton.

Tasks:

- Add `CPP/CMakeLists.txt`.
- Add library targets for `webtransport_quic`, `webtransport_tls`, `webtransport_crypto`, `webtransport_http3`, `webtransport_runtime`, and `webtransport`.
- Add executable targets for `wt-client`, `wt-server`, and `wt-conformance`.
- Add compiler matrix support for Clang, GCC, MSVC, and Clang-CL.
- Add warnings-as-errors configuration.
- Add core utilities: byte buffer, span helpers, endian helpers, result/error types, logging surface, and clock/time abstractions.

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

Port the Swift TLS behavior into a portable C++ TLS state machine.

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

Tests:

- SETTINGS round-trip and malformed SETTINGS.
- Control stream duplicate and request-frame errors.
- Request stream invalid IDs, duplicate headers, and forbidden data.
- GOAWAY drain behavior.

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

Tests:

- Mirror Swift QPACK tests.
- Add RFC vectors.
- Add malformed dynamic refs.
- Add malformed length tests.
- Add invalid table reference tests.

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

- C++ conformance matrix matches the Swift draft-15 matrix.
- All required session, stream, datagram, close, drain, flow-control, and error paths are covered by passing tests.

## Phase 8: Public C++ API

Design the production C++ API after the protocol core is stable.

Example shape:

```cpp
webtransport::ClientConfig config;
config.authority = "example.com";
config.path = "/wt";
config.origin = "https://example.com";
config.protocols = {"demo.v1"};

auto client = webtransport::Client::create(config);
auto session = co_await client->connect({"example.com", 443});
auto stream = co_await session->open_bidirectional_stream();
co_await stream->send("hello", webtransport::EndStream::yes);
auto response = co_await stream->receive();
```

API requirements:

- RAII lifecycle.
- Coroutine-friendly async API.
- Synchronous CLI wrappers.
- Clear cancellation.
- Backpressure-aware streams and datagrams.
- Explicit close/drain operations.
- Sanitized error surface.
- No placeholders or in-process facades exposed as production API.

Completion criteria:

- Public sample app compiles on all target platforms.
- Public API documentation covers trust, endpoints, sessions, streams, datagrams, backpressure, close, and drain.

## Phase 9: CLI Apps

Implement CLI apps that mirror the Swift tools.

Targets:

- `wt-client`
- `wt-server`
- `wt-conformance`

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

Mirror Swift tests into C++.

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

- Catch2 or GoogleTest.
- CTest for all runners.
- libFuzzer/AFL++ for parser fuzzing where available.

Completion criteria:

- `ctest` passes locally.
- CI passes on macOS, Linux, FreeBSD, and Windows.

## Phase 11: External Interop

Reuse the five independent VPS endpoints already installed under `/var/webtransport`.

Add:

```sh
CPP/scripts/run-vps-third-party-interop.sh
```

Required C++ proof matrix:

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

- C++ client proves real external interoperability against all five implementations.
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

Audit the implementation before public release.

Required checks:

- ASan clean.
- UBSan clean.
- TSAN clean where feasible.
- Parser fuzzing for QUIC varints, QUIC frames, transport parameters, HTTP/3 frames, QPACK, capsules, and WebTransport stream prefixes.
- Static analysis with clang-tidy.
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

- Update `CPP/README.md` with actual C++ status.
- Add generated API docs.
- Update root README status table.
- Update `CHANGELOG.md`.
- Generate release artifacts for all supported platforms.
- Publish SHA256 checksums.
- Add external interop proof table.
- Tag/release when C++ reaches the milestone.

Completion criteria:

- C++ can be consumed as a normal CMake package.
- Release artifacts are reproducible.
- Public docs match actual behavior.

## Definition of Done for C++ 100%

The C++ implementation can be marked 100% only when all of the following are true:

- Full draft-15 spec matrix is implemented.
- All Swift-equivalent conformance tests pass in C++.
- C++ client/server CLI passes local IPv4 and IPv6.
- C++ passes the five-implementation VPS interop matrix.
- CI is green on macOS 26, Debian, FreeBSD, and Windows 11.
- Sanitizers and static checks are clean.
- Public API is documented.
- No placeholder, facade, deterministic test runtime, or spike source is exposed as production.
- README status is updated from `0%` to the measured final score.

## Suggested Execution Order

1. Build system and project skeleton.
2. QUIC varints, frames, and packets.
3. Crypto and packet protection.
4. TLS 1.3 QUIC handshake.
5. QUIC connection runtime.
6. HTTP/3.
7. QPACK.
8. WebTransport session logic.
9. Public API.
10. CLI apps.
11. Local conformance tests.
12. VPS third-party interop.
13. CI and platform hardening.
14. Documentation and release polish.
