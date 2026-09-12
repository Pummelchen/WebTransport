# C99 WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-16`, dated 2026-07-06.

Draft-16 score: **0%** — the protocol is not implemented yet. What exists is the
foundation the protocol is built on, and it is real, tested code rather than
scaffolding.

## Current Status

**Phases 0 and 1 of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) are
complete.** Phases 2 to 14 are not started.

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
- 18 unit test files and 72,577 checks, run by `ctest` and again under
  AddressSanitizer and UndefinedBehaviorSanitizer. Most of that count is the
  malformed-input corpus, which drives every parser with a fixed pseudo-random
  byte stream: a random buffer is a better generator of the case nobody thought
  of than a list of cases somebody did, and under the sanitizers an out-of-bounds
  read is a failure rather than a plausible value. Note that Darwin has no
  LeakSanitizer, so a leak in the tests is found by the Linux CI leg and not by a
  local run on this machine; that is how the first one was found.
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
    `CONNECTION_ID_LIMIT_ERROR` of RFC 9000 section 5.1.1. Most of that count is two
  loops rather than two thousand hand-written cases: 4,096 of them come from
  appending a byte at a time to prove buffer growth is logarithmic, and about
  2,000 from reading a monotonic clock and checking the deadline arithmetic does
  not wrap near the counter's top. The hand-written cases are around 200.
- A package consumer test: the library is installed and a separate CMake project
  links it, which is the only way to know the install tree works.

What is not here: TLS, HTTP/3, QPACK and WebTransport, the QUIC connection
runtime, the CLI tools' actual behavior, external interoperability evidence, and
the platform runtimes. The wire core parses and builds QUIC messages; nothing yet
decides what to send.

## Building

```sh
C99/scripts/build-and-test.sh              # Debug, build and test
C99/scripts/build-and-test.sh --release    # Release
C99/scripts/build-and-test.sh --sanitize   # Debug with ASan and UBSan
C99/scripts/build-and-test.sh --all        # all three
C99/scripts/check-package.sh               # install and build a consumer
```

Output goes under `C99/out/<platform>/`, which is gitignored; see
[out/README.md](out/README.md). The packaging entry points under
[platform/](platform/) are wrappers around the same CMake project.

## Layout

```text
include/webtransport/   public headers, installed
src/core/               the Phase 0 utilities
apps/                   wt-client-c99, wt-server-c99, wt-conformance-c99
tests/unit/             one file per module, registered with CTest
tests/package/          a consumer of the installed package
scripts/                the development loop
platform/               per-OS packaging entry points
```

The protocol phases add `src/quic`, `src/tls`, `src/crypto`, `src/http3` and
`src/runtime` beside `src/core`, and their headers under the matching
`include/webtransport/` directories, which already exist.
