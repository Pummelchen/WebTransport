# C99 WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-16`, dated 2026-07-06.

Draft-16 score: **0%** — the protocol is not implemented yet. What exists is the
foundation the protocol is built on, and it is real, tested code rather than
scaffolding.

## Current Status

**Phase 0 of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) is complete.**
Phases 1 to 14 are not started.

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
- 10 unit test files, 5,392 checks, run by `ctest` and again under
  AddressSanitizer and UndefinedBehaviorSanitizer. Note that Darwin has no
  LeakSanitizer, so a leak in the tests is found by the Linux CI leg and not by
  a local run on this machine; that is how the first one was found. Most of that count is two
  loops rather than two thousand hand-written cases: 4,096 of them come from
  appending a byte at a time to prove buffer growth is logarithmic, and about
  2,000 from reading a monotonic clock and checking the deadline arithmetic does
  not wrap near the counter's top. The hand-written cases are around 200.
- A package consumer test: the library is installed and a separate CMake project
  links it, which is the only way to know the install tree works.

What is not here: any QUIC, TLS, HTTP/3, QPACK or WebTransport code, the CLI
tools' actual behavior, external interoperability evidence, and the platform
runtimes.

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
