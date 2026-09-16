# WebTransport 1.4.0

The pre-production audit's fixes, the first release whose version is single-sourced,
and the first that carries **both libraries** of this repository.

This is one project's release, not one library's. The Swift package and the portable
C99 library carry the same version (`1.4.0`), ship under one tag, and are described
together here; the source of both is on this Release as
**Source code (tar.gz)** / **Source code (zip)** for the tag.

| Asset | What it is |
| --- | --- |
| `WebTransport-swift-1.4.0-macos-arm64.tar.gz` | the Swift products: `WebTransportClient`, `WebTransportServer`, `SHA256SUMS`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `README-binaries.txt` |
| `WebTransport-c99-1.4.0-macos-arm64.tar.gz` | the C99 library: `libwebtransport.1.4.0.dylib` + `libwebtransport.a`, 64 public headers, the `find_package` CMake package, the three `wt-*-c99` tools, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `README-binaries.txt` |
| each `….tar.gz.sha256` | the digest of the archive beside it |

`lipo -archs` reports exactly `arm64` for every Mach-O in both archives — the two
Swift products, the C99 dylib, the C99 static library and the three C99 tools — and
the release script asserts that before packaging. Neither archive is Developer ID
signed or notarized; each `README-binaries.txt` says so and gives the quarantine
command. The C99 dylib additionally requires the platform's **OpenSSL 3** at runtime
(macOS ships LibreSSL, not OpenSSL 3), which its `README-binaries.txt` states with the
path this build resolved.

## The pre-production audit landed

A full audit of both implementations — 108 findings, 99 fixed and verified, the rest
recorded with their reasons — is on `main` and in this release. The four S0s, each with
a regression test:

- the Swift 6.4 test bundle did not link (`WebTransportTLSCore` was an implicit
  dependency);
- the CONNECT-stream capsule reader could be driven into remote memory exhaustion: a
  peer's declared capsule payload was buffered whole before anything checked it, and
  `maximumConnectStreamCapsulePayloadBytes` (1028) is now enforced before the buffer
  grows, so an oversized `WT_CLOSE_SESSION` is an `H3_MESSAGE_ERROR` on that stream;
- ten QPACK static-table entries were truncated at RFC 9204's line wrap, and the
  `--check` written to catch that re-derived the same error and could not fail;
- the draft-16 `:protocol` token was defined as the HTTP/2 capsule token, so
  `webtransport-h3` was neither sent nor accepted.

The audit that produced this release kept a ledger, per-finding evidence and environment notes in the
tree; that working material has since been removed so a later audit does not read a finished pass as a
live one. It remains in the repository's history at this release's own commit (`509fa91`) and the audit's
merge commit `6607d71`.

Check: `swift test` reports **360 tests, 0 failures**; `ctest` reports **97/97** in the
Debug, Release and ASan+UBSan configurations.

## The C99 library, now in the release

The C99 tree is built and packed by `C99/platform/macos26/compile-dylib.sh` (Part 2's
named builder for this platform) and was previously only built and tested. It is
complete as an implementation: the QUIC wire core and crypto layer with vectors
extracted from the RFCs, the TLS 1.3 handshake, the QUIC connection runtime, HTTP/3,
QPACK including its dynamic table, the draft-16 WebTransport session layer and the
public consumer API.

- Its identity is observable from the artifact alone: the archive carries the
  version-stamped `libwebtransport.1.4.0.dylib` and its symlinks, and
  `wt_version_string()` returns `1.4.0`.
- `WT_ABI_VERSION` and `wt_protocol_draft()` are separate axes and did not move with
  this release.
- The archive's `README-binaries.txt` names the OpenSSL 3 runtime dependency and the
  path the build resolved, because the library is deliberately not bundled with it (the
  project's documented decision is that the platform supplies it, so fixes arrive
  through the distributor).

Checks: `C99/scripts/build-and-test.sh --all` — **97/97 CTest** in Debug, Release and
ASan+UBSan, 0 warnings; `check-vectors.sh` (RFC 8448/7748/9204/7541 vectors
re-extracted and compared), `check-matrix.sh` (91 named symbols/tests),
`check-portability.sh`, `check-static-analysis.sh` (94 sources, no findings),
`check-cppcheck.sh`, `check-package.sh` (the installed package builds a consumer),
`check-workflows.py`, and the three Windows gates (see below).

## New public API: peer-initiated unidirectional streams

- `WebTransportSession.acceptUnidirectionalStream(maximumInitialBytes:)` returns a
  `WebTransportUnidirectionalStream`, with the runtime equivalents on
  `WebTransportNetworkSession`. A peer-initiated unidirectional stream previously had
  no consumer at all: it was queued, and the queue grew until it refused.
- The type is **receive only** — the stream identifier and `receive(maximumBytes:)`,
  no send path — and a prefix naming another session is refused with `sessionGone`
  before the stream is registered or buffered, as the bidirectional path already did.
- `WebTransportLogText.escaped(_:)` escapes backslash, quote, CR, LF, HTAB and every
  other C0 control and DEL, for peer-controlled text in operator output.

Check: the audit added 52 tests (308 → 360); both the new API's tests and the
`F-swift-line-security-03` ceiling (`refusedQueueFull(limit: 16)`) are in that count.

## Capability and bound corrections

- `datagramsAvailable` — and therefore the capability `echo()` reports — follows
  `SETTINGS_H3_DATAGRAM` from both endpoints instead of being a constant `true`.
- `receive(maximumBytes:)` honours its bound when the stream already holds a buffered
  initial payload, and keeps the remainder for the next read.
- `maxConcurrentConnections` is `Int?`: `nil` is the only "not supplied", so an
  explicit `16` is no longer read as the old sentinel.
- The per-connection inbound-stream queue is bounded by the advertised WebTransport
  stream limits, and a full queue is refused explicitly rather than growing without
  bound; teardown resets only the stream halves this endpoint owns.
- CRYPTO-stream reassembly is linear and bounded; the TLS transcript is capped at 1 MiB.
- `FINAL_SIZE_ERROR` is reachable: the checks ran after the gate that already returned.
- The QUIC short-header decoder validates its reserved bits, as the long-header and
  Retry decoders did.
- The HKDF-Expand-Label block counter refuses output past RFC 5869's cap instead of
  wrapping, and an Ed25519 key name no longer maps to an EC key type.

Checks: `swift test` under AddressSanitizer (360 tests) and Thread Sanitizer (338 —
the CI job skips `CLIProcess`/`ReleaseArtifacts`, whose wall-clock timeouts TSan's
slowdown blows through), plus the regression test each finding carries.

## Toolchain, gates and repository hygiene

- **Swift 6.4 / Xcode 27** is the floor in both manifests
  (`swift-tools-version: 6.4`), in `Swift/check-toolchain.sh`, and in the README; the
  macOS jobs run on the `xcode-27` image. Two things the compiler made explicit were
  fixed rather than suppressed: 12 redundant `unsafe` effect markers, and the
  `WebTransportHTTP3CoreTests` dependency on `WebTransportTLSCore`.
- **The version is single-sourced.** `VERSION` at the repository root is authoritative,
  mirrored in `C99/include/webtransport/version.h` and
  `Swift/Sources/WebTransport/WebTransportVersion.swift`, with
  `Swift/check-version-sync.sh` (bump: `--write`) and the C99 CMake configure both
  failing on a mismatch. This is what makes "one repository, one version" true rather
  than aspirational: the C99 side moves from its pre-1.0 `0.1.0` identity to 1.4.0.
- C99 changes in this release include the QPACK static table, the `:protocol` token,
  the stream-table counters, transport-parameter validation, the Windows monotonic
  clock, capsules arriving after `WT_CLOSE_SESSION`, and the HTTP/3 field-name and
  field-value grammar.
- Both manifests build with warnings-as-errors and strict memory safety; the manifests
  are under the formatting gate; every workflow action is pinned to a commit SHA with
  least-privilege `permissions:`; a blocking `security-scan` workflow runs gitleaks over
  the full history and trivy over the tree.
- 185 files of committed CMake build output left the tree, and
  `THIRD_PARTY_NOTICES.md` carries the Apache-2.0 notice for OpenSSL, the C99 build's
  required dependency.

Checks: `Swift/check-toolchain.sh 6.4 27.0`, `Swift/check-manifest-sync.sh` (19 shared
targets), `Swift/check-version-sync.sh`, `Swift/check-target-imports.sh` (42 targets /
202 imports), `Swift/check-api-compatibility.sh`, `swift format lint --strict`.

## What is not in this release

- **0-RTT and resumption** are not implemented in either library; the draft-16
  compliance matrix records that as a deliberate `--` row.
- The C99 library's **FreeBSD and native-Windows CI legs** are not jobs yet (the code
  on those platforms is measured by hand; see the Windows gates below).

## Checks that ran elsewhere, and what did not run

Named here because "not checked, no input" and "checked and identical" are different
sentences (RELEASE.md Part 1 §1.2.7):

- **The three Windows C99 gates ran in full, but not all of them on the release host.**
  That host has no Wine and cannot get one: every Homebrew Wine cask is disabled
  ("does not pass the macOS Gatekeeper check", disabled 2026-09-01), and no unsigned
  Wine build was improvised for a release. So:
  - `check-windows-platform.sh` and `check-windows-build.sh` ran **on the release host**
    (macOS, mingw-w64 14.0.0 / GCC 16.2.0): the `_WIN32` branch, all 76 library sources
    and all 108 test and app sources compile with the warning subset as errors, and the
    tree links into 91 PE32+ executables and one shared library.
  - `check-windows-wine.sh` ran on the **Linux host the enforced CI leg uses**, against
    this exact commit: **85 test executables, 85 passed, 0 failed, 0 hung, 64,900
    checks.** The release host's copy of that gate reports `unsupported -- no Wine on
    this machine` and is not counted as a pass.
- Nothing else was waived, skipped or left unchecked for this release.

## Checksums

```
WebTransport-swift-1.4.0-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.4.0-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```

Both digests are substituted at publish time from the archives that are uploaded. A dry
run's numbers are never copied here, because publishing rebuilds.
