# WebTransport Swift 1.4.0

The pre-production audit's fixes, and the first release whose version is
single-sourced across both libraries.

This release ships the **Swift** products only. The portable C99 implementation in
`C99/` is built and tested on every push but is **not released** here; when it joins,
it joins this tag and these notes rather than getting its own.

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

The full ledger, per-finding evidence and the Phase E state are in the repository:
`AUDIT/ledger.md`, `AUDIT/environment.md`, `AUDIT/phaseE.md`.

Check: `swift test` reports **360 tests, 0 failures**; `ctest` reports **97/97** in the
Debug, Release and ASan+UBSan configurations.

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
- CRYPTO-stream reassembly is linear and bounded (it re-summed its consumed-byte count
  and retained every consumed byte forever); the TLS transcript is capped at 1 MiB.
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
  failing on a mismatch. The two libraries now carry the same number: the C99 side
  moves from its pre-1.0 `0.1.0` identity to 1.4.0. `WT_ABI_VERSION` and the protocol
  draft are separate axes and did not move.
- Both manifests build with warnings-as-errors and strict memory safety; the manifests
  are under the formatting gate; every workflow action is pinned to a commit SHA with
  least-privilege `permissions:`; a blocking `security-scan` workflow runs gitleaks over
  the full history and trivy over the tree.
- 185 files of committed CMake build output left the tree, the hand-maintained
  "Views (14d)" badge's data source is gone, and `THIRD_PARTY_NOTICES.md` carries the
  Apache-2.0 notice for OpenSSL, the C99 build's required dependency.

Checks: `Swift/check-toolchain.sh 6.4 27.0`, `Swift/check-manifest-sync.sh` (19 shared
targets), `Swift/check-target-imports.sh` (42 targets / 202 imports),
`Swift/check-api-compatibility.sh`, `swift format lint --strict`, and the C99
`check-*.sh` family — `check-vectors.sh` (RFC 8448/7748/9204/7541 vectors re-extracted
and compared), `check-matrix.sh` (91 named symbols/tests), `check-portability.sh`,
`check-static-analysis.sh` (94 sources, no findings), `check-cppcheck.sh`,
`check-package.sh`, `check-workflows.py`.

## What is not in this release

- **The C99 library.** Built and tested (97/97, ASan+UBSan, Windows under Wine, FreeBSD
  by hand) but not released, and its artifacts are not attached here.
- **0-RTT and resumption** are not implemented in either library; the draft-16
  compliance matrix records that as a deliberate `--` row.

## Checks that did not run for this release

Named here because "not checked, no input" and "checked and identical" are different
sentences (RELEASE.md Part 1 §1.2.7):

- The Windows cross-compile, cross-link and Wine suites are **not checked on the release
  host**, which has no mingw or Wine toolchain. They run in CI on Linux legs
  (`windows-wine` enforced, `windows-native` on `windows-latest` not yet enforced) and
  are re-run during this release from the hosts that do have them; the results are
  recorded in the release evidence rather than implied by a green build here.

## Checksums

```
SHA256: SHA256_PENDING
Bytes:  ARCHIVE_BYTES_PENDING
```

The digests are substituted at publish time from the archive that is uploaded. A dry
run's numbers are not copied here, because publishing rebuilds.
