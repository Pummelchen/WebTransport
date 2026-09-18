# WebTransport 1.5.1

Both libraries, one tag, one artifact each: **WebTransport 1.5.1** ships the Swift package
and the portable C99 library built for Apple Silicon (arm64), with a `.sha256` beside each
archive. This release carries the fix set that landed after 1.5.0: a wire-visible capsule
framing correction in both libraries, a Swift certificate check that now follows the
configured authority, the C99 library's first build and run under MSVC and Clang-CL, and the
CI and interop tooling that proves them.

These notes are the changelog for this release. Each change is under the library it belongs
to, and the work that is genuinely one item for both is under **Both**.

### Swift

Fixed:

- **The client verifies the server's certificate against the configured `authority`** (WT-261). `authority` was the extended CONNECT's `:authority` and nothing else, while TLS validation was the framework's, against the address the connection was opened with — the new `NetworkConnection` API exposes no TLS server-name control — so dialling an address for a name the server's certificate carried failed the handshake with a TLS alert, a case the C99 client handled routinely because its address and authority are separate parameters. The fix changes one input to the framework's own check rather than adding a check of its own: when the authority names a different host than the one dialled, the client installs `QUIC.tls.certificateValidator` and evaluates the platform's trust chain for that name with `SecPolicyCreateSSL` and the platform's own anchors, so only *which name the certificate must prove* changes and nothing about *who is trusted* does; when the two agree, the framework's validation is untouched. `WebTransportQUICPeerTrustPolicy.certificateName(endpoint:authority:)` is the decision as a pure function, so the rule is testable without a live handshake: an authority may be `host`, `host:port` or a bracketed IPv6 literal, and its host is compared case-insensitively with the dialled host reduced the same way. The interop runner now separates the two on purpose — it dials `WEBTRANSPORT_VPS_INTEROP_ADDRESS` and names `WEBTRANSPORT_VPS_INTEROP_AUTHORITY`, matching the C99 runner's variables — so the split is what the suite exercises rather than a workaround for its absence. Measured against the five VPS peers: **7 of 7** dialling `91.99.176.243` for a certificate that carries only `pummelchen.91.99.176.243.nip.io`, every proof on its first attempt; `--authority wrong.example.com` and the pre-fix behaviour of validating the dialled address are both refused, with the peer logging a TLS alert error (`0x12E` and `0x12A`). A matching name is still refused for a self-signed fixture, because the anchors were not touched. What remains is not tracker work and is recorded in Known Limitations: SNI itself still cannot be set, so a server that selects its certificate from the requested server name presents its default one.
- **A session hands its QUIC connection back when the peer closes it** (WT-85). A cleanly closed session kept its connection until QUIC idled out, because Network.framework declares no `cancel()` for a started `NetworkConnection`. The release path was measured before it was used: writing `applicationError` only stores the code and leaves the connection ready; dropping a session cancels its tasks and the peer's connection then fails within **50 ms**; and the side that must not release on its own initiative is the **closing** one, whose `WT_CLOSE_SESSION` capsule may still be in flight with the session's code and reason. So the release happens at the point that cannot overtake anything — when the session's capsule reader delivers the peer's `WT_CLOSE_SESSION`, or sees the peer end the CONNECT stream — and a clean close now ends both connections promptly instead of leaving either end holding it. A third-party peer that does not release is still entitled to keep its connection open, which the documentation says with the workaround.
- **A control stream the transport never delivered is named** (WT-221). The condition now reports `WebTransportNetworkRuntimeError.peerControlStreamNotDelivered` instead of a bare timeout, with the measured cause (13 of 1600 connections on a saturated receiver) and why a longer deadline cannot help: the stream is never resent and no other stream has to arrive for the drop to become observable. Without the name, a caller could not tell this apart from a slow peer.

Checks: `swift test` under `-warnings-as-errors -strict-concurrency=complete
-require-explicit-sendable` (393 tests), ASan and TSan, `swift format lint --strict` over both
manifests, the DocC catalog, `check-api-compatibility.sh`, `check-manifest-sync.sh`,
`check-target-imports.sh`, `check-version-sync.sh`, both CLI conformance suites at 40/40, the
library smoke pair, 20000 parser-fuzz iterations under ASan, and the arm64 release build.

### C99

Fixed:

- **A client that selects a zero-length connection ID is answered** (WT-258). RFC 9000 section 5.1 permits a zero-length connection ID, and section 5.1.1 uses a zero-length *Destination* Connection ID in every packet sent back to such an endpoint; the listener required a non-empty one before it would learn the peer, so it dropped every datagram from a client that chose one and reported only a timeout. The packet was the evidence — a relay capture of the first datagram showed the source length byte `0x00` — and it came from the second independent client (below), not from a synthetic case. The listener now requires only the **destination** connection ID, which section 7.3 makes mandatory and which the client checks back as `original_destination_connection_id`.
- **The tools' capsule bound is per capsule, not per delivery** (WT-257). A close carrying the draft's maximum 1024-byte reason is 1032 bytes of capsule and fits comfortably in one DATA frame, but the bound was applied to the delivery, so the session closed with `H3_EXCESSIVE_LOAD` (`0x107`), and so did any DATA frame carrying more than the buffer of smaller capsules. Reproduced first — the new scenario failed as `refused=1, error=0x107, serverClosed=1` — then the walker takes what fits and walks again while bytes remain, and its buffer clears the draft's largest capsule.
- **The static archive and the DLL's import library stop claiming one file, and the DLL says what it exports** (WT-260). Both libraries are named `webtransport`, and on Windows a shared library's import library is named after the DLL, so the static archive and the DLL's import library were the same `webtransport.lib` — which Ninja refuses outright, and mingw never showed because its import library is `libwebtransport.dll.a`. The static archive is `webtransport_static.lib` where the collision exists (MSVC and clang-cl); the DLL and its import library keep the names a Windows consumer expects, and every other platform is unchanged. The DLL itself had exported **nothing**: mingw's `--export-all-symbols` had been exporting every symbol by accident of the toolchain, and MSVC wrote an import library with no symbols, so `WINDOWS_EXPORT_ALL_SYMBOLS` now makes CMake generate the module-definition file from the objects — which covers the functions, but not a data symbol, so `WT_QUIC_DATA` carries the standard `dllexport`/`dllimport` pair keyed on `WT_BUILDING_SHARED_LIBRARY`/`WT_LINKING_SHARED_LIBRARY` for `wt_quic_initial_salt_v1`, whose consumer needs `dllimport` because a data reference has no import-library thunk. The property is scoped to `WIN32 AND NOT MINGW`, because asking CMake for a module definition on mingw **replaces** its implicit export-all and left internal functions unexported, which broke both mingw legs until it was scoped.

Added:

- **A second independent client, quic-go with webtransport-go** (`WT-153`). One client is not a matrix: a server that happened to suit aioquic's habits would look correct. `C99/tests/interop/peer/go-client/` is a different language, a different QUIC stack and a different WebTransport layer, built as a container image and driven by `C99/scripts/run-container-interop-server.sh` beside pywebtransport/aioquic; both complete a session, exchange the message in both directions, and the server reads the peer's close capsule. It found WT-258 on its first run.

Changed:

- **MSVC and Clang-CL now build and pass the suite** (WT-260), which is the plan's Phase 12 matrix complete on every compiler it names. Both Windows legs had used mingw GCC, so `cl` and `clang-cl` had never built this tree; making them pass took seven defects no POSIX compiler can report, and the two jobs are now in `c99-ci.yml` rather than a dispatch-only probe, so a regression in either compiler fails a pull request: the `webtransport.lib` collision above; an uninitialized `const` array (`wt_tls13_zeros`, C99 6.7.9p3, MSVC C4132); the MSVC CRT's deprecation of portable C (`getenv`, `fopen`, answered once with `_CRT_SECURE_NO_WARNINGS`/`_CRT_NONSTDC_NO_DEPRECATE` in `wt_set_c99`); `rpcndr.h` defining `small` as a macro, which renamed two receive buffers in `test_windows_udp.c`; a libFuzzer probe that applied `-fsanitize=fuzzer,address` but tested only `-fsanitize=fuzzer` and read MSVC's exit status for a command MSVC did not understand; the DLL that exported nothing; the data symbol whose consumer needs `dllimport`; and the corpus helper `run_file`, unused where `WT_FUZZ_NO_CORPUS` compiles the corpus out. The probe workflow that found them is deleted.
- **Every packaging script clears its build and install directory** (WT-253). `out/<platform>/{build-install,install}` was never cleared, so after a version bump the previous version's library was still there and the release archive shipped both: the first 1.5.0 dry run produced an archive containing `libwebtransport.1.4.0.dylib` *and* `libwebtransport.1.5.0.dylib` (618,971 bytes) where a clean build gives 500,238. All three scripts now `rm -rf` their pair before configuring, per script rather than in a shared helper, because each wrapper owns its own `out/<platform>` pair and is that platform's entrypoint. Reproduced before fixing with a planted stale dylib; after the fix only the current version remains and `check-package.sh` passes.
- **The interop environment is reproducible from the repository, and the proofs are 7 of 7 again** (WT-196, WT-254, WT-255). The environment lived only on one host and no longer produced its full result. The erlang failure was a **stale image**, not a trust problem: `erlang-webtransport` keeps only the first certificate in the PEM, and the image serving port 54007 predated `tests/interop/peer/patch-erlang-chain.py`, so it served the leaf alone; rebuilt from the patched source, all five published ports verify. The single quinn stream timeout did not reproduce, and the summary is `passedProofCount 7`, `requiredProofCount 7`, `allPassed true`, `failedProofs []`, every proof on its first attempt under `--trust system`. What was only on the host is now in the tree: the Caddy site block that obtains and renews the certificate, `deploy-vps-peers.sh` (which builds and starts all five endpoints from the committed contexts over pinned upstream revisions, measured cold at 7 m 38 s), `reset-vps-peers.sh` — the real implementation of a variable the runner had only been *reading* — and the certificate sync that compares Caddy's store with the two places the peers read, refuses a mismatched pair and restarts only on a change (proved on the host: a no-op when unchanged, and a repair of both destinations in 27.5 seconds after one file in each was corrupted).
- **The container interop runners build and run again** (WT-259). Both built from `tests/interop/client/Dockerfile` with `C99/` as the context, and that file configures `-S /src/c99`, whose lockstep gate reads `../VERSION` at the repository root, so the configure failed before anything compiled. With the context fixed, the client-direction runner still failed because it never passed `--upgrade-token`, so it offered the draft-16 `webtransport-h3` to peers that predate the rename and every one refused the CONNECT before reading anything else. Neither runner is in CI, which is why nothing had noticed.
- **The Definition-of-Done audit and the score say what is measured** (WT-256). The audit was stale and `score-matrix.sh` printed it as current: it claimed "all seven Phase 11 proofs" and scored the interop criterion **met** against 5 of 7 reproducible at the time, and its counts disagreed with the tree. It now reads 39 of 40 draft-16 requirements exercised with one `partial` (Origin policy, which the library exposes and leaves to the application) and 9 of 9 criteria met; the score is counted from the audit's own State column rather than asserted in prose.

Checks: `C99/scripts/build-and-test.sh` in Debug, Release and ASan+UBSan (97 CTest tests each),
the conformance tool at 57 scenarios over IPv4 and IPv6, `check-vectors.sh`,
`check-matrix.sh`, `check-portability.sh`, `check-static-analysis.sh`,
`check-cppcheck.sh`, `check-package.sh` (which builds a consumer of the installed package and
runs all three installed tools), `check-workflows.py`, `check-windows-platform.sh`,
`check-windows-build.sh` and `check-windows-wine.sh` on the CI legs, and the mingw
`-Werror` link.

### Both

Changed:

- **A capsule on the CONNECT stream travels inside an HTTP/3 `DATA` frame** (WT-249, both libraries). RFC 9297 section 3.1 makes the capsule protocol the *contents of a request's data stream*, and RFC 9114 section 4.4 permits only `DATA` frames on a stream that carried CONNECT; writing the capsule TLV straight to the stream therefore put a frame of an **unknown type** on the wire, which section 9 requires the peer to ignore. The capsule was dropped in silence and interop passed anyway, because both directions were dropped — which is also why the credit and the close went missing. Writing now wraps the capsule in a `DATA` frame and reading takes capsules from `DATA` payloads, concatenated across frame boundaries, with an unknown frame skipped as section 9 requires and a known non-`DATA` frame refused with `H3_FRAME_UNEXPECTED`; a `DATA` frame's payload moves through in chunks, so a huge announced frame is never buffered whole, and the old raw form is still tolerated on receipt because a peer that is skipped must not be refused. The C99 half adds the reservation-and-wrap pair (`wt_http3_frame_data_writer`, `wt_http3_frame_wrap_data_in_place`) that makes it possible in one buffer, since a capsule carries its own length and the header cannot be written first. All five interop peers wrap their own — Quinn says so in a comment, aioquic writes the `DATA` header, Chromium's quiche writes it in `WriteOrBufferBody` — and their readers take capsules from `DATA` payloads only. The Swift and C99 suites each assert the framed form byte for byte, and the raw form being ignored rather than refused.
- **FreeBSD is a CI job rather than a by-hand measurement** (WT-223). Phase 12 names FreeBSD, GitHub provides no FreeBSD runner, and the platform was measured by hand on a real kernel — real evidence, but evidence no pull request could fail on. `vmactions/freebsd-vm` boots a FreeBSD 15.1 VM on an Ubuntu runner and runs the project's own configure, build and `ctest` there, with `cmake ninja python3` installed from FreeBSD's packages (`python3` because the first hand-run found that harness dependency the hard way) and OpenSSL 3 plus the C compiler from the base system. The hand measurement is not displaced: it stays the record of what was run on a real kernel, and this is the gate that keeps it true.
- **The security scan's remaining findings are settled rather than suppressed in the dark.** gitleaks' `generic-api-key` rule read the `--all-curves` help text as a label and a value, because the sentence begins a clause with "key" and the next token is the name of a post-quantum key-agreement group; the help text is reworded, and the finding — which lives in the commit that added it, since gitleaks scans the full history — is recorded in `.gitleaks.toml` with path **and** secret both required to match. The Go interop client moves to `webtransport-go` 0.11.1, which fixes CVE-2026-57497 (memory exhaustion from buffering unknown capsules), and its `golang.org/x/*` dependencies and builder image follow; the one unfixed advisory is written down rather than ignored. Two Trivy findings in the peer images (DS-0002, DS-0026) are accepted explicitly.
- **The release notes are the changelog, split `Swift` / `C99` / `Both`** (`c727076`, `RELEASE.md`). There is no separate changelog file: each release's notes are organised so a reader of one library does not have to filter the other's entries out, and a change that is genuinely one item — a wire fix made on both sides for the same RFC reason, the version lockstep, repository-wide tooling — is one entry under `Both` with both halves named rather than two entries. The split starts with 1.5.0; earlier releases keep the form they were published with.

Checks: CI on the released commit — Swift CI, C99 CI (macOS, both Ubuntu legs, Debian 13,
Wine, the enforced native Windows leg and the new FreeBSD VM job) and the security scan — all
green; the Swift VPS interop suite and the C99 VPS interop suite each 7 of 7 under system
trust against the five independent implementations.

## What is not in this release

- **0-RTT and session resumption** are not implemented, in either library.
- **The HTTP/2 capsule binding** is not implemented; this is WebTransport over HTTP/3.
- **Server push and connection migration** are out of scope for this implementation. HTTP/3 push is refused deterministically rather than ignored, and a connection has one peer address.
- The Swift package is macOS-only and needs macOS 26+, Xcode 27 and Swift 6.4; the shipped binaries are arm64 only and are not notarized.
- The **Swift `SETTINGS_WT_INITIAL_MAX_*` flow-control limits are not negotiated by the Network.framework runtime**, which serves one WebTransport session per connection; the C99 library negotiates them.

## Checks that ran elsewhere, and what did not run

Not run on the release machine, and reported as not checked rather than assumed: the Wine
suite runs on the Linux CI host (Wine is not installable on this machine), the FreeBSD suite
runs in the VM job, and there is no LeakSanitizer on Darwin. The VPS interop suites need the
routable host and its peer containers; the Swift and C99 results quoted above are the
recorded runs on this source, not a re-run at publish time. The MSVC and Clang-CL legs run on
`windows-latest`.

## Checksums

```
WebTransport-swift-1.5.1-macos-arm64.tar.gz
  SHA256: SHA256_PENDING
  Bytes:  ARCHIVE_BYTES_PENDING

WebTransport-c99-1.5.1-macos-arm64.tar.gz
  SHA256: C99_SHA256_PENDING
  Bytes:  C99_ARCHIVE_BYTES_PENDING
```
