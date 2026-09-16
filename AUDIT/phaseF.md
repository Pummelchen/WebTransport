# Phase F — third-pass audit (Swift 6.4 / Xcode 27 and C99), with fixes

This is the record of the third audit pass over the same repository, run after `1.4.0` shipped. Unlike
Phase E, this pass was asked to **fix** what it found, so the findings here carry a fix status and, where
the fix is landed, a commit. The two full audit reports are committed verbatim beside this file:

- `AUDIT/third-pass-swift.md` — the Swift 6.4 audit report (135 lines).
- `AUDIT/third-pass-c99.md` — the C99 audit report including its addendum (399 lines).

Nothing in either report has been edited; where this file and a report disagree, the report is the evidence
and this file is wrong.

## Method

Two independent agents audited one side each, read-only, in parallel, against a frozen tree. The protocol
given to both was the same: execute the checks rather than read for them, keep every scratch artefact under
`/tmp`, never modify the repository, and report a finding only with the command and the observed output —
or mark it `unfinished`/`suspected` and say so. The lead auditor (this session) held the fix queue, reserved
the codec files for its own fixes, and ran the second pair of agents that implemented the runtime/API fixes
under a no-commit rule, so every change was reviewed and committed centrally.

### Tree integrity

| Claim | Evidence |
| --- | --- |
| Both agents read the same source | `git rev-parse HEAD` → `46937e29eb734887ca7b739abfedaf68ae565de2`; the Swift agent started at `6be4315` and `git diff --stat 6be4315..46937e2 -- Swift/ Package.swift` is empty, so only `AUDIT/` moved under it |
| Neither agent modified the repository | `git status --porcelain` empty, `git diff --name-only HEAD` empty, `git ls-files --others --exclude-standard` empty, at report time, from both agents |
| Build output stayed out of the tree | both used gitignored `C99/out/audit-r1/*` and `/tmp/sa-*`, `/tmp/ca-*` |

## Findings register

Severity is the report's; `P1` = wire-visible/interop. The ledger (`AUDIT/ledger.json`) is authoritative for
the full text of each entry; this table is the index. `WT` numbers are the tracker rows.

| WT | Sev | Side | Location | Finding | Fix status |
| --- | --- | --- | --- | --- | --- |
| WT-1 | P2 | Swift | `Swift/…/QUICPacket.swift` (Retry decode) | The Retry Integrity Tag was never computed or verified, and the packet type did not retain the original Destination Connection ID verification needs | **fixed + verified** (5818448) -- `QUICRetryIntegrityTag` (RFC 9001 section 5.8 key/nonce, `AES.GCM.open` so the comparison is constant-time), CryptoKit-free `encodedWithoutIntegrityTag()` and `integrityPseudoPacket(...)`, and a decode that returns a packet only when the tag validates; asserted against the RFC's own A.4 vector |
| WT-227 | P1 | Swift + C99 | `Swift/…/QUICPacket.swift:214`, `C99/src/quic/packet.c:466` | A Retry's `Unused (4)` field was required to be zero, so a conformant server's Retry was refused — including RFC 9001 A.4's own packet, which begins `0xff` | **fixed + verified** (9d13d19 C99, 5818448 Swift) -- the check is gone from both decoders; the Swift type now retains the nibble so the pseudo-packet is the packet that arrived. Found independently by the lead auditor (probe against the repository's own extracted vector) and by the C99 agent as `CAUD-8` |
| WT-228 | P3 | Swift | `Swift/…/QUICPacket.swift:77` | `QUICLongHeaderPacket.decode` reads the reserved bits and packet-number length from a first byte that RFC 9001 §5.4 header-protects, with no stated precondition, and refuses where C99 reports (`WT-167`) | **fixed (documented)** (5818448) -- the precondition is now part of the API doc; no public shape change, because the codec has no AEAD layer to authenticate with |
| WT-229 | P2 | C99 | `C99/src/api/session.c` | The public capsule entry point had no session-termination gate and accepted a non-zero-length `WT_DRAIN_SESSION`, disagreeing with the machine walker on the same bytes | **fixed + verified** (9d13d19) -- the public capsule entry point applies the machine walker's two checks before the lookup; see fix log |
| WT-230 | P2 | C99 | `C99/src/api/events.c` | After termination the API still delivered stream and datagram events to the consumer | **fixed + verified** (9d13d19) -- the four feed functions are gated on the machine state being non-CLOSED, before the callback; see fix log |
| WT-231 | P2 | C99 | `C99/src/webtransport/session_request.c` | `:scheme` was required to be present but never required to be `https` (§3.2 MUST) | **fixed + verified** (9d13d19) -- the scheme is compared to `https` ASCII-case-insensitively (RFC 3986 section 3.1), so `HTTPS` still passes; see fix log |
| WT-232 | P2 | C99 | `C99/src/webtransport/capsule.c` | The 2^60 stream-count ceiling was unenforced for `WT_STREAMS_BLOCKED`/`WT_MAX_STREAMS`, and the writers emitted forbidden values | **fixed + verified** (9d13d19) -- one `WT_WEBTRANSPORT_MAX_STREAMS_VALUE` ceiling covers both capsule families and both directions; see fix log |
| WT-233 | P3 | C99 | `C99/src/webtransport/capsule.c:148,153` | `wt_webtransport_close_session_parse` dereferenced a NULL capsule value (ASan SEGV; not peer-reachable) | **fixed + verified** (9d13d19) -- a NULL capsule value is refused before the length/UTF-8/code reads; see fix log |
| WT-234 | P3 | C99 | `C99/src/http3/message.c:183-191` | The response-status encoder wrote values its own decoder refuses (`:status: 005`) | **fixed + verified** (9d13d19) -- the status encoder is bounded to 100..599 (RFC 9114 section 4.3.2); see fix log |
| WT-235 | P3 | C99 | `C99/src/webtransport/session_request.c`, `include/…/http3/message.h` | Origin is never verified and the API cannot see it (§3.2) | **fixed + verified** (4a50c21) -- `wt_http3_message_field` makes Origin readable; the library exposes the value and leaves which origins are acceptable to application policy; see fix log |
| WT-236 | P2 | C99 | `C99/src/http3/settings.c` | `SETTINGS_H3_DATAGRAM` accepted values other than 0/1 and treated them as enabled (RFC 9297 §2.1.1) | **fixed + verified** (4a50c21) -- both the setter and the parser apply the 0/1 rule with H3_SETTINGS_ERROR; see fix log |
| WT-237 | P3 | C99 | `C99/src/http3/headers.c`, `message.c` | An extended CONNECT with `:protocol` but no `:path` passed message validation (RFC 8441 §4) | **fixed + verified** (4a50c21) -- the `:scheme`+`:path` requirement belongs to any request carrying `:protocol`, and the plain CONNECT keeps its exemption (which also fixed a latent refusal of a legal plain CONNECT); see fix log |
| WT-238 | P2 | C99 | `C99/src/quic/protection.c:109-135` | `wt_quic_packet_keys_update(&k, &k)` returned the new header-protection key (RFC 9001 §6.1); unreachable in-tree | **fixed + verified** (4a50c21) -- the aliased call snapshots the header-protection key before deriving, so it returns what the two-object call returns; see fix log |
| WT-239 | P3 | C99 | `C99/src/quic/packet.c:687,691` | `wt_quic_retry_packet_encode` dereferenced NULL connection-ID/token pointers | **fixed + verified** (9d13d19) -- the same argument guards as the long-header encoder, with a regression test that also pins that nothing is written before the refusal |
| WT-240 | P3 | C99 | `C99/src/quic/packet.c:495-498` | The decoder's comment described a zero-length-token refusal the code did not implement | **fixed (comment)** (9d13d19) -- the parser is deliberately permissive because the field is `Retry Token (..)`; section 17.2.5.2 puts the MUST on the client, and the connection's `on_retry_packet` enforces it |
| WT-241 | P3 | C99 | `C99/src/crypto/crypto_openssl.c:175-183` | `wt_sha256_final(ctx, NULL)` crashed inside OpenSSL while ten siblings refuse a NULL out-parameter | **fixed + verified** (4a50c21) -- `wt_sha256_final` refuses a NULL out-parameter with WT_ERR_INVALID_ARGUMENT like its ten siblings; see fix log |
| WT-242 | P3 | C99 | `C99/src/http3/qpack_field.c` | A >62-bit string length was reported `WT_ERR_TRUNCATED` + NO_ERROR while a truncated index is `WT_ERR_PROTOCOL` | **fixed + verified** (4a50c21) -- each site propagates the integer decoder's own answer: malformed stays malformed, truncated stays truncated; see fix log |
| WT-243 | P3 | C99 | `C99/include/webtransport/http3/settings.h:56-58` | A comment stated the RFC's opposite about exerciser setting `0x21` | **fixed (comment)** (4a50c21) -- the stale comment is replaced; the code three lines away was already correct |
| WT-244 | P1 | Swift | `Swift/…/WebTransportInteroperableNetworkRuntime.swift:819-828, 2547-2561` | An unknown/reserved unidirectional stream type was reported as a session error; RFC 9114 §6.2 says it MUST NOT be | **fixed + verified** (a31b0dc) -- the accept path and `readPeerControlStream` classify the type: control/QPACK retained, reserved/unknown dropped and the wait continues, malformed still reported, push keeps its previous report; see fix log |
| WT-245 | P1 | Swift | `Swift/…/WebTransportHTTP3Core/WebTransportSession.swift:826-836` | An over-limit `WT_MAX_STREAMS` capsule on the CONNECT stream never closed the session; §5.6.2 requires `WT_FLOW_CONTROL_ERROR` | **fixed + verified** (a31b0dc) -- the parse failure is routed through `closeForFlowControlViolation`, and the CONNECT reader resets the stream with WT_FLOW_CONTROL_ERROR; see fix log |
| WT-246 | P2 | Swift | `Swift/…/WebTransportInteroperableNetworkRuntime.swift:2507-2513` | A second control/QPACK stream was silently retained instead of `H3_STREAM_CREATION_ERROR` (RFC 9114 §6.2.1) | **fixed + verified** (a31b0dc) -- retention is bounded by the connection's entitlement and a duplicate/ unentitled stream raises `HTTP3ConnectionError(.streamCreationError)`; see fix log |
| WT-247 | P2 | Swift | `Swift/…/WebTransportInteroperableNetworkRuntime.swift:3037-3041` | Critical-stream retention had no ceiling and consumed the peer's unidirectional-stream credit | **fixed + verified** (a31b0dc) -- `retainCritical` refuses anything beyond one control and two QPACK streams; see fix log |
| WT-248 | P3 | Swift | `Swift/…/WebTransportInteroperableNetworkRuntime.swift:800-812` | `acceptUnidirectionalStream` could wait twice its documented deadline | **fixed + verified** (a31b0dc) -- the budget is recomputed before each await; the test is a budget guard, because the double wait is not reachable on this transport; see fix log |
| WT-249 | P2 | Swift | `Swift/…/WebTransportInteroperableNetworkRuntime.swift:1082-1084, 1135-1217` | **Suspected, unresolved:** CONNECT-stream capsules are read/written as raw stream bytes while RFC 9114 §4.4 permits only DATA frames after CONNECT. The audit could not settle it (no external peer on the host); the repository's own interop evidence (7/7 across five implementations) and the C99 library both use the raw form | **open** — kept as a tracker row rather than "fixed", because closing it needs an external peer or a deliberate documented deviation |
| WT-250 | P3 | Swift | `Swift/…/QUICTransportParameters.swift:30-79` | `validated()` missed RFC 9000 §4.6's 2^60 cap on `initial_max_streams_bidi`/`uni` (the C99 twin is the ledger's F-05) | **fixed + verified** (5818448) -- both caps added with the boundary (exactly 2^60 is accepted) asserted |
| WT-251 | P3 | C99 | `C99/apps/support/session_loop.c:127`, `C99/src/http3/driver.c` | **Unfinished, filed:** what, if anything, consumes the peer's HTTP/3 SETTINGS payload in the shipped tools. `grep -rn "wt_http3_settings_parse\|WT_HTTP3_SETTING_" C99/apps/support C99/src/http3/driver.c` returns nothing (re-verified this pass) and `side_on_frame_payload` acts only on HEADERS, so the peer's `WT_INITIAL_MAX_DATA`/`WT_INITIAL_MAX_STREAMS` settings may never reach `wt_session_flow_configure`. Flagged, not proven | **open** -- filed as a tracker row (the next free number after WT-250) so it has an owner; it may be a resource-accounting gap or dead code |

## Coverage, and what was not covered

Both agents executed, rather than read, the bulk of their side: Swift `swift test` (all targets) plus
targeted probes through a real loopback QUIC session; C99 `build-and-test.sh` Debug and
ASan+UBSan (97/97 each), 12 × 3,000,000-iteration `fuzz_smoke` runs, a 300,000-run chunked
`wt_http3_driver_*` fuzz probe, cppcheck, Clang Static Analyzer (94 sources, no findings), the seven RFC
vector extractors, the Windows compile and link legs `x86_64-w64-mingw32-gcc`, and the harness gates
(`check-matrix`, `check-portability`, `check-workflows.py`).

Honest gaps, recorded rather than papered over:

1. **Swift ASan and TSan runs were not done by the Swift agent** (`unfinished` in its report), because
   it spent its budget on the protocol findings. **Closed by the lead auditor on the fixed tree:**
   `swift test --scratch-path /tmp/lead-swift --sanitize=address` → exit 0, and `--sanitize=thread
   --skip CLIProcess --skip ReleaseArtifacts` → exit 0, both with **0 failures** in every bundle, and
   the same suite under the CI's strict flags
   (`-warnings-as-errors -strict-concurrency=complete -require-explicit-sendable`) → **369 tests in 7
   bundles, 0 failures, exit 0**. Logs: `/tmp/lead-swift-strict.log`, `/tmp/lead-swift-asan.log`,
   `/tmp/lead-swift-tsan.log`. **Re-verified on the committed tree while writing this log**
   (`/tmp/sub-swift-strict.log`: 369 tests in 7 bundles, 0 failures, exit 0), so the gap is closed with
   evidence on two runs rather than one.
2. **The C99 Wine suite could not run**: Wine is not installed on this host and cannot be (the Homebrew
   casks are disabled). The Windows leg compiles and links 91 PE32+ executables and the shared library
   (reproduced on the fixed tree: `check-windows-build.sh` exit 0, 352/352 steps, 91 PE32+ executables);
   it is not executed here. `WT-224` is now closed — the *native* leg is enforced and green in CI — but
   `WT-223` (no FreeBSD job) is untouched, and the Windows *behaviour* claim still rests on the CI Wine
   leg rather than a local run.
3. **No FreeBSD or Debian-13 host beyond CI, and no LeakSanitizer** (Darwin has none). `WT-225` is closed:
   the Debian 13 leg now exists in CI (run 35111066674, after the `libc6-dev` fix); what is still missing
   is a non-CI Debian-13 or FreeBSD host, and `WT-223` covers the FreeBSD job.
4. **No external interop peer.** The repository's recorded interop evidence stands; nothing in this pass
   re-measured it, which is why `WT-249` stays open.
5. The C99 agent's question of **what consumes the peer's SETTINGS payload** in the shipped tools is
   `unfinished` and is now **filed as `WT-251`** rather than left as a sentence in the report. The grep was
   re-verified this pass (`grep -rn "wt_http3_settings_parse\|WT_HTTP3_SETTING_" C99/apps/support
   C99/src/http3/driver.c` returns nothing) and it may be a resource-accounting gap or dead code; it needs
   its own investigation, which this pass did not do.
6. **Swift ASan/TSan (gap 1) and Debian-13 (gap 3) are the two gaps this pass actually closed.** The
   remaining gaps are the Wine *execution* (2), the non-CI FreeBSD host (3) and the external peer (4).

## Findings the audits rejected (kept, because a rejection is evidence too)

- Swift: QPACK dynamic-table index arithmetic, Required-Insert-Count wrap and Base sign (4 table states ×
  ~4,000 random inputs, no trap); all 257 QPACK Huffman entries against RFC 7541 Appendix B (exact); the
  ACK range bookkeeping; unbounded ACK-range allocation in `QUICFrame.decode`; receive-only enforcement;
  datagram drop-on-full; and the F-03 queue ceiling's regression behaviour.
- C99: an HTTP/3 header-parser infinite loop (unreachable — exactly two 8-byte varints); a stale `state`
  pointer after capsule-stream compaction; `NULL + 0` pointer arithmetic (formal UB, unobservable);
  ACK `range_count`/`ranges_len` inconsistency; `memcpy`/`memcmp` with NULL and zero length;
  `wt_buf_consume(n >= len)` semantics; the installed-tool rpath, the version lockstep and the `WT-201`
  skip path (all verified *working*); the QPACK static table (re-derived from the RFC); and
  `authority_matches` port stripping.

## Fix log

Numbering: every finding this pass fixed or filed carries a ledger entry whose id is `F-audit3-<WT row number>`
(for example `F-audit3-WT-244`), so a ledger entry is traceable to exactly one tracker row; that scheme is used
nowhere else in the ledger. The full text of each entry is in `AUDIT/ledger.json`; this section is the running
record of the seven commits that carry the pass, what each was verified with, and what is deliberately left. The pass fixed **25 findings** and closed **one review-progress row** (`WT-222`, closed by reading the whole file rather than by a finding of its own), which is why the ledger's `F-audit3-*` set has 28 `DONE` entries for 26 tracker rows.

### `a312253` — repo-ops: one sequential Windows DLL staging edge, the native leg enforced, a Debian 13 leg, and the docs that named them

**Fixed:** `F-repo-ops-26` (the Windows staging race: `wt_stage_windows_runtime` attached a POST_BUILD
`copy_if_different` of `libwebtransport.dll` to every app and test target, so 90 copies of one file were
scheduled in parallel into two directories and the loser of that Ninja race failed with `Permission denied`),
and the three tracker rows that depended on it: `WT-224` (the native Windows leg was `continue-on-error`),
`WT-225` (no Debian 13 leg) and `WT-226` (the root README said Phase 10 was "under way" while the DoD called
the equivalent criterion met).

**Verified:** the staging fix was re-proved rather than cited — the pre-patch tree generated **90 copy edges /
90 commands**, the patched tree **1 edge / 2 commands** on the shared-library linker edge; `cmake --build -j 8`
exit 0 with **352/352 steps**, **91/91** executables PE32+ x86-64, the DLL in the build root, `apps/` and
`tests/`, and **0** `Permission denied`; on this host the WIN32 branch is inert (configure and build exit 0,
`ctest` **97/97**, no copy edge in `build.ninja` at all). For the docs: `check-workflows.py` (3 files parse, no
duplicate keys), `check-matrix.sh` (91 symbols), `check-portability.sh` (inventory complete),
`score-matrix.sh` (8 of 9 criteria met, 1 partial) and the host suite 97/97.

**Remains:** `WT-223` (no FreeBSD CI job) and the plan's MSVC and Clang-CL Windows variants are still named as
outstanding, because they are.

### `9d13d19` — C99 batch 1

**Fixed:** `WT-227` (C99 half of the Retry `Unused` field), `WT-229`, `WT-230` (the public API's
session-termination gate and its post-termination event delivery), `WT-231` (`:scheme` must be `https`),
`WT-232` (the 2^60 stream-count ceiling on both sides and both directions), `WT-233` (NULL capsule value),
`WT-234` (`:status` bounded to 100..599), `WT-239` (`wt_quic_retry_packet_encode` NULL guards) and `WT-240`
(the Retry decoder's comment).

**Verified:** the new gate was seen to fail first, then pass — the Retry/A.4 test failed **40 of 194 checks**
before the change and the same binary runs **199 checks green**. Then `C99/scripts/build-and-test.sh --all`:
Debug **100% of 97**, Release **100% of 97**, ASan+UBSan **100% of 97**, exit 0; `check-cppcheck.sh` clean;
Clang Static Analyzer over **94 sources**, no findings; the Windows cross-compile gate green (76 library + 108
test/app sources). The commit message also names what it did **not** do: CAUD-9, CAUD-10, CAUD-11, CAUD-14,
CAUD-15, CAUD-16 and CAUD-7 stayed open at that point and became `WT-236`…`WT-243` and `WT-235`.

### `5818448` — Swift codec: Retry integrity, the `Unused` field, the 2^60 caps, the decode precondition

**Fixed:** `WT-1` (the Retry Integrity Tag was never computed or verified; RFC 9001 section 5.8), `WT-227`
(Swift half), `WT-228` (the header-protected-bits precondition is now documented) and `WT-250` (the missing
2^60 caps on `initial_max_streams_bidi`/`uni`, asserted with exactly 2^60 accepted). Asserting against RFC 9001
appendix A.4's own packet and tag caught a defect in the first version of the code (`compute` passed an empty
associated-data value, so it disagreed with the RFC while `verify` agreed with itself) — which is the argument
for the RFC vector over a round trip.

**Verified:** `swift test -Xswiftc -warnings-as-errors -Xswiftc -strict-concurrency=complete -Xswiftc
-require-explicit-sendable` — **369 tests in 7 bundles, 0 failures, exit 0**; `--sanitize=address` exit 0;
`--sanitize=thread --skip CLIProcess --skip ReleaseArtifacts` exit 0; `swift format lint --strict` exit 0.
Logs `/tmp/lead-swift-{strict,asan,tsan}.log`, reproduced on this tree as `/tmp/sub-swift-strict.log`.

### `a31b0dc` — Swift runtime: four wire-visible findings

**Fixed:** `WT-244` (an unknown/reserved unidirectional stream type was a session error; RFC 9114 section 6.2
says it MUST NOT be), `WT-245` (an over-limit `WT_MAX_STREAMS` on the CONNECT stream never closed the session;
section 5.6.2), `WT-246` (a duplicate control/QPACK stream was silently retained instead of
`H3_STREAM_CREATION_ERROR`) and `WT-247` (retention had no ceiling and consumed the peer's unidirectional-stream
credit), plus `WT-248` (a wait budget that could double). Every fix is internal code: no public API shape moved.

**Verified:** each was reproduced against a real loopback QUIC session with a test that failed before the change;
then the same strict run as above — **369 tests in 7 bundles, 0 failures**, ASan exit 0, TSan exit 0,
`swift format lint --strict` exit 0, `check-target-imports.sh` and `check-manifest-sync.sh` green. `WT-248`'s
test is recorded as a budget guard rather than a reproduction, because a unidirectional stream is delivered only
once its first byte exists, so the double wait is not reachable on this transport.

**Also closed by this commit's review:** `WT-222`, the unfinished line-by-line review of
`WebTransportInteroperableNetworkRuntime.swift`. This pass read all 3381 lines; the findings above, `WT-249` and
`WT-250` are what that read produced.

### `59cb125` — the Debian 13 leg's own fix

The new leg failed its first run, and not in this tree. CI run **35046915707**, job **104638677120**:
`/usr/bin/ld: cannot find Scrt1.o: No such file or directory`, `/usr/bin/ld: cannot find crti.o: No such file or
directory`, `-- Check for working C compiler: /usr/bin/cc - broken`. On Debian, `gcc` **RECOMMENDS** `libc6-dev`
rather than depending on it, and the step uses `--no-install-recommends` to keep the container lean, so the C
runtime's startup objects were absent; the Ubuntu legs never saw it because their runner image already carries a
toolchain, while a bare `debian:trixie` has to name every part of the one it uses. `libc6-dev` is now named, and
the comment records the failure so the next person changing the step knows why it is not simply "the same four
tools". Verified after the fix locally: `python3 C99/scripts/check-workflows.py .github/workflows` → "3 file(s)
parse with no duplicate keys", exit 0. The rest of the run is what the change was for: the newly enforced
`windows-native` leg passed, as did macOS, both Ubuntu legs and the Wine leg.

### `3ca9720` — merge of the automated badge-refresh commit

No content of its own; the tree the C99 CI run below is measured on. `35c4329` ("chore: refresh the 14-day views
badge") is the automated commit merged here.

### `4a50c21` — C99 batch 2

**Fixed:** `WT-236` (`SETTINGS_H3_DATAGRAM` accepts only 0/1, H3_SETTINGS_ERROR otherwise), `WT-237` (an
extended CONNECT needs `:path`; the plain CONNECT keeps its exemption — which also fixed a latent refusal of a
legal plain CONNECT that the audit had not named), `WT-238` (`wt_quic_packet_keys_update(&k, &k)` returned the
new header-protection key; RFC 9001 section 6.1), `WT-241` (`wt_sha256_final(ctx, NULL)` SEGV inside OpenSSL),
`WT-242` (the string-length sites collapsed every integer failure into `WT_ERR_TRUNCATED`, the index sites did
the reverse), `WT-243` (the settings header stated the RFC's opposite about exerciser `0x21`) and `WT-235`
(Origin was unreachable through the public API; `wt_http3_message_field` makes it readable).

**Verified:** the tests were written first and `WT-235`'s test itself was wrong first (it asserted a field was
absent while looking it up in a section that carried it), and `WT-242`'s first vectors used `0x7f` as a
continuation byte, which clears the continuation bit and encodes the legal value 190 — both are recorded in the
commit rather than quietly corrected. Then the full C99 loop: Debug **100% of 97**, Release **100% of 97**,
ASan+UBSan **100% of 97**, exit 0; `check-cppcheck.sh` clean; `check-static-analysis.sh` **94 sources, no
findings**; Windows cross-compile gate green. Reproduced while writing this log: `build-and-test.sh --all` exits
0 with all three legs at 100% of 97 (`/tmp/sub-c99-all.log`).

### CI evidence (authoritative)

**C99 CI run [35111066674](https://github.com/Pummelchen/WebTransport/actions/runs/35111066674) on `3ca9720` —
all six jobs success:** `windows-native` (newly enforced by `a312253`), `Debian 13 (trixie, gcc)` (the new job,
after the `libc6-dev` fix in `59cb125`), both Ubuntu legs, macOS, and `windows-wine`. The Debian job's first run
is the failure story above (run `35046915707`, job `104638677120`). **Swift CI on `a31b0dc` was green.**

**Lead-auditor local verification of the Swift tree** (logs `/tmp/lead-swift-{strict,asan,tsan}.log`):
**369 tests in 7 bundles, 0 failures** under `-warnings-as-errors -strict-concurrency=complete
-require-explicit-sendable` — reproduced on the committed tree while writing this log — plus
`--sanitize=address` exit 0 and `--sanitize=thread --skip CLIProcess --skip ReleaseArtifacts` exit 0.

**C99 local:** Debug **97/97**, Release **97/97**, ASan+UBSan **97/97** (reproduced), cppcheck clean, static
analysis **94 sources** with no findings, and the Windows cross-compile gate green. Independently re-run on the
committed tree while writing this log: `build-and-test.sh --all` exit 0 with all three legs at 100% of 97
(`/tmp/sub-c99-all.log`); `check-cppcheck.sh` → "cppcheck: clean over the library and the tools"
(`/tmp/sub-cppcheck.log`); `check-windows-build.sh` → "linked 91 PE32+ executables and 1 shared library", 352/352
steps (`/tmp/sub-winbuild.log`).

### What is deliberately left

- **`WT-249` (`SWAUD-6`) stays open**, and the history says so plainly. CONNECT-stream capsules are read and
  written as raw stream bytes while RFC 9114 section 4.4 permits only DATA frames after CONNECT. The audit
  marked it **suspected/unverified** because no external peer was reachable from this host, and both the
  repository's recorded 7/7 interop evidence and the C99 library use the raw form. Closing it needs an external
  peer or a deliberate documented deviation, not a code change made on a guess.
- **`WT-251` is filed**, not fixed: the C99 agent's one `unfinished` item, what consumes the peer's SETTINGS
  payload in the shipped tools. It is flagged, not proven, and is now a tracker row rather than a sentence in a
  report.
- **`WT-85`, `WT-221` (Swift), `WT-39`, `WT-153`, `WT-223` (C99) and `WT-196` (infra) stay open and untouched.**
  `WT-191` and `WT-197` were closed after this record was first written, in `851a198`: the framework error now has a
  name at both queue boundaries, and the RSA PKCS#12 fixture is a PBES2/AES-256-CBC container that OpenSSL 3 reads
  (the row's `OSStatus -26276` does **not** reproduce on macOS 27.0, and both the fix report and the ledger say so
  rather than claiming a reproduction). The obsolete text this replaces said
  nothing in the fix log claims otherwise.
