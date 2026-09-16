# C99 portable-implementation audit — CONSOLIDATED FINAL REPORT

Read-only audit of the portable C99 implementation under `C99/` at `/Users/node3/Downloads/WebTransport`
(protocol target `draft-ietf-webtrans-http3-16`; QUIC RFC 9000/9001, TLS 1.3 RFC 8446, HTTP/3 RFC 9114,
QPACK RFC 9204, HTTP Datagrams RFC 9297, extended CONNECT RFC 9220). This document is the main report plus
the addendum, consolidated; nothing has been shortened.

---

## 1. HEAD and tree proof

- `git rev-parse HEAD` → `46937e29eb734887ca7b739abfedaf68ae565de2` (`1.4.0-4-g46937e2`). **HEAD moved during the
  audit**: I started at `6be4315`; two audit-doc commits landed (`49e2b68`, `46937e2`).
  `git diff --stat 6be4315..HEAD -- C99/src C99/include C99/scripts C99/CMakeLists.txt` printed **nothing**, so
  the C99 code audited is byte-identical to current HEAD.
- `git status --porcelain` → *(empty)*. `git diff --name-only HEAD` → *(empty)*.
  `git diff --cached --name-only` → *(empty)*. `git ls-files --others --exclude-standard` → *(empty)*.
  **Source files changed: none**, so there are no sha256s to report.
- Build dirs I created, all inside the gitignored `C99/out/`: `audit-r1/build`, `audit-r1/build-sanitize`,
  `audit-r1/analyze`, `windows/build` (created by `check-windows-build.sh`, which `rm -rf`s it first). All probes
  are `/tmp/ca-*`.
- Three scans contributed: my own pass plus two delegated sub-scans (Q1: `src/quic/packet.c`,
  `protection.c`, `packet_io.c`, `crypto_stream.c`, `pn_space.c`, `connection_id.c`, `retry_token.c`, `close.c`,
  `src/crypto/crypto_openssl.c`; Q2: `src/http3/qpack*.c`, `control.c`, `settings.c`, `frame.c`, `goaway.c`,
  `headers.c`; Q3: `src/webtransport/*.c`, `src/api/*.c`). Findings executed by a delegated scan and not
  re-executed by me say so explicitly.

---

## 2. Coverage

| Area | Checks actually executed | Result |
|---|---|---|
| Whole tree (Debug) | cmake Ninja Debug + `ctest --test-dir C99/out/audit-r1/build` | 100% passed, **97/97** |
| Whole tree (ASan+UBSan) | `-DWEBTRANSPORT_C99_SANITIZE=ON`, rebuild, `ctest` | 100% passed, **97/97**, no report |
| Parser families | `fuzz_smoke --runs 3000000 --seed 1..12` (ASan+UBSan) | 12× "3000000 generated input(s) … no crash" |
| Whole tree | `C99/scripts/check-cppcheck.sh` | "cppcheck: clean over the library and the tools (warning,performance,portability)" |
| Whole tree | `C99/scripts/check-static-analysis.sh clang out/audit-r1/analyze` | "94 source(s) analyzed / no findings" |
| RFC vectors | `WEBTRANSPORT_RFC_DIR=/tmp C99/scripts/check-vectors.sh` (9001/8448/7748/7541 fetched fresh; 9204 cached) | 7/7 "committed … match the RFC" |
| Windows compile | `C99/scripts/check-windows-platform.sh` | 76 library + 108 tests/apps sources compile under `x86_64-w64-mingw32-gcc` |
| Windows link | `WT_WINDOWS_OPENSSL=/tmp/windows-openssl/mingw64 C99/scripts/check-windows-build.sh` | "linked 91 PE32+ executables and 1 shared library … (linked, not run HERE)" |
| Other gates | `check-matrix.sh`, `check-portability.sh`, `check-workflows.py` | 91 named symbols/tests exist; every POSIX-only name inventoried; 3 workflow files parse |
| Changed: install rpath | manual `cmake --install` into `/tmp/ca-pkg` (apps+tests on), then each installed tool `--help` | install OK; all three exit 0 |
| Changed: version lockstep | `/tmp/ca-ver` copy with `WT_VERSION_MINOR` 4→9, configure | exit 1: "version mismatch: … says 1.4.0 but … declares 1.9.0" |
| Changed: WT-201 | `env -i PATH=<no-python3> … check-cli-session.sh` | exit 77 "unsupported -- python3 is not installed … (WT-201)"; guards present in all three python3-using check-cli scripts and in check-vectors.sh |
| Own harness | `/tmp/ca-driverfuzz.c`: 300 000 randomized chunked feeds into `wt_http3_driver_on_stream_bytes` / `on_uni_stream_data` / `on_quic_frame`, ASan+UBSan | "no crash" |
| Q1 area (delegated) | 10 scope unit tests + probes `/tmp/ca-q1-*` | see CAUD-8/11/12/13/14 |
| Q2 area (delegated) | RFC 9204 B.2/B.3/B.4 vectors, 13M+ randomized ops, probes `/tmp/ca-q2-*` | see CAUD-9/10/15/16 |
| Q3 area (delegated) | 650k+ randomized ASan/UBSan iterations over capsule/session/api/request paths, probes `/tmp/ca-q3-*` | see CAUD-1/2/3/4/5/7 |
| **NOT run** | Wine suite (`check-windows-wine.sh`) | **Wine is NOT installed** — the Windows suite was compiled and linked, never run |
| **NOT run** | FreeBSD / Debian legs, LeakSanitizer | no such host; Darwin has no LSan (per AGENTS.md) |
| **NOT covered** | Swift tree, `_WIN32` runtime behaviour, apps/cli UX, end-to-end interop against a live third-party peer | out of scope / environment |
| **UNFINISHED** | what (if anything) consumes the peer's SETTINGS payload in the shipped tools | `grep -rn "wt_http3_settings_parse\|WT_HTTP3_SETTING_" C99/apps/support/ C99/src/http3/driver.c` → nothing; `side_on_frame_payload` acts only on HEADERS. Flagged, not filed. |
| **UNFINISHED** | Q1/Q2 line-by-line passes | both delegated scans completed and their findings are folded in below; I did not re-execute their probes except CAUD-8/9/10 |

---

## 3. Findings

### CAUD-8 · P1 (interop, wire-visible) · Retry decoder rejects the Unused bits a client MUST ignore
`C99/src/quic/packet.c:466` (`if ((first & 0x0cU) != 0U) return … PROTOCOL_VIOLATION;`), reached from the wire
via `C99/src/quic/connection.c:3015→3019→on_retry_packet:2600` (which discards the packet and returns `WT_OK`).
Citation: RFC 9000 §17.2.5 — "The value in the Unused field is set to an arbitrary value by the server. Clients
MUST ignore the value of this field." (verified at `/tmp/ca-q1-rfc9000.txt:5106`).
Repro: `/tmp/ca-final.c`, 24-byte Retry with the Unused nibble varied:
```
Retry first=0xf0 (Unused=0x0) -> 0 err=0
Retry first=0xfc (Unused=0xc) -> 4 err=10     (WT_ERR_PROTOCOL / PROTOCOL_VIOLATION)
Retry first=0xf3 (Unused=0x3) -> 0 err=0
```
The check is also partial (0x0c rejected, 0x03 ignored). Fix: delete the test — a Retry has no header protection,
so §17.2's reserved-bit rule does not apply to it. **Verified by EXECUTION (by me).** The "handshake cannot
complete" consequence is inferred from the call chain, not observed against a live peer.

### CAUD-1 · P2 · Public capsule entry point has no session-termination gate and accepts a non-zero-length WT_DRAIN_SESSION
`C99/src/api/session.c:117-225` (DRAIN `:144-158`, MAX_DATA `:179-199`).
Citations: draft-ietf-webtrans-http3-16 §6 ("If any additional stream data is received on the CONNECT stream
after receiving a WT_CLOSE_SESSION capsule, the stream MUST be reset with code H3_MESSAGE_ERROR") and §4.7 Fig. 5
(WT_DRAIN_SESSION `Length (i) = 0`).
Repro `/tmp/ca-refute2.c`:
```
A) API: DRAIN len=1 before close -> 0 (ok)
B) machine walker on the same bytes -> 4 (protocol) h3err=270
F) API MAX_DATA 200 AFTER CLOSE -> 0 allowance=200     (limit had been 100)
G) machine walker MAX_DATA after close -> 4 (protocol) h3err=270
```
Two entry points in one library disagree about identical bytes; the ledger's F-30 fixed only
`src/webtransport/session.c` (the machine walker), not this duplicate. Fix: delegate to
`wt_webtransport_session_on_capsule_bytes` or add its two checks. **EXECUTION.**

### CAUD-2 · P2 · After termination the API still delivers stream and datagram events
`C99/src/api/events.c:49` (`wt_session_on_stream_opened`), `:92/:106` (`wt_session_on_stream_data`),
`:133` (`wt_session_on_datagram`). Citation: §6 ("MUST reset the send side and abort reading on the receive side
of all unidirectional and bidirectional streams associated with the session … it MUST NOT send any new datagrams
or open any new streams").
Repro `/tmp/ca-refute2.c`:
```
D) API valid datagram AFTER CLOSE -> 0 (ok) datagram_callbacks=1
E) API on_stream_opened AFTER CLOSE -> 0 (ok) opened_callbacks=1
```
Fix: gate the four feed functions on `session->machine.state != WT_WEBTRANSPORT_SESSION_CLOSED`. **EXECUTION.**

### CAUD-3 · P2 · `:scheme` is required to be present but never required to be `https`
`C99/src/webtransport/session_request.c:124-129`. Citation §3.2: "The :scheme field MUST be https."
Repro `/tmp/ca-scheme.c` (encode via `wt_http3_message_encode` → decode via `wt_http3_message_decode` →
`wt_webtransport_session_request_validate` with the in-tree server policy):
```
encoded 92 bytes of field section with :scheme=http
decoded :scheme=http
outcome=0 (0=ACCEPT 1=NOT_WEBTRANSPORT 2=REJECT) status=404
```
Fix: compare the scheme bytes to "https". Not ledger F-08 (that is pseudo-header character grammar). **EXECUTION.**

### CAUD-4 · P2 · 2^60 stream-count ceiling unenforced for WT_STREAMS_BLOCKED and not honoured by the writers
`C99/src/webtransport/capsule.c:309-319` (parse), `:270-274` (`streams_blocked_write`), `:256-259`
(`max_streams_write`); unhandled by the accept-everything fallback at `C99/src/api/session.c:221`.
Citation §5.6.3/§5.6.2: "This value cannot exceed 2^60 … Recipients of a capsule with a Maximum Streams value
larger than this limit MUST close the WebTransport session with a WT_FLOW_CONTROL_ERROR error code."
Repro `/tmp/ca-streamsblocked.c`:
```
1) streams_blocked_write(2^61) -> 0 (ok), 13 bytes
2) streams_blocked_parse(2^61) -> 0 (ok) value=2305843009213693952 err=256   (0x100 = NO_ERROR)
3) API session on WT_STREAMS_BLOCKED(2^61) -> 0 (ok) state=1                 (still ESTABLISHED)
```
The library emits a value the draft forbids, its own reader accepts it, and the API session stays established.
Fix: check `maximum > WT_WEBTRANSPORT_MAX_STREAMS_VALUE` in `streams_blocked_parse`, in both writers, and handle
the capsule in `wt_session_on_capsule`. **EXECUTION.**

### CAUD-9 · P2 · SETTINGS_H3_DATAGRAM accepts values other than 0/1 and treats them as enabled
`C99/src/http3/settings.c:122-125` (parse) and `:54` (set) range-check only ENABLE_CONNECT_PROTOCOL.
Citation RFC 9297 §2.1.1 (`/tmp/rfc9297.txt:227`): "The value of the SETTINGS_H3_DATAGRAM setting MUST be either
0 or 1. … If the SETTINGS_H3_DATAGRAM setting is received with a value that is neither 0 nor 1, the receiver MUST
terminate the connection with error H3_SETTINGS_ERROR."
Repro `/tmp/ca-final.c`:
```
H3_DATAGRAM=2 payload: 2 bytes -> parse 0 err=0x100
  present=1 value=2
```
The sibling `ENABLE_CONNECT_PROTOCOL=2` is correctly refused (`status=4 error=0x109`). **EXECUTION.** Caveat
(my own grep): `wt_http3_settings_parse` has no caller in `src/http3/driver.c` or `apps/support/` (only tests,
the conformance app's refusal scenario, and the fuzzer), so this is a public-API/conformance-surface defect, not
reachable through the shipped tools.

### CAUD-11 · P2 reported · `wt_quic_packet_keys_update(&k,&k)` returns the NEW header-protection key
`C99/src/quic/protection.c:109-135` (copy at `:132`); `wt_quic_derive_packet_keys` memsets/overwrites
`out == current` before the copy, so `:132` clones the new `hp` onto itself.
Citation RFC 9001 §6.1: "The header protection key is not updated."
Probe `/tmp/ca-q1-findings.c`: `update(&k,&out): out.hp = 760a` / `update(&k,&k): k.hp = e3df` / `hp equal? NO`.
Fix: snapshot `current->hp`/`hp_len`/`secret` into locals before deriving, or reject `out == current`.
Not reachable in-tree (`connection.c`'s `derive_next_keys` uses distinct objects).
**Executed by delegated scan (not re-executed by me); behaviour verified, production impact none.**

### CAUD-5 · P3 · `wt_webtransport_close_session_parse` dereferences a NULL capsule value
`C99/src/webtransport/capsule.c:148` and `:153`. Not peer-reachable: `wt_webtransport_capsule_decode` returns
`WT_ERR_TRUNCATED` when `value == NULL && length != 0`, so no shipped decoder produces the input; it is a
robustness defect for a caller that fills the documented capsule struct itself (sibling parsers `parse_one`/
`parse_two` tolerate NULL via the cursor).
Repro `/tmp/ca-nullcap.c` under ASan+UBSan (capsule
`{type = WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION, value = NULL, value_length = 4}`):
```
capsule.c:148:43: runtime error: applying non-zero offset 4 to null pointer
capsule.c:153:34: runtime error: load of null pointer of type 'const uint8_t'
AddressSanitizer: SEGV … #0 wt_webtransport_close_session_parse capsule.c:153
exit=134
```
Fix: reject `capsule->value == NULL` before the length/UTF-8/code reads. **EXECUTION.**

### CAUD-6 · P3 · Response-status encoder writes a value its own decoder refuses
`C99/src/http3/message.c:183-191` (guard is `message->status > 999U`).
Citation RFC 9114 §4.3.2 (status is three digits, 100–599), which the library's own reader enforces at
`message.c:15-27`.
Repro `/tmp/ca-status.c`:
```
status 5:   ENCODED OK but its own decoder refuses it
status 99:  ENCODED OK but its own decoder refuses it
status 100: encode+decode ok -> 100
status 599: encode+decode ok -> 599
status 600: ENCODED OK but its own decoder refuses it
status 999: ENCODED OK but its own decoder refuses it
status 5 wire: 000027003a73746174757303303035        (:status: 005)
```
Fix: bound the check to 100–599. **EXECUTION.**

### CAUD-7 · P3 · Origin is never verified — and the API cannot see it
`C99/src/webtransport/session_request.c:91-154`; `C99/include/webtransport/http3/message.h:36-45` carries only
method/scheme/path/authority/protocol (+status).
Citation §3.2: "When the request contains the Origin header, the WebTransport server MUST verify the Origin
header … If the verification fails … SHOULD reply with status code 403."
My `grep -rni origin C99/src C99/include` shows no Origin handling anywhere in the library (only the QPACK
static table, QUIC "original destination", and a CLI report field); the acceptance run was executed by my
delegated scan (`/tmp/ca-q3-probe6`, field section carrying `origin: https://evil.example` →
`validate -> 0 outcome=0`, accepted).
Fix: carry Origin (or regular fields generally) into `wt_http3_message_t` and add an origin policy to
`wt_webtransport_request_policy_t`. **Absence: EXECUTION (mine); acceptance: sub-scan execution, not
re-executed by me.**

### CAUD-10 · P3 · Extended CONNECT with `:protocol` and no `:path` passes message validation
`C99/src/http3/headers.c:109-113` (sets `is_connect` for any CONNECT, so `header_finish:188-194` then requires
only `:authority`) and `C99/src/http3/message.c:114-119` (deliberately skips the path requirement for CONNECT).
Citation RFC 8441 §4 (verified, `/tmp/rfc8441.txt`): "On requests that contain the :protocol pseudo-header field,
the :scheme and :path pseudo-header fields of the target URI MUST also be included."
Repro `/tmp/ca-bidi.c` (`:method CONNECT, :scheme https, :authority localhost, :protocol webtransport-h3`,
no `:path`):
```
message_decode -> 0 err=0x100 scheme_len=5 path_len=0 protocol_len=15
```
The no-`:scheme` variant *is* refused by `message.c:110` with 0x10e, so only the `:path` half is open; the
WebTransport validator re-checks `path_length` (`session_request.c:124-125`), so no effect on the session flow.
Fix: track "saw :protocol" and require `:scheme`+`:path` when it is present. **EXECUTION.**

### CAUD-12 · P3 · `wt_quic_retry_packet_encode` dereferences NULL for a non-zero length
`C99/src/quic/packet.c:687` and `:691` (the same arguments are validated at `:545-559`).
Probe `/tmp/ca-q1-findings.c`: `wt_quic_retry_packet_encode(dcid=NULL, len=4) -> 134`,
`(token=NULL, len=4) -> 134`; ASan: `SEGV on unknown address 0x000000000000 … #1 wt_writer_put writer.c:65`.
Fix: add the two `len != 0 && ptr == NULL` guards.
**Executed by delegated scan (not re-executed by me).**

### CAUD-13 · P3 · Retry decoder accepts a zero-length Retry Token
`C99/src/quic/packet.c:494-500`. Citation RFC 9000 §17.2.5.2: "A client MUST discard a Retry packet with a
zero-length Retry Token field."
Probe `/tmp/ca-q1-findings.c`: `retry first=0xf0 … token_len=0 -> WT_OK out.token_len=0`, with `token` pointing
at the integrity tag. The only in-tree caller re-checks at `connection.c:2610-2614`, so no live accept; the
comment at `:495-498` claims the refusal is implemented.
Fix: `if (out->token_len == 0U) return WT_ERR_PROTOCOL;`.
**Executed by delegated scan (not re-executed by me).**

### CAUD-14 · P3 · `wt_sha256_final(ctx, NULL)` crashes inside OpenSSL
`C99/src/crypto/crypto_openssl.c:175-183` (`EVP_DigestFinal_ex(impl->ctx, out, …)` at `:183`), while ten sibling
entry points reject a NULL out-parameter (`:200, :215, :254, :290, :311, :340, :392, :434, :524, :547, :592`).
Probe `/tmp/ca-q1-findings.c`: `wt_sha256_final(ctx, NULL) -> 134`.
Fix: `if (ctx == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;`.
**Executed by delegated scan (not re-executed by me).**

### CAUD-15 · P3 · Field-line decoder inverts malformed vs truncated
`C99/src/http3/qpack_field.c:49-51, 70-72, 82-84` (strings hard-code `WT_ERR_TRUNCATED`) versus
`:40, 45, 75, 79` (integers hard-code `WT_ERR_PROTOCOL`).
Citation RFC 9204 §4.1.1/§6: an integer over the 62-bit bound is a decoding error (`QPACK_DECOMPRESSION_FAILED`).
Probe `/tmp/ca-q2-line`: `literal-name-ref with a 62-bit-overflowing value length -> status=8 (TRUNCATED)`;
`truncated indexed-dynamic index integer -> status=4 (PROTOCOL)`. `/tmp/ca-q2-malformed` through
`message_decode`: `status=8 error=0x100` (NO_ERROR).
A caller waiting for more bytes can hang, and the peer is told the wrong close code. Fix: propagate the string
decoder's status at 49/70/82 and return `WT_ERR_TRUNCATED` when the integer decoder reports truncation at
40/45/75/79. **Executed by delegated scan (not re-executed by me).**

### CAUD-16 · P3 · Public header states the RFC's opposite for exercise setting 0x21
`C99/include/webtransport/http3/settings.h:56-58`. Citation RFC 9114 §7.2.4.1: identifiers of the form
`0x1f*N + 0x21` "are reserved to exercise the requirement that unknown identifiers be ignored … MUST NOT consider
such settings to have any meaning".
Probe `/tmp/ca-q2-probe-exerciser`: `parse 0x21: status=0 error=0x100 present=0 value=0`, while the comment says
receipt "MUST [be] H3_SETTINGS_ERROR" — contradicting the comment three lines above (`:53-55`), which agrees with
the RFC. Fix: delete/replace the stale comment. Comment-only.
**Executed by delegated scan (not re-executed by me).**

---

## 4. Investigated and rejected

- **Header-parser infinite loop** in `C99/src/http3/driver.c:405-442` (if `header_length` reached
  `WT_HTTP3_DRIVER_FRAME_HEADER_MAX` = 16 with `in_frame == 0`, `if (!state->in_frame) continue;` would spin with
  `position` unchanged): unreachable — 16 bytes is exactly two 8-byte varints and the loop sets `in_frame` on the
  16th byte. Also exercised by 300 000 randomized chunked runs with no hang. **Rejected.**
- **Dangling/stale `state` pointer after `settle_capsule_stream` → `forget_frame` compaction**
  (`driver.c:466-500`): the frames table is a fixed array (not freed memory) and the next loop iteration returns
  at the `is_capsule_stream` check before `state` is read again; no ASan report in 300 000 runs. **Rejected.**
- **`NULL + 0` pointer arithmetic** (`C99/src/core/cursor.c:46` and `:90`, `C99/src/http3/qpack_field_section.c:24`
  with `scratch == NULL, capacity == 0`): formally UB under C11 6.5.6p8, but UBSan does not flag it, every caller
  guards `len != 0`, and `/tmp/ca-nullcur.c` prints the expected result. **Rejected as pedantic-only.**
- **ACK `range_count` vs `ranges_len` inconsistency** (`C99/src/quic/frame.c`): a range count the bytes cannot
  satisfy returns `WT_ERR_TRUNCATED` at parse time, so `range_count` is consistent whenever the decode succeeds;
  `validate_ack`/`ack_covers` walk a cursor and fail closed with FRAME_ENCODING_ERROR anyway. **Rejected.**
- **`memcpy`/`memcmp` with NULL and zero length** (`driver.c:663`, `session_request.c`'s `token_is`,
  `core/writer.c:65`): every site is guarded by a `length != 0` test or short-circuits on a length comparison
  before the call. **Rejected.**
- **`wt_buf_consume(b, n >= len)` discarding the whole buffer** (`C99/src/core/buffer.c:94`): documented
  consume-all semantics; no caller passes a length it did not receive. **Rejected.**
- **Install rpath, `check-package.sh`'s installed-tool execution, the version lockstep, and WT-201**: all verified
  *working* by execution (section 2), not defects. **Rejected.**
- **QPACK static-table truncation (ledger F-01)**: re-derived from freshly fetched RFC 9204 — "committed entries
  match the RFC"; the ledger's fix is real and the extractor now joins wrapped continuation lines. **Rejected as a
  regression.**
- **`authority_matches` port stripping** (`C99/src/webtransport/session_request.c:30-52`): the bracket-aware
  colon scan is correct for `host:port`, `[::1]:port` and bare `::1`; the in-tree WT-153 fix holds. **Rejected.**
- **The "extended CONNECT with no `:scheme`" half of the Q2 report**: refuted by my own probe — `message.c:110`
  refuses it with `0x10e`; only the missing `:path` half is real (CAUD-10). **Rejected as reported.**
- **`(int)` size_t→int narrowings in `crypto_openssl.c`** (HMAC `key_len`, AEAD `aad_len`/`len`, chacha20 `len`):
  judged unreachable because every in-tree caller passes a bounded small length; no finding claimed. **Rejected.**
- **QPACK eviction aliasing, ACK O(n²), driver frame slots, RIC enforcement, static table, etc.** (the ledger's
  fixed set): the delegated Q2 scan re-checked eviction-aliasing and the RFC 9204 Appendix B vectors and found
  them still fixed; the parser-fuzz and ASan/UBSan suites are green. **Rejected as regressions.**

---

## 5. What the maintainers may have wrong about their own code

- `C99/src/http3/message.c`'s comment says it refuses to write a section "whose peer must report
  H3_MESSAGE_ERROR", yet it writes `:status: 005` (CAUD-6).
- `C99/src/quic/packet.c:495-498`'s comment describes a zero-length-token refusal that the code below it does not
  implement (CAUD-13), and `:466` treats a Retry's *Unused* field as if §17.2's *Reserved Bits* rule applied to it
  (CAUD-8).
- `C99/include/webtransport/http3/settings.h:56-58` states the RFC's opposite for exerciser settings,
  contradicting the comment three lines above (CAUD-16) — the same inversion the ledger records as once having
  been in `settings.c` itself.
- `C99/IMPLEMENTATION_PLAN.md:128` advertises `config.origin = "https://example.com"` in the "expected API style";
  no origin field exists in `wt_endpoint_config_t`/`wt_session_config_t`, no Origin field is ever put on the wire,
  and the CLI's `--origin` is used as the *authority/host* fallback (`apps/wt-client-c99/main.c:157`,
  `apps/wt-server-c99/main.c:129`) plus a JSON report field. The name invites the belief that the draft's §3.2
  Origin rule is handled (CAUD-7).
- `C99/include/webtransport/webtransport/capsule.h:117-120` exports readers for the two capsules
  `api/session.c:136-143` and `docs/COMPLIANCE-MATRIX.md` call prohibited; they are used only by tests, so the
  header's API surface suggests support the protocol layer deliberately refuses.
- `C99/apps/CMakeLists.txt:136`'s comment that a skip is visible and an exit 0 would have been counted as a pass
  is accurate: verified that the three python3-using check-cli scripts and check-vectors.sh exit 77 with a reason
  when python3 is absent (WT-201 closed).
- The docs' open-work statement (WT-223 FreeBSD job, WT-224 native Windows leg, WT-225 Debian-13 leg, WT-226
  stale "under way") is consistent with what I could observe: the Windows legs compile and link here but
  **cannot be run** (no Wine), and no runner for the others exists in this checkout.
- `C99/README.md`/`docs/PORTABILITY.md` say the Windows suite is green under Wine (85 executables, 64,900 checks);
  I could not reproduce that claim on this host and did not attempt to contradict it — Wine is simply absent, so
  the Windows behaviour claim remains unverified here rather than false.

---

## Appendix A — Addendum as sent (verbatim)

ADDENDUM to my C99 audit (after the two still-running delegated scans both returned). Tree still untouched:
`git status --porcelain` empty, `git diff --name-only HEAD` empty, `git rev-parse HEAD` =
46937e29eb734887ca7b739abfedaf68ae565de2. New findings, only the first three were re-executed by me; the rest are
from my delegated scans with their probe paths.

CAUD-8 | P1 (interop, wire-visible) | **Retry decoder rejects the Unused bits RFC 9000 §17.2.5 orders a client to
ignore, so a conformant server's Retry is silently discarded and the handshake cannot complete.**
`C99/src/quic/packet.c:466` `if ((first & 0x0cU) != 0U) return PROTOCOL_VIOLATION;`, reached from the wire via
`connection.c:3015→3019→on_retry_packet:2600` (which discards and returns WT_OK). RFC 9000 §17.2.5 (verified from
the RFC text, /tmp/ca-q1-rfc9000.txt:5106): "The value in the Unused field is set to an arbitrary value by the
server. Clients MUST ignore the value of this field." My probe `/tmp/ca-final.c` (24-byte Retry, Unused nibble
varied):
```
Retry first=0xf0 (Unused=0x0) -> 0 err=0
Retry first=0xfc (Unused=0xc) -> 4 err=10     (WT_ERR_PROTOCOL / PROTOCOL_VIOLATION)
Retry first=0xf3 (Unused=0x3) -> 0 err=0
```
Note the check is also partial: it rejects 0x0c but not 0x03. Fix: delete the test (a Retry has no header
protection, so §17.2's reserved-bit rule does not apply to it). EXECUTED by me; the end-to-end "handshake fails"
consequence is inferred from the call chain, not observed against a live peer.

CAUD-9 | P2 | **SETTINGS_H3_DATAGRAM accepts values other than 0/1 and treats them as enabled.**
`C99/src/http3/settings.c:122-125` (parse) and `:54` (set) check only ENABLE_CONNECT_PROTOCOL. RFC 9297 §2.1.1
(verified, /tmp/rfc9297.txt:227): "The value ... MUST be either 0 or 1. ... If the SETTINGS_H3_DATAGRAM setting
is received with a value that is neither 0 nor 1, the receiver MUST terminate the connection with error
H3_SETTINGS_ERROR." My probe `/tmp/ca-final.c`:
```
H3_DATAGRAM=2 payload: 2 bytes -> parse 0 err=0x100     (WT_OK, NO_ERROR)
  present=1 value=2
```
EXECUTED by me. Caveat, verified by my own grep: `wt_http3_settings_parse` has no caller in
`src/http3/driver.c` or `apps/support/` (only tests, the conformance app's refusal scenario, and the fuzzer), so
this is a public-API/conformance-surface defect, not reachable through the shipped tools.

CAUD-10 | P3 | **An extended CONNECT carrying `:protocol` but no `:path` passes `wt_http3_message_decode`.**
`C99/src/http3/headers.c:109-113` sets `is_connect` for any CONNECT (so `header_finish:188-194` then requires only
`:authority`), and `message.c:114-119` deliberately skips the path requirement for CONNECT. RFC 8441 §4 (verified,
/tmp/rfc8441.txt): "On requests that contain the :protocol pseudo-header field, the :scheme and :path
pseudo-header fields of the target URI MUST also be included." My probe `/tmp/ca-bidi.c` (`:method CONNECT,
:scheme https, :authority localhost, :protocol webtransport-h3`, no `:path`):
```
message_decode -> 0 err=0x100 scheme_len=5 path_len=0 protocol_len=15
```
(the no-`:scheme` variant IS refused by message.c:110 with 0x10e, so only the `:path` half is open). EXECUTED by
me. Impact on WebTransport is nil because `session_request.c:124-125` re-checks `path_length`; the defect is in
the HTTP/3 message layer.

Also verified by me in the same run: H3_DATAGRAM aside, the peer's SETTINGS **payload** is never parsed by the
shipped endpoints — `grep -rn "wt_http3_settings_parse|WT_HTTP3_SETTING_" C99/apps/support/ C99/src/http3/driver.c`
returns nothing, and `apps/support/session_loop.c:127`'s `side_on_frame_payload` acts only on HEADERS. So the
peer's `WT_INITIAL_MAX_DATA/STREAMS` SETTINGS cannot be reaching `wt_session_flow_configure` through that path.
UNFINISHED — I did not trace what (if anything) consumes them, or whether this is a real resource-accounting gap;
flagged, not filed.

From my delegated scans (their probes under /tmp; executed by them, NOT re-executed by me — treat as
reported-with-evidence):
- CAUD-11 P2 `C99/src/quic/protection.c:109-135` (copy at :132): `wt_quic_packet_keys_update(&k,&k)` yields the
  NEW header-protection key because `wt_quic_derive_packet_keys` memsets/overwrites `out == current` before the
  copy; RFC 9001 §6.1 "the header protection key is not updated". Probe `/tmp/ca-q1-findings.c`. Not reachable
  in-tree (`derive_next_keys` uses distinct objects), so P3 in practice.
- CAUD-12 P3 `C99/src/quic/packet.c:687,691`: `wt_quic_retry_packet_encode` SEGVs on `dcid=NULL,len=4` /
  `token=NULL,len=4` (the long-header encoder validates the same arguments at :545-559).
- CAUD-13 P3 `C99/src/quic/packet.c:494-500`: the Retry decoder returns WT_OK for a zero-length token (RFC 9000
  §17.2.5.2 says discard); the sole in-tree caller re-checks at `connection.c:2610-2614`, so no live accept.
- CAUD-14 P3 `C99/src/crypto/crypto_openssl.c:175-183`: `wt_sha256_final(ctx, NULL)` crashes inside OpenSSL
  while ten sibling entry points reject a NULL out-parameter.
- CAUD-15 P3 `C99/src/http3/qpack_field.c:49-51,70-72,82-84` vs `:40,45,75,79`: a >62-bit integer in a string
  length is reported WT_ERR_TRUNCATED with NO_ERROR (caller may wait forever) while a genuinely truncated index is
  reported WT_ERR_PROTOCOL; RFC 9204 §4.1.1/§6.
- CAUD-16 P3 `C99/include/webtransport/http3/settings.h:56-58`: the comment says receipt of exerciser setting 0x21
  "MUST [be] H3_SETTINGS_ERROR"; RFC 9114 §7.2.4.1 and the code say ignore (the comment three lines above agrees
  with the RFC). Comment-only.

No P1 memory-safety or auth-bypass issue was found by any of the three scans; the only P1-class item is the Retry
Unused-bits interop defect (CAUD-8).
