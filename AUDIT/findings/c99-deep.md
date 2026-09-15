# c99-deep — pre-production audit of the C99 WebTransport implementation (L0–L4)

Scope: `/Users/node3/Downloads/WebTransport/C99/**` (src, include, apps, tests, scripts, docs, platform,
CMakeLists.txt), branch `audit/2026-09-15`. Read-only pass: the only files touched are this report and
`c99-deep.json`. The already-known-and-fixed list (HTTP/3 push OOB, QPACK eviction aliasing, uni-stream
session check, ACK O(n²), driver frame slots, QPACK RIC enforcement, encoder-stream insert errors, capsule
fail-open set, Retry decode underflow, dropped peer transport parameters, hp key-update rule, signature
scheme/key binding, Winsock refcount, callback use-after-free, CLI JSON escaping, allocator zero-size,
endpoint host bound, stream-table reclaim, MAX_PUSH_ID role, packet version validation) was excluded and none
of the findings below restates it.

Method: static reading of every peer-reachable parser and state machine in `src/quic`, `src/http3`,
`src/webtransport`, `src/tls`, `src/runtime`, `src/api`; every wire constant compared against
`/Users/node3/Downloads/WebTransport/Swift/Sources` and against the normative texts (RFC 9000, RFC 9001,
RFC 9114, RFC 9204, RFC 9297, draft-ietf-webtrans-http3-16, draft-ietf-quic-reliable-stream-reset-09);
the test suite and the check scripts read for assertions that cannot fail. Commands run (all read-only):

```
$ clang -std=c99 -pedantic-errors -fsyntax-only -Iinclude -Iapps/support <each src/*.c and apps/*.c>
(no output — strict C99 clean)
$ for h in $(find include -name '*.h'); do echo "#include \"$h\"" | clang -std=c99 -pedantic-errors -fsyntax-only -x c -Iinclude -; done
(no output — every public header self-contained)
$ python3 tests/vectors/extract_rfc9204_static_table.py <rfc9204.txt> --check
rfc9204 static table: committed entries match the RFC        <- and that is the defect: see F-01
```

Findings: **3 × S0, 6 × S1, 18 × S2, 8 × S3**. Confidence is `confirmed` (reproduced or proved by code) or
`suspected`. The findings were produced by this pass directly and by four delegated sub-scans (tests, docs and
check scripts, Swift-vs-C99 wire constants, unchecked returns and dead code); every finding below was
re-read and confirmed against the quoted lines by the author of this report before it was written down.

---

## S0 — go-live blockers

### F-01 — S0 — bug — `C99/src/http3/qpack_static_table.h:60` (and 71, 74, 75, 77, 82, 84, 87, 88, 115)
**Ten QPACK static-table entries are truncated, so indexed static references decode to different field values
than the peer encoded — and the check that exists to prevent this passes.**

What is wrong: the committed table holds values cut at the RFC's printed line wrap. `check-vectors.sh` runs the
extractor with `--check`; the extractor's row regex only matches lines whose first column is an index, so the
RFC's continuation lines (`|       |        | message |`) are silently dropped, and `--check` re-derives exactly
the same truncated text, so it can never fail.

Evidence — the file:

```
src/http3/qpack_static_table.h:60:     {"accept", "application/dns-"},
src/http3/qpack_static_table.h:71:     {"cache-control", "public, max-"},
src/http3/qpack_static_table.h:74:     {"content-type", "application/dns-"},
src/http3/qpack_static_table.h:75:     {"content-type", "application/"},
src/http3/qpack_static_table.h:77:     {"content-type", "application/x-www-"},
src/http3/qpack_static_table.h:82:     {"content-type", "text/html;"},
src/http3/qpack_static_table.h:84:     {"content-type", "text/"},
src/http3/qpack_static_table.h:88:     {"strict-transport-security", "max-age=31536000;"},
src/http3/qpack_static_table.h:115:    {"content-security-policy", "script-src 'none';"},
```

RFC 9204 Appendix A prints those cells wrapped, and says so itself ("Any line breaks that appear within field
names or values are due to formatting"):

```
   | 52    | content-type                     | text/html;            |
   |       |                                  | charset=utf-8         |
```

The extractor's silently-skipped continuation line:

```python
tests/vectors/extract_rfc9204_static_table.py:42  ROW = re.compile(r"^\s*\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$")
tests/vectors/extract_rfc9204_static_table.py:63  for line in text[start:end].splitlines():
tests/vectors/extract_rfc9204_static_table.py:64      match = ROW.match(line)
tests/vectors/extract_rfc9204_static_table.py:65      if match is None:
tests/vectors/extract_rfc9204_static_table.py:66          continue
```

And the check passing on the defective table (exit 0):

```
$ python3 tests/vectors/extract_rfc9204_static_table.py <rfc9204.txt> --check
rfc9204 static table: committed entries match the RFC
$ echo $?
0
```

This is consumed by both directions: `wt_qpack_static_entry` (`src/http3/qpack.c`) is what
`wt_qpack_field_section_next` (`src/http3/qpack_field_section.c`) calls for an
`INDEXED_STATIC`/`LITERAL_NAME_REF_STATIC` line, so a peer that sends static index 52 gets
`content-type: text/html;` instead of `content-type: text/html; charset=utf-8` — a wrong header field, on a
normal path, silently. No test covers any of the ten: `tests/unit/test_qpack_static.c` asserts entries 0, 1, 98
and the short ones only.

What correct looks like — the ten values must be the RFC's full cells (index 30/44 `application/dns-message`;
41 `public, max-age=31536000`; 45 `application/javascript`; 47 `application/x-www-form-urlencoded`; 52
`text/html; charset=utf-8`; 54 `text/plain;charset=utf-8`; 57 `max-age=31536000; includesubdomains`; 58
`max-age=31536000; includesubdomains; preload`; 85 `script-src 'none'; object-src 'none'; base-uri 'none'`).

Smallest fix — in `extract()` keep the last index and, for a row whose index column is blank, append the third
column to the previous entry's value; re-run it to regenerate the header; add one assertion per long value
(`wt_qpack_static_entry(52U, &entry)` equals `text/html; charset=utf-8`) so the extraction is pinned by a test
rather than only by the generator.

### F-02 — S0 — bug — `C99/include/webtransport/webtransport/session_request.h:38`
**The draft-16 `:protocol` token is wrong and the "legacy" constant is the same string, so the endpoint can
neither send nor accept `webtransport-h3`.**

What is wrong: draft-ietf-webtrans-http3-16 §2.1.2/§3.2/§9.1 fixes the upgrade token as `webtransport-h3`
(`webtransport` is the *HTTP/2* capsule-protocol token). The C99 header defines the draft-16 token and the
pre-draft token as the same string, and the code's own comment in the `.c` file states the correct value.

Evidence:

```c
C99/include/webtransport/webtransport/session_request.h:37  /* The `:protocol` value that makes a CONNECT a WebTransport request (draft-16 section 3.2). */
C99/include/webtransport/webtransport/session_request.h:38  #define WT_WEBTRANSPORT_PROTOCOL_TOKEN "webtransport"
C99/include/webtransport/webtransport/session_request.h:43  /* The PRE-DRAFT token draft-16 renamed away from. ... */
C99/include/webtransport/webtransport/session_request.h:45  #define WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY "webtransport"
```

```c
C99/src/webtransport/session_request.c:103  /* BOTH tokens name a WebTransport request. Draft-16 section 3.2 defines `webtransport-h3` and the drafts before
C99/src/webtransport/session_request.c:108      !(token_is(message->protocol, message->protocol_length, WT_WEBTRANSPORT_PROTOCOL_TOKEN) ||
C99/src/webtransport/session_request.c:109        token_is(message->protocol, message->protocol_length, WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY))) {
```

The same string is what the client sends (`C99/src/http3/driver.c:1252`), what the conformance scenarios build,
and what `docs/COMPLIANCE-MATRIX.md:12` records as the draft-16 requirement. The Swift reference in the same
repository uses the correct value (`Swift/Sources/WebTransportHTTP3Core/HTTP3Constants.swift:97`
`upgradeToken: "webtransport-h3"`), so a C99 client is refused by a draft-16-strict Swift server and a Swift
strict client is treated as "not WebTransport" by a C99 server (`outcome = WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT`).

What correct looks like: the draft-16 token is `webtransport-h3`; accepting the pre-draft `webtransport` in
addition is the documented interop posture, but it must be the *second* constant, not a duplicate of the first.

Smallest fix: `#define WT_WEBTRANSPORT_PROTOCOL_TOKEN "webtransport-h3"`, leave
`WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY "webtransport"`; update `docs/COMPLIANCE-MATRIX.md:12`.

### F-03 — S0 — bug — `C99/src/quic/stream.c:459-466`
**The stream-table reclaim decrements the "opened" counters, so a long-lived session reuses stream IDs and then
cannot open streams at all — the exact opposite of the comment on the code path that computes them.**

What is wrong: `wt_quic_stream_table_open` reclaims complete streams when the 32-slot table is full and does
`(*opened)--` for each reclaimed slot. `wt_quic_connection_open_stream` derives the *next* stream ID from that
counter, so after the first reclaim the counter no longer names the next index: the next open rebuilds an ID
that either collides with a live stream (→ `WT_ERR_STATE` from `wt_quic_stream_table_open`, surfaced to the
caller as a failed open) or, once that stream is gone, reuses a stream ID that was already used and finished
(RFC 9000 §2.1: "A QUIC endpoint MUST NOT reuse a stream ID within a connection"). Nothing else frees a slot:
`wt_quic_stream_table_close` has no caller in `src/` or `apps/` (only the unit test), so the sweep runs on the
33rd open of a session.

Evidence:

```c
C99/src/quic/stream.c:444  opened = initiated_by_us ? (bidirectional ? &table->opened_by_us_bidi : &table->opened_by_us_uni)
C99/src/quic/stream.c:454    /* RECLAIM BEFORE REFUSING. `wt_quic_stream_table_close` requires a stream to be COMPLETE and had no caller
C99/src/quic/stream.c:459    for (i = 0U; i < WT_QUIC_STREAM_TABLE_MAX; i++) {
C99/src/quic/stream.c:460      if (table->used[i] && wt_quic_stream_complete(&table->streams[i])) {
C99/src/quic/stream.c:461        table->used[i] = 0U;
C99/src/quic/stream.c:462        table->count--;
C99/src/quic/stream.c:463        (*opened)--;              /* <-- the counter is the next index */
```

```c
C99/src/quic/connection.c:2303  /* The number comes from the count of what this endpoint has already opened in that class, so it is
C99/src/quic/connection.c:2304   * never reused and never chosen by the caller (RFC 9000 section 2.1). */
C99/src/quic/connection.c:2305  index = wt_quic_stream_table_opened_by_us(&connection->streams, bidirectional);
C99/src/quic/connection.c:2306  stream_id = wt_quic_stream_id_make(..., index);
```

`grep -rn wt_quic_stream_table_close C99/src C99/include C99/apps` returns only its definition and declaration;
`WT_QUIC_STREAM_TABLE_MAX` is 32 (`include/webtransport/quic/stream.h:255`). No test exercises the reclaim path:
`grep -rn "reclaim" C99/tests` is empty and `test_stream_table` only fills the table with *incomplete* streams.

What correct looks like: `opened_by_us_*`/`opened_by_peer_*` are monotonic counters of stream IDs *issued*
(RFC 9000 §2.1: the "next" ID is only ever larger); reclaim may free `used[i]` and `count` but must not
decrement them.

Smallest fix: delete line 463 (`(*opened)--;`) and, if the granted-stream accounting needs a separate live
count, add a second field for it; add a regression test that opens 33 streams, completes 32, and asserts the
33rd/34th IDs are strictly increasing and never repeat.

---

## S1 — high

### F-04 — S1 — bug — `C99/include/webtransport/quic/transport_parameters.h:64`
**The `reset_stream_at` transport-parameter codepoint is wrong, so the extension draft-16 requires is never
negotiated with a conforming peer (and the two in-repo implementations disagree with each other).**

Evidence:

```c
C99/include/webtransport/quic/transport_parameters.h:64  #define WT_QUIC_TP_RESET_STREAM_AT ((uint64_t)0x17f7586d2cb570)
C99/src/quic/transport_parameters.c:472  status = wt_quic_transport_parameters_add_bytes(params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U);
Swift/Sources/WebTransportQUICCore/QUICTransportParameters.swift:144  public static let resetStreamAt: UInt64 = 0x17f7_586d_2cb5_71
```

The normative reference draft-16 §3.1 points at (draft-ietf-quic-reliable-stream-reset-09, §3 and §8.1)
registers it as **0x1d**:

```
   Support for receiving RESET_STREAM_AT frames is advertised by sending
   the reset_stream_at (0x1d) transport parameter ...
8.1.  QUIC Transport Parameter
   Value:  0x1d
   Parameter Name:  reset_stream_at
```

So C99 advertises `0x17f7586d2cb570`, Swift advertises `0x17f7586d2cb571` (the -05/-06-era value), and a
conforming draft-16 peer looks for `0x1d`. draft-16 §3.1 makes an empty `reset_stream_at` a requirement of
*every* WebTransport endpoint, so the parameter a conforming peer checks is the one neither tree sends; C99's
"non-empty value is TRANSPORT_PARAMETER_ERROR" rule (`transport_parameters.c:250-258`) is likewise enforced on
the wrong codepoint. The RESET_STREAM_AT *frame* type is correct (`0x24` in both trees).

What correct looks like: `WT_QUIC_TP_RESET_STREAM_AT` is `0x1d`; the same fix is needed in Swift.

Smallest fix: change the constant to `((uint64_t)0x1d)` and the Swift one to `0x1d`; add a vector test that
asserts the encoded parameter identifier byte is `0x1d`.

### F-05 — S1 — logic — `C99/src/quic/transport_parameters.c:214-311`
**The transport-parameter value rules omit two RFC 9000 §18.2 MUSTs: `initial_max_streams_*` above 2^60, and a
`stateless_reset_token` sent by a client — while `connection.c` claims the stream limit is checked.**

Evidence — the check function's whole rule set (max_udp_payload_size, ack_delay_exponent, reset_stream_at,
max_ack_delay, active_connection_id_limit, stateless_reset_token *length*, ODCID length, source-CID lengths):

```
C99/src/quic/transport_parameters.c:214  wt_status_t wt_quic_transport_parameters_check(
C99/src/quic/transport_parameters.c:226    params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, &value);
C99/src/quic/transport_parameters.c:238    params, WT_QUIC_TP_ACK_DELAY_EXPONENT, &value);
C99/src/quic/transport_parameters.c:258        WT_QUIC_TP_RESET_STREAM_AT);
C99/src/quic/transport_parameters.c:264    params, WT_QUIC_TP_MAX_ACK_DELAY, &value);
C99/src/quic/transport_parameters.c:275    params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, &value);
C99/src/quic/transport_parameters.c:309  /* A zero max_datagram_frame_size is deliberately NOT refused ...
(grep -n "INITIAL_MAX_STREAMS" ...check() returns nothing)
```

The comment that says otherwise:

```c
C99/src/quic/connection.c:131  /* RFC 9000 section 18.2's own rules -- a max_udp_payload_size below 1200, an ack delay exponent
C99/src/quic/connection.c:132   * above 20, a stream limit above 2^60 -- are an error rather than something to clamp. */
```

RFC 9000 §4.6 is explicit: "If a max_streams transport parameter or a MAX_STREAMS frame is received with a
value greater than 2^60 ... the connection MUST be closed immediately with a connection error of type
TRANSPORT_PARAMETER_ERROR if the offending value was received in a transport parameter". The frame half is
implemented (`src/quic/frame.c:299`, `:329`); the transport-parameter half is not, so a peer may set
`initial_max_streams_bidi = 2^62-1` and this endpoint accepts it and stores it
(`connection.c:149-150`). §18.2 also says a server MUST treat a `stateless_reset_token` from a client as
TRANSPORT_PARAMETER_ERROR; the code checks only that the length is 16 for both roles.

What correct looks like: `check` refuses `initial_max_streams_bidi`/`_uni` above `UINT64_C(1) << 60` (and the
client-side `stateless_reset_token`), returning `WT_ERR_PROTOCOL` with `WT_QUIC_TRANSPORT_PARAMETER_ERROR` and
the offender identifier.

Smallest fix: two more blocks in `wt_quic_transport_parameters_check` next to the existing ones, using the
`parameter_or`/`integer` helpers already there.

### F-06 — S1 — logic — `C99/src/quic/connection.c:183-190`
**A peer's `initial_source_connection_id` is adopted as the destination connection ID without ever being
compared with the Source Connection ID of the packet it arrived in — the RFC 9000 §7.3 MUST.**

Evidence:

```c
C99/src/quic/connection.c:183    const uint8_t *peer_source = NULL;
C99/src/quic/connection.c:184    size_t peer_source_length = 0U;
C99/src/quic/connection.c:185    if (wt_quic_transport_parameters_get(&params, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &peer_source,
C99/src/quic/connection.c:186                                         &peer_source_length) == WT_OK &&
C99/src/quic/connection.c:189      adopt_peer_connection_id(connection, peer_source, peer_source_length);
```

The value the received packet actually carried is decoded and stored, and then never used for this:

```c
C99/src/quic/packet_io.c:196      out->source_connection_id = header.source_connection_id;
C99/src/quic/packet_io.c:197      out->source_connection_id_len = header.source_connection_id_len;
```

RFC 9000 §7.3: "The values provided by a peer for these transport parameters MUST match the values that an
endpoint used in the Destination and Source Connection ID fields of Initial packets that it sent (and received,
for servers). Endpoints MUST validate that received transport parameters match received connection ID values."
and "An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or
PROTOCOL_VIOLATION: ... a mismatch between values received from a peer in these transport parameters and the
value sent in the corresponding Destination or Source Connection ID fields of Initial packets." The
`retry_source_connection_id` half *is* checked (`connection.c:216-226`); the `initial_source_connection_id`
half is not, in either role.

What correct looks like: the connection records the Source Connection ID of the first Initial/Handshake packet
it receives from the peer and compares it with `initial_source_connection_id` (and the server additionally
compares its `original_destination_connection_id` with the client's first DCID), closing with
TRANSPORT_PARAMETER_ERROR on a mismatch.

Smallest fix: pass `packet.source_connection_id`/`_len` from the receive path into
`wt_quic_connection_set_peer_parameters` (or store it on the connection) and compare before adopting.

### F-07 — S1 — bug — `C99/src/http3/driver.c:226-231`
**A WebTransport unidirectional prefix split between the type and the session ID is reported as TRUNCATED
after the stream has already been marked classified; the frame route then aborts and the connection is closed
with INTERNAL_ERROR — and a caller that continues would deliver the remaining session-ID bytes to the session
with no session check at all.**

Evidence — the two returns:

```c
C99/src/http3/driver.c:226      if (take >= length) {
C99/src/http3/driver.c:227        /* The type used the whole frame: the session ID has not arrived. */
C99/src/http3/driver.c:228        return WT_ERR_TRUNCATED;
C99/src/http3/driver.c:229      }
C99/src/http3/driver.c:230      session_cursor = wt_cursor_init(data + take, length - take);
C99/src/http3/driver.c:231      if (wt_quic_varint_decode(&session_cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
```

but the classification one line earlier already recorded the stream in the endpoint's table:

```c
C99/src/http3/driver.c:201    status = wt_http3_endpoint_on_uni_stream(driver->endpoint, stream_id, prefix, have, NULL, out_kind, out_error);
C99/src/http3/endpoint.c:470    if (endpoint->stream_count >= WT_HTTP3_ENDPOINT_STREAMS_MAX) { ... }
C99/src/http3/endpoint.c:473    slot = &endpoint->streams[endpoint->stream_count];
C99/src/http3/endpoint.c:474    slot->stream_id = stream_id;
C99/src/http3/endpoint.c:475    slot->kind = kind;          /* WEBTRANSPORT, before the session ID is read */
```

Consequences: (a) `route_quic_frame` propagates the status, `wt_http3_driver_on_quic_frame` sets no HTTP/3
error code for it, so the connection's `deliver_to_handler` closes the connection with INTERNAL_ERROR
(`connection.c:1391-1405`) — a legal, fragmented prefix kills the session; (b) on a later STREAM frame for that
stream, `route_quic_frame` reads `wt_http3_endpoint_stream_kind(...)`, sees WEBTRANSPORT,
sets `finished_prefix = 1` and hands `frame->as.stream.data` straight to `sink->on_stream_data`
(`driver.c:687-694`) — the session-ID comparison at `driver.c:238-241` and `remember_data_stream` are both
skipped. A QUIC peer may put the type and the session ID in separate STREAM frames (the repo's own README notes
aioquic does exactly that for the bidirectional prefix), so this is peer-reachable.

Evidence that no test covers it: `tests/unit/test_http3_driver.c:79-129` builds the WebTransport uni prefix as
type **and** session ID in one buffer; no test splits between them, and the comment there asserts the
whole-prefix behaviour.

What correct looks like: the session ID is part of the same prefix as the type, so a frame that carries only
the type must be held in the same pending table (its bytes and offset) and the prefix completed on a later
frame before the endpoint is told the stream has a kind — the classification must not be observable until the
whole prefix validated.

Smallest fix: in `wt_http3_driver_on_uni_stream_data`, do the session-ID decode (and the session comparison)
*inside* the pending assembly, before calling `wt_http3_endpoint_on_uni_stream`, and hold the type bytes in the
pending table when the session ID has not arrived (return `WT_OK`, kind UNKNOWN) rather than after
classification.

### F-08 — S1 — bug — `C99/src/http3/headers.c:117-128`
**Pseudo-header values are never checked for the field-content grammar, so `:method`/`:scheme`/`:path`/
`:authority`/`:protocol` may carry CR, LF, NUL or any other C0 control — the malformed-field MUST that the
regular-field branch enforces.**

Evidence — the pseudo-header branch returns without validating the value; the two grammar functions are only
reached for regular fields:

```c
C99/src/http3/headers.c:117    if (bit == 0U) { ... return WT_ERR_PROTOCOL; }
C99/src/http3/headers.c:123    if ((validation->pseudo_seen & bit) != 0U) { ... return WT_ERR_PROTOCOL; }
C99/src/http3/headers.c:127    validation->pseudo_seen |= bit;
C99/src/http3/headers.c:128    return WT_OK;                       /* no field_value_is_valid(value, ...) */
...
C99/src/http3/headers.c:141    if (!field_name_is_valid(name, name_length) || !field_value_is_valid(value, value_length)) {
```

RFC 9114 §4.3.1/§10.3 make a request or response carrying a character not permitted in a field value
malformed; the value of a pseudo-header is a field value. There is no in-tree echo that turns this into header
injection today (the CLI sanitises `request_line` at `apps/support/session_loop.c:1141-1144` and the response
builder writes no caller bytes), so the impact is a malformed message accepted rather than a demonstrated
injection — but the rule is a MUST and the value is fully peer-controlled.

What correct looks like: run `field_value_is_valid` on every pseudo-header value, and additionally require
`:method` to be a token, `:scheme` to be `https` (see observation O-3), and `:path`/`:authority` to be
non-empty and control-free.

Smallest fix: call `field_value_is_valid(value, value_length)` before line 128 and return
`WT_HTTP3_MESSAGE_ERROR` on failure.

### F-28 — S1 — bug — `C99/src/core/time.c:35`
**On Windows the monotonic clock wraps after about 21 days of process uptime (less if the counter runs fast),
because the tick count is multiplied by 10^6 before it is divided by the frequency.**

Evidence:

```c
C99/src/core/time.c:35    return ((uint64_t)counter.QuadPart * 1000000U) / frequency;
```

`counter.QuadPart * 1'000'000` overflows `uint64_t` once the tick count passes `2^64 / 10^6 ≈ 1.84e13`. With
the usual 10 MHz `QueryPerformanceFrequency` that is ≈ 21.4 days of uptime; on a host where QPC reports the TSC
frequency (gigahertz) it is minutes to hours. After the wrap `wt_now_micros()` returns a *smaller* value than
before, breaking the monotonicity the file's own header promises ("It never decreases"), which is exactly the
failure the header says a fallback must not introduce. Every QUIC deadline, idle timeout and PTO on that
connection then mis-fires. The POSIX branch (`time.c:24-27`) is unaffected (`tv_sec * 1e6 ≈ 1.7e15`).

What correct looks like: divide before multiplying, e.g.
`(counter.QuadPart / frequency) * 1000000U + ((counter.QuadPart % frequency) * 1000000U) / frequency`
(the remainder term cannot overflow because `frequency <= 1e9` in practice).

Smallest fix: that expression, plus a test that feeds a counter near `UINT64_MAX / 1000000` and asserts the
result is monotonic.

---

## S2 — medium

### F-09 — S2 — unsafe — `C99/src/http3/qpack_field.c:56,58`
**A peer's QPACK name length is narrowed with a bare `(size_t)` cast instead of the checked helper, so on a
32-bit target the field line is mis-parsed.**

Evidence:

```c
C99/src/http3/qpack_field.c:53      uint64_t name_length;
C99/src/http3/qpack_field.c:54      if (wt_qpack_integer_decode(c, 3U, &name_length) != WT_OK) return WT_ERR_PROTOCOL;
C99/src/http3/qpack_field.c:56      out->name = wt_cursor_bytes(c, (size_t)name_length);
C99/src/http3/qpack_field.c:58      out->name_length = (size_t)name_length;
```

The sibling string path guards explicitly (`qpack_primitives.c:110` `if (length > (uint64_t)SIZE_MAX) return
WT_ERR_LIMIT;`), and `checked.h` states the library's rule ("so `(uint32_t)some_u64` never appears in a length
field"). On a 64-bit build the cast is lossless; on a 32-bit build a `name_length` of `2^32 + n` truncates, the
cursor consumes the wrong number of bytes and the value string that follows is read from the wrong offset.

What correct looks like: refuse when the value does not fit `size_t` (as `wt_qpack_string_decode` does) and use
the narrowed local.

Smallest fix: add `if (name_length > (uint64_t)SIZE_MAX) return WT_ERR_LIMIT;` before line 56 (or route it
through `wt_checked_narrow_u64_to_size`).

### F-10 — S2 — test — `C99/tests/unit/test_runtime_session_pair.c:742-758`
**The suite is green only because the synthetic clock stops 733 ms short of the earliest possible probe
timeout, and the assertions pin a defect the implementation has already fixed.**

Evidence — the loop advances 1000 µs per round for 600 rounds:

```c
C99/tests/unit/test_runtime_session_pair.c:683  for (round = 0U; round < 600U; round++) {
C99/tests/unit/test_runtime_session_pair.c:695    pair.now += 1000U;
```

while the only PTO a connection with no RTT sample can arm is the initial one:

```c
C99/src/quic/connection.c:37  #define WT_QUIC_CONNECTION_INITIAL_PTO 1333000U
C99/src/quic/connection.c:332    backoff = WT_QUIC_CONNECTION_INITIAL_PTO * (1ULL << (...pto_count...));
C99/src/quic/connection.c:333    *out_time = earliest + backoff;
```

and the retransmission the test says does not exist is implemented and wired:

```c
C99/src/quic/connection.c:3199    /* RFC 9002 section 6.2.4: a probe timeout MUST send new frames OR RETRANSMIT unacknowledged data. ... */
C99/src/quic/connection.c:3225      connection->probes_with_data++;
C99/src/quic/connection.c:3226      if (connection->lost_handler != NULL) {
C99/src/quic/connection.c:3227        connection->lost_handler(connection->lost_context, &connection->frames[connection->loss.sent[oldest].tag]);
C99/apps/support/session_loop.c:377  static void client_on_lost_frame(void *context, const wt_quic_tx_frame_t *frame) { ... wt_http3_driver_resend_request(...) }
```

The test asserts the opposite ("the lost stream frame is NOT reported yet: the application space never armed
its probe (WT-135)", "the exchange did NOT complete, because nothing resends it yet (WT-135)"). Raising the
round budget past ~1333 ms makes those lines fail.

What correct looks like: advance the clock past the initial PTO and assert the exchange completes
(`connect_arrived(&pair) != 0`), or keep a known-fail marker rather than a passing assertion.

Smallest fix: raise the round count (or the per-round step) so the synthetic time exceeds
`WT_QUIC_CONNECTION_INITIAL_PTO`, then flip the two assertions.

### F-11 — S2 — test — `C99/tests/unit/test_http3_driver.c:633`
**An always-true assertion: the "unidirectional" property of every stream this endpoint opens is never
checked.**

Evidence:

```c
C99/tests/unit/test_http3_driver.c:633  WT_EXPECT_INT("streams this endpoint opens are unidirectional", 0, bidirectional ? 0 : 0);
```

`bidirectional ? 0 : 0` is 0 for both values, so the check cannot fail. Smallest fix:
`WT_EXPECT_INT(..., 0, bidirectional);`.

### F-12 — S2 — test — `C99/tests/unit/test_quic_frame.c:54-55`
**The two-pass writer property — the stated purpose of the helper used by all 26 frame round-trips — is
checked by comparing a variable with itself.**

Evidence:

```c
C99/tests/unit/test_quic_frame.c:36  /* Encode into a measurement first, then into a buffer of exactly that size, and
C99/tests/unit/test_quic_frame.c:37   * decode, returning the status. Checks that the two passes agree, which is the
C99/tests/unit/test_quic_frame.c:38   * property the whole writer design exists for. */
C99/tests/unit/test_quic_frame.c:54    (void)encode_ok("  the encode", frame, buffer, capacity);
C99/tests/unit/test_quic_frame.c:55    WT_EXPECT_U64("  the encode wrote what the measurement said",
C99/tests/unit/test_quic_frame.c:56                  (uint64_t)wt_writer_offset(&measure),
C99/tests/unit/test_quic_frame.c:57                  (uint64_t)wt_writer_offset(&measure));
```

The written length returned by `encode_ok` is discarded. Smallest fix: capture it and compare it with
`wt_writer_offset(&measure)` (and initialise the decode cursor from it).

### F-13 — S2 — test — `C99/tests/unit/test_quic_connection.c:1295`
**The synthetic clock is passed as the stream-id out-parameter, so it is clobbered to zero and the whole loss
scenario runs at time 0.**

Evidence:

```c
C99/tests/unit/test_quic_connection.c:1274  uint64_t now = 101000000U;
C99/tests/unit/test_quic_connection.c:1294  WT_EXPECT_OK("the client sends stream data",
C99/tests/unit/test_quic_connection.c:1295               wt_quic_connection_open_stream(&pair.client, 1, &now));
...
C99/tests/unit/test_quic_connection.c:1301               wt_quic_connection_send_stream(&pair.client, 0U, i * 2U, data, sizeof(data), 0, ... now)
```

`wt_quic_connection_open_stream`'s third parameter is `uint64_t *out_stream_id` and the callee writes 0 into it
(`connection.c:2299`). Every later `send_stream(..., now)` therefore uses 0, and the timestamps the loss
assertions read are all zero. Smallest fix: `uint64_t id = 0U;` and pass `&id`.

### F-14 — S2 — test — `C99/tests/unit/test_quic_malformed.c:77-80,162-168`
**Two assertions in the malformed-input corpus cannot fail, including the only Retry check.**

Evidence:

```c
C99/tests/unit/test_quic_malformed.c:77    WT_EXPECT_TRUE("a failed varint consumed nothing", c.offset <= length);
...
C99/tests/unit/test_quic_malformed.c:162    wt_quic_retry_packet_t retry;
C99/tests/unit/test_quic_malformed.c:163    (void)wt_quic_retry_packet_decode(buffer, cut, &retry, &error);
C99/tests/unit/test_quic_malformed.c:164    if (cut != 0U) {
C99/tests/unit/test_quic_malformed.c:165      WT_EXPECT_TRUE("a parsed Retry fits its buffer", retry.total_len <= cut);
```

A cursor can never advance past its length, so line 77 is a tautology (the intended property is
`c.offset == 0U`). At 163 the status is discarded; on failure the decoder memsets `out` to 0
(`src/quic/packet.c:451`), so `0 <= cut` passes, and on success `total_len == cut`. The neighbouring
long/short-header blocks gate on `== WT_OK`, so this one is the odd one out — and the WT-203 "token view past
the end" class is what it was written for. Smallest fix: `c.offset == 0U`, and
`if (wt_quic_retry_packet_decode(...) == WT_OK) { WT_EXPECT_U64(..., (uint64_t)cut, (uint64_t)retry.total_len); }`.

### F-15 — S2 — unsafe — `C99/tests/unit/test_http3_driver.c:912-918`
**An uninitialised `wt_http3_endpoint_t` is handed to the code under test, which reads its `role` and walks its
request table.**

Evidence:

```c
C99/tests/unit/test_http3_driver.c:912    wt_http3_driver_t other;
C99/tests/unit/test_http3_driver.c:913    wt_http3_endpoint_t other_endpoint;
C99/tests/unit/test_http3_driver.c:914    wt_http3_driver_init(&other, &other_endpoint);   /* only stores the pointer */
...
C99/tests/unit/test_http3_driver.c:918    wt_http3_driver_on_quic_frame(&other, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U)
```

`wt_http3_driver_on_quic_frame` reaches `stream_is_ours(driver->endpoint, ...)` (`driver.c:492-494`, called at
`:574`) and `wt_http3_endpoint_request_state`, which loops `endpoint->request_count` over `endpoint->requests[]`
(`endpoint.c:299-306`) before the session-mismatch return — so routing depends on indeterminate stack bytes and
a garbage count walks the array. Same pattern at `test_http3_limits.c:117-119` and
`test_http3_malformed.c:245-246`. Smallest fix:
`wt_http3_endpoint_init(&other_endpoint, WT_HTTP3_ROLE_SERVER);` before `driver_init`.

### F-16 — S2 — test — `C99/tests/unit/test_http3_headers.c:93-103`
**The peer-reachable field-name/field-value grammar fix has no regression test.**

Evidence: `src/http3/headers.c:136-144` records that "a value carrying CR, LF or NUL all passed -- which an
audit demonstrated with a value of `a\r\nX: y` and a name of `bad name`", but every refusal in the test uses a
printable value (`refuse(&validation, "connection", "close", ...)`, `"transfer-encoding"/"chunked"`,
`"keep-alive"/"timeout=5"`, `"upgrade"/"h2c"`, `"te"/"gzip"`) and the only non-token name is uppercase
`"X-Test"` (`:93`), which the pre-fix code already rejected. Smallest fix: add
`refuse(&validation, "x-test", "a\r\nX: y", ...)` and `refuse(&validation, "bad name", "1", ...)`.

### F-17 — S2 — test — `C99/scripts/run-container-interop.sh:92-94`
**The container interop check cannot fail: the client's exit status is discarded and the script always exits 0.**

Evidence:

```sh
C99/scripts/run-container-interop.sh:92   docker run --rm --network "container:wt-interop-$peer" -v "$log_dir:/logs" $client_env "$client_image" \
C99/scripts/run-container-interop.sh:93     --connect "127.0.0.1:$port" --trust local-development --exchange stream \
C99/scripts/run-container-interop.sh:94     --message "${WT_INTEROP_MESSAGE:-hello-interop}" --timeout-ms "$timeout_ms" || true
...
C99/scripts/run-container-interop.sh:111  echo "container interop: done (the client tool's own output above is the result)"
```

A run in which every session fails still reports "done" with status 0. Smallest fix: drop `|| true`, capture
`status=$?`, count failures, `exit 1` if any.

### F-18 — S2 — test — `C99/scripts/check-matrix.sh:16,25-26`
**The compliance-matrix check never validates the column it was written for, and "the symbol exists" means
"the word appears somewhere".**

Evidence:

```sh
C99/scripts/check-matrix.sh:16  symbols="$(grep -o '`[A-Za-z_][A-Za-z0-9_]*`' "$matrix" | tr -d '`' | sort -u | grep -E '^(wt_|WT_)' || true)"
C99/scripts/check-matrix.sh:25    if ! grep -rq --include='*.h' --include='*.c' -w "$symbol" "$root/include" "$root/src" "$root/apps" "$root/tests" \
C99/scripts/check-matrix.sh:26       && ! grep -rq --include='CMakeLists.txt' --include='*.sh' -w "$symbol" "$root/apps" "$root/scripts" "$root/tests"; then
```

The filter on line 16 drops every `test_*` name, so the Evidence column (`test_webtransport_flow`,
`test_http3_driver`, …) is never resolved against anything — yet `docs/COMPLIANCE-MATRIX.md:3-5` claims "Every
symbol named here is checked". Line 25's grep matches comments and string literals as readily as declarations,
so a `wt_` symbol deleted from the library still passes if any test label contains the word. Smallest fix:
remove the `grep -E '^(wt_|WT_)'` filter, resolve `test_*` against `tests/CMakeLists.txt`/scripts, and resolve
`wt_`/`WT_` against header/source declarations.

### F-19 — S2 — test — `C99/scripts/score-matrix.sh:40`
**The Definition-of-Done result is a hardcoded `echo`, and a requirement counts as "exercised by a test"
purely because its status cell says so.**

Evidence:

```sh
C99/scripts/score-matrix.sh:38  echo "compliance matrix: $draft_tested of $draft_total draft-16 requirements exercised by a test in this tree"
C99/scripts/score-matrix.sh:39  echo "compliance matrix: $draft_partial of $draft_total partial, and $layer_total row(s) describing lower layers"
C99/scripts/score-matrix.sh:40  echo "definition of done: 8 of 9 criteria met, 1 partial, 0 not met"
```

The script's own header says it "prints the nine Definition-of-Done criteria as they stand" and the README says
the number is "measured rather than remembered" — line 40 is neither. The 34/34 count on line 38 is computed,
but from a status cell, not from resolving any test name (which line 16 of `check-matrix.sh` cannot do either).
Smallest fix: move the criteria into a machine-readable table and count it, or label the line as quoted prose.

### F-20 — S2 — test — `C99/scripts/check-vectors.sh:43-46`, `C99/scripts/check-static-analysis.sh:29-32,37-40`
**Two hard CI checks exit 0 when the tool they need is missing, so a green run does not prove they ran.**

Evidence:

```sh
C99/scripts/check-vectors.sh:43  if ! command -v python3 >/dev/null 2>&1; then
C99/scripts/check-vectors.sh:44    echo "check-vectors: unsupported -- python3 is not installed, so the RFC vectors cannot be re-derived"
C99/scripts/check-vectors.sh:45    exit 0
C99/scripts/check-vectors.sh:46  fi
C99/scripts/check-static-analysis.sh:29  if ! "$analyzer" --analyze -x c /dev/null -o /dev/null >/dev/null 2>&1; then
C99/scripts/check-static-analysis.sh:30    echo "static analysis: unsupported -- $analyzer has no --analyze, ..."
C99/scripts/check-static-analysis.sh:31    exit 0
C99/scripts/check-static-analysis.sh:32  fi
C99/scripts/check-static-analysis.sh:37  if ! command -v python3 >/dev/null 2>&1; then
C99/scripts/check-static-analysis.sh:38    echo "static analysis: unsupported -- python3 is not installed, ..."
C99/scripts/check-static-analysis.sh:39    exit 0
```

These are the evidence for two claimed Definition-of-Done criteria ("the RFC vectors are re-derived",
"sanitizers and static checks"), and FreeBSD — a platform the docs claim passes the suite — has no `python3` in
its base system (`docs/PORTABILITY.md:190-193`). Smallest fix: `exit 77` (CTest's skip code) from these guards
so the aggregate shows the gap instead of a pass.

### F-21 — S2 — docs — `C99/README.md:61,290,293` vs `C99/docs/PORTABILITY.md:93,126`
**Documented counts contradict each other and no script produces either number.**

Evidence:

```
C99/README.md:61   - 84 test programs and 91,552 checks, plus a 200,000-input parser fuzz run, run by `ctest` and again under
C99/README.md:290    length type. The check now sweeps the **whole tree** — 72 library sources and 92 test/app sources —
C99/README.md:293    a mingw toolchain and a Windows OpenSSL the whole tree **links** — 84 PE32+ executables and
C99/docs/PORTABILITY.md:126  **85 test executables ran, 85 passed, 0 failed, 0 hung, and the reported checks sum to 91,674.**
C99/docs/PORTABILITY.md:93   library sources and 108 test, probe and app sources**, which is the script's own count
C99/docs/PORTABILITY.md:103  and builds **91 PE32+ executables** plus `libwebtransport.dll`
```

The tree is 76 `src/*.c` and 91 linked executables, and the only Wine runner reports no check count at all
(`grep -n checks C99/scripts/check-windows-wine.sh` finds nothing; its summary is
`echo "windows wine: ran $total test executable(s) -- $passed passed, $failed failed, $hung hung"`). The
README's 91,552 appears nowhere else. Smallest fix: quote the scripts' own numbers (76/108/91, 91,674) or stop
restating them, and have `check-windows-wine.sh` sum the per-test check counts into its summary.

### F-22 — S2 — docs — `C99/docs/PORTABILITY.md:76-77` vs `C99/scripts/check-windows-platform.sh:36`
**"the same warnings the POSIX build turns into errors" is 7 flags, not the project's 24.**

Evidence:

```
C99/scripts/check-windows-platform.sh:36  "$compiler" -std=c99 -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual \
C99/cmake/WTCompilerWarnings.cmake:23-48  (24 flags, adding -Wpedantic -Wcast-align -Wstrict-prototypes
                                           -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition
                                           -Wredundant-decls -Wundef -Wwrite-strings -Wpointer-arith -Wfloat-equal
                                           -Wswitch-enum -Wvla -Wformat=2 -Wnull-dereference -Wdouble-promotion)
```

So the "76 library sources and 108 test/app sources compile for Windows, warnings-as-errors" claim excludes,
among others, every prototype and `-Wformat=2` diagnostic. Smallest fix: append the missing flags to the four
command lines in that script (lines 36, 43, 98, 119), or state which subset is used.

### F-23 — S2 — docs — `C99/docs/COMPLIANCE-MATRIX.md:35`
**A "tested" draft-16 row claims strict-increase for `WT_MAX_STREAM_DATA`, which the session layer deliberately
refuses as prohibited.**

Evidence:

```
C99/docs/COMPLIANCE-MATRIX.md:35  | 5.1 | WT_MAX_DATA / WT_MAX_STREAM_DATA / WT_MAX_STREAMS strictly increase | `wt_webtransport_flow_on_max_data`, `wt_webtransport_flow_on_max_streams` | `test_webtransport_flow` | tested |
C99/src/api/session.c:136  /* Draft-16 section 5.4 PROHIBITS these two: stream-level flow control is WebTransport's own, and a peer that
C99/src/api/session.c:137     sends either is telling this endpoint about a limit it must not act on. Receipt is a session error of type
C99/src/api/session.c:142    return WT_ERR_PROTOCOL;
```

There is no `..._on_max_stream_data` handler anywhere in `include/` or `src/`, and `test_webtransport_flow` only
round-trips the codec. Smallest fix: split the row — MAX_DATA/MAX_STREAMS `tested`, WT_MAX_STREAM_DATA recorded
as prohibited by §5.4.

### F-29 — S2 — bug — `C99/src/http3/driver.c:433-434` (and `:459-460`)
**A stale frame-state pointer is written after the slot has been released and refilled, so settling one
stream's HEADERS clears another stream's in-flight flag and desynchronises its framing.**

Evidence:

```c
C99/src/http3/driver.c:432        if (state->payload_received == state->payload_length) {
C99/src/http3/driver.c:433          if (state->type == (uint64_t)WT_HTTP3_FRAME_HEADERS) settle_capsule_stream(driver, stream_id);
C99/src/http3/driver.c:434          state->in_frame = 0;      /* state points into driver->frames[] */
```

and the settle path releases the slot by moving the last entry into it:

```c
C99/src/http3/driver.c:1146    (void)wt_http3_driver_forget_frame(driver, stream_id);
C99/src/http3/driver.c:308        driver->frames[i] = driver->frames[driver->frame_count - 1U];
C99/src/http3/driver.c:309        driver->frame_count--;
```

`state` is `&driver->frames[i]`, so when the settled stream is not the last slot, `state->in_frame = 0` writes
through the pointer into the entry that was just moved in from slot `frame_count - 1` — a *different* live
stream's frame state — clearing `in_frame` there. That stream's remaining payload is then parsed as a new frame
header (framing desync: spurious frames, wrong routing, or a spurious truncation at FIN). The trigger is a
marked CONNECT stream's HEADERS completing while the frames table holds another stream mid-frame, which is
ordinary on a connection with a control stream and a request stream in flight. No test covers it: the driver
tests use one stream at a time.

What correct looks like: clear the flag before the settle call, or have `forget_frame` not move the entry the
caller still points at.

Smallest fix: in both places, set `state->in_frame = 0` on the line *before* `settle_capsule_stream(...)`.

### F-30 — S2 — bug — `C99/src/webtransport/session.c:144` (caller `C99/apps/support/capsule_stream.c:76`)
**A WT_MAX_DATA / WT_MAX_STREAMS capsule that arrives in a STREAM frame *after* the frame carrying
WT_CLOSE_SESSION is still applied, because the "close is the last thing on the stream" rule is only checked
against the remaining bytes of the current cursor.**

Evidence:

```c
C99/src/webtransport/session.c:144      if (status == WT_OK && wt_cursor_remaining(&ahead) > 0U) {
C99/src/webtransport/session.c:145        /* Section 5.4: a WT_CLOSE_SESSION capsule is the LAST thing on the CONNECT stream. ... */
C99/src/webtransport/session.c:147        return WT_ERR_PROTOCOL;
C99/apps/support/capsule_stream.c:76    cursor = wt_cursor_init(stream->bytes, stream->length);
```

`wt_webtransport_session_on_capsule_bytes` never tests `session->state == WT_WEBTRANSPORT_SESSION_CLOSED` at
entry (`grep -n CLOSED C99/src/webtransport/session.c` finds lines 27, 56, 62, 66, 79, 92 — none inside the
walker), and the caller keeps a reusable buffer and rebuilds a fresh cursor for each delivery, so the check
sees only the new bytes. A peer can close the session in one STREAM frame and grant itself MAX_DATA/MAX_STREAMS
in the next; `observe` (the flow-control observer) still honours the grant, where draft-16 §6 requires the
stream to be reset with H3_MESSAGE_ERROR.

What correct looks like: a delivery to a CLOSED session is a message error regardless of what it contains.

Smallest fix: at the top of the loop in `wt_webtransport_session_on_capsule_bytes`, after the `remaining == 0`
test, return `WT_ERR_PROTOCOL` with `*out_error = WT_HTTP3_MESSAGE_ERROR` when
`session->state == WT_WEBTRANSPORT_SESSION_CLOSED`.

### F-31 — S2 — bug — `C99/src/quic/connection.c:384-386`
**A control frame whose loss re-send fails is never retransmitted again, and its table slot leaks.**

Evidence:

```c
C99/src/quic/connection.c:384        (void)send_encoded_frame(connection, kept->space, kept->wire, kept->wire_length, 1,
C99/src/quic/connection.c:385                                 tag_for_control(connection, slot), &sent, connection->last_activity);
C99/src/quic/connection.c:766      if (tag != (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) free_frame(connection, tag);
```

`send_packet` can fail with `WT_ERR_LIMIT` (congestion window or the sent-packet list full), `WT_ERR_AGAIN`,
`WT_ERR_STATE` or an I/O error. The descriptor allocated by `tag_for_control` is released, and the control slot
is deliberately left `in_use` ("the slot stays in_use: the re-sent packet answers for the same obligation"),
but nothing re-drives it: the only triggers are this `on_lost` path and the first-send failure
(`connection.c:708`), and no later loss names this packet. So a MAX_STREAMS / MAX_DATA / NEW_CONNECTION_ID /
RETIRE_CONNECTION_ID lost at the moment the connection cannot send is dropped for the life of the connection,
and one of the eight control slots stays occupied.

What correct looks like: treat a failed re-send as "still owed" and re-drive it on a later flush.

Smallest fix: check the status and, on failure, mark the retained slot for a re-send from `flush_space`.

---

## S3 — low

### F-24 — S3 — dead — `C99/src/http3/qpack_field.c:105`
**A no-op statement in the literal-literal-name encoder.**

Evidence:

```c
C99/src/http3/qpack_field.c:104      if (line->never_indexed) flags |= 0x10U;
C99/src/http3/qpack_field.c:105      if (line->never_indexed != 0) flags |= 0x00U;
```

`flags |= 0x00U` changes nothing and reads like a missing bit. Smallest fix: delete line 105.

### F-25 — S3 — test — `C99/tests/wt_test.h:116-125`
**The harness reports a test file that ran zero checks as passing.**

Evidence:

```c
C99/tests/wt_test.h:116  #define WT_TEST_MAIN_END(name)                                              \
C99/tests/wt_test.h:117    do {                                                                      \
C99/tests/wt_test.h:118      if (wt_test_failures != 0) { ... return 1; }                            \
C99/tests/wt_test.h:124      printf("%s: all %d checks passed\n", name, wt_test_checks);             \
C99/tests/wt_test.h:125      return 0;                                                               \
```

With `wt_test_checks == 0` this prints "all 0 checks passed" and returns 0, so a test whose body is emptied or
preprocessed away is indistinguishable from a passing one. (Every current file does run ≥8 checks; this is the
guard, not a live miss.) Related literal tautologies that inflate the count:
`test_quic_pn_space.c:211`, `test_quic_protection.c:252`, `test_quic_varint.c:200`,
`test_tls13_keyschedule.c:493`, `test_webtransport_capsule.c:28`, `test_public_api.c:96`. Smallest fix: fail
when `wt_test_checks == 0`.

### F-26 — S3 — test — `C99/scripts/check-portability.sh:15`
**The "inventory completeness" check is a fixed nine-name list, so it cannot catch a new POSIX call — which is
the rot its header describes.**

Evidence:

```sh
C99/scripts/check-portability.sh:15  posix_names="fcntl poll recvmsg sendmsg inet_pton recvfrom sendto close O_NONBLOCK"
C99/scripts/check-portability.sh:19    used="$(grep -rlw "$name" "$root/src" "$root/include" 2>/dev/null || true)"
```

The library also uses `inet_ntop` (`src/runtime/udp_platform.h:430,637`), `setsockopt` (`:312,510`),
`getsockopt` (`:183`), `socket` (`src/runtime/udp.c:96`) and `bind` (`udp.c:145`), none of which is in the list,
so none can ever fail the check — `inet_ntop` missing beside `inet_pton` is the clearest gap, and
`docs/PORTABILITY.md:6,70` claims the inventory is "complete and mechanically checked". Smallest fix: add the
socket-layer names (or derive the list from `src/runtime/udp_platform.h`).

### F-27 — S3 — docs — `C99/docs/DIAGNOSTICS.md:15,52-54`
**The diagnostics document describes a library-side secret dump that the code says was deliberately removed.**

Evidence:

```
C99/docs/DIAGNOSTICS.md:15  | `WT_TLS_SECRET_LOG` | **`src/tls/session.c` (at derivation)** and `apps/support/session_loop.c` ...
C99/src/tls/session.c:601   /* There was a diagnostic here that appended both handshake traffic secrets to the file named by the
C99/src/tls/session.c:602    * `WT_TLS_SECRET_LOG` environment variable. It is GONE, ...
```

`grep -rn WT_TLS_SECRET_LOG C99/src` returns only that comment; the live writer is
`apps/support/session_loop.c:608`. Smallest fix: name only the app in the table and drop "a secret derivation"
from the `getenv` cost paragraph.

### F-32 — S3 — bug — `C99/src/http3/endpoint.c:314-321,330,334,338`
**`wt_http3_endpoint_write_prefix` returns `WT_OK` without checking that the prefix was written, and it sets
its once-only latch before the write.**

Evidence:

```c
C99/src/http3/endpoint.c:319    wt_writer_bytes(w, encoded, length);
C99/src/http3/endpoint.c:320    return WT_OK;                        /* wt_writer_ok(w) never consulted */
...
C99/src/http3/endpoint.c:330      endpoint->control_sent = 1;        /* latched before the write */
C99/src/http3/endpoint.c:331      return write_type_prefix(WT_HTTP3_STREAM_CONTROL, w);
```

With a writer too small for the one-to-eight-byte type prefix, the function reports success, the latch makes a
retry `WT_ERR_STATE`, and `wt_http3_driver_start_qpack_stream` (`driver.c:104-110`) propagates the `WT_OK` while
`wt_writer_offset(&w)` is 0 — the caller then sends an empty stream and believes the control/QPACK stream
exists. The in-tree callers pass a large scratch, so this is a public-API contract defect rather than a live
wire bug. Smallest fix: `return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;` and set the latch only after a
successful write.

### F-33 — S3 — bug — `C99/src/core/allocator.c:82-83`
**`wt_alloc_array` reports `WT_OK` while returning `NULL` on allocation failure.**

Evidence:

```c
C99/src/core/allocator.c:82    if (out_status != NULL) *out_status = WT_OK;
C99/src/core/allocator.c:83    return wt_alloc(a, total);
```

The sibling `wt_calloc_array` sets `WT_ERR_OUT_OF_MEMORY` when the block is NULL (`allocator.c:96-100`). The
header documents `out_status` as reporting the failure. No in-tree caller today (`grep -rn wt_alloc_array C99/src
C99/apps` finds the definition only), so the impact is a public API that lies to its caller. Smallest fix:

```c
void *block = wt_alloc(a, total);
if (block == NULL && out_status != NULL) *out_status = WT_ERR_OUT_OF_MEMORY;
return block;
```

### F-34 — S3 — bug — `C99/src/webtransport/capsule.c:144-150`
**`wt_webtransport_close_session_parse` writes its out-parameter before a check that fails, contrary to the
status contract.**

Evidence:

```c
C99/src/webtransport/capsule.c:144    if (out_error_code != NULL) {
C99/src/webtransport/capsule.c:145      *out_error_code = ((uint32_t)capsule->value[0] << 24) | ... ;
C99/src/webtransport/capsule.c:147    }
C99/src/webtransport/capsule.c:150    if (!utf8_is_well_formed(capsule->value + 4U, capsule->value_length - 4U)) {
C99/src/webtransport/capsule.c:152      return WT_ERR_PROTOCOL;
```

`include/webtransport/status.h` states that out-parameters are written only when the result is `WT_OK`, so a
caller that reads `out_error_code` after this failure reads a value from a capsule the function just refused.
The shipped callers happen to set the code only on success, so no live misreport was found. Smallest fix: move
the assignment below the UTF-8 check.

### F-35 — S3 — dead — `C99/src/http3/driver.c:398-404`, `C99/src/http3/driver.c:723-730`, `C99/src/api/flow.c:149-155`
**Three provably unreachable blocks.**

Evidence:

- `driver.c:398-404` copies a header remainder that is always zero: the header loop appends one byte at a time
  and `break`s as soon as both varints parse, so `state->header_length == type_bytes + length_bytes` and
  `leftover == 0`.
- `driver.c:723-730` is an `if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN)` branch that cannot be reached: the
  identical test at `:708-711` already returned, and any kind that reaches `:723` came from the endpoint's
  stored table, which never stores UNKNOWN (`endpoint.c:463-466`).
- `api/flow.c:149-155` handles `flow_enabled != 0 && max_data_set == 0`, which cannot happen: the only writer
  of `flow_enabled` (`flow.c:43`) is immediately followed by `wt_webtransport_flow_on_max_data`, which sets
  `max_data_set = 1` after `wt_webtransport_flow_limits_init`.

Smallest fix: delete the three blocks (or, for the first, assert `leftover == 0`).

---

## Checked and found CLEAN (explicit negative results)

- **Strict C99 / no GNU extensions** — `clang -std=c99 -pedantic-errors -fsyntax-only` over every `src/*.c`
  and `apps/*.c`, and over a translation unit consisting of each public header alone, produces no diagnostic.
  Static search finds no `__attribute__`, `__extension__`, `typeof`, statement expressions, `__builtin_*`,
  computed goto, case ranges, zero-length arrays, anonymous unions or variadic macros. `-Wpedantic` and
  `C_EXTENSIONS OFF` are genuinely applied (`cmake/WTCompilerWarnings.cmake:27,62-67`). No finding.
- **Core primitives (L0/L1)** — `checked.c` (the multiply test divides rather than multiplying), `cursor.c`
  (`n > len - offset` invariant), `writer.c` (`len > cap - offset`, measuring capacity bound), `buffer.c`
  (`WT_BUF_MAX_CAPACITY`, checked add, doubling clamp), `allocator.c` (zero-size normalised to one byte in both
  alloc and free), `endian.c`, `varint.c` (62-bit bound, minimal-encoding check), `time.c` (saturating deadline
  arithmetic). No new defect found. Category `perf`: no finding.
- **QUIC wire decode** — `frame.c` (minimal frame type, per-frame lengths narrowed through
  `wt_checked_narrow_u64_to_size`, ACK range walk is single-pass, NEW_CONNECTION_ID/RETIRE/NEW_TOKEN limits),
  `packet.c` (long/short/Retry framing, the WT-203 token bound), `packet_number.c`, `protection.c` (sample
  bound, `out_capacity - frames_len` check, Retry pseudo-packet bound, RFC 9001 §5.8 key/nonce),
  `crypto_stream.c`, `pn_space.c` (`ack_record`/`ack_build` keep disjoint ordered ranges; the `gap - 2`
  subtraction cannot underflow for a validated frame). No new memory-safety defect found.
- **TLS 1.3 message/extension parsing** — `handshake.c` (`message_body`/`sub_cursor` bound every declared
  length to its enclosing region, `ClientHello` compression vector written by index), `extension.c`
  (`key_share`/`alpn`/`signature_algorithms` vectors bounded and non-empty). No finding. Category `deps`: the
  only dependency is OpenSSL 3, pinned at configure time (`CMakeLists.txt:33-41`); no finding.
- **QPACK** — `qpack_primitives.c` (62-bit bound, 63-bit shift guard, `SIZE_MAX` guard on the string path),
  `qpack_dynamic.c` (aliasing staged before eviction, `dropped`/`insert_count` bounds,
  `WT_QPACK_DYNAMIC_MAX_BYTES` staging), `qpack_field_section.c` (RIC enforcement, scratch cursor),
  `qpack_header_prefix.c` (both §4.5.1 error exits), encoder/decoder streams (`increment == 0` refused,
  capacity above the advertised maximum refused). No new defect beyond F-01 (data) and F-09/F-24.
- **WebTransport framing/session/capsules** — `framing.c` (quarter-ID overflow refused at the parse boundary),
  `capsule.c` (UTF-8 validation, 1024-byte reason ceiling, strict single/two-varint parsers),
  `session.c` (capsule walk commits its cursor only on success; bytes after WT_CLOSE_SESSION are a message
  error), `buffered.c` (bounds from the header, rejection recorded in one place). No finding.
- **Wire constants** — apart from F-02 and F-04, every constant checked matches both the normative texts and
  the Swift reference: ALPN `h3`; QUIC TP identifiers 0x00-0x10/0x20; QUIC error codes 0x00-0x10 and
  CRYPTO_ERROR 0x0100-0x01ff; H3 error codes 0x0100-0x0110; the five WebTransport protocol codes
  (0x3994bd84, 0x170d7b68, 0x045d4487, 0x0817b3dd, 0x212c0d48); the WT application-error range
  (0x52e4a40fa8db..0x52e5ac983162 with the 0x1e/0x1f gap arithmetic); stream types 0x41/0x54; frame type 0x24;
  settings 0x2c7cf000, 0x2b61, 0x2b64, 0x2b65, 0x33, 0xc671706a, 0x2b603742, 0x2b603743; capsules 0x2843,
  0x78ae, 0x190b4d3d-0x190b4d44; the close-capsule layout; varint max, QUIC v1, the Initial salt and the
  `quic key`/`quic iv`/`quic hp` labels; cipher suite 0x1301 and signature schemes 0x0403/0x0804/0x0807.
- **Tests as a whole** — no test file asserts nothing: all 84 unit files have a `main`, a `WT_TEST_MAIN_END`
  and at least 8 checks, there is no `#if 0`, no zero-iteration loop, and the failure path returns non-zero
  (`tests/wt_test.h:116-125`). The fuzzer's eight families are all reachable (`selector = data[0] % 8`).
  Category `placeholder`: none found on a production path.
- **Dead static functions** — an `nm`-enumerated sweep of every local symbol in `out/macos26/build/libwebtransport.a`
  and every app object, cross-checked with a tree-wide `grep -w`, finds no uncalled project function (the only
  hit is the system macro `_OSSwapInt16`). The three zero-internal-caller symbols (`wt_quic_space_name`,
  `wt_tls_certificate_verify_build`, `wt_tls_encrypted_extensions_build`) are installed public API, not dead.
- **Unchecked returns, TLS/crypto and the send paths** — `src/tls/*` and `src/crypto/*` discard only
  `wt_tls_extensions_encode`/`wt_sha256_final` results on measure or clear paths; `src/core/{buffer,cursor,
  writer,checked}.c`, `src/runtime/udp.c`, `src/runtime/server_retry.c` and `src/api/{endpoint,events}.c`
  latch every writer result and re-check it with `wt_writer_ok`, so no partially written message is sent or
  hashed. No finding.

## Observations (not numbered findings)

- **O-1** `C99/src/http3/qpack_encoder_stream.c:91-96,161-164` refuses a Huffman-coded name or value in an
  Insert With Literal Name with `WT_ERR_STATE`; RFC 9204 §4.3.2/§4.3.3 allow both. It is not reachable with a
  conforming peer today only because nothing in `src/` advertises a non-zero QPACK dynamic-table capacity
  (`grep -rn QPACK_MAX_TABLE_CAPACITY C99/src` finds only `settings.h`'s identifier), and the code marks it as
  the next part's work. It becomes a live interop failure the moment a caller advertises capacity.
- **O-2** `C99/include/webtransport/webtransport/session_request.h:50`
  `WT_WEBTRANSPORT_AVAILABLE_PROTOCOLS_HEADER "wt-available-protocols"` is defined and referenced nowhere in
  `src/`/`include/`/`apps/`, so the C99 CONNECT builder never offers sub-protocols
  (`driver.c:1242-1253` sets only `:protocol`). The negotiation helpers are exercised only by the conformance
  app. Draft-16 §3.3 is optional, so this is a capability gap rather than a violation.
- **O-3** `C99/src/webtransport/session_request.c:117-122` accepts any non-empty `:scheme`; draft-16 §3.2 makes
  it MUST be `https`. The Swift reference enforces it (`WebTransportHeaders.swift:51`). Same class as F-08.
- **O-4** `C99/src/webtransport/session_request.c:120,129,137` answers a resource/authority mismatch with 404
  (and 501 for "not enabled"); draft-16 §3.2 says a server that does not support the target resource SHOULD
  reply 405. Swift uses 405.
- **O-5** The Swift reference's QUIC key-update label is `"traffic upd"`
  (`Swift/Sources/WebTransportTLSCore/TLS13KeyAgreement.swift:149`) where RFC 9001 §6 requires `"quic ku"`; the
  C99 side is correct (`src/quic/protection.c:119`). The reverse of the usual direction, recorded because it is
  a wire divergence between the two trees.
- **O-6** `C99/scripts/run-vps-third-party-interop.sh:180-181` has an unreachable duplicate case arm and
  `:195-198` aggregates every `*.json` under an uncleaned output directory, so stale proofs count as passed;
  `:92` of `check-cli-contract.sh` captures `status=$?` and never reads it. Both are check-strength issues of
  the same family as F-17/F-18 and are listed here for the fix round rather than numbered separately.
- **O-7** The CLI's report writers discard every `fputs`/`fputc`/`fprintf` result and never call `ferror` or
  `fflush` (`src/cli/report.c:80-102`, `src/cli/endpoint.c:59-75`, `src/cli/options.c:266-307`,
  `src/cli/cli_json.h:20-46`; `grep -rn "ferror\|fflush\|fwrite" C99/src/cli C99/apps` is empty). The tool then
  returns `wt_cli_report_exit_status(&report)`, so a full disk or a closed pipe yields a truncated "product"
  with exit 0 — the opposite of the contract `include/webtransport/cli/report.h:4-15` states.
- **O-8** The public `wt_session_on_capsule` (`src/api/session.c:144-158`) applies `WT_CAPSULE_DRAIN_SESSION`
  without the `value_length != 0U` check its sibling walker enforces (`src/webtransport/session.c:130`), so the
  public API accepts a malformed capsule the shipped path refuses.
- **O-9** `apps/support/capsule_stream.c:128-131` discards the status of the refusal-capsule send and returns
  `WT_CAPSULE_REFUSAL_SESSION`; the callers (`session_loop.c:186-191`, `scenario_pair.c:56-61`) then report
  success while the local session is CLOSED and the peer was never told.
- **O-10** Write-only fields and a dangling reference, all grep-confirmed: `connection.c:2664`
  (`next_keys_out`), `loss.c:159,232` (`loss_time`), `crypto_stream.c:76` (`has_received`), and
  `include/webtransport/tls/session.h:98` naming a `wt_tls_client_hello_size` that exists nowhere.
- **O-11** The QPACK encoder-stream Huffman refusal (O-1) and the three dead blocks in F-35 are the only
  "not implemented yet" markers found on the protocol paths; no `TODO`/`FIXME`/placeholder string is reachable
  from a shipped code path.
