# C99 WebTransport

Protocol reference: IETF `draft-ietf-webtrans-http3-16`, dated 2026-07-06.

Draft-16 score: **0%** — the protocol is not implemented yet. What exists is the
foundation the protocol is built on, and it is real, tested code rather than
scaffolding.

## Current Status

**Phases 0 to 4 of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) are complete, and
Phase 5 (HTTP/3) and Phase 7 (the draft-16 session layer) have their message-level pieces in, and
Phase 8's public API has begun: one umbrella header exposes every layer and states the rules that hold
across them.** Phase 3 finishes the TLS 1.3 handshake end to end, and Phase 4
is the QUIC connection runtime: packet number spaces with ACK generation, loss detection
and probe timeouts, NewReno congestion control, the stream state machines and flow
control, QUIC DATAGRAM, the close paths, connection IDs (issued, retired and received),
the packet build/read seam, and the IPv4/IPv6 UDP runtime, with two connections completing
a whole handshake and exchanging protected, acknowledged packets over IPv6 and IPv4
loopback in the tests. Phase 4's completion criteria are met: those loopback tests pass on
macOS and Linux in CI, the loss, probe-timeout and close-path suites pass, and every suite
runs again under AddressSanitizer and UndefinedBehaviorSanitizer.
The rest of Phase 5, and Phases 6 to 14, are not started: no WebTransport protocol is
implemented yet, so the draft-16 score is 0%.

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
- 82 test programs and 82,293 checks, run by `ctest` and again under
  AddressSanitizer and UndefinedBehaviorSanitizer. Most of that count is the
  malformed-input corpus, which drives every parser with a fixed pseudo-random
  byte stream: a random buffer is a better generator of the case nobody thought
  of than a list of cases somebody did, and under the sanitizers an out-of-bounds
  read is a failure rather than a plausible value. Two more of the large counts
  are loops rather than hand-written cases: 4,160 checks in `test_buffer`, 4,096
  of them from appending a byte at a time to prove buffer growth is logarithmic,
  and 1,013 in `test_time` from stepping a monotonic clock and checking the
  deadline arithmetic does not wrap near the counter's top. Note that Darwin has
  no LeakSanitizer, so a leak in the tests is found by the Linux CI leg and not by
  a local run on this machine; that is how the first one was found.
- **The command-line tools' options** (Phase 9): `cli/options.h` is the one parser the
  three tools share, because a flag that means one thing in one tool and another in the
  next is worse than a flag that is missing. Two rules shape it: an UNSUPPORTED mode is
  not an unknown one — `--transport packet` is what this build has, and
  `--transport quic` is refused by name with exit code 2, because a tool that silently
  ignores a mode it cannot honour produces reports nobody can trust — and a flag that
  takes a value never swallows the NEXT FLAG, so a script's typo cannot become a
  connection attempt. `--json` writes the parsed options as one machine-readable object
  with stable field names, and the parser is a library function rather than argv walking
  inside each `main`, which is what lets all of this be a failing check rather than a
  manual attempt.
- **Two sessions handshaking over loopback** (Phase 9): the runtime session driver is
  proven end to end — two loopback UDP sockets, two sessions, and a full TLS 1.3 handshake
  inside QUIC Initial and Handshake packets, authenticated with the repository's trust
  fixtures (a real leaf, a real CA and a real signature, so the client validates the server
  rather than trusting it). Both sides end confirmed with application keys installed. That
  is the plan's "run local IPv4 and IPv6 packet sessions" at the library level; the tools'
  own session loop is what remains before the CLI can claim it.
- **The bidirectional-stream classifier** (Phase 10): a peer's opening bytes on a bidirectional
  stream are either an HTTP/3 request (a QPACK field-section prefix) or a WebTransport
  bidirectional stream (the draft's `0x41` type and the session ID), and
  `wt_http3_driver_classify_bidi_start` decides which as a PURE function of those bytes — it reads,
  it does not route. That separation is deliberate: the routing that uses it is where WT-120's
  release-only crash lived, so the classifier is proven in all three build configurations before
  anything is routed by it. A prefix that has not fully arrived is `WT_ERR_TRUNCATED` — a wait on a
  stream, never a refusal — and a stream with no bytes yet is a request stream until proven
  otherwise. The routing then landed on its own: a WebTransport bidirectional stream reaches the
  **session** sink with its prefix removed, a stream naming **another session** is refused with
  HTTP/3's identifier error rather than delivered to the wrong one, and a request-shaped stream goes
  to the HTTP/3 request path instead — each asserted separately, with all three configurations in the
  loop from the first build. A prefix that arrives **in pieces** is assembled from the same pending
  table the unidirectional path uses, and for a *request* the held bytes are **replayed** so the
  request path sees a stream's first bytes rather than the middle of them. The bug that hid there
  for two attempts is instructive: a continuation frame has a **non-zero offset**, so an
  offset-zero condition skipped the assembly for exactly the frame that would complete the prefix —
  and the counter that made the frame path say so is what found it.
- **The bounded tables, at their bounds** (Phase 10): every table in HTTP/3 and the session
  layer is fixed, because a table that grows with a peer is a heap exhaustion path with the peer's
  name on it. The suite drives each one — the endpoint's peer-stream and request tables, the
  driver's pending-prefix and frame-boundary tables — to its bound and asserts three things about
  what happens then: the refusal is `WT_ERR_LIMIT`, it carries **no error code** (the bound is this
  endpoint's, so blaming the peer for it would tell the peer's story about a local limit), and the
  table does not move — a refused stream consumes no slot, and a stream that ends gives its slot
  back, because these are bounds on *concurrency* and not lifetime totals. A table that quietly
  dropped the entry past its bound would show a short, clean run, which is exactly why the count
  assertions are the ones that matter.
- **A malformed-input corpus for HTTP/3, QPACK and the session layer** (Phase 10): the same
  treatment the QUIC parsers already had — a deterministic pseudo-random byte stream fed to the
  frame decoder, the SETTINGS parser, the capsule decoder and its value parsers, the datagram
  parser, the QPACK field-section decoder with **no dynamic table** (the strictest configuration)
  and the draft-16 request validator, plus the HTTP/3 driver's stream classifier and frame-boundary
  reassembler. The assertion is that a refusal is a STATUS and never a crash — under ASan+UBSan a
  read past a buffer is a failure rather than a plausible value — and the corpus also asserts that
  it refuses *and* accepts, because a generator change that made every input valid would turn the
  suite into a no-op. Where the corpus is a refusal corpus by construction (a random field section
  against an empty dynamic table), the test says so instead of pretending to be balanced.
- **An extended CONNECT across a real connection** (Phase 9): `test_runtime_session_pair` now
  drives the WHOLE WebTransport handshake-over-HTTP/3 path — two sessions complete a TLS 1.3
  handshake inside QUIC, the client opens HTTP/3's control and QPACK streams and sends an
  extended CONNECT as a QPACK field section, and the server assembles that section from the
  pieces the driver reports, decodes it off the wire, and accepts it with the draft-16
  validator. The bug that had blocked it for several rounds was a missing RECEIVE credit: the
  connection's flow account started at zero because nothing paired the `initial_max_data` each
  endpoint ADVERTISES with the local grant that enforces it, so the first stream frame was
  refused as `FLOW_CONTROL_ERROR` (code 3, frame type 8) and the connection closed — which
  presents as a peer that says nothing, not as a missing grant. `runtime/session.h` now states
  the rule, and pairing it automatically is recorded as a task.
- **The advertised limits are put in force in one place**: `wt_runtime_session_advertise`
  applies what an endpoint promised in its transport parameters — the session-level data limit, the
  per-stream limit and the stream counts — so the promise and the enforcement cannot disagree. The
  failure this removes is the one that cost several rounds of measurement: an endpoint that
  advertised a limit, granted nothing, and then closed its own connection on the FIRST stream
  frame as `FLOW_CONTROL_ERROR`, which presents as a peer that says nothing. It is deliberately a
  separate call rather than four more parameters on a call that already takes seven: a caller's
  arguments cannot drift out of order, and a caller that advertises nothing simply does not call it.
- **A packet session driver** (Phase 9): `runtime/session.h` is the only place where the
  socket, the QUIC connection and the TLS handshake meet — the connection needs somewhere to
  send, the handshake needs a connection with Initial keys, and the socket needs a caller to
  pump it. It encodes the rules that are hard to see afterwards: the Initial keys come from
  the destination connection ID in **both** directions with the `from_server` flag *opposite*
  for the receive direction (get that backwards and the connection encrypts nothing, which
  looks like a peer that never answers); the handshake's frame handler is **chained rather
  than replaced**, so the HTTP/3 layer can be installed behind it; and a **pump never waits** —
  it reads what is there, flushes what is owed and returns, because a tool that waited inside
  a library call could not honour its own `--timeout-ms`. The test covers the session's own
  contract: arming, a bounded pump with an empty socket, an unstarted session refusing to
  pump, clearing twice (an error path that unwinds must not double free), and a server with no
  certificate being refused at start rather than at the first ClientHello.
- **A message as a datagram** (Phase 9): `--exchange datagram` end to end. The client frames the
  message the way the draft does — a quarter stream ID and then the payload — and sends it in a
  QUIC DATAGRAM frame; the server's session sink receives it whole, and parsing it with the
  session layer's own parser yields this session's quarter stream ID and exactly the payload.
  Datagram support is *advertised* (`max_datagram_frame_size`), the same match-the-advertisement
  rule as the flow-control grants: a peer may only send a DATAGRAM when those parameters said it
  would accept one. A datagram IS the unit, so there is no reassembly and no ordering — what
  arrives is the whole thing or nothing.
- **A message on a WebTransport stream** (Phase 9): `--exchange stream` end to end. After the
  exchange's response, the client opens a **bidirectional** WebTransport data stream — the draft's
  signal value (`0x41`, encoded as the two-byte varint `40 41`) **and the session ID**, then the
  session's own bytes, FINishing the stream with them — and the server's session sink receives
  exactly the message. Two of the draft's own details are the whole of it. The classifier reads
  only the TYPE, so the session ID is part of the prefix that must be consumed before the session
  sees any data: passing it through as data arrived as one leading byte nobody could explain, and a
  prefix that stops after the type is `WT_ERR_TRUNCATED` rather than a stream whose payload begins
  with its own session ID. And the prefix belongs to the stream's **initiator** and to nobody else
  (§4.2/§4.3), so a peer's bytes on a stream this endpoint opened are payload: the driver remembers
  the data streams it opens, which is why the Swift library's shape — open a bidirectional stream,
  send with `endOfStream: true` — is the one both ends speak.
- **A session with an independent implementation** (WT-135): the C99 client against
  `pywebtransport`/`aioquic` in a container, one Docker network, the client in the peer's own
  network namespace. `"connectAccepted":true "responseStatus":200` and **the peer's echo of the
  message arrives**: the peer logs `stream in: 13 bytes`, `stream echoed`, and the client reports
  `received 13 byte(s)`. This is the criterion no self-test could satisfy — every local test runs
  both ends of this same code — and it is the reason four separate defects were found only here:
  the client never adopted the server's Source Connection ID (WT-138), never sent
  `initial_source_connection_id` (WT-141), sent nothing to a peer after a lost frame (WT-135), and
  re-read its own data stream's answer as a prefix (WT-135, above).
- **A self-signed identity for local development** (Phase 9): `tls/self_signed.h` generates the
  pair a local server needs *in memory* — an ECDSA P-256 key and a certificate for the loopback
  names — and returns its SHA-256 fingerprint. The pin is the point: a self-signed certificate is
  trusted by nothing by definition, so a client reaches it through
  `WT_TLS_TRUST_PINNED_CERTIFICATE` with that fingerprint, or through the development bypass the
  trust layer already restricts to loopback names. One call therefore produces both halves of a
  local development setup, and `--listen --trust local-development` needs no certificate file. The
  test is a closed loop rather than a self-comparison: generate, pin what the generator returned,
  let the trust layer accept it, and let it refuse a different pin.
- **The two CLI tools talk to each other** (Phase 9): `wt-server-c99 --listen` and
  `wt-client-c99 --connect` run a real WebTransport session over a real socket, in two processes,
  each with its own command line and its own machine-readable JSON — handshake, CONNECT accepted
  (response `200`), and a four-byte message each way. A CTest script runs them against each other,
  so the plan's CLI criterion is checked rather than demonstrated. **Both** exchange modes are
  registered (`wt_cli_session_stream` and `wt_cli_session_datagram`), and each asserts the mode in
  both tools' reports — they are different code paths, and a report that claimed the same thing for
  both would be worth nothing. The piece that made it work is
  `wt_udp_peek`: a listener learns its peer's address by PEEKING at the first datagram and leaving
  it in the queue, because a connection must be armed with the peer's address before it can process
  the packet that names the peer — a listener that consumed that packet would wait for a
  retransmission that may never come, which is exactly what the first version did.
- **The tools' local socket** (Phase 9): `cli/endpoint.h` turns a `host:port` into a bound or
  targeted UDP endpoint, and both tools open theirs and report it in the `--json` output. The
  FAMILY comes from the address rather than a flag — an IPv4 address on an IPv6 socket is not
  reachable, because the runtime sets `IPV6_V6ONLY` explicitly (the platform default differs),
  so a tool that guessed would work on one machine and not the next. A listener binds and
  reports the port it actually got, which is what makes `--listen 127.0.0.1:0` usable from a
  test; a client parses without binding, so two clients on one machine can reach one server. A
  wildcard is spelled `0.0.0.0:4433`, not `:4433`: a host with no family is a guess, and the
  runtime refuses to make it rather than inventing one. IPv4 is asserted unconditionally and
  IPv6 is available-or-skipped, because a test that fails without an IPv6 loopback is a test
  about the machine.
- **A draft-16 compliance matrix for this tree** (`docs/COMPLIANCE-MATRIX.md`): every requirement the
  draft places on a WebTransport endpoint — the extended CONNECT and its refusals, the response, the
  session-as-a-request-stream rules, WebTransport streams and their prefixes (including a prefix that
  arrives in pieces), datagrams and their advertisement, the capsules with the strict-increase and
  `2^60` flow-control rules, drain, close and the CONNECT stream ending — mapped to the function that
  implements it and the test that exercises it. **The matrix cannot drift:** `scripts/check-matrix.sh`
  greps every symbol it names for a C declaration or a registered CTest name and fails if one is
  missing, and CI runs it. The two rows that are not "tested" are stated rather than hidden — server
  push is refused deterministically by design, and a peer that changes its connection ID during the
  handshake is not tracked, which is the recorded transport gap.
- **Five diagnostics, and what each one answers** (`docs/DIAGNOSTICS.md`): the environment-gated dumps
  that record what was on the wire — every packet sent, the TLS traffic secrets at derivation, the
  ClientHello this client hashed, the request's field section and the frames on the request stream, and
  every STREAM frame the HTTP/3 driver was asked to route. They are off unless a variable names a file,
  they write secrets when they are on, and one page states what each records and which interop defect
  it closed — because a diagnostic nobody can find is a diagnostic that gets rewritten (WT-157).
- **The platform surface, inventoried and checked** (`docs/PORTABILITY.md`): what a Windows or
  FreeBSD build would need, item by item — and the socket is now ONE header:
  `src/runtime/udp_platform.h` names all five differences that used to be spelled out as POSIX in a
  dozen places (closing, non-blocking mode, waiting for readability, the error number, and the
  datagram calls themselves, through `wt_udp_platform_message_t`). The `_WIN32` branch is no longer
  "written from the inventory": `scripts/check-windows-platform.sh` compiles it with a mingw
  cross-compiler under the same warnings-as-errors the POSIX build uses — and found a real defect on
  its first run (`FIONBIO` does not fit a signed `long` on Windows). The socket lifetime owns
  `WSAStartup` through a reference count, the public handle is `intptr_t` so a pointer-sized `SOCKET`
  cannot be truncated, CMake links `ws2_32` on Windows, and the **address layer** went behind the
  same header (`wt_udp_platform_address_*`), so `udp.c` no longer includes a socket header at all —
  **it now compiles for Windows**, which is the claim that check is measured by. The cross-compile
  found four real differences the inventory had not named, including `EHOSTDOWN` not existing there
  (which is why the error *classification*, not just the number, is per platform) and `inet_ntop`'s
  length type. The check now sweeps the **whole tree** — 72 library sources and 92 test/app sources —
  and they all compile for Windows, which is the claim a runner needs before it is worth adding. Two
  more defects came out of that sweep, both invisible to clang. It goes further than compiling now: with
  a mingw toolchain and a Windows OpenSSL the whole tree **links** — 84 PE32+ executables and
  `libwebtransport.dll` — and CI does that on the legs it already has, because the MSYS2 OpenSSL
  package is a plain tarball. That link found a defect the compile could not (`-Wstringop-overflow` in
  a Release build, which clang never reported). What remains is *running* those binaries, which needs
  Windows or Wine, and FreeBSD.
  `scripts/check-portability.sh` fails if the library uses a POSIX-only call the inventory does not
  name — it caught `sendto`/`recvfrom` missing on its first run — and CI runs it. FreeBSD is close to
  Debian: the same POSIX calls, a toolchain and OpenSSL-package decision.

- **Where this stands, measured** — the score the plan's Definition of Done asks for, from
  `scripts/score-matrix.sh` rather than from memory: **26 of 26 draft-16 requirements in
  `docs/COMPLIANCE-MATRIX.md` are exercised by a test in this tree, and 7 of the plan's 9 completion
  criteria are met, with 2 partial and none unmet.** The matrix coverage is 100% *of the matrix*,
  which is not the same as being done. The two partial criteria are outside the matrix: the FreeBSD
  and Windows CI legs need portability work before a job for them would be anything but red, and the
  interop matrix now **runs** — `scripts/run-container-interop.sh` completes a whole session and the
  message exchange against **every** peer this repository can start: `pywebtransport`/`aioquic`,
  `quinn`/`web-transport` and `quiche`. The last of the three was `WT-146`, and it was not a handshake
  defect at all: quiche's server sends a **Retry**, which this connection used to discard by name, and
  answering one (WT-166) is what closed it. What keeps the criterion partial is the VPS matrix's five
  implementations, which still need a host. The conformance-coverage criterion is **met**, and the
  evidence is the audit rather than a total: the Swift suite was walked scenario by scenario --
  fifty-three C99 scenarios, all five of that suite's interop matrices mirrored case for case, its two
  release checks mirrored into `scripts/check-package.sh` (which installs the tree and asserts the
  product list is the three tools and nothing that tests them), and every remaining entry mapped to
  the unit suite that covers it. The walk found one real gap, `protocol-structured-fields`, which is
  implemented and exercised end to end. What is met: the CLIs run local IPv4 **and IPv6**
  sessions, sanitizers and static checks are clean, the public API is documented, nothing
  placeholder-shaped is exposed as production, and the matrix itself exists and is checked.

- **The CLI tools over IPv6 too** (Phase 10): `wt-client-c99` and `wt-server-c99` exchange a
  session over `[::1]` as well as IPv4 — the same script, parameterised by host, registered as
  `wt_cli_session_ipv6`. A machine with no IPv6 loopback returns CTest's **skip** code (77) with the
  reason, because that is a fact about the machine rather than a failure of the tools; the skip is
  decided by the conformance tool's own IPv6 scenario, so there is one probe rather than two.
- **The CLI tools' process contract** (Phase 10): the tools' exit statuses, refused command
  lines and JSON report are part of their interface, because scripts drive them. A CTest script
  checks them without a peer — an unsupported mode exits **2** and names what it refused, no mode
  exits 2, `--help` exits **0** and prints usage, and a client that cannot reach anybody exits
  **non-zero** while reporting `"established":false` and never `"status":"ok"`. It found a real
  usability bug on its first run: `--help` was rejected as an **unknown flag** by the parser, so
  `--help` and `--version` are now the parser's business and are answered *before* the mode and
  address are checked — asking what a tool does is not asking it to do anything.
- **The conformance tool's scenarios, positive and negative** (Phase 9-10): **fifty-three scenarios, all
  passing** in one machine-readable report — the codec ones, **eleven refusal scenarios** (a wrong path
  is `404` compared exactly, an extended CONNECT for another protocol is not a WebTransport request, a
  server without `WT_ENABLED` refuses the session, a **repeated** SETTINGS identifier is
  `H3_SETTINGS_ERROR`, a **reserved** one is the same error, a QPACK section needing a table that was
  never advertised is refused with a code, the session keeps the **first** close's code, a drain stops
  new streams, a capsule over the bound is excessive load, a peer stream past the bound is
  `WT_ERR_LIMIT` with **no** error code because the bound is ours, and an empty datagram is malformed
  rather than short), **two refusals over a real connection** (a frame cut off by the end of its stream
  closes the connection as an *application* close with `H3_FRAME_ERROR`, asserted on the end that refused
  **and** on the end that is told -- a decision is a different claim from what a peer receives, and both
  halves are read rather than inferred), **two capsule scenarios** (a `MAX_DATA` capsule the client sends on
  the CONNECT stream moving the limit the server enforces, and a drain plus a close ending the session with
  the peer's application code while the connection stays up -- before WT-164 the first was silently skipped
  as an unknown HTTP/3 frame and the other two were parsed as frames and refused), **two capsule refusals**
  (a capsule declaring more than the receiver will buffer closing the *connection* with `H3_EXCESSIVE_LOAD` and
  the peer reading that code, and a repeated grant closing the *session* with the draft's own
  `WT_WEBTRANSPORT_FLOW_CONTROL_ERROR` while both connections stay up -- the second is the case where returning
  the failure to the transport would have closed the connection over the session's own error), the positive edge this project earned the hard way (half a prefix
  decides nothing until it is whole), **thirteen connection-control scenarios** (GOAWAY identifiers that must not
  increase and must name a client stream, the reject-at-or-above boundary, one control stream per
  connection, a request frame refused on it, SETTINGS that must come first, a closed critical stream,
  the QPACK static table's exact bound and a dynamic capacity of zero, the session-stream predicate,
  and the datagram's quarter-id round trip), **five header and QPACK scenarios** (an extended CONNECT
  and a 200 response round-tripped through a field section, `:path /` as static entry 1, a literal
  line whose whole representation is consumed, and a Huffman-coded line that is shorter than the plain
  one and keeps its H bits), **two isolation scenarios** (two sessions in one connection whose state
  does not cross, and a datagram for a session this endpoint does not have being dropped rather than
  delivered to a neighbour), **one interop matrix** (eleven stream cases -- the four prefix directions,
  a session that cannot exist refused on both sides, another stream type, half a prefix as a wait, and
  the classifier's session and length, all in one table), **two interop matrices** in that table shape
  (eleven stream cases and eight datagram cases, the latter covering both directions, the two malformed
  forms a whole-unit datagram has, the unknown session with no owner, and the send-side payload bound
  re-derived from its definition), **three interop matrices** (stream, datagram, and GOAWAY/close/drain --
  the last with ten cases: a GOAWAY gating the streams at or above its identifier, a drain in either
  direction stopping new streams without ending the session, a repeated drain, the first close's code, a
  capsule after the end refused, and both capsules round-tripped), **four interop matrices** (stream,
  datagram, GOAWAY/close/drain and CONNECT -- the last with nine cases: the server's authority and path
  compared exactly, another protocol token, a server without `WT_ENABLED`, DATA before HEADERS,
  HEADERS then DATA, a request ended before its HEADERS, an untracked stream, and a client receiving a
  request stream), **five interop matrices** (stream, datagram, GOAWAY/close/drain, CONNECT and
  malformed/flow-control -- the last with nine cases: a capsule over the caller's bound and one that has
  not arrived, the control stream's three rules, a field section needing a table nobody advertised, a
  four-byte limit accepting four and refusing the fifth with the draft's own flow-control code, a
  one-stream limit, and a session with flow control disabled enforcing nothing), and **the flow-control
  matrix** (seven cases: a granted limit must strictly increase, so a repeat or a decrease is
  `WT_FLOW_CONTROL_ERROR` and neither moves the limit; an explicit zero allows nothing rather than
  everything; and one session's disabled flow control does not loosen another's), and **the sub-protocol
  negotiation** (three entries: the client's list offered through `wt-protocol`, the server selecting the
  first token it supports, the client accepting the answer only because it offered it, a required
  selection that cannot be met answering 400, and a response naming an unoffered token being refused),
  and the two **real sessions** over IPv4 and IPv6, and one **connection-ID scenario** (WT-171: both sides keep a
  spare, the client retires the server's and the server replaces it with the next sequence, with both connections
  still up -- the case where the two endpoints' bookkeeping has to agree on which IDs are still active). The
  reserved-SETTINGS scenario is what **found** a real spec violation in this tree's own parser, and
  the fix is in — see `IMPLEMENTATION_PLAN.md`. Registered with CTest.
- **The conformance tool runs real sessions** (Phase 9): `wt-conformance-c99 --scenario all`
  stands up two endpoints in **one process** over loopback — a generated, pinned identity, a real
  TLS 1.3 handshake inside QUIC, an extended CONNECT accepted by the draft-16 layer, the response,
  an 11-byte message on a WebTransport stream and a message as a datagram — on **IPv4 and IPv6**,
  and reports every scenario as passed in its machine-readable output
  (`"summary"` with `"failed":0` and `"unsupported":0`, exit 0). IPv6 reports
  `unsupported` with its reason on a machine with no IPv6 loopback, because that is a fact about
  the machine rather than a failure of the code. The tool is run by CTest, so the plan's criterion
  is checked rather than demonstrated by hand.
- **The conformance tool's report** (Phase 9): `cli/report.h` is the machine-readable product
  of a conformance run, and its three rules are all about not lying — a scenario that did not
  run is `unsupported` with a reason and never a pass, the report is ordered and named by the
  tool so two runs compare without sorting, and the exit status carries the same information
  rather than replacing it (0 all passed, 1 anything failed, 3 nothing failed but something
  was not attempted). `wt-conformance-c99 --scenario all [--json]` runs the in-process
  scenarios this build can genuinely verify — varints across every form, a capsule round trip,
  an extended CONNECT decision — and reports the two session scenarios as unsupported with the
  reason. The tool found a real bug in itself on its first run: a scenario compared against a
  stale loop index and reported `failed`, which is exactly what a conformance report is for.
- **The public API** (Phase 8), which is what a consumer outside this repository
  builds against; `docs/PUBLIC-API.md` is its contract, and
  `apps/wt-api-sample/main.c` is a consumer that includes only the umbrella header
  and is built and run by CTest on every platform, so the document is checked rather
  than described:
  - `webtransport.h` — the one header a consumer includes, carrying the three rules
    that hold across every layer: a bound is this endpoint's and the code says so
    rather than blaming the peer, incomplete is not malformed on a stream (a
    datagram is the deliberate exception, because a datagram is the unit), and a
    refusal keeps the peer's code.
  - `api/session.h` — the opaque session handle: `wt_session_create`/`wt_session_destroy`
    take the allocator the object was made with, so a session created from a pool
    returns to that pool; the state a consumer reads is this header's own enum,
    mapped member by member rather than cast, so a renumbering of the internal
    machine is a compile error and not a silent contract change; and
    `wt_session_last_error` reports a stable status NAME and the peer's CODE, never
    a peer's text. The two bounds the API owns are the session's own: an authority
    too long for the handle's copy is refused rather than truncated (a truncated
    authority names a different session) and a capsule value over
    `max_capsule_bytes` is refused as excessive load rather than buffered.
  - `api/events.h` — the event-loop seam: a callback table with a context and
    nothing else, so a caller needs no synchronization it did not already have for
    the call it made. The contract is written down where a caller can see it: the
    library never calls a callback from a thread of its own and never re-enters
    itself, a pointer passed to a callback is a view valid for the call only, and
    no callback for an event means the event is accepted and discarded rather than
    turned into a connection error. Peer streams live in a fixed table sized by
    `max_streams` (the peer runs into the bound; the table never grows for one), and
    a stream or datagram naming another session is refused with HTTP/3's identifier
    error instead of being delivered to the wrong session or dropped silently.
    `wt_session_config_default()` returns every bound at its default, because a C
    caller that forgot a field would otherwise pass whatever its stack held into a
    bound.
  - `http3/driver.h` — the seam between a connection and the endpoint: it turns a
    stream's opening bytes into a classified stream, and it exists because a stream's
    type prefix is a varint that a peer may SPLIT across frames. Deciding a type from
    half a varint is how an implementation reads someone else's stream, so the driver
    holds at most the first eight bytes of each opening stream until they add up to a
    prefix — in a fixed table, because a buffer that grows with a peer's stream count
    is a heap exhaustion path with the peer's name on it. A prefix that does not start
    at offset zero, or a stream resumed out of order, is the caller's accounting rather
    than the peer's, and the payload after the prefix is a view into the frame that
    completed it, so nothing is copied. The same header starts this endpoint's OWN
    streams: the control stream is its `0x00` prefix followed by a SETTINGS frame built
    from the caller's settings, measured into scratch before the frame is written — the
    same measure-then-write rule as everywhere else — and the QPACK streams are their
    prefixes alone, with the endpoint's once-per-connection rule refusing a second one
    before any bytes go out. The same header reassembles a stream's HTTP/3 FRAME
    boundaries, where a frame's own varints can be split the same way — and it
    deliberately does not buffer a frame's payload: it reports pieces to a sink with a
    `last` flag, because how much of a HEADERS section to hold is a bound, and a bound
    belongs to whoever owns the memory. The one number the driver does bound is the
    frame's declared length, refused as excessive load before the sink allocates for
    it. A frame whose header or payload is cut off by the stream's end is
    `WT_ERR_TRUNCATED` — one byte of a two-varint header is exactly as incomplete as
    one byte of a payload, which is the case a naive reassembler misses. The same header
    carries the routing that makes the driver installable as a QUIC connection's frame
    handler: a STREAM frame on a peer's unidirectional stream has its prefix
    reassembled and its bytes then sent either to the frame sink (HTTP/3's own streams)
    or to the session (the draft's stream type, whose bytes are not frames at all), a
    peer's bidirectional stream becomes a request stream, a DATAGRAM's payload goes to
    the session uninterpreted, and a frame on a stream this endpoint OPENED is not
    routed at all — the peer's answer belongs to the connection's own stream state. The
    outbound half goes through a three-call transport table (`open_stream`,
    `send_stream`, `send_datagram`) rather than naming a QUIC connection, so the HTTP/3
    layer stays independent of the connection implementation and its bytes are checked
    against a recording transport instead of a live handshake. Each stream is BUILT
    before it is opened, which puts the once-per-connection rules ahead of the open and
    means a refused start cannot orphan a stream the peer would see and this endpoint
    could not explain. `wt_http3_driver_quic_transport` binds that table to a real
    connection, and it reads the send offset from the CONNECTION's own stream state
    (`stream->send_offset`) rather than keeping its own — an adapter with its own counter
    would be a second opinion about a number the connection already owns, which is how two
    layers come to disagree about where a stream is. A stream the connection does not know
    is refused by this layer as the caller's error, and everything else is passed through
    unchanged: congestion and connection state are the connection's to report.
  - `http3/endpoint.h` — the HTTP/3 endpoint's own streams, which is the lifecycle a
    consumer never sees: our control stream (`0x00`) and QPACK streams (`0x02`/`0x03`)
    exist once each, the peer's unidirectional streams are classified by their type
    prefix, an UNKNOWN type is ignored rather than failed (section 6.2.1) while a
    second control stream, a second QPACK stream and an unrequested push stream each
    commit the connection to the error the RFC names, and the draft's WebTransport
    stream (`0x54`) is recognised as the session layer's rather than mistaken for an
    unknown one -- which would lose a session's streams one at a time. The peer-stream
    table is fixed, so running into it is `WT_ERR_LIMIT` with no error code: this
    endpoint's bound, not the peer's mistake.
  - the same header's request-stream lifecycle, which is the session's own stream: only
    a client opens one (HTTP/3 has no server-initiated request, and section 6.1 makes a
    client that receives a server-initiated bidirectional stream a
    `H3_STREAM_CREATION_ERROR`), a complete request keeps its state until the stream
    ends, and the request-ordering rules stay in `request.h` rather than being
    re-implemented. The request table is bounded too, at
    `WT_HTTP3_ENDPOINT_REQUESTS_MAX` sessions per connection, and a duplicate is found
    before the bound so a caller's mistake is never reported as a limit.
  - the same header's QPACK decode path, which is what turns a HEADERS frame into a
    request: the endpoint owns the decoder state (the dynamic table its peer's encoder
    stream fills, and the insertion count), a capacity below 32 makes `MaxEntries` zero
    so no section may reference a dynamic table this endpoint never advertised, and the
    draft-16 layer then decides whether the decoded pseudo-headers are a WebTransport
    request — the endpoint deliberately does not know what one is. The RFC's "trailers
    MUST NOT contain pseudo-header fields" is enforced here, because the message
    decoder has one request shape and one response shape and cannot tell a trailer from
    a request on its own.
  - the encode side of that same header: `wt_http3_message_encode` writes a field
    section for a request or a response, and
    `wt_http3_endpoint_write_headers` writes the HEADERS frame around it. The section
    is encoded into the caller's scratch FIRST because a frame's length prefix is a
    varint whose width depends on the length — the frame can only be written once the
    section has been measured, which is the rule this library follows everywhere a
    length is written. The lines are literal (always valid, never needing a dynamic
    table, larger on the wire than a static-table reference would be), and the round
    trip is the test: what a client writes is fed to a server's decode path and then to
    the draft-16 validator, so the two directions cannot disagree without a test
    failing.
  - `api/endpoint.h` — which side this program is, the name the peer's certificate
    must be valid for, and how it is judged, so a trust misconfiguration is a return
    value before any packet rather than a handshake failure afterwards. The
    development bypass is tied to a loopback name through the trust layer's own
    `wt_tls_trust_host_is_loopback`, which is exported precisely so the configuration
    check and the handshake cannot disagree about the rule; a server must carry no
    trust policy, because this draft has no client authentication and a policy there
    would be a promise the library cannot keep.
  - `api/flow.h` — the session's send-side flow control, which is what backpressure
    means when there is no socket to block on. The draft's rules are the
    implementation: flow control is off until both endpoints' SETTINGS say otherwise
    (and a capsule arriving while it is off is ignored, not refused, because the
    draft makes it conditional); limits strictly increase, so a repeat and a decrease
    are both the draft's flow-control error; a stream count above the draft's
    `2^60` ceiling is that error too; and the allowance functions answer "may I send
    this" before the refusal rather than after it. The initial limits come from the
    peer's SETTINGS through `wt_session_flow_advertised`, so a setting the peer
    omitted is zero rather than unlimited -- which is what it means on the wire.
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
    `CONNECTION_ID_LIMIT_ERROR` of RFC 9000 section 5.1.1.
- **Crypto and packet protection** (Phase 2), which turns bytes into a QUIC
  packet an observer cannot read:
  - `crypto/crypto.h` — one interface, one backend. SHA-256, HMAC, HKDF extract,
    expand and expand-label, AES-128-GCM and ChaCha20-Poly1305, the AES block and
    ChaCha20 keystream header protection is built from, a constant-time comparison
    and a secure zero. `wt_aead_open` verifies the tag itself and clears the
    plaintext when it does not, so there is no way for a caller to act on
    unauthenticated bytes by forgetting a comparison.
  - `quic/protection.h` — the Initial secret and packet keys, the traffic-secret
    and key-update derivations, the packet nonce, and the four header protection
    operations. The order is the documented part: a sample of the payload masks the
    header, and the unmasked header carries the packet number the payload's nonce
    needs, so the receive path cannot be reordered.
- **The TLS 1.3 key schedule** (Phase 3, first part), which is what turns a
  handshake into the secrets QUIC protects with:
  - `tls/keyschedule.h` — RFC 8446 section 7.1's two chains: the extracts that build
    the Early, Handshake and Master secrets from the PSK and the ECDHE shared
    secret, and the derivations that turn them into both directions' handshake and
    application traffic secrets, the exporter and resumption secrets, the record
    traffic keys, the Finished keys and verify data, and the key update secret. An
    all-zero shared secret is refused where it enters, per RFC 8446 section 7.4.2.
  - The handshake transcript lives here too. It absorbs whole handshake messages
    into a running SHA-256 and reads the hash at each point without consuming it, so
    a transcript is a few hundred bytes whatever the peer's certificate chain
    weighs; a message whose framing disagrees with its length is refused rather than
    hashed.
- **The TLS handshake messages and extensions** (Phase 3, second part):
  - `tls/handshake.h` — the four-byte handshake framing and the ClientHello and
    ServerHello, parsed into views, re-encoded byte for byte and built from
    parameters. A parsed message keeps extensions this implementation does not
    implement, which is what lets a server answer a shape it does not interpret.
  - `tls/extension.h` — the extension list codec and the typed readers and writers for
    the extensions a QUIC handshake uses: `server_name`, `supported_groups`,
    `signature_algorithms`, `supported_versions`, `key_share`,
    `psk_key_exchange_modes`, ALPN and `quic_transport_parameters`. Every list a peer
    can grow is bounded by a capacity and refused rather than written past.
- **The X25519 key agreement** (Phase 3, third part): `tls/keyshare.h` carries RFC 7748's
  primitive, key generation, the public key a private key produces, and the shared secret,
  and refuses an all-zero secret where it is computed, because RFC 8446 section 7.4.2
  makes a point of small order a handshake failure. X25519 is the only group the
  implementation can complete, so it is the only one a client should advertise: a group
  offered without a key share invites a HelloRetryRequest, which this implementation
  refuses.
- **The certificate messages** (Phase 3, fourth part): Certificate and CertificateVerify
  are parsed as framing -- a chain of DER views and a scheme with a signature -- and
  Finished is exactly Hash.length bytes. Nothing here validates anything, which is what
  lets the codec be pinned to RFC 8448's own certificate message byte for byte; the trust
  layer is a separate question that this layer deliberately does not answer.
- **Peer authentication** (Phase 3, fifth part): `tls/trust.h` validates a certificate
  chain through OpenSSL and verifies a CertificateVerify signature, with a prompt-free
  policy that mirrors the Swift library -- system trust, a caller-supplied store, pinned
  leaf fingerprints, and a development bypass that is restricted to loopback names because
  the restriction is part of the mode. The chain is parsed, validated and discarded inside
  one call, so no X.509 object outlives it and no OpenSSL type appears in a public header.
- **The client handshake** (Phase 3, sixth part): `tls/session.h` sequences the whole
  handshake -- the ClientHello as bytes, the ServerHello's version, ciphersuite, session id
  echo and key share, ALPN and the transport parameters QUIC requires, the certificate chain
  through the trust policy, CertificateVerify over the transcript through the Certificate,
  the server's Finished over the transcript through CertificateVerify, and the client's
  Finished over the transcript through the server's. The application secrets exist in no
  state before the last of those, so every security condition is a precondition for them.
  The machine is driven end to end by RFC 8448's recorded flight: it is started with the
  RFC's ClientHello and client key and must produce the RFC's own secrets and Finished.
- **The server handshake** (Phase 3, seventh part): `tls/session.h` also carries the server --
  the ClientHello's version, ciphersuite, key share, ALPN and transport parameters checked, the
  flight built in the order the client's checks expect, the signature over the transcript
  through the Certificate, and the client's Finished gating the application secrets. The flight
  is two calls because QUIC has two encryption levels. `tests/unit/test_tls13_server.c` runs a
  whole handshake between the two halves and requires that they agree, including that each end's
  application secret is the other's in the opposite direction.
- **The QUIC packet number space** (Phase 4, first part): `quic/pn_space.h` holds the received
  set as a bounded list of ranges, the ACK frame it produces, the acknowledgement debt that
  decides prompt or delayed, and RFC 9002 section 5's round trip estimator with its probe
  timeout. No I/O, no policy -- which is why the ranges are checked for order-independence and
  the RTT arithmetic against section 5.3 worked out by hand.
- **Loss detection and probe timeouts** (Phase 4, second part): `quic/loss.h` holds the sent-packet
  list, RFC 9002 section 6's packet and time thresholds, the loss timer they imply, the bytes in
  flight the congestion controller will read, and the probe timeout with its backoff. The list is
  bounded and being at the bound is an error rather than a drop, because a forgotten packet is one
  that is never retransmitted.
- **Control-frame retransmission** (WT-170): RFC 9000 section 13.3 asks for a frame's *information* to be sent
  again rather than the packet, and the frames carrying the connection's OWN state -- MAX_DATA, MAX_STREAMS,
  NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, HANDSHAKE_DONE, RESET_STREAM, STOP_SENDING -- had no owner that
  could re-send them, so a lost one was simply gone. `send_control_frame` encodes such a frame once into an
  eight-slot table, the packet's descriptor names the slot, and `on_lost` sends those bytes again -- a new
  packet carrying the same frame -- until an acknowledgement releases the slot. Which kinds are kept is
  decided in ONE predicate rather than by each sender remembering: PING and PADDING "contain no information",
  an ACK is replaced rather than repeated, a CONNECTION_CLOSE is section 10's business, a DATAGRAM is never
  retransmitted at all (RFC 9221 section 5.2), a PATH_RESPONSE is sent once while a PATH_CHALLENGE must carry
  a fresh payload, and CRYPTO and STREAM bytes are answered by the layers that own them.
- **Path validation, driven by the connection** (WT-172): RFC 9000 section 8.2 is the liveness test of section
  10.1.1, and the rules are the protocol's rather than a caller's, so the connection owns them.
  `wt_quic_connection_validate_path` sends a PATH_CHALLENGE with eight unpredictable bytes; a PATH_RESPONSE
  carrying those bytes validates the path; a path that does not answer is retried with a **new payload** -- which
  section 8.2.1 requires by hand, because a repeated one is indistinguishable from an attacker replaying an old
  challenge -- up to `WT_QUIC_PATH_VALIDATION_ATTEMPTS` times, and the failure is then counted for the caller.
  The retry is driven by the connection's own probe timeout rather than by the loss machinery, for that same
  reason: a retransmitted PATH_CHALLENGE would carry the payload that must not repeat. A peer's challenge is
  echoed IMMEDIATELY, from inside the receive, because section 8.2.2 forbids delaying a PATH_RESPONSE. The
  decision to validate is the caller's, and so is the reaction to a failure -- a path that stops answering is a
  diagnostic, not a close, because only the caller knows whether it has another path to try. **MIGRATION is
  deliberately out of scope** for this tree: a connection has ONE peer address, given at `attach`, and a caller
  that needs to move a session re-establishes it rather than migrating this one.
- **A server can send a Retry, and serve the client that answers it** (WT-168): RFC 9000 section 8.1.2 lets a
  server answer a client's first Initial with a Retry, which proves the client's address before the server has
  spent any state on it -- the only defence section 21.3 accepts, and the reason quiche's server retries.
  `runtime/server_retry.h` is the flow: `build` reads a peeked Initial and writes the Retry (a token from
  `quic/retry_token.h`, a fresh Source Connection ID, and an integrity tag over the ORIGINAL destination
  connection ID, so only a server that saw the first Initial could have written it), and `accept` checks the
  token a client echoes against the address the packet actually came from, handing back the original destination
  connection ID the token carried. Between the two calls the server keeps NOTHING about the client, which is what
  makes it address validation rather than a state allocation. Two rules make it more than plumbing:
  `wt_runtime_session_start_server_retried` separates the two connection IDs a retried server has (the Initial
  keys come from the Retry's Source Connection ID, while the parameters must name the ID the client chose FIRST),
  and the answering Initial is left IN the socket queue for the connection to read -- so the wait loop peeks,
  checks, and CONSUMES only the datagrams that are not the answer. `wt-server-c99 --retry` turns it on, CTest's
  `wt_cli_session_retry` runs a whole session through it, and `pywebtransport`'s client completes one too.
- **Retry tokens** (WT-168): RFC 9000 section 8.1.2 lets a server answer
  a client's first Initial with a Retry, which proves the client's address before the server has spent any state
  on it -- the only defence section 21.3 accepts. Statelessness makes the token's integrity the server's own
  business, and section 8.1.4 names the construction this implements: a format byte, the server's timestamp, the
  client's address in a canonical byte form (`wt_udp_address_encode`), the original destination connection ID
  the connection must still name after a Retry, and an HMAC-SHA256 tag over all of it truncated to sixteen bytes.
  Validation checks the tag over the bytes as they arrived, checks the address, and takes a maximum age, so a
  token is proof of a round trip rather than a permanent credential. The answers are split by WHOSE fault a
  failure is: everything about the token bytes is `WT_ERR_AUTHENTICATION` (a server answers all of them the same
  way, and a forger learns nothing), an authentic but stale token is `WT_ERR_STATE`, and the caller's own
  mistakes are `WT_ERR_INVALID_ARGUMENT`. `wt_quic_transport_parameters_build` now also takes the
  `retry_source_connection_id` a server sends only when it retried, refusing BOTH mistakes -- a Retry the
  parameters do not name, and a name for a Retry that was never sent (section 7.3 makes each a close on the
  peer's side).
- **Congestion control** (Phase 4, third part): `quic/congestion.h` is RFC 9002 section 7's NewReno
  -- the initial window with its 14720-byte bound, slow start, congestion avoidance's fractional
  increment, the recovery epoch that makes a burst of losses cost one halving, the two-datagram
  floor, and persistent congestion. It reads the bytes in flight from the loss module rather than
  counting them, so the two cannot disagree after a retransmission.
- **Stream state machines and flow control** (Phase 4, fourth part): `quic/stream.h` carries RFC 9000
  sections 2, 3 and 4 -- both halves' state machines, the final size as the boundary that stops a
  peer appending to an ended stream, RESET_STREAM and STOP_SENDING, and flow control at the
  connection's level and the stream's. Flow control counts *offsets* rather than delivered bytes,
  which is the RFC's model: a gap cannot be used to escape the accounting.
- **QUIC DATAGRAM and the close paths** (Phase 4, fifth part): `quic/datagram.h` is RFC 9221's
  unreliable messages -- the size rule against both the peer's frame limit and the path's packet size,
  and a bounded receive queue whose discard policy is the newest rather than the oldest.
  `quic/close.h` is the two forms of CONNECTION_CLOSE, which are different messages, and the draining
  period of three probe timeouts.
- **The wire seam** (Phase 4, sixth part): `quic/packet_io.h` is where frames become a datagram and a
  datagram becomes frames. `wt_quic_packet_build` writes the header, seals the frames with the header
  through the packet number as associated data, appends the tag, and applies header protection last;
  `wt_quic_packet_read` removes header protection first, reconstructs the packet number against the
  largest this endpoint has seen, and only then authenticates and decrypts -- because the header
  protection sample is ciphertext and the packet number's own length is behind the mask. Two codec
  additions came out of it: `wt_quic_long_header_encode_prefix` writes a long header for a payload the
  caller has not produced yet, and `wt_quic_protected_pn_offset` walks a header that is *still
  protected* by its layout alone, which no decoder can do because the masked first byte hides both the
  packet number length and the two reserved bits. Because a round trip would let a shared mistake pass,
  the test flips every byte of a packet and requires that the frames never come back.
- **The UDP socket layer** (Phase 4, seventh part): `runtime/udp.h` moves whole datagrams between two
  addresses on IPv4 and IPv6 and knows nothing about QUIC. It is the only POSIX file in the tree
  (WT-13), so it is also the only place a syscall failure is classified -- one `map_errno`, with
  `WT_ERR_IO` for what it cannot classify rather than a guess. IPv6 sockets set `IPV6_V6ONLY`
  explicitly because Linux and the BSDs disagree, and a datagram larger than the buffer is
  `WT_ERR_TRUNCATED` with no length reported rather than a short read that would let QUIC parse the
  prefix of a packet (WT-36). A link-local address carries its scope id, because dropping it is the
  difference between reaching the peer and reaching nobody.
- **The connection runtime** (Phase 4, eighth part): `quic/connection.h` is one connection over one
  borrowed socket -- its three packet number spaces and their keys, the received sets and the
  acknowledgements they owe, the sent-packet list with loss detection and probe timeouts, NewReno, the
  close paths and the acknowledgement-delay timer. The frames it does not own (CRYPTO, STREAM, the
  limits, DATAGRAM) go to a caller-installed handler, which is the seam the handshake and the stream
  layer plug into. `now` is a parameter and the event loop is the caller's, so the timers are tested by
  moving a number rather than by sleeping. `tests/unit/test_quic_connection.c` runs two connections over
  two real loopback sockets on IPv4 and on IPv6 with Initial keys both ends derive from one connection
  ID, so a packet travels the whole path -- build, protect, send, receive, unprotect, walk, acknowledge,
  account -- without a handshake.
- **The 1-RTT key update** (Phase 4, tenth part): RFC 9001 section 6's lifecycle, which the derivation alone
  never was. `wt_quic_connection_initiate_key_update` moves the traffic secret forward, toggles the Key Phase
  bit and refuses before the handshake is confirmed or before the previous update is acknowledged; a peer's
  update is answered with this endpoint's send keys moved *before* the acknowledgement; the phase being retired
  is retained for packets the network reordered; and `KEY_UPDATE_ERROR` closes the cases section 6.2 and 6.4
  name. Two layers had to move for it. The packet layer is now two steps -- `wt_quic_packet_unprotect_header`
  and `wt_quic_packet_open` -- because the Key Phase bit is INSIDE the header protection mask and the header
  protection key is the one thing an update does not change (section 6.1); and the connection keeps the two
  packet numbers section 6 reasons about, since the phase being retired and the phase arriving carry the SAME
  bit (section 6.5). A packet whose tag does not verify is wiped by design, so a second attempt at one packet
  reads a saved copy. And the limits that exist to make an update happen (RFC 9001 section 6.6) are counted
  and enforced: the packets protected with each key set, the received packets that fail authentication across
  the connection's whole life, the two very different limits the suite implies (2^23 and 2^52 for AES-GCM,
  2^36 for ChaCha20-Poly1305's integrity), a rotation before the limit is reached, and `AEAD_LIMIT_REACHED`
  when a rotation is not possible.
- **Consuming and retiring connection IDs** (Phase 4, eleventh part): RFC 9000 section 5.1.2's other half, which
  the identity table alone never was. `wt_quic_connection_use_new_connection_id` switches the destination to an ID
  the peer issued -- "an endpoint can change the connection ID it uses for a peer to another available one at any
  time" -- and retires the one it abandons with a RETIRE_CONNECTION_ID, because the section forbids forgetting one
  without saying so. A NEW_CONNECTION_ID whose `retire_prior_to` covers IDs this endpoint holds retires them all,
  and the ORDER is not arbitrary: section 19.16 forbids a RETIRE from naming the destination of the packet that
  carries it, so when the ID in use is one of the retired ones the replacement in that same frame is adopted
  first and the retires ride it. A test caught exactly that: the first version retired first and the peer refused
  the frame, which is what a test with a real peer is for.
- **A connection ID the peer retires is REPLACED** (WT-171): RFC 9000 section 5.1.2 makes a
  RETIRE_CONNECTION_ID a request -- "Sending a RETIRE_CONNECTION_ID frame ... requests that the peer replace it
  with a new connection ID" -- and section 5.1.1 sizes the spare, because the peer's
  `active_connection_id_limit` COUNTS the handshake's ID: the default of two allows exactly one.
  `wt_runtime_session_keep_spare_connection_id` is that policy, opt-in, and it needs no state of its own: it
  issues a spare once the peer's limit is known and this endpoint can protect a 1-RTT packet, and issues another
  whenever `issued_count` shows one was retired, in the same pump round that read the retire. The bytes come from
  `wt_random_bytes`, which is what sections 5.1 and 10.3.2 ask of an ID and its stateless reset token.
  `wt_quic_connection_retire_peer_connection_id` is the other half a caller needs, and it exists because the test
  found the hole: retiring an ID sends the frame AND forgets it here, in that order, and a caller that built its
  own RETIRE_CONNECTION_ID frame left this layer holding an ID the peer counted as gone -- so the peer's
  replacement was refused with CONNECTION_ID_LIMIT_ERROR, a healthy connection closed by our own bookkeeping.
  The pair test and the `a-retired-connection-id-is-replaced` scenario both drive it.
- **The CRYPTO stream** (Phase 4, ninth part): `quic/crypto_stream.h` is the handshake bytes, which
  arrive by offset rather than in order. The receive half is a window with a bitmap of what has
  arrived, delivering only up to the first hole, so a ClientHello split across two packets reads
  correctly; the send half keeps what was sent, because a packet can be declared lost after a later one
  was acknowledged and its bytes are the peer's only copy. Both are bounded and a frame that does not
  fit is refused whole, which is what lets the connection answer with the transport error code
  RFC 9000 gives this case.
- **The TLS 1.3 handshake over CRYPTO** (Phase 4, tenth part): `quic/handshake.h` joins the TLS machine to
  the packet layer -- reassembling each level's CRYPTO stream, walking it into whole handshake messages,
  feeding them to TLS in order, installing the keys each step makes available, and sending a lost flight
  again from the bytes it kept. `tests/unit/test_quic_handshake.c` runs a whole handshake between two
  connections over real loopback sockets on IPv4 and IPv6, with a real certificate and trust check, then a
  1-RTT frame -- the phase's completion criterion in one test.
- **The peer's limits** (Phase 4, eleventh part): the connection parses the transport parameters the
  handshake carried into `wt_quic_peer_limits_t` -- the flow control limits at both levels, the stream
  counts, the connection ID limit, the datagram size -- with RFC 9000 section 18.2's own defaults, where
  an absent parameter and a zero one are different facts. The effective idle timeout becomes the smaller
  of the two ends', because RFC 9000 section 10.1 makes it the minimum. This is the other half of every
  resource limit the stream and datagram work will enforce.
- **QUIC DATAGRAM over the connection** (Phase 4, twelfth part): `wt_quic_connection_send_datagram`
  sends an RFC 9221 frame bounded by both the peer's `max_datagram_frame_size` and what the path carries,
  with no retransmission descriptor -- that is what makes it unreliable -- and the receive half is a
  bounded queue whose newest datagram is discarded when it is full. The receive path is a function a
  composed frame handler calls, which is the layering the handshake, the stream layer and the session
  layer all use.
- **The key lifecycle** (Phase 4, thirteenth part): `wt_quic_connection_discard_keys` zeroes a space's
  keys and marks it gone, and the connection calls it where RFC 9001 section 4.9 says to -- the Initial
  keys when the first Handshake packet is processed, the Handshake keys when the handshake is confirmed.
  Both are a MUST, not a tidy-up: the Initial keys come from a connection ID either end can see, so
  keeping them leaves the connection readable to anyone who saw its first packet.
- **The STREAM send path** (Phase 4, fourteenth part): `wt_quic_connection_send_stream` encodes and sends
  an RFC 9000 section 19.8 frame with the stream number checked against the peer's grant -- and a stream
  number is four fields in one, so whether a limit applies depends on who opened the stream. It is
  deliberately not the stream layer: nothing remembers the bytes, so nothing retransmits them, which is
  what the stream layer adds.
- **The connection-level limit this endpoint grants** (Phase 4, fifteenth part):
  `wt_quic_connection_send_max_data` sends an RFC 9000 section 19.9 MAX_DATA frame and the connection
  seeds and reads the value -- the other direction from the peer limits, and one that may only ever rise,
  because section 4.1 makes a limit that decreases a protocol error.
- **The stream counts this endpoint grants** (Phase 4, sixteenth part):
  `wt_quic_connection_send_max_streams` sends an RFC 9000 section 19.11 MAX_STREAMS frame, with the same
  only-ever-rising rule as MAX_DATA and a count per direction, since a bidirectional stream costs the peer
  one of its own and a unidirectional one only ours.
- **The peer's limits are acted on** (Phase 4, seventeenth part): a received MAX_DATA or MAX_STREAMS is
  applied by the connection itself -- what the peer grants is what this endpoint may send -- and a limit
  that falls is the PROTOCOL_VIOLATION RFC 9000 sections 4.1 and 4.6 make it, with the frame type named.
- **A closed connection stops processing frames** (Phase 4, eighteenth part): RFC 9000 section 10.2.1
  allows only PADDING, the close's own frames and the probes once a connection is closed, and the frame
  walk now enforces it -- through `wt_quic_close_accepts_frame_type`, so the rule is stated once, in the
  module that owns it.
- **HANDSHAKE_DONE only reaches a client** (Phase 4, nineteenth part): RFC 9000 section 19.20 makes a
  server that receives one refuse the connection with a PROTOCOL_VIOLATION, which the connection now does
  while a client still has the frame handed on to the handshake layer.
- **Frames are refused in the wrong packet type** (Phase 4, twentieth part): RFC 9000 section 12.4 makes a
  frame that may not appear where it arrived a PROTOCOL_VIOLATION, and the connection now enforces section
  12.5's table -- including that a CRYPTO frame at the application level is refused, which is what stops a
  peer injecting handshake data into a finished connection.
- **The four fields in a stream number** (Phase 4, twenty-first part): `quic/stream.h` reads and writes
  RFC 9000 section 2.1's initiator bit, directionality bit and index in one place, and the connection's
  stream-number check uses them instead of shifting at the call site. The first piece of the stream layer.
- **The stream table** (Phase 4, twenty-second part): `quic/stream.h` holds a bounded table of stream state
  machines -- the resource limit the plan names -- with per-class counts, a full table refusing a new
  stream rather than dropping a live one, and a stream forgotten only when both halves are done
  (RFC 9000 section 3.3). The limit is the opener's, so a peer's stream costs the peer's allowance.
- **Opening a stream** (Phase 4, twenty-third part): the connection owns a stream table and
  `wt_quic_connection_open_stream` derives the number from the table's counts, bounds it by the peer's
  `initial_max_streams_*`, and starts the stream with the two directions' flow control limits -- this
  endpoint's own for receiving, the peer's for sending.
- **A stream is created by its first frame** (Phase 4, twenty-fourth part): a received frame for a
  peer-initiated stream this endpoint has never seen opens it (RFC 9000 section 3.2), bounded by the count
  it granted -- beyond which is STREAM_LIMIT_ERROR, and a frame for an unopened number of its own is
  STREAM_STATE_ERROR. MAX_STREAM_DATA raises one stream's send allowance.
- **RESET_STREAM and STOP_SENDING reach their state machines** (Phase 4, twenty-fifth part): the two
  frames that change a stream's lifecycle rather than carrying data are applied by the connection as they
  arrive, before the caller's handler sees them, with FINAL_SIZE_ERROR and STREAM_STATE_ERROR for the
  states RFC 9000 sections 4.5 and 19.5 make errors.
- **Received stream data is accounted against both limits** (Phase 4, twenty-sixth part): the connection
  keeps the connection-level flow control and charges every STREAM frame's data against it and the
  stream's, with the RFC's code chosen by asking each limit in turn -- because the stream module reports a
  per-stream overrun and a final-size contradiction with the same status.
- **The receive limits are raised as data arrives** (Phase 4, twenty-seventh part): when the connection's
  received total reaches the limit it granted it sends MAX_DATA for the next window and moves the limit,
  and the same for a stream's MAX_STREAM_DATA -- RFC 9000 section 4.1's rule, applied where arrival is
  consumption because this runtime hands each frame's bytes to the caller immediately.
- **A sender can cancel a stream** (Phase 4, twenty-eighth part): `wt_quic_connection_reset_stream` sends
  RESET_STREAM (RFC 9000 section 19.4) with the final size computed from what was sent, moves the send half
  to Reset Sent, and refuses a stream that is not this endpoint's to send on or one already finished --
  with the receive side already handling an arriving reset, both directions of the cancellation path exist.
- **A lost stream packet names what to send again** (Phase 4, twenty-ninth part): a STREAM send carries a
  retransmission descriptor -- the stream, the offset and the length -- which the connection hands to the
  owner when loss detection declares its packet lost, so the layer that keeps the bytes can send them
  again. The same shape the CRYPTO stream uses, with the stream id added to `wt_quic_tx_frame_t`.
- **STOP_SENDING, the other half of cancellation** (Phase 4, thirtieth part): the receiver of a stream's
  data asks the peer to stop, once and only on a stream it receives on -- so with RESET_STREAM the
  cancellation path exists in both roles, and a frame that could not be sent leaves the stream unchanged
  for a caller that retries.
- **The Retry integrity tag** (Phase 4, thirty-first part): RFC 9001 section 5.8's AES-128-GCM tag over
  `ODCID Length || ODCID || Retry packet`, with the version's own key and nonce, so a client can tell a
  Retry the server sent from an injected one before any handshake. Its value is not asserted yet -- RFC
  9001 A.4's Retry packet still has to be extracted, and vectors here are extracted, never transcribed.
- **Issuing connection IDs** (Phase 4, thirty-second part): `wt_quic_connection_issue_connection_id` sends
  NEW_CONNECTION_ID (RFC 9000 section 19.15) and keeps what it issued, bounded by both its own table and
  the peer's `active_connection_id_limit` less the handshake's ID (section 5.1.1), with the stateless reset
  token taken from the caller because section 10.3 requires it to be unguessable.
- **The peer's connection IDs are stored** (Phase 4, thirty-third part): a received NEW_CONNECTION_ID is
  kept with its reset token, with RFC 9000's FRAME_ENCODING_ERROR for a bad length or a `retire_prior_to`
  above the sequence, PROTOCOL_VIOLATION for a sequence whose connection ID or token changes, and
  CONNECTION_ID_LIMIT_ERROR beyond what this endpoint advertised it would store (section 5.1.1).
- **A short packet is padded until it can be sampled** (Phase 4, thirty-fourth part): RFC 9001 section
  5.4.2 samples header protection from four bytes past the packet number, so a packet too short to hold
  sixteen bytes from there cannot be protected at all -- which made a two-byte frame such as
  RETIRE_CONNECTION_ID or PING impossible to send, and the builder refused it with a truncation error. It
  now fills the plaintext with PADDING frames (RFC 9000 section 19.1), which carry nothing and are ignored
  by every receiver. The header's length cancels out of the requirement, so the shortfall is at most three
  bytes and no caller has to know the rule.
- **RETIRE_CONNECTION_ID retires an issued ID** (Phase 4, thirty-fifth part): the frame gives the ID back,
  freeing both the table slot and the peer's `active_connection_id_limit` budget, with PROTOCOL_VIOLATION
  for a sequence that was never issued and for the sequence the carrying packet was addressed to
  (section 19.16) -- which this endpoint numbers 0, because it receives only on the ID the handshake used
  (section 5.1.1). A repeat of a retirement already made is tolerated, since the frame is retransmitted
  when it is lost, and issued sequences now start at 1 instead of colliding with the handshake's own.
- **A client's Initial datagram is expanded to the minimum** (Phase 4, thirty-sixth part): RFC 9000
  section 14.1 requires every UDP datagram carrying an Initial packet to be at least 1200 bytes, because a
  server discards one that is smaller -- an unpadded Initial cannot start a connection against a
  conformant server at all. The client now expands the packet with PADDING frames and the server discards
  a short Initial datagram before reading it. The expansion is applied by rebuilding rather than
  computed ahead of the build, because the long header's Length varint widens with the value it carries;
  a pass that lands a byte over trims padding instead of putting a datagram above the path's limit.
- **The Retry integrity tag is checked against the RFC** (Phase 4, thirty-seventh part): RFC 9001
  appendix A.4's Retry packet and the tag it prints are extracted by
  `tests/vectors/extract_rfc9001_retry.py`, which refuses to write a block that does not parse as a
  version-1 Retry whose original destination connection ID agrees with A.2's client Initial packet. The
  tag was computed but never asserted against the document before this -- the test that existed proved it
  was computed consistently, which a wrong constant would also satisfy. Now the RFC's own tag is the
  expectation, and the same packet with one changed byte, or with another original connection ID, is
  refused.
- **A frame the decoder refuses closes the connection** (Phase 4, thirty-eighth part): RFC 9000 section
  12.4 makes an undecodable frame a connection error, and the decoder reports the code -- but the error
  was returned to the caller instead of being sent, so a peer that sent a malformed frame was never told
  and the connection stayed open with the failure visible only to whoever called
  `wt_quic_connection_receive`. A decode failure now closes the connection with the code the frame's own
  rule names, or FRAME_ENCODING_ERROR for a truncated frame. Found by the test WT-83 asked for: a
  hand-written NEW_CONNECTION_ID whose `retire_prior_to` is above its sequence, which the encoder cannot
  produce because this library refuses to encode what it would refuse to decode.
- **Packets addressed to an issued connection ID are accepted** (Phase 4, thirty-ninth part): the receive
  path compared every packet's Destination Connection ID with the handshake's alone, so the IDs this
  endpoint issued with NEW_CONNECTION_ID were write-only -- a peer that used one, which is exactly what
  they are for, had its packets discarded as somebody else's. The handshake's ID and every issued ID that
  has not been retired are now recognised, and which sequence a packet used travels with its frames so
  RFC 9000 section 19.16's "cannot retire the ID the packet was addressed to" is applied to the ID that was
  actually addressed rather than to sequence 0. A packet addressed to a retired ID is discarded, and
  `wt_quic_connection_issue_connection_id` now refuses an ID whose length is not this endpoint's own,
  because a short header carries no length and such an ID could never be received.
- **The HTTP/3 frame codec** (Phase 5, first part): `http3/frame.h` is RFC 9114's varint type, varint
  length and payload, with the registered frame types, the section 8.1 error codes, the stream type
  prefixes of section 6.2.1 and the section 7.2.8 test for the frame types HTTP/2 reserved. It is a codec
  and nothing more -- what a SETTINGS identifier or a GOAWAY identifier means belongs to the stream layer
  -- so a length that does not fit `size_t` or does not fit the bytes present is refused as a frame error,
  a refusal leaves the caller's cursor where it was so the caller can name the frame that failed, and an
  unknown frame type is a frame like any other rather than an error the codec invents.
- **HTTP/3 SETTINGS** (Phase 5, second part): `http3/settings.h` parses and encodes the identifier/value
  pairs of RFC 9114 section 7.2.4 into a fixed table, so duplicate detection covers the settings this build
  does not understand as well as the ones it does. A reserved HTTP/2 identifier (`0x02` to `0x05`) and a
  non-boolean `ENABLE_CONNECT_PROTOCOL` are H3_SETTINGS_ERROR, a payload that ends between an identifier and
  its value is one too, more identifiers than the table holds is H3_EXCESSIVE_LOAD, and the exercise
  identifiers of the `0x1f * N + 0x21` range are ignored rather than refused -- refusing them would break
  the one rule they exist to exercise. The encoder writes ascending identifier order, so the same set is
  always the same bytes.
- **The control stream's lifecycle** (Phase 5, third part): `http3/control.h` is RFC 9114 section 6.2.1's
  state machine for the peer's control stream, where all four rules are connection errors -- a first frame
  that is not SETTINGS (H3_MISSING_SETTINGS), a second control stream (H3_STREAM_CREATION_ERROR), the
  stream closing at any point (H3_CLOSED_CRITICAL_STREAM), and a frame the section does not allow there,
  including a second SETTINGS and the types section 7.2.8 reserved for HTTP/2 (H3_FRAME_UNEXPECTED). It
  decides permission only: what a SETTINGS, GOAWAY or MAX_PUSH_ID frame says is parsed by whoever owns it.
- **GOAWAY** (Phase 5, fourth part): `http3/goaway.h` carries RFC 9114 sections 7.2.6 and 5.2 -- the
  identifier is a client-initiated bidirectional stream ID from a server (anything else is H3_ID_ERROR)
  and a push ID from a client, it may not grow between frames (H3_ID_ERROR), requests at or above it are
  rejected, no new request may be started after it arrives, and the graceful-shutdown maximum is `2^62 - 4`
  for a server and `2^62 - 1` for a client. The payload is exactly one varint: a second field or a trailing
  byte is a frame error rather than a frame read partially.
- **Which frame belongs on which stream** (Phase 5, fifth part): `http3/streams.h` is RFC 9114 section
  7.2's table -- DATA and HEADERS on request and push streams, the connection-management frames on the
  control stream, PUSH_PROMISE from a server to a client on a request stream, no HTTP/3 frame at all on a
  QPACK stream (section 4.2), and the section 7.2.8 reserved types refused everywhere. The role decides two
  of the rules, so the receiver's role is a parameter: MAX_PUSH_ID is a client's frame (section 7.2.7) and
  PUSH_PROMISE a server's (section 7.2.5), and receiving one's own frame is H3_FRAME_UNEXPECTED. Unknown
  frame types stay allowed, because HTTP/3 grows by extension frames.
- **The request stream's frame order** (Phase 5, sixth part): `http3/request.h` is RFC 9114 section 4.1's
  shape for the request direction -- one HEADERS frame, optional DATA, one optional trailing HEADERS -- with
  anything else, and anything after the trailer, H3_FRAME_UNEXPECTED. A stream that ends before the
  request's HEADERS is an incomplete request instead: H3_REQUEST_INCOMPLETE, which section 4.1 defines as
  the code a server aborts its own RESPONSE stream with, so it is reported as a stream error rather than a
  connection error. The response direction is deliberately not here: whether a HEADERS frame is an
  informational 1xx response is only known from the decoded `:status`, so that machine lands with QPACK.
- **QPACK's static table** (Phase 6, first part): `http3/qpack.h` exposes RFC 9204 appendix A's 99
  name/value pairs with the exact-pair and by-name lookups a field line needs, and the section 8 error
  codes. The table is generated from the RFC by `tests/vectors/extract_rfc9204_static_table.py` and checked
  by `check-vectors.sh`, because an encoder and a decoder that disagree on one entry produce two different
  header sections with nothing in the exchange to say so.
- **Prefixed integers and strings** (Phase 6, second part): QPACK's two primitives (RFC 9204 section 4.1)
  -- an integer behind an N-bit prefix, and a string whose length is one behind a seven-bit prefix with the
  H bit above it. The section's 62-bit bound is enforced, a continuation that runs past it or never ends is
  refused, and a string's Huffman flag is RETURNED rather than ignored: this build does not decode Huffman
  yet, and a caller that treated coded bytes as field content would produce a header section the peer
  cannot parse.
- **Huffman decoding** (Phase 6, third part): `qpack_huffman.c` decodes RFC 7541 appendix B's code, which
  RFC 9204 adopts, against a table generated from the RFC by `tests/vectors/extract_rfc7541_huffman.py` --
  the script checks the code is symbol-ordered, prefix-free and canonical (and derives the decode index from
  that) and extracts C.4.1's worked example as the one vector the decoder is checked against. EOS in a
  string, padding that is not all ones or is longer than seven bits, and a decoded size larger than the
  caller's buffer are all refused, because accepting a string the peer could not have encoded is how two
  implementations come to disagree silently.
- **Huffman encoding** (Phase 6, fourth part): the encoder side of the same table, with the section 5.2
  padding rule (one-bits, the EOS prefix) and a size helper so a caller can bound its buffer without
  guessing. It is checked against the RFC's own appendix C.4.1 bytes rather than only against a round trip
  through this implementation -- an encoder and decoder that share a wrong table round-trip happily -- and
  then over all 256 symbols, which is what says the bit packing survives both the five-bit codes and the
  thirty-bit ones.
- **The field line representations** (Phase 6, fifth part): `qpack_field.c` reads and writes all seven of
  RFC 9204 section 4.5's forms, and the TYPE says which table a line needs -- static, dynamic or post-base
  -- so a decoder cannot resolve a dynamic index against the static table by accident, which is the mistake
  that silently produces a different header section. The static forms resolve to a name; the dynamic and
  post-base ones report that they need the dynamic table, which is the next part's work.
- **The dynamic table** (Phase 6, sixth part): `qpack_dynamic.c` is RFC 9204 section 3.2's FIFO with the
  section's size rule (name and value plus 32), eviction from the oldest end, and absolute indices that never
  change meaning, so a reference to an evicted entry is reported as such rather than resolved to whatever now
  occupies its place. It is bounded like every other peer-driven table here: 32 entries, a 4 KiB arena, and an
  entry larger than the capacity refused rather than truncated.
- **The encoder stream instructions** (Phase 5/6, seventh part): `qpack_encoder_stream.c` applies RFC 9204
  section 4.3's four instructions -- the capacity, a name from a table, a name written out, a duplication --
  to the dynamic table, and writes them from this implementation's own encoder. Both errors only visible at
  this layer are enforced: a capacity above what SETTINGS granted this peer, and an index naming an entry the
  table has already evicted, are QPACK_ENCODER_STREAM_ERROR rather than a clamp or a guess.
- **The decoder stream instructions** (Phase 6, eighth part): `qpack_decoder_stream.c` applies RFC 9204
  section 4.4's three instructions -- section acknowledgement, stream cancellation, insert count increment --
  and writes them, with the section's own errors: a zero increment and one that would pass the number of
  insertions are QPACK_DECODER_STREAM_ERROR. An instruction whose bytes have not all arrived is treated as
  INCOMPLETE rather than malformed, in both stream modules: QPACK delivers instructions in pieces, so the
  caller waits for more, and only a malformed instruction is the peer's error.
- **The field section prefix** (Phase 6, ninth part): `qpack_header_prefix.c` is RFC 9204 section 4.5.1's
  Required Insert Count and Base -- the count is sent modulo twice the table's size in entries so it stays
  inside the window the decoder knows, the Base is a signed delta from it, and both of the section's error
  exits are enforced. `wt_qpack_max_entries` derives the window from the capacity, which is why the prefix
  cannot be read without knowing what this endpoint advertised.
- **The field section decoder** (Phase 6, tenth part): `qpack_field_section.c` resolves one line at a time
  against the static table, the dynamic table and the section's prefix -- the index arithmetic is where
  QPACK's dynamic references live, `Base - Index - 1` for a dynamic reference and `Base + Index` for a
  post-base one -- and decodes an inline Huffman name or value into the caller's scratch, because a resolved
  field has to be plain bytes. A reference the table cannot resolve is QPACK_DECOMPRESSION_FAILED; a scratch
  buffer too small is the caller's limit, not the peer's error, and the two are reported apart.
- **Huffman strings on the way out** (Phase 6, eleventh part): `wt_qpack_string_encode_coded` writes a string
  with the H bit set, coding it into the caller's scratch (the coded length has to be known before the
  length byte that precedes it), and `wt_qpack_field_line_encode_coded` does the same for a line's name and
  value. The plain `wt_qpack_field_line_encode` now REFUSES a line whose flags ask for coding rather than
  writing it plainly: the flags are part of the representation, so a plain string with the H bit clear is a
  different line.
- **Whole field sections** (Phase 6, twelfth part): `qpack_field_section_codec.c` writes a section -- prefix,
  then lines -- and reads one back, with the section's BLOCKED case kept apart from a decompression failure:
  RFC 9204 section 2.1.2 lets a decoder wait for the encoder stream when a section needs insertions that have
  not arrived, so that is `WT_ERR_AGAIN` with no error code rather than a connection error over an
  instruction still in flight.
- **The encoder's eviction bookkeeping** (Phase 6, thirteenth part): `qpack_encoder_state.c` remembers what
  each outstanding section was written with, because RFC 9204 section 2.1.1 forbids evicting an entry an
  unacknowledged section might reference -- `wt_qpack_encoder_state_evictable_below` is the SMALLEST required
  insert count among them, and a section that references nothing holds nothing back. Section
  acknowledgements, stream cancellations and the decoder's insert count increments are what move it.
- **HTTP/3 message header rules** (Phase 5, seventh part): `http3/headers.h` validates a decoded field section
  as a request or a response -- pseudo-headers first and at most once, only the ones the message type defines,
  :method/:scheme/:path required except for CONNECT (which requires :authority), lowercase names, the
  connection-specific fields forbidden and `te` only for `trailers`. Every breach is H3_MESSAGE_ERROR, and the
  validator consumes fields one at a time because the rules are about ORDER.
- **HTTP/3 messages** (Phase 5, eighth part): `http3/message.h` is the join between the two phases -- a
  QPACK field section in, a validated request or response out, with the method, scheme, path, authority and
  status kept where a caller can read them instead of walking the fields again. It adds the two rules that
  live at this layer: a `:status` must be three digits in 100..599, and the values that must be present must
  also be non-empty. A blocked section is WT_ERR_AGAIN, and QPACK's own failure codes travel through
  unchanged -- they are HTTP/3 application errors, so they belong in the same place.
- **The WebTransport session request** (Phase 7, first part): `webtransport/session_request.h` decides what a
  decoded request is -- an ordinary request, an extended CONNECT for another protocol, or a WebTransport
  session request this server accepts or refuses with a status. It is a DECISION rather than an error, because
  "not mine" and "mine, but refused" are ordinary answers. Two rules are easy to get backwards and are tested
  both ways: the CONNECT exception does NOT excuse a WebTransport request from carrying :scheme and :path
  (it applies to the plain CONNECT), and a server that never advertised `WT_ENABLED` refuses rather than
  serving a session the client could not have known about. `:protocol` is now a recognised request
  pseudo-header in the HTTP/3 layer, which is what makes any of this reachable.
- **WebTransport capsules** (Phase 7, second part): `webtransport/capsule.h` reads and writes the CONNECT
  stream's control messages -- a varint type, a varint length and that many bytes -- with the draft's capsule
  types, `DRAIN_WEBTRANSPORT_SESSION` (no value) and `CLOSE_WEBTRANSPORT_SESSION` (a four-byte code and a
  reason no longer than 1024 bytes). An incomplete capsule is `WT_ERR_TRUNCATED` rather than malformed, an
  unknown type is handed on rather than refused, and a value longer than the caller will buffer is
  `H3_EXCESSIVE_LOAD` -- the same three rules the QPACK instruction parsers and the frame codec follow.
- **The session lifecycle** (Phase 7, third part): `webtransport/session.h` is the draft's three rules about
  what a session may DO -- after a drain in either direction no new stream may start (existing ones may
  finish), after a close nothing at all, and the FIRST close's code is the one the session reports however
  many more arrive. A stream that simply ends has no application code, which the state records separately
  from a close whose code happens to be zero.
- **The session's flow control** (Phase 7, fourth part): the draft's flow-control capsules -- MAX_DATA,
  MAX_STREAM_DATA, MAX_STREAMS in both directions, and the blocked signals -- each carrying one or two
  varints, with a value that is not exactly that being a message error rather than a bigger number. The
  connection-level limits may only grow: a limit below one already granted would invalidate data sent against
  the old one, so it is `WT_FLOW_CONTROL_ERROR` rather than a new limit.
- **Stream and datagram framing** (Phase 7, fifth part): `webtransport/framing.h` is the draft's stream prefix
  (type 0x41 or 0x54, then the session ID) and its datagram frame (a quarter stream ID, then the data), with
  the identifier SHAPE checked: a session ID must be the CONNECT stream's -- client-initiated and
  bidirectional -- and a prefix naming anything else describes a session that cannot exist. An incomplete
  prefix is `WT_ERR_TRUNCATED`; a datagram without its quarter ID is malformed, because a datagram is the
  unit.
- **The umbrella header** (Phase 8, first part): `include/webtransport/webtransport.h` is the one header a
  consumer includes, and it states the three rules that hold across every layer -- nothing is allocated for a
  peer, incomplete is not malformed on a stream (a datagram is the exception), and a refusal keeps the peer's
  code. A test including ONLY that header uses a piece of every layer, so a module missing from it, or a header
  that does not include what it uses, fails here rather than in a consumer's build.
- The vectors are RFC 9001 appendix A and RFC 8448 section 3, extracted from the RFC
  text rather than
  transcribed: `tests/vectors/extract_rfc9001_keys.py` re-derives every value it
  writes -- the Initial secret from the version-1 salt and the connection ID, each
  key from its traffic secret, each header protection sample as the packet's bytes
  at `pn_offset + 4`, each mask by turning the printed unprotected header into the
  printed protected one, and the short header's nonce from the IV and the packet
  number -- and refuses to write one that does not check. The tests then take each
  protected packet apart and put it back together, so a mistake that was symmetric
  between the two directions fails the second one.
- The TLS vectors are RFC 8448's own key schedule trace, including the handshake
  messages it prints: `tests/vectors/extract_rfc8448_keyschedule.py` recomputes every
  secret, key and Finished value from the RFC's inputs, checks the schedule as a
  chain, and checks the trace's three transcript hashes against the messages it
  extracted -- so a message read from the wrong place in a 3,800-line document fails
  generation rather than becoming a vector a wrong implementation would pass.
- A package consumer test: the library is installed and a separate CMake project
  links it, which is the only way to know the install tree works. It found that the
  installed config did not declare its OpenSSL dependency, which no build inside
  this tree could have noticed.

What is not here: TLS, HTTP/3, QPACK and WebTransport, the QUIC connection
runtime, the CLI tools' actual behavior, external interoperability evidence, and
the platform runtimes. The wire core parses and builds QUIC messages and the crypto
layer protects them; nothing yet decides what to send.

## Building

```sh
C99/scripts/build-and-test.sh              # Debug, build and test
C99/scripts/build-and-test.sh --release    # Release
C99/scripts/build-and-test.sh --sanitize   # Debug with ASan and UBSan
C99/scripts/build-and-test.sh --all        # all three
C99/scripts/check-package.sh               # install and build a consumer
C99/scripts/check-vectors.sh               # re-extract the RFC vectors and compare
```

Output goes under `C99/out/<platform>/`, which is gitignored; see
[out/README.md](out/README.md). The packaging entry points under
[platform/](platform/) are wrappers around the same CMake project.

## Layout

```text
include/webtransport/   public headers, installed
src/core/               the Phase 0 utilities
src/crypto/             the OpenSSL-backed crypto provider
src/quic/               the QUIC wire core and packet protection
src/tls/                the TLS 1.3 key schedule and transcript
tests/vectors/          generated RFC vectors and the scripts that extract them
apps/                   wt-client-c99, wt-server-c99, wt-conformance-c99
tests/unit/             one file per module, registered with CTest
tests/package/          a consumer of the installed package
scripts/                the development loop
platform/               per-OS packaging entry points
```

The remaining protocol phases add `src/tls`, `src/http3` and `src/runtime` beside
`src/core`, `src/crypto` and `src/quic`, and their headers under the matching
`include/webtransport/` directories, which already exist.
