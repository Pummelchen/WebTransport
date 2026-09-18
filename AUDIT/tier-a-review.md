# AUDIT — the Tier A deep review

`inventory.md` §2.4 puts most of this repository in Tier A, because untrusted parsing and native
memory *are* the product rather than a corner of it. `passes.md` claimed that tier was "read
manually and in full"; measuring the claim against the evidence showed it was written too early —
Tier A is 274 files and roughly 63,000 lines, and most of what the audit touched was the
mechanical `clang-format` reformat, which is not a reading. This file is the review being done
properly, module by module, and it is the record the tier's coverage claim rests on.

**It is not finished.** A module is listed as read only when its files have actually been read in
this review, and the entry says what was looked for.

## Method

One module at a time, files read in full, with the questions that apply to the tier:

- **Untrusted input**: every length, count and index that comes off the wire is checked before
  use; a narrowing conversion is checked rather than cast; a loop bound is bounded by the
  structure rather than by the input.
- **Native memory**: allocation, ownership and lifetime are stated at the boundary; a zero-length
  write or read is safe with a null pointer; no buffer arithmetic can wrap.
- **State machines**: every transition a peer can drive is either handled or refused explicitly;
  an error path returns a status rather than a default value.
- **The RFC rule the code cites**: where a comment names a section, the code is checked against
  the rule rather than the comment being trusted.

Findings become ledger tasks like any other. A module with no findings is recorded as read with
the checks that were applied, because "no findings" is only meaningful next to what was examined.

## Progress

| Tier A module | State |
| --- | --- |
| `C99/src/quic/transport_parameters.c` | **Read in full** (485 lines) — `AUD-0021` |
| `C99/src/quic/{frame,connection_receive,packet,connection_send,stream}.c` | Read in the structural refactors (frame dispatch, packet-range merge, STREAM receive) |
| `C99/src/http3/qpack_encoder_stream.c` | Read around the finding — `AUD-0021`; not yet in full |
| Everything else under `C99/src`, `C99/apps`, `C99/include` | **Not yet read in this review** |
| `Swift/Sources/**` (77 files) | **Not yet read in this review** |

## `C99/src/quic/transport_parameters.c` — read in full

Read in three sittings, whole file, against the four questions above.

**Untrusted input.** Decode walks the extension with a cursor; each value length is narrowed with
`wt_checked_narrow_u64_to_size` *before* it is compared against the remaining bytes, so a 64-bit
length on a 32-bit `size_t` cannot wrap into a passing comparison. Minimal encoding of the length
is enforced (`wt_quic_varint_is_minimal`), duplicates are refused after the walk with a bound of
32² comparisons and no peer-controlled loop, and the entry count is bounded before each insert.
The integer accessor refuses trailing bytes, which is the framing rule the RFC states and the
easy thing to leave out.

**Value rules.** `wt_quic_transport_parameters_check` enforces the section 18.2 limits with the
boundary cases on the right side — `max_streams` above 2^60 is refused and 2^60 itself is legal;
`active_connection_id_limit` below 2 is refused; `max_udp_payload_size` below 1200 is refused.
The role-dependent rules are present and not merely the length ones: a `stateless_reset_token`
from a client is refused because it is a server-only parameter, which a length check cannot
express, and `reset_stream_at` must be empty because it is a flag.

**Native memory.** `add_integer` encodes into the structure's own storage so a caller need not
keep a buffer alive per integer, and it consumes a slot only when the insert succeeded, so a
refused duplicate does not leak capacity. `build` stores the flag parameter with a null value and
zero length; that reaches `wt_writer_put`, which guards `len != 0U` before `memcpy` and says why
in a comment — checked rather than assumed, because `memcpy(NULL, 0)` is undefined even though it
is harmless on every implementation that matters.

**Found:** `AUD-0021` — `start` and `start_offset` were declared, computed and never read, with
`(void)` casts suppressing the warning; the same pattern in two other files. Fixed, and now
checked by `C99/scripts/check-unused-locals.py`.
