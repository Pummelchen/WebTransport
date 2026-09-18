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
| `C99/src/quic/frame.c` | **Read in full** (726 lines) — `AUD-0022` |
| `C99/src/quic/packet.c` | **Read in full** (680 lines) — `AUD-0023` |
| `C99/src/quic/{connection_receive,connection_send,stream}.c` | Read in the structural refactors (packet-range merge, STREAM receive); not yet in full |
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

## `C99/src/quic/frame.c` — read in full

726 lines, the whole file, against the same four questions.

**Untrusted input.** Every length that comes off the wire goes through `wt_quic_take`, which
narrows the 64-bit value with `wt_checked_narrow_u64_to_size` *before* comparing it against the
cursor, so a 2^40 length is `WT_ERR_TRUNCATED` and not a walk off the end. Minimal encoding of
the frame type is enforced against the encoding's own size, and an unknown type is a
`FRAME_ENCODING_ERROR` rather than a guess at its length.

The ACK range walk is the subtlest thing in the file and it is correct: `consumed` accumulates
each probe's offset and cannot exceed `available`, because a probe's offset is bounded by its own
length, so `available - consumed` cannot underflow; and because every iteration consumes at
least two bytes, a peer-supplied `range_count` of 2^62 terminates through the truncation path
rather than by looping. The RFC boundaries are on the right side throughout — 2^60 is legal and
2^60+1 is not, `retire_prior_to > sequence` is refused, a connection ID of 0 or 21 bytes is
refused, and `reliable_size > final_size` is refused on both the decode and the encode side.

**Native memory.** `wt_quic_frame_make` and the decoder both memset the whole structure, and the
comment records why: the first version cleared one byte, and a mostly-uninitialised union copied
differently at `-O2` than at `-O0`, which failed only in Release. That is a memory-safety bug
that was found and is now documented where the next person will read it.

**Found:** `AUD-0022` — `new_token.token_length`, assigned from unvalidated input before the take
was known to have succeeded, and read by nothing in the tree. Fixed without an ABI change, with a
regression test that was checked to fail against the unfixed code.

## `C99/src/quic/packet.c` — read in full

680 lines: classification, the two peeks, both header decoders, the Retry parser and the three
encoders.

**Three functions walk the same long header, and two of them skipped the version unread.** That
asymmetry is `AUD-0023`. It is worth recording how each one is answered now, because the class is
only closed if all three are pinned, which they are in `test_quic_packet.c`:

| Walker | Version zero | Why |
| --- | --- | --- |
| `wt_quic_packet_kind` | reports `VERSION_NEGOTIATION` | it is the classifier; the caller wants to know |
| `wt_quic_protected_pn_offset` | refuses (`WT_ERR_INVALID_ARGUMENT`) | the walk would read the version list as a Length field -- the guard existed, with a comment, and had **no test** until this review added one |
| `wt_quic_initial_token` | refuses (`WT_ERR_PROTOCOL`) | the fix: it reports no version, so the caller cannot decide for itself |
| `wt_quic_long_header_connection_ids` | accepts, deliberately | RFC 9000 section 17.2.1 puts a VN's connection IDs at the same offsets, and this function reports no version -- the decision belongs to the token reader above it |
| `wt_quic_long_header_decode` | reports the version in its output | the caller can decide, and on this path it does not have to: the payload is AEAD-verified next, so a VN packet fails authentication and is discarded |

Each answer is now asserted, and the two that refuse were each proved by deliberate violation:
removing the `initial_token` guard fails with `FAIL a version negotiation is not an Initial: want
protocol, got ok`, and removing the older `protected_pn_offset` guard fails with `FAIL and the
packet-number walk refuses it: want invalid-argument, got truncated`. A guard with no test is a
guard nobody knows is still there.

**The Swift mirror has no equivalent path**, checked rather than assumed: `wt_quic_initial_token`
exists because a C99 listener may hold only the front of a 1200-byte Initial, and the Swift
decoder has no such peek -- `VersionNegotiation` appears once in `Swift/Sources`, as the list of
versions this endpoint supports, not as a parse of an incoming VN packet. The finding is
C99-specific.

The rest of the file is careful in the ways the tier asks for. The Retry parser refuses a zero or
over-long connection ID, and its comment records the memory-safety defect an earlier audit found
here -- `length - header_len - 16` underflowing for a datagram whose header ran into the tag, so
the token view pointed past the buffer while the function returned `WT_OK` (WT-203). The encoders
refuse a non-zero length with a null pointer rather than letting `wt_writer_bytes` dereference it
(WT-239), the Length field is computed rather than taken from the caller, and the Retry encoder
writes zero into the `Unused (4)` field while the decoder must ignore whatever it finds there,
because RFC 9001's own A.4 example writes `0xf` (WT-227).
