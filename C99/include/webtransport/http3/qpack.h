/* QPACK's static table and error codes (RFC 9204 sections 3.1, 4.5 and 8).
 *
 * The static table is 99 name/value pairs that every implementation must agree on
 * byte for byte: an encoder that indexes entry 17 as one field and a decoder that
 * reads it as another produce two different header sections, and nothing in the
 * exchange would say so. The table is therefore generated from RFC 9204 appendix
 * A by `tests/vectors/extract_rfc9204_static_table.py` and checked by
 * `check-vectors.sh`, not typed into C.
 *
 * This part is the table and its lookups. The prefixed-integer and prefixed-string
 * codecs, the dynamic table and the field-line representations build on it and
 * come next, which is why nothing here encodes or decodes a header section yet.
 */

#ifndef WEBTRANSPORT_HTTP3_QPACK_H
#define WEBTRANSPORT_HTTP3_QPACK_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The number of entries, which RFC 9204 section 3.1 fixes at 99. */
#define WT_QPACK_STATIC_TABLE_SIZE 99U

/* The error codes of RFC 9204 section 8, which travel as HTTP/3 application
 * errors. DECOMPRESSION_FAILED is a connection error; the two stream errors are
 * fatal to their stream only. */
#define WT_QPACK_DECOMPRESSION_FAILED ((uint64_t)0x0200)
#define WT_QPACK_ENCODER_STREAM_ERROR ((uint64_t)0x0201)
#define WT_QPACK_DECODER_STREAM_ERROR ((uint64_t)0x0202)

/* One static entry, as a view into the generated table: neither string is
 * terminated data the caller owns, and the value may be empty (many entries are
 * name-only). */
typedef struct wt_qpack_static_entry {
  const char *name;
  size_t name_length;
  const char *value;
  size_t value_length;
} wt_qpack_static_entry_t;

/* The entry at this index. An index outside 0..98 is WT_ERR_LIMIT: it is a peer's
 * or a caller's arithmetic that went wrong, not a malformed frame. */
wt_status_t wt_qpack_static_entry(uint64_t index, wt_qpack_static_entry_t *out);

/* The first entry with this name and exactly this value, for an indexed field
 * line. WT_ERR_CLOSED when the table has no such entry -- the pair is not there,
 * which is an ordinary answer for a header a table does not carry. */
wt_status_t wt_qpack_static_find(const char *name, size_t name_length, const char *value,
                                 size_t value_length, uint64_t *out_index);

/* The first entry with this name, whatever its value, for a literal field line
 * with a name reference. WT_ERR_CLOSED when the name is not in the table. */
wt_status_t wt_qpack_static_find_name(const char *name, size_t name_length, uint64_t *out_index);

/* ------------------------------------------------ RFC 9204 section 4.1's primitives */

/* An integer with an N-bit prefix, as every QPACK field line and the dynamic
 * table use: the first byte carries as much of the value as fits in the prefix,
 * and a prefix full of ones means "keep reading seven bits at a time".
 *
 * `prefix_bits` is 1..8. Values are limited to 62 bits (section 4.1.1); a peer's
 * integer that exceeds that, or one whose continuation never ends, is
 * QPACK_DECOMPRESSION_FAILED, which is what section 8 makes of a malformed
 * representation. */
wt_status_t wt_qpack_integer_decode(wt_cursor_t *c, unsigned prefix_bits, uint64_t *out_value);

/* The same integer, on the wire. `prefix_flags` are the bits above the prefix --
 * the field line's own pattern, already shifted into place -- and only those bits
 * are written, so a caller cannot accidentally encode part of the value there.
 * Refuses a value whose low `prefix_bits` would collide with the flags. */
wt_status_t wt_qpack_integer_encode(wt_writer_t *w, unsigned prefix_bits, uint8_t prefix_flags,
                                    uint64_t value);

/* A string: a length as an integer with a seven-bit prefix, then that many bytes
 * (section 4.1.2). The length field's top bit is the H bit, so the bytes may be
 * Huffman-coded; this returns the bytes as they are on the wire and says which,
 * because decoding them is the Huffman part's job and a caller that ignored the
 * flag would read coded bytes as field content. */
wt_status_t wt_qpack_string_decode(wt_cursor_t *c, const uint8_t **out_bytes, size_t *out_length,
                                   int *out_huffman);

/* Write a string that is not Huffman-coded. The Huffman encoder is a later part,
 * so this is what every representation written by this build looks like. */
wt_status_t wt_qpack_string_encode(wt_writer_t *w, const uint8_t *bytes, size_t length);

/* Decode a Huffman-coded string (RFC 7541 appendix B, which RFC 9204 section
 * 4.1.2 adopts). The code comes from the RFC table generated into the source tree.
 *
 * Refuses the EOS symbol -- a string that carries it is malformed, and a decoder
 * that produced anything for it would accept a representation the peer could not
 * have meant -- a padding longer than seven bits or one that is not all ones
 * (section 5.2 makes padding the EOS prefix), and an output larger than the
 * caller's buffer (WT_ERR_LIMIT), because the decoded size is the peer's to choose
 * and the caller's to bound. */
wt_status_t wt_qpack_huffman_decode(const uint8_t *coded, size_t coded_length, uint8_t *out,
                                    size_t capacity, size_t *out_length);

/* The bytes a Huffman encoding of these bytes occupies, so a caller can size the
 * buffer it hands to the encoder without guessing (the code is not a fixed width,
 * and the final byte is padded with one-bits to the boundary). */
wt_status_t wt_qpack_huffman_encoded_size(const uint8_t *bytes, size_t length, size_t *out_size);

/* Encode a string with the same table. Refuses an output buffer that cannot hold
 * the result (WT_ERR_LIMIT) rather than writing part of it: a half-written string
 * is a representation the peer would decode into something else. */
wt_status_t wt_qpack_huffman_encode(const uint8_t *bytes, size_t length, uint8_t *out,
                                    size_t capacity, size_t *out_length);

/* ------------------------------------------- RFC 9204 section 4.5's field lines */

/* The five representations of section 4.5, split by what a decoder needs to resolve
 * them: the two that name a static entry need only the static table, the two that
 * name a dynamic one need the dynamic table, and the two post-base forms need the
 * header block's base. Modelling the difference in the type is what keeps a decoder
 * from resolving a dynamic index against the static table by accident -- the bug
 * that would silently produce a different header section. */
typedef enum wt_qpack_field_kind {
  /* 1 1 index(6+): an entry of the static table. */
  WT_QPACK_FIELD_INDEXED_STATIC = 0,
  /* 1 0 index(6+): an entry of the dynamic table. */
  WT_QPACK_FIELD_INDEXED_DYNAMIC = 1,
  /* 01 N 1 index(4+) then a value string. */
  WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC = 2,
  /* 01 N 0 index(4+) then a value string. */
  WT_QPACK_FIELD_LITERAL_NAME_REF_DYNAMIC = 3,
  /* 001 N H name-length(3+) then the name and the value. */
  WT_QPACK_FIELD_LITERAL_LITERAL_NAME = 4,
  /* 0001 index(4+): a dynamic entry counted from the base. */
  WT_QPACK_FIELD_POST_BASE_INDEX = 5,
  /* 0000 N index(3+) then a value string. */
  WT_QPACK_FIELD_POST_BASE_NAME_REF = 6
} wt_qpack_field_kind_t;

typedef struct wt_qpack_field_line {
  wt_qpack_field_kind_t kind;
  /* The N bit: the field must never be put in a dynamic table. */
  int never_indexed;
  /* The index, whose meaning depends on the kind. */
  uint64_t index;
  /* The inline name, for the literal-literal form only. */
  int name_huffman;
  const uint8_t *name;
  size_t name_length;
  /* The value, which every form except the indexed ones carries. Its H bit is
   * reported rather than acted on, for the reason the string primitive gives. */
  const uint8_t *value;
  size_t value_length;
  int value_huffman;
  /* How many bytes the representation occupies, so a caller can walk a field
   * section without re-deriving it. */
  size_t bytes_consumed;
} wt_qpack_field_line_t;

/* Read one field line. A truncated representation is WT_ERR_TRUNCATED and a
 * malformed one WT_ERR_PROTOCOL; the caller maps both to QPACK_DECOMPRESSION_FAILED
 * (section 8), because a field section that does not parse is not recoverable. */
wt_status_t wt_qpack_field_line_decode(wt_cursor_t *c, wt_qpack_field_line_t *out);

/* Write one. Refuses a kind whose fields are not set, so the encoder cannot emit a
 * representation its own decoder would refuse. */
wt_status_t wt_qpack_field_line_encode(wt_writer_t *w, const wt_qpack_field_line_t *line);

/* The name of a static-referencing line, from the static table or from the line
 * itself. WT_ERR_STATE for the kinds that need the dynamic table or a base. */
wt_status_t wt_qpack_field_line_static_name(const wt_qpack_field_line_t *line, const char **out_name,
                                            size_t *out_length);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_QPACK_H */
