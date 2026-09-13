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

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_QPACK_H */
