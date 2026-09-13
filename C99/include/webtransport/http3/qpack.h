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

#include "webtransport/status.h"

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

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_QPACK_H */
