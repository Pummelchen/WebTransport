/* Shared by the two halves of test_http3_endpoint.c after the split.
 * Composed in the order it has to be read: guard, includes, body defines, shared helpers.
 * The defines come before the helpers because the helpers use them, and `static inline`
 * because a file-static helper cannot cross a translation unit. */
#ifndef TEST_HTTP3_ENDPOINT_REQUEST_HEADERS_ARE_DECODED_SUPPORT_H
#define TEST_HTTP3_ENDPOINT_REQUEST_HEADERS_ARE_DECODED_SUPPORT_H

/* The HTTP/3 endpoint's own streams (Phase 9).
 *
 * The tests are the lifecycle rules, which are the ones a consumer never sees and a bug in
 * which looks like a peer misbehaving: our three streams exist once each; a peer's unknown
 * stream type is IGNORED rather than failed (section 6.2.1), while a second control stream,
 * a second QPACK stream and an unrequested push stream each commit the connection to the
 * error the RFC names; the draft's WebTransport stream is classified as the layer above's
 * rather than mistaken for an unknown one; and the peer-stream table is this endpoint's
 * bound, so running into it reports WT_ERR_LIMIT with no error code instead of inventing a
 * peer error. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/http3/endpoint.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

static inline void write_type(uint8_t *out, size_t *length, uint64_t type) {
  wt_writer_t w = wt_writer_init(out, 16U);
  uint8_t encoded[8];
  size_t n = wt_quic_varint_encode(type, encoded, sizeof(encoded));
  wt_writer_bytes(&w, encoded, n);
  *length = wt_writer_offset(&w);
}

static inline size_t build_section(uint8_t *out, size_t capacity, const char *name,
                                   const char *value) {
  wt_writer_t w = wt_writer_init(out, capacity);
  wt_qpack_header_prefix_t prefix;
  wt_qpack_field_line_t line;
  uint8_t scratch[64];

  prefix.required_insert_count = 0U;
  prefix.base = 0U;
  line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line.never_indexed = 0;
  line.index = 0U;
  line.name_huffman = 0;
  line.name = (const uint8_t *)name;
  line.name_length = strlen(name);
  line.value = (const uint8_t *)value;
  line.value_length = strlen(value);
  line.value_huffman = 0;
  line.bytes_consumed = 0U;

  if (wt_qpack_field_section_encode(&w, &prefix, 0U, &line, 1U, scratch, sizeof(scratch)) !=
      WT_OK) {
    return 0U;
  }
  return wt_writer_offset(&w);
}

#endif
