/* Shared by packet.c and packet_encode.c.
 * `static inline` because both halves need these and a file-static helper cannot cross a
 * translation unit; they are removed from packet.c so the header and the source do not both
 * define them. The body-level defines come first because the helpers below use them. */
#ifndef WT_QUIC_PACKET_INTERNAL_H
#define WT_QUIC_PACKET_INTERNAL_H

/* QUIC packet headers. See webtransport/quic/packet.h.
 *
 * Both decoders read the first byte first and dispatch on its top bit, and both
 * check the fixed bit and -- for a long header -- the reserved bits, because
 * those are the fields that decide whether the bytes are a QUIC packet at all
 * before any of the rest can be trusted.
 *
 * The Length field is re-derived on encode rather than taken from the caller.
 * RFC 9000 section 17.2 defines it as the packet number length plus the payload
 * length, and an API that let a caller pass it separately would let the two
 * disagree -- a class of defect that is silent until a peer refuses the packet
 * for a reason that names neither field.
 */

#include "webtransport/quic/packet.h"

#include "webtransport/checked.h"
#include "webtransport/endian.h"
#include "webtransport/quic/packet_number.h"

#include <string.h>

#define WT_QUIC_MAX_CID_LEN 20U
#define WT_QUIC_RETRY_INTEGRITY_TAG_LEN 16U

static inline wt_status_t wt_quic_packet_fail(wt_quic_error_t *out_error, wt_quic_error_t code,
                                              wt_status_t status) {
  if (out_error != NULL) *out_error = code;
  return status;
}

static inline wt_status_t wt_quic_read_connection_id(wt_cursor_t *c, const uint8_t **out,
                                                     size_t *out_len, wt_quic_error_t *out_error) {
  const uint8_t *length_byte = wt_cursor_bytes(c, 1U);
  uint8_t length;
  const uint8_t *id;
  if (length_byte == NULL) return WT_ERR_TRUNCATED;
  length = length_byte[0];
  if ((size_t)length > WT_QUIC_MAX_CID_LEN) {
    return wt_quic_packet_fail(out_error, WT_QUIC_PROTOCOL_VIOLATION, WT_ERR_PROTOCOL);
  }
  id = wt_cursor_bytes(c, (size_t)length);
  if (id == NULL && length != 0U) return WT_ERR_TRUNCATED;
  *out = id;
  *out_len = (size_t)length;
  return WT_OK;
}

#endif
