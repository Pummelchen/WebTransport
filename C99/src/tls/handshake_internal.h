/* Shared by handshake.c and handshake_messages.c after the split.
 * `static inline`: both halves call these, and a file-static helper cannot cross a translation
 * unit. They are removed from the source, or both would define them. */
#ifndef WT_TLS_HANDSHAKE_INTERNAL_H
#define WT_TLS_HANDSHAKE_INTERNAL_H

/* TLS 1.3 handshake messages. See webtransport/tls/handshake.h. */

#include "webtransport/tls/handshake.h"

#include <string.h>

static inline wt_status_t sub_cursor(wt_cursor_t *cursor, size_t len, wt_cursor_t *out) {
  const uint8_t *bytes = wt_cursor_bytes(cursor, len);
  if (bytes == NULL) return WT_ERR_PROTOCOL;
  *out = wt_cursor_init(bytes, len);
  return WT_OK;
}

static inline wt_status_t message_body(const uint8_t *message, size_t len, uint8_t type,
                                       wt_cursor_t *body) {
  wt_cursor_t cursor;
  wt_tls_handshake_header_t header;
  const uint8_t *bytes;
  wt_status_t status;

  if (message == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len < WT_TLS_HANDSHAKE_HEADER_LEN) return WT_ERR_TRUNCATED;
  cursor = wt_cursor_init(message, len);
  status = wt_tls_handshake_header_parse(&cursor, &header);
  if (status != WT_OK) return status;
  if (header.type != type) return WT_ERR_PROTOCOL;
  bytes = wt_cursor_bytes(&cursor, header.length);
  if (bytes == NULL) return WT_ERR_TRUNCATED;
  *body = wt_cursor_init(bytes, header.length);
  return WT_OK;
}

#endif
