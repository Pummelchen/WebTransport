/* The CONNECT stream's capsules, as an application sees them (WT-164). */

#include "capsule_stream.h"

#include <string.h>

#include "webtransport/cursor.h"

void wt_capsule_stream_init(wt_capsule_stream_t *stream) {
  if (stream == NULL) return;
  memset(stream, 0, sizeof(*stream));
  wt_webtransport_session_init(&stream->session);
  wt_webtransport_flow_limits_init(&stream->peer_limits);
}

void wt_capsule_stream_established(wt_capsule_stream_t *stream) {
  if (stream == NULL) return;
  (void)wt_webtransport_session_established(&stream->session);
}

wt_status_t wt_capsule_stream_apply_flow(void *context, const wt_webtransport_capsule_t *capsule,
                                         wt_http3_error_t *out_error) {
  wt_webtransport_flow_limits_t *limits = context;
  uint64_t maximum = 0U;
  uint64_t flow_error = 0U;
  wt_status_t status;

  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (limits == NULL) return WT_OK; /* no account kept: the capsule is dropped, which section 2 allows */
  if (capsule->type == WT_CAPSULE_MAX_DATA) {
    status = wt_webtransport_max_data_parse(capsule, &maximum, out_error);
    if (status != WT_OK) return status;
    return wt_webtransport_flow_on_max_data(limits, maximum, &flow_error);
  }
  if (capsule->type == WT_CAPSULE_MAX_STREAMS_BIDI || capsule->type == WT_CAPSULE_MAX_STREAMS_UNI) {
    status = wt_webtransport_max_streams_parse(capsule, &maximum, out_error);
    if (status != WT_OK) return status;
    return wt_webtransport_flow_on_max_streams(limits,
                                               capsule->type == WT_CAPSULE_MAX_STREAMS_BIDI ? 1 : 0, maximum,
                                               &flow_error);
  }
  return WT_OK;
}

wt_status_t wt_capsule_stream_on_bytes(wt_capsule_stream_t *stream, const uint8_t *data, size_t length, int fin,
                                       wt_capsule_stream_fn observe, void *context) {
  wt_cursor_t cursor;
  wt_status_t status;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > sizeof(stream->bytes) - stream->length) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(stream->bytes + stream->length, data, length);
  stream->length += length;

  cursor = wt_cursor_init(stream->bytes, stream->length);
  status = wt_webtransport_session_on_capsule_bytes(&stream->session, &cursor, sizeof(stream->bytes), observe,
                                                    context, &error);
  if (status == WT_ERR_TRUNCATED) {
    const uint8_t *rest = NULL;
    size_t unread = 0U;

    /* A capsule that has not fully arrived is a WAIT, and the walker left the cursor on its first byte: keep
     * exactly those bytes and let the next delivery complete them. The stream ending here is the other case --
     * nothing more is coming, so the capsule is incomplete, and that is a refusal rather than a wait that will
     * never end. */
    rest = wt_cursor_rest(&cursor, &unread);
    if (unread > 0U && rest != NULL) memmove(stream->bytes, rest, unread);
    stream->length = unread;
    if (fin == 0) return WT_OK;
    stream->refused++;
    return WT_ERR_TRUNCATED;
  }
  stream->length = 0U;
  if (status != WT_OK) {
    stream->refused++;
    return status;
  }
  stream->walked++;
  if (fin != 0) {
    /* The CONNECT stream ended without a close capsule: the session is over with code to report (section 4.4). A
     * close that arrived first already ended it, and a second end is not a second event. */
    (void)wt_webtransport_session_on_stream_end(&stream->session);
  }
  return WT_OK;
}
