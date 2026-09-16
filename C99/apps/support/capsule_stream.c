/* The CONNECT stream's capsules, as an application sees them (WT-164, WT-165). */

#include "capsule_stream.h"

#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/writer.h"

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
  wt_capsule_stream_t *stream = context;
  uint64_t maximum = 0U;
  uint64_t flow_error = 0U;
  wt_status_t status;

  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream == NULL) return WT_OK; /* no account kept: the capsule is dropped, which section 2 allows */
  if (capsule->type == WT_CAPSULE_MAX_DATA) {
    status = wt_webtransport_max_data_parse(capsule, &maximum, out_error);
    if (status != WT_OK) return status;
    if (wt_webtransport_flow_on_max_data(&stream->peer_limits, maximum, &flow_error) != WT_OK) {
      /* Section 5.1's error is a SESSION code, and it is recorded where the caller states refusals from -- not in
       * `out_error`, which is the HTTP/3 error space. */
      stream->refused_session_code = flow_error;
      stream->refused_session_code_set = 1;
      return WT_ERR_PROTOCOL;
    }
    return WT_OK;
  }
  if (capsule->type == WT_CAPSULE_MAX_STREAMS_BIDI || capsule->type == WT_CAPSULE_MAX_STREAMS_UNI ||
      capsule->type == WT_CAPSULE_STREAMS_BLOCKED_BIDI || capsule->type == WT_CAPSULE_STREAMS_BLOCKED_UNI) {
    int blocked = capsule->type == WT_CAPSULE_STREAMS_BLOCKED_BIDI ||
                  capsule->type == WT_CAPSULE_STREAMS_BLOCKED_UNI;

    status = blocked ? wt_webtransport_streams_blocked_parse(capsule, &maximum, out_error)
                     : wt_webtransport_max_streams_parse(capsule, &maximum, out_error);
    if (status != WT_OK) {
      /* Sections 5.6.2 and 5.6.3: the 2^60 ceiling reaches this layer from the parser as WT_FLOW_CONTROL_ERROR in
       * the HTTP/3 slot, and it is a SESSION error -- record it where the caller states refusals from, so
       * `wt_capsule_stream_refuse` writes the WT_CLOSE_SESSION capsule that ends the session instead of the
       * connection. A malformed value keeps its own code and is the connection's to answer for. */
      if (out_error != NULL && (uint64_t)*out_error == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR) {
        stream->refused_session_code = WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
        stream->refused_session_code_set = 1;
      }
      return status;
    }
    if (blocked) {
      /* Informational only (section 5.6.3): the ceiling above is the one rule a WT_STREAMS_BLOCKED carries that
       * this layer must act on, and it grants nothing to account for. */
      return WT_OK;
    }
    if (wt_webtransport_flow_on_max_streams(&stream->peer_limits,
                                            capsule->type == WT_CAPSULE_MAX_STREAMS_BIDI ? 1 : 0, maximum,
                                            &flow_error) != WT_OK) {
      stream->refused_session_code = flow_error;
      stream->refused_session_code_set = 1;
      return WT_ERR_PROTOCOL;
    }
    return WT_OK;
  }
  return WT_OK;
}

wt_status_t wt_capsule_stream_on_bytes(wt_capsule_stream_t *stream, const uint8_t *data, size_t length, int fin,
                                       wt_capsule_stream_fn observe, void *context,
                                       wt_http3_error_t *out_error) {
  wt_cursor_t cursor;
  wt_status_t status;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > sizeof(stream->bytes) - stream->length) {
    stream->refused++;
    if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
    return WT_ERR_LIMIT;
  }
  if (length > 0U) memcpy(stream->bytes + stream->length, data, length);
  stream->length += length;

  cursor = wt_cursor_init(stream->bytes, stream->length);
  status = wt_webtransport_session_on_capsule_bytes(&stream->session, &cursor, sizeof(stream->bytes), observe,
                                                    context, &error);
  if (out_error != NULL) *out_error = error;
  if (status == WT_ERR_TRUNCATED) {
    const uint8_t *rest = NULL;
    size_t unread = 0U;

    /* A capsule that has not fully arrived is a WAIT, and the walker left the cursor on its first byte: keep
     * exactly those bytes and let the next delivery complete them. The stream ending here is the other case --
     * nothing more is coming, so the capsule is incomplete, and that is a refusal rather than a wait that will
     * never end. An incomplete capsule at FIN is a FRAME_ERROR, the rule WT-158 settled for frames. */
    rest = wt_cursor_rest(&cursor, &unread);
    if (unread > 0U && rest != NULL) memmove(stream->bytes, rest, unread);
    stream->length = unread;
    if (fin == 0) {
      if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
      return WT_OK;
    }
    stream->refused++;
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_TRUNCATED;
  }
  stream->length = 0U;
  if (status != WT_OK) {
    stream->refused++;
    return status;
  }
  stream->walked++;
  if (fin != 0) {
    /* The CONNECT stream ended without a close capsule: the session is over with no code to report (section 4.4).
     * A close that arrived first already ended it, and a second end is not a second event. */
    (void)wt_webtransport_session_on_stream_end(&stream->session);
  }
  return WT_OK;
}

wt_capsule_refusal_t wt_capsule_stream_refuse(wt_capsule_stream_t *stream,
                                              const wt_http3_driver_transport_t *transport, uint64_t stream_id,
                                              wt_quic_connection_t *connection, uint64_t now,
                                              wt_http3_error_t error) {
  if (stream == NULL) return WT_CAPSULE_REFUSAL_NONE;
  if (stream->refused_session_code_set != 0) {
    uint8_t framed[WT_CAPSULE_STREAM_MAX];
    wt_writer_t w = wt_writer_init(framed, sizeof(framed));

    /* The session's own error code, in the capsule that says so. The connection is NOT closed: section 5.1 makes
     * this the session's end, and a peer that ended a session has not broken the transport. */
    if (wt_webtransport_session_write_close(&stream->session, &w,
                                            (uint32_t)stream->refused_session_code, NULL, 0U) != WT_OK) {
      return WT_CAPSULE_REFUSAL_NONE;
    }
    if (transport != NULL && transport->send_stream != NULL) {
      (void)transport->send_stream(transport->context, stream_id, framed, wt_writer_offset(&w), 0, now);
    }
    return WT_CAPSULE_REFUSAL_SESSION;
  }
  if (error != WT_HTTP3_NO_ERROR && connection != NULL) {
    /* RFC 9114 section 8: an HTTP/3 error reaches the peer in the application form of CONNECTION_CLOSE, and the
     * hint is what the close actually uses -- the caller still has to return its failure. */
    wt_quic_connection_refuse_application(connection, (uint64_t)error, 0U);
    return WT_CAPSULE_REFUSAL_HTTP3;
  }
  return WT_CAPSULE_REFUSAL_NONE;
}
