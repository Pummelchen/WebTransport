/* The CONNECT stream's capsules, as an application sees them (WT-164, WT-165). */

#include "capsule_stream.h"

#include <string.h>

#include "webtransport/api/flow.h"
#include "webtransport/cursor.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/settings.h"
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

void wt_capsule_stream_set_flow_advertised(wt_capsule_stream_t *stream,
                                           const wt_http3_settings_t *local_settings) {
  if (stream == NULL) return;
  /* One predicate, so "advertised" means the same thing here as in the public session API. */
  stream->flow_advertised_local = wt_session_flow_advertised(local_settings);
}

wt_status_t wt_capsule_stream_on_peer_settings(wt_capsule_stream_t *stream, const uint8_t *payload,
                                               size_t length, int last, wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (stream == NULL) return WT_OK; /* no account kept: the capsule is dropped, which section 2 allows */
  if (payload == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > sizeof(stream->peer_settings) - stream->peer_settings_length) {
    /* The control machine's own bound, so a validated payload cannot reach it; a caller that delivered more
     * than the machine would have is refused rather than silently truncated. */
    return WT_ERR_LIMIT;
  }
  if (length > 0U) memcpy(stream->peer_settings + stream->peer_settings_length, payload, length);
  stream->peer_settings_length += length;
  if (last == 0) return WT_OK;

  {
    wt_http3_settings_t parsed;
    wt_status_t status;

    wt_http3_settings_init(&parsed);
    status = wt_http3_settings_parse(stream->peer_settings, stream->peer_settings_length, &parsed, out_error);
    stream->peer_settings_length = 0U;
    if (status != WT_OK) {
      /* The control machine already validated this payload, so this is unreachable; answering 0 rather than a
       * second refusal keeps a sink from closing a connection the machine has accepted. */
      stream->flow_advertised_peer = 0;
      return WT_OK;
    }
    stream->flow_advertised_peer = wt_session_flow_advertised(&parsed);
  }
  return WT_OK;
}

wt_status_t wt_capsule_stream_apply_flow(void *context, const wt_webtransport_capsule_t *capsule,
                                         wt_http3_error_t *out_error) {
  wt_capsule_stream_t *stream = context;
  uint64_t maximum = 0U;
  uint64_t flow_error = 0U;
  wt_status_t status;

  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (stream == NULL) return WT_OK; /* no account kept: the capsule is dropped, which section 2 allows */
  /* Section 5.1: the session's flow control applies only when BOTH endpoints advertised one of the three
   * initial limits, and an endpoint that did not negotiate it MUST IGNORE -- not refuse -- a flow-control
   * capsule. This is the same rule `src/api/session.c` applies to its `flow_enabled` flag. */
  if (stream->flow_advertised_local == 0 || stream->flow_advertised_peer == 0) return WT_OK;
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
  size_t taken = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (stream == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  /* Only as much of the delivery as fits is taken at a time, and the walk repeats while bytes remain. The bound is
   * therefore on ONE CAPSULE, which is what `WT_CAPSULE_STREAM_MAX` says it is: a delivery larger than the buffer
   * is not a capsule larger than the buffer, and refusing the delivery refused the largest close the draft allows (a
   * 1024-byte reason is 1032 bytes of capsule) and every peer that coalesced several capsules into one DATA frame
   * payload, however small those capsules were (WT-257). */
  for (;;) {
    wt_cursor_t cursor;
    wt_status_t status;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    size_t room = sizeof(stream->bytes) - stream->length;
    size_t chunk = length - taken;
    int progressed;

    if (chunk > room) chunk = room;
    if (room == 0U && taken < length) {
      /* Nothing more fits and bytes remain, so the capsule the buffer is holding is longer than this caller will
       * hold. Named as excessive load, because that is what a bound this endpoint imposed is (WT-158's rule). */
      stream->refused++;
      if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
      return WT_ERR_LIMIT;
    }
    if (chunk > 0U) {
      memcpy(stream->bytes + stream->length, data + taken, chunk);
      stream->length += chunk;
      taken += chunk;
    }

    progressed = (taken < length);
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
      if (progressed) continue; /* more of this delivery to take: nothing has been refused */
      if (fin == 0) return WT_OK;
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
    if (!progressed) break;
  }

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
    /* The reservation is in the buffer ahead of the capsule, and the frame header is written into it once the
     * capsule's own length is known (see `wt_http3_frame_wrap_data_in_place`): a capsule written raw is the header
     * of an unknown frame type, which the peer ignores in silence, so the session would never be told it had ended
     * (WT-249). */
    uint8_t framed[WT_HTTP3_FRAME_DATA_HEADER_MAX + WT_CAPSULE_STREAM_MAX];
    wt_writer_t w = wt_http3_frame_data_writer(framed, sizeof(framed));
    size_t frame_length = 0U;

    /* The session's own error code, in the capsule that says so. The connection is NOT closed: section 5.1 makes
     * this the session's end, and a peer that ended a session has not broken the transport. */
    if (wt_webtransport_session_write_close(&stream->session, &w,
                                            (uint32_t)stream->refused_session_code, NULL, 0U) != WT_OK) {
      return WT_CAPSULE_REFUSAL_NONE;
    }
    if (wt_http3_frame_wrap_data_in_place(framed, sizeof(framed), wt_writer_offset(&w), &frame_length) != WT_OK) {
      return WT_CAPSULE_REFUSAL_NONE;
    }
    if (transport != NULL && transport->send_stream != NULL) {
      (void)transport->send_stream(transport->context, stream_id, framed, frame_length, 0, now);
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
