/* Driving an HTTP/3 endpoint from a connection (Phase 9): routing a connection's frames.
 *
 * Every frame the connection delivers passes through here and is either this layer's or nobody's: a
 * STREAM frame on a data stream, on a request stream or on one of HTTP/3's own unidirectional
 * streams, and a DATAGRAM that is the session's uninterpreted. A refusal is stated to the connection
 * as an APPLICATION close carrying the HTTP/3 error, which is why the driver holds the connection. */

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/http3/driver.h"

#include "webtransport/webtransport/error.h"

#include "webtransport/cursor.h"
#include <string.h>

#include "webtransport/quic/stream.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/quic/varint.h"

#include "driver_internal.h"

/* ---------------------------------------------- routing a connection's frames */

/* Whether this endpoint is the one that opens a stream with this ID: the low bit of a QUIC
 * stream ID says which side initiated it (RFC 9000 section 2.1). */
static int stream_is_ours(const wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  int from_client = wt_quic_stream_id_from_client(stream_id);
  return endpoint->role == WT_HTTP3_ROLE_CLIENT ? from_client : !from_client;
}

static wt_status_t route_quic_frame(wt_http3_driver_t *driver, wt_quic_space_t space,
                                    const wt_quic_frame_t *frame, const wt_http3_driver_sink_t *sink,
                                    uint64_t max_frame_bytes, wt_http3_error_t *out_error);

wt_status_t wt_http3_driver_on_quic_frame(void *context, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame,
                                          const wt_http3_driver_sink_t *sink,
                                          uint64_t max_frame_bytes) {
  wt_http3_driver_t *driver = context;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Cleared first, so that the code below is this frame's refusal rather than an older one's: the caller reads it
   * only when the status is a failure, and a stale code would name a rule the peer did not break. */
  driver->last_error = WT_HTTP3_NO_ERROR;
  status = route_quic_frame(driver, space, frame, sink, max_frame_bytes, &driver->last_error);
  if (status != WT_OK && driver->connection != NULL && driver->last_error != WT_HTTP3_NO_ERROR) {
    /* The refusal IS an HTTP/3 error, so the peer is told the HTTP/3 code -- in the application form, which is the
     * only form that carries one (RFC 9114 section 8). A refusal WITHOUT an HTTP/3 error is a caller's own bound
     * and leaves the connection's default in force. */
    wt_quic_connection_refuse_application(driver->connection, (uint64_t)driver->last_error, 0U);
  }
  return status;
}

void wt_http3_driver_bind_connection(wt_http3_driver_t *driver, wt_quic_connection_t *connection) {
  if (driver == NULL) return;
  driver->connection = connection;
}

/* The routing itself, with the HTTP/3 error code OUT so that the caller can record it: a refusal is reported to
 * the connection with this code, and an HTTP/3 error is an APPLICATION close (RFC 9114 section 8), which is a
 * different frame from the transport close a bare status would otherwise produce (WT-158). */
static wt_status_t route_quic_frame(wt_http3_driver_t *driver, wt_quic_space_t space,
                                    const wt_quic_frame_t *frame, const wt_http3_driver_sink_t *sink,
                                    uint64_t max_frame_bytes, wt_http3_error_t *out_error) {
  wt_status_t status;

  (void)space;

  /* An if-chain rather than a switch, and the reason is the compiler: -Wswitch-enum requires
   * every enumerator of a switch to be named, and this handler deliberately acts on two of
   * them and ignores the rest. Naming twenty-one no-op cases to satisfy the warning would
   * make the two that matter harder to find, which is the opposite of what the warning is
   * for. */
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM) {
      uint64_t stream_id = frame->as.stream.id;
      /* A DIAGNOSTIC, gated by WT_HTTP3_STREAM_LOG: the STREAM frames this layer is asked to route, as the
       * connection reported them. Which of the two -- a WebTransport data stream or an HTTP/3 request stream -- is
       * decided below, and "the prefix arrived in two frames" and "the prefix was never recognized" look the same
       * from the caller's side without this (WT-156). */
      {
        const char *stream_log_path = getenv("WT_HTTP3_STREAM_LOG");
        if (stream_log_path != NULL) {
          FILE *stream_log = fopen(stream_log_path, "a");
          if (stream_log != NULL) {
            size_t index;
            fprintf(stream_log, "stream=%llu offset=%llu has_length=%d length=%llu fin=%d bytes=",
                    (unsigned long long)stream_id, (unsigned long long)frame->as.stream.offset,
                    frame->as.stream.has_length, (unsigned long long)frame->as.stream.length,
                    frame->as.stream.fin);
            for (index = 0U; index < frame->as.stream.length && index < 48U; index++) {
              fprintf(stream_log, "%02x", frame->as.stream.data[index]);
            }
            fprintf(stream_log, "\n");
            (void)fclose(stream_log);
          }
        }
      }
      /* A WebTransport data stream THIS endpoint opened: the prefix went out with the first bytes, so what
       * arrives on it is the responder's payload. Classifying it again is what the peer's echo tripped over --
       * its first bytes were read as a signal value, refused, and the refusal closed the connection (WT-135). */
      if (wt_http3_driver_is_data_stream(driver, stream_id)) {
        if (sink == NULL || sink->on_stream_data == NULL) return WT_OK;
        return sink->on_stream_data(sink->context, stream_id, frame->as.stream.data,
                                    frame->as.stream.length, frame->as.stream.fin);
      }
      if (stream_is_ours(driver->endpoint, stream_id) &&
          !wt_quic_stream_id_is_bidirectional(stream_id)) {
        /* A UNIDIRECTIONAL stream this endpoint opened: the peer cannot write on it, so there is nothing to
         * route. A BIDIRECTIONAL one is a different matter, and dropping it here (which this code did) is why
         * the response never reached the caller: the peer's frames on a stream WE opened ARE the response, and
         * RFC 9114 section 4.1 gives the two directions of one exchange their own HEADERS frames on that same
         * stream. The connection delivered the frame, the chain called this layer, and this early return said
         * there was nothing to route. */
        return WT_OK;
      }
      if (wt_quic_stream_id_is_bidirectional(stream_id)) {
        /* A bidirectional stream is a request stream -- and there are TWO ways this layer meets one. If the
         * endpoint already tracks it, this endpoint OPENED it and what arrives is the RESPONSE, which is the
         * other direction of the same exchange (RFC 9114 section 4.1 gives each direction its own HEADERS).
         * If it does not, the peer initiated it and it becomes a request stream now.
         *
         * Getting this wrong is what stopped the response from arriving: routing a tracked stream through
         * `on_request_stream` again is refused as a duplicate, and the refusal ABORTED the frame routing, so
         * the response was never reported to the caller at all. */
        wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
        int tracked = wt_http3_endpoint_request_state(driver->endpoint, stream_id, &state) == WT_OK;

        /* A prefix that arrives in PIECES: hold the bytes in the same pending table the unidirectional path
         * uses, and when enough arrive either deliver what follows the prefix to the session or REPLAY the held
         * bytes into the request path (which must see a stream's first bytes, not the middle of them).
         *
         * The held-bytes lookup comes FIRST, and that is the whole bug the counter found: a CONTINUATION frame
         * has a non-zero offset, so a condition of "offset zero" skipped the assembly for exactly the frame that
         * would have completed the prefix -- and the frame then fell into the request path, where its middle
         * bytes were read as a stream's first and refused. */
        {
          wt_http3_driver_pending_t *held = find_pending(driver, stream_id);
          if (!tracked && (held != NULL || (frame->as.stream.offset == 0U && frame->as.stream.length > 0U))) {
          uint8_t assembled[WT_HTTP3_DRIVER_PREFIX_MAX];
          size_t have = 0U;
          size_t copied;
          wt_http3_bidi_start_kind_t start_kind = WT_HTTP3_BIDI_START_REQUEST;
          size_t consumed = 0U;
          uint64_t prefix_session = 0U;
          wt_status_t classified;

          if (held != NULL) {
            have = held->length;
            memcpy(assembled, held->bytes, have);
          }
          copied = frame->as.stream.length;
          if (copied > (size_t)WT_HTTP3_DRIVER_PREFIX_MAX - have) {
            copied = (size_t)WT_HTTP3_DRIVER_PREFIX_MAX - have;
          }
          memcpy(assembled + have, frame->as.stream.data, copied);
          classified = wt_http3_driver_classify_bidi_start(assembled, have + copied, &start_kind, &prefix_session,
                                                           &consumed);
          if (classified == WT_ERR_TRUNCATED) {
            if (held == NULL) {
              if (driver->pending_count >= WT_HTTP3_DRIVER_PENDING_MAX) {
                      return WT_ERR_LIMIT;
              }
              held = &driver->pending[driver->pending_count];
              held->stream_id = stream_id;
              held->length = 0U;
              driver->pending_count++;
            }
            memcpy(held->bytes, assembled, have + copied);
            held->length = have + copied;
            return WT_OK;
          }
          if (held != NULL) forget_pending(driver, stream_id);
          if (classified == WT_OK && start_kind == WT_HTTP3_BIDI_START_WEBTRANSPORT) {
            if (driver->session_id_set != 0 && prefix_session != driver->session_id) return WT_ERR_PROTOCOL;
            /* The prefix is settled: recorded so that the bytes the peer sends NEXT on this stream are the
             * session's payload rather than a second prefix or an HTTP/3 frame. A peer may send the prefix and
             * its message in separate STREAM frames -- which is what aioquic does, and what this tree's own
             * client never did, so the omission was invisible (WT-156). */
            {
              /* The prefix that was just classified is the PEER's: this endpoint has written nothing on this
               * stream, so what a later reset may commit to is zero bytes. */
              wt_status_t remembered = remember_data_stream(driver, stream_id, 0U, prefix_session, 1);
              if (remembered != WT_OK) return remembered;
            }
            if (sink != NULL && sink->on_stream_data != NULL) {
              size_t from_assembled = have + copied - consumed;
              if (from_assembled > 0U) {
                wt_status_t delivered = sink->on_stream_data(sink->context, stream_id, assembled + consumed,
                                                             from_assembled,
                                                             frame->as.stream.length > copied
                                                                 ? 0
                                                                 : frame->as.stream.fin);
                if (delivered != WT_OK) return delivered;
              }
              if (frame->as.stream.length > copied) {
                return sink->on_stream_data(sink->context, stream_id, frame->as.stream.data + copied,
                                            frame->as.stream.length - copied, frame->as.stream.fin);
              }
            }
            return WT_OK;
          }
          if (have > 0U) {
            wt_status_t replayed = wt_http3_driver_on_stream_bytes(driver, stream_id, assembled, have, 0,
                                                                   max_frame_bytes, sink, NULL);
              if (replayed != WT_OK) return replayed;
          }
        }
        }

        if (!tracked) {
          status = wt_http3_endpoint_on_request_stream(driver->endpoint, stream_id, out_error);
          if (status != WT_OK) return status;
        }
        return wt_http3_driver_on_stream_bytes(driver, stream_id, frame->as.stream.data,
                                               frame->as.stream.length, frame->as.stream.fin,
                                               max_frame_bytes, sink, out_error);
      }

      /* A peer-initiated unidirectional stream: its type prefix first, then whichever of the
       * two kinds of bytes the type says follow it. */
      {
        wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
        const uint8_t *payload = NULL;
        size_t payload_length = 0U;
        size_t consumed = 0U;
        int finished_prefix;

        /* A stream the endpoint already classified does not carry a prefix any more. */
        kind = wt_http3_endpoint_stream_kind(driver->endpoint, stream_id);
        finished_prefix = kind != WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
        if (finished_prefix) {
          payload = frame->as.stream.data;
          payload_length = frame->as.stream.length;
        } else {
          status = wt_http3_driver_on_uni_stream_data(driver, stream_id, frame->as.stream.offset,
                                                      frame->as.stream.data, frame->as.stream.length,
                                                      &kind, &payload, &payload_length, &consumed,
                                                      out_error);
          if (status != WT_OK) return status;
          if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN) {
            /* Either the prefix is still incomplete -- the bytes are held in the pending
             * table and nothing is routed -- or it named a stream type this build does not
             * know, which section 6.2.1 says to stop reading. Both drop the bytes. */
            return WT_OK;
          }
        }

        if (kind == WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT) {
          /* The session's own stream: its bytes are not HTTP/3 frames, so they go to the
           * session as they are. */
          if (sink != NULL && sink->on_stream_data != NULL && payload_length > 0U) {
            return sink->on_stream_data(sink->context, stream_id, payload, payload_length,
                                        frame->as.stream.fin);
          }
          return WT_OK;
        }

        /* HTTP/3's own streams carry frames, and the frame boundary is reassembled for them
         * the same way it is for a request stream. */
        if (payload_length > 0U || frame->as.stream.fin != 0) {
          status = wt_http3_driver_on_stream_bytes(driver, stream_id, payload, payload_length,
                                                   frame->as.stream.fin, max_frame_bytes, sink,
                                                   out_error);
          if (status != WT_OK) return status;
        }
        if (frame->as.stream.fin != 0) {
          return wt_http3_driver_on_uni_stream_end(driver, stream_id, out_error);
        }
        return WT_OK;
      }
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_DATAGRAM) {
    /* The payload is the session's, and this layer does not look inside it: what a datagram
     * means is the draft's framing, which the session layer reads. */
    if (sink != NULL && sink->on_datagram != NULL) {
      return sink->on_datagram(sink->context, frame->as.datagram.data, frame->as.datagram.length);
    }
    return WT_OK;
  }
  /* Every other kind belongs to the connection or to nobody here. */
  return WT_OK;
}
