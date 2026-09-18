/* QUIC frame codec. See webtransport/quic/frame.h. */

#include "webtransport/quic/frame.h"

#include "webtransport/checked.h"

#include "webtransport/endian.h"
#include <string.h>

#include "webtransport/quic/frame.h"

static wt_status_t wt_quic_encode_fail(void) {
  return WT_ERR_INVALID_ARGUMENT;
}

wt_status_t wt_quic_frame_encode(wt_writer_t *w, const wt_quic_frame_t *frame) {
  if (w == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (w->overflow) return WT_ERR_LIMIT;

  switch (frame->kind) {
    case WT_QUIC_FRAME_KIND_PADDING:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PADDING);
      return WT_OK;

    case WT_QUIC_FRAME_KIND_PING:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PING);
      return WT_OK;

    case WT_QUIC_FRAME_KIND_ACK: {
      uint64_t i;
      (void)wt_quic_writer_varint(w, frame->as.ack.has_ecn ? WT_QUIC_FRAME_ACK_ECN
                                                           : WT_QUIC_FRAME_ACK);
      (void)wt_quic_writer_varint(w, frame->as.ack.largest);
      (void)wt_quic_writer_varint(w, frame->as.ack.delay);
      (void)wt_quic_writer_varint(w, frame->as.ack.range_count);
      (void)wt_quic_writer_varint(w, frame->as.ack.first_range);
      for (i = 0U; i < frame->as.ack.range_count; i++) {
        wt_quic_ack_range_t range;
        if (wt_quic_frame_ack_range_at(frame, i, &range) != WT_OK) {
          return wt_quic_encode_fail();
        }
        (void)wt_quic_writer_varint(w, range.gap);
        (void)wt_quic_writer_varint(w, range.length);
      }
      if (frame->as.ack.has_ecn) {
        (void)wt_quic_writer_varint(w, frame->as.ack.ect0);
        (void)wt_quic_writer_varint(w, frame->as.ack.ect1);
        (void)wt_quic_writer_varint(w, frame->as.ack.ecn_ce);
      }
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
    }

    case WT_QUIC_FRAME_KIND_CRYPTO:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_CRYPTO);
      (void)wt_quic_writer_varint(w, frame->as.crypto.offset);
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.crypto.length);
      wt_writer_bytes(w, frame->as.crypto.data, frame->as.crypto.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
      if (frame->as.new_token.length == 0U || frame->as.new_token.token == NULL) {
        return wt_quic_encode_fail();
      }
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_NEW_TOKEN);
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.new_token.length);
      wt_writer_bytes(w, frame->as.new_token.token, frame->as.new_token.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STREAM: {
      uint8_t flags = 0U;
      uint64_t type;
      if (frame->as.stream.has_offset) flags |= WT_QUIC_STREAM_FLAG_OFF;
      if (frame->as.stream.has_length) flags |= WT_QUIC_STREAM_FLAG_LEN;
      if (frame->as.stream.fin) flags |= WT_QUIC_STREAM_FLAG_FIN;
      type = WT_QUIC_FRAME_STREAM_BASE | (uint64_t)flags;
      (void)wt_quic_writer_varint(w, type);
      (void)wt_quic_writer_varint(w, frame->as.stream.id);
      if (frame->as.stream.has_offset) {
        (void)wt_quic_writer_varint(w, frame->as.stream.offset);
      }
      if (frame->as.stream.has_length) {
        (void)wt_quic_writer_varint(w, (uint64_t)frame->as.stream.length);
      }
      wt_writer_bytes(w, frame->as.stream.data, frame->as.stream.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
    }

    case WT_QUIC_FRAME_KIND_RESET_STREAM:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_RESET_STREAM);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream.id);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream.application_error_code);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream.final_size);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
      if (frame->as.reset_stream_at.reliable_size > frame->as.reset_stream_at.final_size) {
        return wt_quic_encode_fail();
      }
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_RESET_STREAM_AT);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.id);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.application_error_code);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.final_size);
      (void)wt_quic_writer_varint(w, frame->as.reset_stream_at.reliable_size);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STOP_SENDING:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_STOP_SENDING);
      (void)wt_quic_writer_varint(w, frame->as.stop_sending.id);
      (void)wt_quic_writer_varint(w, frame->as.stop_sending.application_error_code);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_MAX_DATA:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_MAX_DATA);
      (void)wt_quic_writer_varint(w, frame->as.max_data.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_MAX_STREAM_DATA);
      (void)wt_quic_writer_varint(w, frame->as.max_stream_data.id);
      (void)wt_quic_writer_varint(w, frame->as.max_stream_data.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_MAX_STREAMS:
      (void)wt_quic_writer_varint(w,
                                  (frame->as.max_streams.direction == WT_QUIC_STREAM_BIDIRECTIONAL)
                                      ? WT_QUIC_FRAME_MAX_STREAMS_BIDI
                                      : WT_QUIC_FRAME_MAX_STREAMS_UNI);
      (void)wt_quic_writer_varint(w, frame->as.max_streams.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_DATA_BLOCKED);
      (void)wt_quic_writer_varint(w, frame->as.data_blocked.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_STREAM_DATA_BLOCKED);
      (void)wt_quic_writer_varint(w, frame->as.stream_data_blocked.id);
      (void)wt_quic_writer_varint(w, frame->as.stream_data_blocked.offset);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
      (void)wt_quic_writer_varint(
          w, (frame->as.streams_blocked.direction == WT_QUIC_STREAM_BIDIRECTIONAL)
                 ? WT_QUIC_FRAME_STREAMS_BLOCKED_BIDI
                 : WT_QUIC_FRAME_STREAMS_BLOCKED_UNI);
      (void)wt_quic_writer_varint(w, frame->as.streams_blocked.maximum);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
      if (frame->as.new_connection_id.connection_id_length < 1U ||
          frame->as.new_connection_id.connection_id_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH ||
          frame->as.new_connection_id.connection_id == NULL ||
          frame->as.new_connection_id.stateless_reset_token == NULL) {
        return wt_quic_encode_fail();
      }
      if (frame->as.new_connection_id.retire_prior_to > frame->as.new_connection_id.sequence) {
        return wt_quic_encode_fail();
      }
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_NEW_CONNECTION_ID);
      (void)wt_quic_writer_varint(w, frame->as.new_connection_id.sequence);
      (void)wt_quic_writer_varint(w, frame->as.new_connection_id.retire_prior_to);
      wt_writer_u8(w, (uint8_t)frame->as.new_connection_id.connection_id_length);
      wt_writer_bytes(w, frame->as.new_connection_id.connection_id,
                      frame->as.new_connection_id.connection_id_length);
      wt_writer_bytes(w, frame->as.new_connection_id.stateless_reset_token,
                      WT_QUIC_STATELESS_RESET_TOKEN_LENGTH);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_RETIRE_CONNECTION_ID);
      (void)wt_quic_writer_varint(w, frame->as.retire_connection_id.sequence);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
      if (frame->as.path_challenge.data == NULL) return wt_quic_encode_fail();
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PATH_CHALLENGE);
      wt_writer_bytes(w, frame->as.path_challenge.data, WT_QUIC_PATH_CHALLENGE_LENGTH);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
      if (frame->as.path_response.data == NULL) return wt_quic_encode_fail();
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_PATH_RESPONSE);
      wt_writer_bytes(w, frame->as.path_response.data, WT_QUIC_PATH_CHALLENGE_LENGTH);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
      (void)wt_quic_writer_varint(w, (frame->kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT)
                                         ? WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT
                                         : WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION);
      (void)wt_quic_writer_varint(w, frame->as.connection_close.error_code);
      if (frame->as.connection_close.has_frame_type) {
        if (frame->kind != WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT) {
          /* The application close form has no frame type field, so a caller
           * that set one is asking for something the wire cannot carry. */
          return wt_quic_encode_fail();
        }
        (void)wt_quic_writer_varint(w, frame->as.connection_close.frame_type);
      } else if (frame->kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT) {
        /* A transport close always carries the field, and RFC 9000 section
         * 19.19 says an endpoint that cannot name the frame uses 0. */
        (void)wt_quic_writer_varint(w, 0U);
      }
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.connection_close.reason_length);
      wt_writer_bytes(w, frame->as.connection_close.reason,
                      frame->as.connection_close.reason_length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_HANDSHAKE_DONE);
      return WT_OK;

    case WT_QUIC_FRAME_KIND_DATAGRAM:
      /* The frame the parser produced for either DATAGRAM form encodes as the
       * length-carrying form, because a frame without a length must be last in
       * a packet and an encoder here cannot know that. A caller that wants the
       * other form writes the type itself; this is the safe encoding. */
      (void)wt_quic_writer_varint(w, WT_QUIC_FRAME_DATAGRAM_LEN);
      (void)wt_quic_writer_varint(w, (uint64_t)frame->as.datagram.length);
      wt_writer_bytes(w, frame->as.datagram.data, frame->as.datagram.length);
      return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;

    default:
      return wt_quic_encode_fail();
  }
}
