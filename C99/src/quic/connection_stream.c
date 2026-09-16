/* The stream table and the flow control over it, plus the DATAGRAM surface. */

#include "connection_internal.h"

wt_status_t ensure_peer_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                      uint64_t frame_type, uint64_t now,
                                      wt_quic_stream_t **out_stream) {
  wt_quic_stream_t *stream = wt_quic_stream_table_find(&connection->streams, stream_id);
  int bidirectional;
  uint64_t granted;
  wt_status_t status;

  if (out_stream != NULL) *out_stream = NULL;
  if (stream != NULL) {
    if (out_stream != NULL) *out_stream = stream;
    return WT_OK;
  }
  if (wt_quic_stream_id_from_client(stream_id) ==
      (connection->config.role == WT_QUIC_ROLE_CLIENT)) {
    /* This endpoint's own number, never opened: the peer is inventing a stream. */
    return close_with(connection, WT_QUIC_STREAM_STATE_ERROR, frame_type, now);
  }
  bidirectional = wt_quic_stream_id_is_bidirectional(stream_id);
  granted = connection->local_max_streams[bidirectional ? 0 : 1];
  if (wt_quic_stream_id_index(stream_id) >= granted) {
    /* More streams than this endpoint allowed. */
    return close_with(connection, WT_QUIC_STREAM_LIMIT_ERROR, frame_type, now);
  }
  status = wt_quic_stream_table_open(&connection->streams, stream_id, 0, granted);
  if (status != WT_OK) return status;
  stream = wt_quic_stream_table_find(&connection->streams, stream_id);
  if (stream != NULL) {
    stream->max_stream_data = connection->config.local_max_stream_data;
    stream->window = connection->config.local_max_stream_data;
  }
  if (out_stream != NULL) *out_stream = stream;
  return WT_OK;
}
wt_status_t wt_quic_connection_set_max_data(wt_quic_connection_t *connection, uint64_t maximum) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (connection->local_max_data_set && maximum < connection->local_max_data) return WT_ERR_LIMIT;
  connection->local_max_data = maximum;
  connection->local_max_data_set = 1;
  connection->flow.max_data = maximum;
  connection->flow.window = maximum;
  return WT_OK;
}
uint64_t wt_quic_connection_max_data(const wt_quic_connection_t *connection) {
  return connection == NULL ? 0U : connection->local_max_data;
}
wt_status_t wt_quic_connection_send_max_data(wt_quic_connection_t *connection, uint64_t maximum,
                                             uint64_t now) {
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->local_max_data_set) return WT_ERR_STATE;
  if (maximum < connection->local_max_data) return WT_ERR_LIMIT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
  frame.as.max_data.maximum = maximum;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) return status;
  if (sent) connection->local_max_data = maximum;
  return sent ? WT_OK : WT_ERR_STATE;
}
static int direction_index(wt_quic_stream_direction_t direction) {
  return direction == WT_QUIC_STREAM_BIDIRECTIONAL ? 0 : 1;
}
wt_status_t wt_quic_connection_set_max_streams(wt_quic_connection_t *connection,
                                               wt_quic_stream_direction_t direction,
                                               uint64_t maximum) {
  int index;
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (direction != WT_QUIC_STREAM_BIDIRECTIONAL && direction != WT_QUIC_STREAM_UNIDIRECTIONAL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  index = direction_index(direction);
  if (connection->local_max_streams_set[index] && maximum < connection->local_max_streams[index]) {
    return WT_ERR_LIMIT;
  }
  connection->local_max_streams[index] = maximum;
  connection->local_max_streams_set[index] = 1;
  return WT_OK;
}
uint64_t wt_quic_connection_max_streams(const wt_quic_connection_t *connection,
                                        wt_quic_stream_direction_t direction) {
  if (connection == NULL) return 0U;
  if (direction != WT_QUIC_STREAM_BIDIRECTIONAL && direction != WT_QUIC_STREAM_UNIDIRECTIONAL) {
    return 0U;
  }
  return connection->local_max_streams[direction_index(direction)];
}
wt_status_t wt_quic_connection_send_max_streams(wt_quic_connection_t *connection,
                                                wt_quic_stream_direction_t direction,
                                                uint64_t maximum, uint64_t now) {
  wt_quic_frame_t frame;
  int index;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (direction != WT_QUIC_STREAM_BIDIRECTIONAL && direction != WT_QUIC_STREAM_UNIDIRECTIONAL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  index = direction_index(direction);
  if (!connection->local_max_streams_set[index]) return WT_ERR_STATE;
  if (maximum < connection->local_max_streams[index]) return WT_ERR_LIMIT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_STREAMS);
  frame.as.max_streams.direction = direction;
  frame.as.max_streams.maximum = maximum;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) return status;
  if (sent) connection->local_max_streams[index] = maximum;
  return sent ? WT_OK : WT_ERR_STATE;
}
static int stream_id_allowed(const wt_quic_connection_t *connection, uint64_t stream_id) {
  int ours = (int)(stream_id & 0x01U) == (connection->config.role == WT_QUIC_ROLE_CLIENT ? 0 : 1);
  int bidi = (stream_id & 0x02U) == 0U;
  uint64_t index = stream_id >> 2;
  uint64_t granted;

  /* A peer's stream is theirs to send on when it is BIDIRECTIONAL; a unidirectional one carries data
   * one way, and that way is the peer's (RFC 9000 section 2.1). Allowing this endpoint to send there was
   * a bug the receive-side creation rule exposed. */
  if (!ours) return bidi;
  granted = bidi ? connection->peer_limits.initial_max_streams_bidi
                 : connection->peer_limits.initial_max_streams_uni;
  return index < granted;
}
wt_status_t wt_quic_connection_stop_sending(wt_quic_connection_t *connection, uint64_t stream_id,
                                            uint64_t error_code, uint64_t now) {
  wt_quic_stream_t *stream;
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;
  stream = wt_quic_stream_table_find(&connection->streams, stream_id);
  if (stream == NULL) return WT_ERR_STATE;
  /* Only the RECEIVER of a stream's data may ask for it to stop, and only once: RFC 9000 section 19.5
   * makes a second one a STREAM_STATE_ERROR rather than something to ignore. The field is the stream
   * machine's own record of having asked, which is why it is set here rather than kept beside it.
   *
   * For a unidirectional stream the receiver is the endpoint that did NOT open it, and this test used to be
   * inverted: it refused a STOP_SENDING for the peer's unidirectional stream -- the very case the frame exists
   * for -- and allowed one for this endpoint's own, which RFC 9000 section 19.5 makes a STREAM_STATE_ERROR at
   * the peer. Nothing had exercised it, because the only senders were section 6's resets, which the library
   * gates on a stream it can receive on; section 4.6's stream rejection is what reached it (WT-188). */
  if (!wt_quic_stream_id_is_bidirectional(stream_id) &&
      wt_quic_stream_id_from_client(stream_id) ==
          (connection->config.role == WT_QUIC_ROLE_CLIENT)) {
    return WT_ERR_STATE;
  }
  if (stream->sent_stop_sending) return WT_ERR_STATE;
  if (wt_quic_stream_recv_finished(stream)) return WT_ERR_STATE;
  stream->sent_stop_sending = 1;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STOP_SENDING);
  frame.as.stop_sending.id = stream_id;
  frame.as.stop_sending.application_error_code = error_code;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) {
    /* A frame that could not be sent leaves the stream as it was, so a caller that retries is not told it
     * has already asked. */
    stream->sent_stop_sending = 0;
    return status;
  }
  return sent ? WT_OK : WT_ERR_STATE;
}
wt_status_t wt_quic_connection_stream_send_offset(const wt_quic_connection_t *connection,
                                                  uint64_t stream_id, uint64_t *out_offset) {
  const wt_quic_stream_t *stream;

  if (connection == NULL || out_offset == NULL) return WT_ERR_INVALID_ARGUMENT;
  stream = wt_quic_stream_table_find_const(&connection->streams, stream_id);
  if (stream == NULL) return WT_ERR_STATE;
  *out_offset = stream->send_offset;
  return WT_OK;
}
wt_status_t wt_quic_connection_reset_stream_at(wt_quic_connection_t *connection, uint64_t stream_id,
                                               uint64_t error_code, uint64_t reliable_size, uint64_t now) {
  wt_quic_stream_t *stream;
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;
  /* The extension is negotiated by ONE parameter, and a frame that used it without the peer having advertised it
   * would rely on something the peer never said. A plain RESET_STREAM is what a caller has instead; that is why
   * this is a state error rather than a fallback to the frame the peer cannot read. */
  if (connection->peer_limits.reset_stream_at == 0) return WT_ERR_STATE;
  stream = wt_quic_stream_table_find(&connection->streams, stream_id);
  if (stream == NULL) return WT_ERR_STATE;
  if (wt_quic_stream_id_from_client(stream_id) !=
          (connection->config.role == WT_QUIC_ROLE_CLIENT) &&
      !wt_quic_stream_id_is_bidirectional(stream_id)) {
    return WT_ERR_STATE;
  }
  /* A commitment past the end of the stream is one the receiver MUST reject, so a sender must not make it -- and
   * the check comes BEFORE the reset for the same reason: a refused call that had already ended the send half
   * would leave a stream reset by a frame that was never sent. The bound is the bytes sent so far, because that is
   * what the final size becomes when this endpoint resets the stream. */
  if (reliable_size > stream->send_offset) return WT_ERR_INVALID_ARGUMENT;
  status = wt_quic_stream_on_reset_sent(stream, error_code);
  if (status != WT_OK) return status;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RESET_STREAM_AT);
  frame.as.reset_stream_at.id = stream_id;
  frame.as.reset_stream_at.application_error_code = error_code;
  frame.as.reset_stream_at.final_size = stream->final_size;
  frame.as.reset_stream_at.reliable_size = reliable_size;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}
wt_status_t wt_quic_connection_reset_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                            uint64_t error_code, uint64_t now) {
  wt_quic_stream_t *stream;
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;
  stream = wt_quic_stream_table_find(&connection->streams, stream_id);
  if (stream == NULL) return WT_ERR_STATE;
  /* Only the sender of a stream's data may reset it, and this endpoint only sends on its own streams
   * and on the peer's BIDIRECTIONAL ones (RFC 9000 section 2.1). */
  if (wt_quic_stream_id_from_client(stream_id) !=
          (connection->config.role == WT_QUIC_ROLE_CLIENT) &&
      !wt_quic_stream_id_is_bidirectional(stream_id)) {
    return WT_ERR_STATE;
  }
  status = wt_quic_stream_on_reset_sent(stream, error_code);
  if (status != WT_OK) return status;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RESET_STREAM);
  frame.as.reset_stream.id = stream_id;
  frame.as.reset_stream.application_error_code = error_code;
  frame.as.reset_stream.final_size = stream->final_size;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}
wt_status_t wt_quic_connection_send_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           int fin, uint64_t now) {
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;
  if (!stream_id_allowed(connection, stream_id)) return WT_ERR_LIMIT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = stream_id;
  frame.as.stream.offset = offset;
  /* The offset is omitted when it is zero, which is what a sender does for the first bytes of a stream:
   * one byte saved per frame, and the flag is what an encoder needs to reproduce the choice. */
  frame.as.stream.has_offset = offset != 0U;
  frame.as.stream.length = length;
  frame.as.stream.has_length = 1;
  frame.as.stream.fin = fin;
  frame.as.stream.data = data;

  /* A descriptor, so a loss names the stream and the range to send again: the CALLER keeps the bytes --
   * this layer cannot, and should not -- and the lost handler hands the descriptor back to it. */
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 1, 0, stream_id, offset,
                          length, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}
wt_status_t wt_quic_connection_open_stream(wt_quic_connection_t *connection, int bidirectional,
                                           uint64_t *out_stream_id) {
  uint64_t index;
  uint64_t limit;
  uint64_t stream_id;
  wt_status_t status;

  if (connection == NULL || out_stream_id == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;
  *out_stream_id = 0U;

  /* The number comes from the count of what this endpoint has already opened in that class, so it is
   * never reused and never chosen by the caller (RFC 9000 section 2.1). */
  index = wt_quic_stream_table_opened_by_us(&connection->streams, bidirectional);
  stream_id = wt_quic_stream_id_make(connection->config.role == WT_QUIC_ROLE_CLIENT, bidirectional,
                                     index);
  limit = bidirectional ? connection->peer_limits.initial_max_streams_bidi
                        : connection->peer_limits.initial_max_streams_uni;
  status = wt_quic_stream_table_open(&connection->streams, stream_id, 1, limit);
  if (status != WT_OK) return status;

  /* The two flow control limits are the two directions': this endpoint's own for what it will receive,
   * the peer's for what it may send. They are different numbers and are set from different places. */
  {
    wt_quic_stream_t *stream = wt_quic_stream_table_find(&connection->streams, stream_id);
    if (stream != NULL) {
      stream->max_stream_data = connection->config.local_max_stream_data;
      stream->window = connection->config.local_max_stream_data;
      stream->peer_max_stream_data =
          bidirectional ? connection->peer_limits.initial_max_stream_data_bidi_remote
                        : connection->peer_limits.initial_max_stream_data_uni;
    }
  }
  *out_stream_id = stream_id;
  return WT_OK;
}
wt_quic_stream_table_t *wt_quic_connection_streams(wt_quic_connection_t *connection) {
  return connection == NULL ? NULL : &connection->streams;
}
wt_quic_stream_t *wt_quic_connection_stream(wt_quic_connection_t *connection, uint64_t stream_id) {
  if (connection == NULL) return NULL;
  return wt_quic_stream_table_find(&connection->streams, stream_id);
}
uint64_t wt_quic_connection_max_datagram_payload(const wt_quic_connection_t *connection) {
  if (connection == NULL || !connection->peer_limits.set) return 0U;
  if (connection->peer_limits.max_datagram_frame_size == 0U) return 0U;
  return wt_quic_datagram_max_payload(connection->peer_limits.max_datagram_frame_size,
                                      (uint64_t)connection->config.max_datagram_size,
                                      WT_QUIC_DATAGRAM_PACKET_OVERHEAD);
}
wt_status_t wt_quic_connection_send_datagram(wt_quic_connection_t *connection, const uint8_t *data,
                                             size_t length, uint64_t now) {
  wt_quic_frame_t frame;
  uint64_t maximum;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;
  if (connection->peer_limits.max_datagram_frame_size == 0U) {
    /* The peer did not offer DATAGRAM at all (RFC 9221 section 3): sending one would be answered with
     * a protocol violation, so it is refused here by name. */
    return WT_ERR_UNSUPPORTED;
  }
  maximum = wt_quic_connection_max_datagram_payload(connection);
  if ((uint64_t)length > maximum) return WT_ERR_LIMIT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_DATAGRAM);
  frame.as.datagram.data = data;
  frame.as.datagram.length = length;
  /* A DATAGRAM frame is never sent again, which is the whole point of it (RFC 9221 section 5.2): said once, in
   * `control_frame_is_retained`, so that no sender can forget it. */
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}
wt_status_t wt_quic_connection_on_datagram(wt_quic_connection_t *connection, const uint8_t *data,
                                           size_t length, uint64_t now) {
  int discarded = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  status = wt_quic_datagram_queue_push(&connection->datagrams, data, length, now, &discarded);
  return status;
}
wt_status_t wt_quic_connection_receive_datagram(wt_quic_connection_t *connection, uint8_t *out,
                                                size_t capacity, size_t *out_length,
                                                uint64_t *out_received_at) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_quic_datagram_queue_pop(&connection->datagrams, out, capacity, out_length,
                                    out_received_at);
}
