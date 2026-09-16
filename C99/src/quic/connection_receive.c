/* The receive path: one datagram's coalesced packets in, the frame visitor, the handlers
 * this layer owns, path validation and the drain of a refused stream. */

#include "connection_internal.h"

/* Defined below in this file; declared here because the callers come first. */
static wt_status_t arm_path_challenge(wt_quic_connection_t *connection);
static wt_status_t visit_frame(void *context, const wt_quic_frame_t *frame);

static wt_status_t handle_connection_close(wt_quic_connection_t *connection,
                                           const wt_quic_frame_t *frame, uint64_t now) {
  size_t length = frame->as.connection_close.reason_length;

  /* RFC 9000 section 10.2.1: the peer's close ends the connection for both ends. This endpoint sends
   * nothing more and waits out the draining period, which the close state already models -- entering
   * it here and not sending is what "the peer closed first" means. */
  if (length > WT_QUIC_CONNECTION_REASON_MAX) length = WT_QUIC_CONNECTION_REASON_MAX;
  connection->peer_closed = 1;
  connection->peer_close_kind = frame->kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION
                                    ? WT_QUIC_CLOSE_APPLICATION
                                    : WT_QUIC_CLOSE_TRANSPORT;
  connection->peer_error_code = frame->as.connection_close.error_code;
  connection->peer_frame_type = frame->as.connection_close.has_frame_type
                                    ? frame->as.connection_close.frame_type
                                    : 0U;
  connection->peer_reason_length = length;
  if (length != 0U && frame->as.connection_close.reason != NULL) {
    memcpy(connection->peer_reason, frame->as.connection_close.reason, length);
  }
  (void)wt_quic_close_transport(&connection->close, connection->peer_error_code,
                                connection->peer_frame_type, NULL, 0U, now, pto_of(connection));
  connection->close_sent = 1;
  return WT_OK;
}
static uint64_t wire_type_of(wt_quic_frame_type_t kind) {
  if (kind == WT_QUIC_FRAME_KIND_PADDING) return WT_QUIC_FRAME_PADDING;
  if (kind == WT_QUIC_FRAME_KIND_PING) return WT_QUIC_FRAME_PING;
  if (kind == WT_QUIC_FRAME_KIND_ACK) return WT_QUIC_FRAME_ACK;
  if (kind == WT_QUIC_FRAME_KIND_RESET_STREAM) return WT_QUIC_FRAME_RESET_STREAM;
  if (kind == WT_QUIC_FRAME_KIND_STOP_SENDING) return WT_QUIC_FRAME_STOP_SENDING;
  if (kind == WT_QUIC_FRAME_KIND_CRYPTO) return WT_QUIC_FRAME_CRYPTO;
  if (kind == WT_QUIC_FRAME_KIND_NEW_TOKEN) return WT_QUIC_FRAME_NEW_TOKEN;
  if (kind == WT_QUIC_FRAME_KIND_STREAM) return WT_QUIC_FRAME_STREAM_BASE;
  if (kind == WT_QUIC_FRAME_KIND_MAX_DATA) return WT_QUIC_FRAME_MAX_DATA;
  if (kind == WT_QUIC_FRAME_KIND_MAX_STREAM_DATA) return WT_QUIC_FRAME_MAX_STREAM_DATA;
  if (kind == WT_QUIC_FRAME_KIND_MAX_STREAMS) return WT_QUIC_FRAME_MAX_STREAMS_BIDI;
  if (kind == WT_QUIC_FRAME_KIND_DATA_BLOCKED) return WT_QUIC_FRAME_DATA_BLOCKED;
  if (kind == WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED) return WT_QUIC_FRAME_STREAM_DATA_BLOCKED;
  if (kind == WT_QUIC_FRAME_KIND_STREAMS_BLOCKED) return WT_QUIC_FRAME_STREAMS_BLOCKED_BIDI;
  if (kind == WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID) return WT_QUIC_FRAME_NEW_CONNECTION_ID;
  if (kind == WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID) return WT_QUIC_FRAME_RETIRE_CONNECTION_ID;
  if (kind == WT_QUIC_FRAME_KIND_PATH_CHALLENGE) return WT_QUIC_FRAME_PATH_CHALLENGE;
  if (kind == WT_QUIC_FRAME_KIND_PATH_RESPONSE) return WT_QUIC_FRAME_PATH_RESPONSE;
  if (kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT) {
    return WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT;
  }
  if (kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION) {
    return WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION;
  }
  if (kind == WT_QUIC_FRAME_KIND_HANDSHAKE_DONE) return WT_QUIC_FRAME_HANDSHAKE_DONE;
  if (kind == WT_QUIC_FRAME_KIND_RESET_STREAM_AT) return WT_QUIC_FRAME_RESET_STREAM_AT;
  if (kind == WT_QUIC_FRAME_KIND_DATAGRAM) return WT_QUIC_FRAME_DATAGRAM;
  return 0x3fU; /* not a frame type this implementation knows, which every rule refuses */
}
static int frame_forbidden_in_space(wt_quic_frame_type_t kind, wt_quic_space_t space) {
  if (kind == WT_QUIC_FRAME_KIND_PADDING || kind == WT_QUIC_FRAME_KIND_PING ||
      kind == WT_QUIC_FRAME_KIND_ACK || kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT ||
      kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION) {
    return 0; /* section 12.5 allows these in every packet type */
  }
  /* RFC 9000 section 12.4's Table 3 gives CRYPTO the packet types `IH01`: every one this implementation has.
   * Forbidding it in the Application space (which this did) is not a safety property but a defect a third-party
   * peer found -- quinn sends its post-handshake NewSessionTicket on a 1-RTT CRYPTO frame, and this endpoint
   * answered with PROTOCOL_VIOLATION blaming the frame, so the session never started (WT-145). What the RFCs
   * actually forbid is CRYPTO in 0-RTT (RFC 9001 section 4.6.1), and this tree implements no 0-RTT. The
   * post-handshake CONTENT is the handshake layer's to accept or ignore; the frame's permission is not. */
  if (kind == WT_QUIC_FRAME_KIND_CRYPTO) return 0;
  return space != WT_QUIC_SPACE_APPLICATION;
}
static uint64_t frame_stream_id(const wt_quic_frame_t *frame) {
  /* If-chains rather than a switch: this tree compiles with -Wswitch-enum, which wants every enumerator
   * named, and a frame that does not name a stream has no identifier to report. */
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM) return frame->as.stream.id;
  if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM) return frame->as.reset_stream.id;
  if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM_AT) return frame->as.reset_stream_at.id;
  if (frame->kind == WT_QUIC_FRAME_KIND_STOP_SENDING) return frame->as.stop_sending.id;
  if (frame->kind == WT_QUIC_FRAME_KIND_MAX_STREAM_DATA) return frame->as.max_stream_data.id;
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED) return frame->as.stream_data_blocked.id;
  return 0U;
}
wt_status_t wt_quic_connection_validate_path(wt_quic_connection_t *connection, uint64_t now) {
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_connection_is_closed(connection) != 0) return WT_ERR_STATE;
  /* Asking twice is not an error: the second call is a caller that wants the path validated, and one is already
   * on its way. A caller that wants a FRESH validation waits for the first to answer or fail. */
  if (connection->path_validating != 0) return WT_OK;

  status = arm_path_challenge(connection);
  if (status != WT_OK) return status;
  connection->path_validating = 1;
  connection->path_validation_attempts = 1U;
  connection->path_validation_deadline = now + pto_of(connection);
  /* And it goes out now rather than at the next flush: a caller asking to validate a path is asking now. */
  return flush_path_challenge(connection, now);
}
int wt_quic_connection_path_validating(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->path_validating : 0;
}
int wt_quic_connection_path_validated(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->path_validated : 0;
}
uint64_t wt_quic_connection_path_challenges_sent(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->path_challenges_sent : 0U;
}
uint64_t wt_quic_connection_path_responses_sent(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->path_responses_sent : 0U;
}
uint64_t wt_quic_connection_path_validation_failures(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->path_validation_failures : 0U;
}
wt_status_t deliver_to_handler(wt_quic_connection_t *connection, wt_quic_visit_t *visit,
                                      const wt_quic_frame_t *frame) {
  connection->frames_delivered++;
  wt_status_t status;

  /* The flag is set once, in `visit_frame`, from the frame's KIND (RFC 9000 section 13.2.1), which is where the
   * rule belongs: a handler that had to remember would be a second owner of it. */
  if (connection->handler == NULL) return WT_OK;
  status = connection->handler(connection->handler_context, visit->space, frame);
  if (status == WT_OK) return WT_OK;
  {
    int application = connection->close_code_set ? connection->close_code_application : 0;
    uint64_t code = connection->close_code_set ? connection->close_code : WT_QUIC_INTERNAL_ERROR;
    uint64_t type = connection->close_code_set ? connection->close_frame_type : 0U;
    connection->close_code_set = 0;
    connection->close_code_application = 0;
    /* Kept, because the hint above is about to be cleared and "why did this endpoint close" is not answerable
     * from a cleared hint: a caller that asked got `WT_OK` and `close_code_set == 0`, which reads exactly like a
     * connection that never closed (WT-144). */
    connection->close_cause = status;
    connection->close_cause_frame = wire_type_of(frame->kind);
    if (application != 0) {
      /* An application close, so the peer is told the code this layer was refused WITH -- an HTTP/3 error code in
       * the application's space -- rather than a transport code invented here (WT-158). */
      (void)wt_quic_close_application(&connection->close, code, NULL, 0U, visit->now, pto_of(connection));
    } else {
      (void)close_with(connection, code, type, visit->now);
    }
  }
  return status;
}
static wt_status_t handle_path_challenge(wt_quic_connection_t *connection, const wt_quic_frame_t *frame,
                                        wt_quic_visit_t *visit) {
  wt_quic_frame_t response = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PATH_RESPONSE);
  int sent = 0;

  response.as.path_response.data = frame->as.path_challenge.data;
  if (frame->as.path_challenge.data != NULL) {
    if (send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &response, 1, &sent, visit->now) == WT_OK &&
        sent != 0) {
      connection->path_responses_sent++;
    }
  }
  return deliver_to_handler(connection, visit, frame);
}
static wt_status_t handle_path_response(wt_quic_connection_t *connection, const wt_quic_frame_t *frame,
                                        wt_quic_visit_t *visit) {
  if (connection->path_validating != 0 && frame->as.path_response.data != NULL &&
      wt_ct_equal(connection->path_challenge, frame->as.path_response.data,
                  WT_QUIC_PATH_CHALLENGE_LENGTH) != 0) {
    connection->path_validating = 0;
    connection->path_challenge_pending = 0;
    connection->path_validated = 1;
    connection->path_responses_matched++;
  }
  return deliver_to_handler(connection, visit, frame);
}
static wt_status_t arm_path_challenge(wt_quic_connection_t *connection) {
  wt_status_t status = wt_random_bytes(connection->path_challenge, WT_QUIC_PATH_CHALLENGE_LENGTH);
  if (status != WT_OK) return status;
  connection->path_challenge_pending = 1;
  return WT_OK;
}
wt_status_t flush_path_challenge(wt_quic_connection_t *connection, uint64_t now) {
  wt_quic_frame_t challenge = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PATH_CHALLENGE);
  int sent = 0;
  wt_status_t status;

  if (connection->path_challenge_pending == 0) return WT_OK;
  if (!connection->has_keys_out[WT_QUIC_SPACE_APPLICATION]) return WT_OK;

  challenge.as.path_challenge.data = connection->path_challenge;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &challenge, 1, &sent, now);
  if (status != WT_OK) return status;
  if (sent == 0) return WT_OK;
  connection->path_challenge_pending = 0;
  connection->path_challenges_sent++;
  return WT_OK;
}
wt_status_t path_validation_on_timeout(wt_quic_connection_t *connection, uint64_t now) {
  wt_status_t status;

  if (connection->path_validating == 0) return WT_OK;
  if (now < connection->path_validation_deadline) return WT_OK;

  if (connection->path_validation_attempts >= WT_QUIC_PATH_VALIDATION_ATTEMPTS) {
    connection->path_validating = 0;
    connection->path_challenge_pending = 0;
    connection->path_validation_failures++;
    return WT_OK;
  }
  connection->path_validation_attempts++;
  connection->path_validation_deadline = now + pto_of(connection);
  status = arm_path_challenge(connection);
  if (status != WT_OK) return status;
  /* And it goes out on this timer rather than waiting for a flush: the timer is what the caller's loop runs, and
   * a challenge that armed here but left the sending to a later call would be a probe this endpoint decided to
   * send and then did not. */
  return flush_path_challenge(connection, now);
}
static wt_status_t visit_frame(void *context, const wt_quic_frame_t *frame) {
  wt_quic_visit_t *visit = context;
  wt_quic_connection_t *connection = visit->connection;

  connection->frames_walked++;
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM) connection->stream_frames_seen++;

  /* RFC 9000 section 10.2.1: once the connection is closed, only PADDING, the close's own frames and the
   * frames a probe needs may still be processed -- everything else is ignored, and ignoring it STOPS the
   * walk rather than failing it, because a peer's late frame is not this endpoint's error and the
   * connection is already closed. */
  if (wt_quic_connection_is_closed(connection) &&
      !wt_quic_close_accepts_frame_type(wire_type_of(frame->kind))) {
    return WT_OK;
  }

  /* RFC 9000 section 12.4: a frame that may not appear in this packet type is a PROTOCOL_VIOLATION,
   * named by the frame's own type so the peer can see which one. */
  if (frame_forbidden_in_space(frame->kind, visit->space)) {
    return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, wire_type_of(frame->kind), visit->now);
  }

  /* RFC 9000 section 13.2.1: "All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered
   * ack-eliciting." That makes it a property of the PACKET -- any such frame makes the whole packet one that
   * asks for an acknowledgement -- so this is OR-ed and never cleared: a padded Initial's trailing PADDING frames
   * must not undo the CRYPTO frame that asked for it, which is exactly what a first version of this did.
   *
   * Doing it here rather than in each case is also why MAX_DATA, MAX_STREAMS, a NEW_CONNECTION_ID, a
   * RETIRE_CONNECTION_ID and a HANDSHAKE_DONE were treated as NOTHING: the peer never acknowledged the packets
   * carrying them, so a sender could not learn that they had arrived, and a frame re-sent on loss would be
   * re-sent for ever (WT-170). */
  if (frame->kind != WT_QUIC_FRAME_KIND_ACK && frame->kind != WT_QUIC_FRAME_KIND_PADDING &&
      frame->kind != WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT &&
      frame->kind != WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION) {
    visit->ack_eliciting = 1;
  }
  switch (frame->kind) {
    case WT_QUIC_FRAME_KIND_PADDING:
      return WT_OK;
    case WT_QUIC_FRAME_KIND_ACK:
      return handle_ack(connection, visit->space, frame, visit->now);
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
      visit->saw_close = 1;
      return handle_connection_close(connection, frame, visit->now);
    case WT_QUIC_FRAME_KIND_MAX_DATA:
      /* The peer raising the connection-level limit it grants. RFC 9000 section 4.1 makes a limit that
       * decreases a protocol error, because this endpoint has already been told it may send that much;
       * raising it is the ordinary way an application that has read data says so. */
      if (frame->as.max_data.maximum < connection->peer_limits.initial_max_data) {
        return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, WT_QUIC_FRAME_MAX_DATA,
                          visit->now);
      }
      connection->peer_limits.initial_max_data = frame->as.max_data.maximum;
      return WT_OK;
    case WT_QUIC_FRAME_KIND_MAX_STREAMS: {
      /* The same for the stream counts, with the direction the frame names: RFC 9000 section 4.6. */
      uint64_t *granted = frame->as.max_streams.direction == WT_QUIC_STREAM_BIDIRECTIONAL
                              ? &connection->peer_limits.initial_max_streams_bidi
                              : &connection->peer_limits.initial_max_streams_uni;
      if (frame->as.max_streams.maximum < *granted) {
        return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, WT_QUIC_FRAME_MAX_STREAMS_BIDI,
                          visit->now);
      }
      *granted = frame->as.max_streams.maximum;
      return WT_OK;
    }
    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      /* RFC 9000 section 19.20: only a CLIENT may receive this frame. A server that receives one has a
       * peer that believes it is the server, which is a PROTOCOL_VIOLATION rather than something to
       * ignore -- this frame is what tells a client its handshake is confirmed, so a client sending one
       * is confused about which end of the connection it is. A client's use of it is the handshake
       * layer's business, so it is still handed on. */
      if (connection->config.role == WT_QUIC_ROLE_SERVER) {
        return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, WT_QUIC_FRAME_HANDSHAKE_DONE,
                          visit->now);
      }
      return deliver_to_handler(connection, visit, frame);
    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
    case WT_QUIC_FRAME_KIND_STREAM:
    case WT_QUIC_FRAME_KIND_RESET_STREAM:
    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
    case WT_QUIC_FRAME_KIND_STOP_SENDING:
    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED: {
      /* Every frame that names a stream makes that stream exist if it does not (RFC 9000 section 3.2),
       * and MAX_STREAM_DATA then raises the one stream's allowance -- the per-stream counterpart of
       * MAX_DATA, and the only one of these this layer acts on for now; the rest are the stream
       * machine's, and are handed on below. */
      wt_quic_stream_t *stream = NULL;
      wt_status_t status = ensure_peer_stream(connection, frame_stream_id(frame),
                                              wire_type_of(frame->kind), visit->now, &stream);
      if (status != WT_OK) return status;
      /* The frames that change a stream's state are handed to its machine here, before the caller
       * sees them: a RESET_STREAM ends the receive half with the peer's final size, and a STOP_SENDING
       * asks this endpoint to stop sending -- both are facts about the stream rather than about the
       * application's data, which is why the state machine owns them and the handler only observes. */
      if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM && stream != NULL) {
        status = wt_quic_stream_on_reset_received(stream,
                                                  frame->as.reset_stream.application_error_code,
                                                  frame->as.reset_stream.final_size);
        if (status != WT_OK) {
          /* A reset whose final size contradicts what arrived is the FINAL_SIZE_ERROR of RFC 9000
           * section 4.5. */
          return close_with(connection, WT_QUIC_FINAL_SIZE_ERROR, wire_type_of(frame->kind),
                            visit->now);
        }
      } else if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM_AT && stream != NULL) {
        /* The reliable-stream-reset extension. Which rule a refusal broke decides the code the peer is told, and
         * the status alone cannot say: a commitment past the end of the stream is a FRAME_ENCODING_ERROR, while a
         * changed error code or final size is a STREAM_STATE_ERROR (draft-ietf-quic-reliable-stream-reset). */
        status = wt_quic_stream_on_reset_at_received(stream,
                                                     frame->as.reset_stream_at.application_error_code,
                                                     frame->as.reset_stream_at.final_size,
                                                     frame->as.reset_stream_at.reliable_size);
        if (status != WT_OK) {
          uint64_t code = frame->as.reset_stream_at.reliable_size > frame->as.reset_stream_at.final_size
                              ? WT_QUIC_FRAME_ENCODING_ERROR
                              : WT_QUIC_STREAM_STATE_ERROR;
          return close_with(connection, code, wire_type_of(frame->kind), visit->now);
        }
      } else if (frame->kind == WT_QUIC_FRAME_KIND_STOP_SENDING && stream != NULL) {
        status = wt_quic_stream_on_stop_sending(stream,
                                               frame->as.stop_sending.application_error_code);
        if (status != WT_OK) {
          return close_with(connection, WT_QUIC_STREAM_STATE_ERROR, wire_type_of(frame->kind),
                            visit->now);
        }
      } else if (frame->kind == WT_QUIC_FRAME_KIND_STREAM && stream != NULL) {
        /* The bytes are accounted against BOTH limits. WHICH limit an overrun broke is decided from the
         * limits rather than from the status: the module reports a per-stream overrun, a connection
         * overrun and a final-size contradiction with two statuses between them, so the caller
         * recomputes the credit the module would have charged and asks each limit in turn -- section 4.1
         * for flow control, section 4.5 for the final size. */
        uint64_t credit = 0U;
        int in_order = 0;
        status = wt_quic_stream_on_data(stream, &connection->flow, frame->as.stream.offset,
                                        frame->as.stream.length, frame->as.stream.fin, &credit,
                                        &in_order);
        if (status != WT_OK) {
          uint64_t code;
          if (frame->as.stream.offset > UINT64_MAX - frame->as.stream.length) {
            code = WT_QUIC_FRAME_ENCODING_ERROR;
          } else {
            uint64_t end = frame->as.stream.offset + frame->as.stream.length;
            uint64_t needed = end > stream->recv_highest ? end - stream->recv_highest : 0U;
            if (end > stream->max_stream_data ||
                connection->flow.data_received + needed > connection->flow.max_data) {
              code = WT_QUIC_FLOW_CONTROL_ERROR;
            } else {
              code = WT_QUIC_FINAL_SIZE_ERROR;
            }
          }
          return close_with(connection, code, wire_type_of(frame->kind), visit->now);
        }
        /* RFC 9000 section 4.1: a receiver extends its limit as the data arrives, so a sender is never
         * blocked by accounting it cannot see. This runtime hands each frame's bytes to the caller's
         * handler immediately, so ARRIVAL IS CONSUMPTION and the extension follows the account. */
        if (wt_quic_flow_should_extend(&connection->flow)) {
          wt_quic_frame_t grant = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
          uint64_t next = wt_quic_flow_next_max_data(&connection->flow);
          int granted = 0;
          grant.as.max_data.maximum = next;
          status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &grant, 1, 0, 0, 0U, 0U, 0U,
                                  &granted, visit->now);
          if (status == WT_OK && granted) {
            wt_quic_flow_on_max_data_sent(&connection->flow, next);
            connection->local_max_data = next;
          }
        }
        if (wt_quic_stream_should_extend(stream)) {
          wt_quic_frame_t grant = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_STREAM_DATA);
          uint64_t next = wt_quic_stream_next_max_stream_data(stream);
          int granted = 0;
          grant.as.max_stream_data.id = frame->as.stream.id;
          grant.as.max_stream_data.maximum = next;
          status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &grant, 1, 0, 0, 0U, 0U, 0U,
                                  &granted, visit->now);
          if (status == WT_OK && granted) {
            wt_quic_stream_on_max_stream_data_sent(stream, next);
          }
        }
      } else if (frame->kind == WT_QUIC_FRAME_KIND_MAX_STREAM_DATA && stream != NULL) {
        status = wt_quic_stream_on_max_stream_data(stream, frame->as.max_stream_data.maximum);
        if (status != WT_OK) {
          return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION,
                            wire_type_of(frame->kind), visit->now);
        }
      }
      return deliver_to_handler(connection, visit, frame);
    }
    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
      return handle_new_connection_id(connection, frame, visit->now);
    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
      return handle_retire_connection_id(connection, frame, visit);
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
      return handle_path_challenge(connection, frame, visit);
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
      return handle_path_response(connection, frame, visit);
    /* PING, CRYPTO, NEW_TOKEN, DATA_BLOCKED, STREAMS_BLOCKED and DATAGRAM carry no work for this layer, so they
     * go to the handler like any other frame. They used to share the PATH_CHALLENGE label above, which was a
     * REMOTE CRASH: `handle_path_challenge` reads `frame->as.path_challenge.data`, and for a frame of any other
     * kind that member is whatever the previous frame left in the decoder's reused union -- for a PING, an
     * uninitialised scalar. A non-NULL garbage pointer passed the null check and was then memcpy'd from, so a
     * peer that merely sent a PING took this endpoint down with SIGSEGV. Found on the VPS matrix against quinn,
     * quiche and h3, which send one; pywebtransport, which did not in the window, was unaffected.
     *
     * Everything that is not PADDING, an acknowledgement or a close makes the packet ack-eliciting, whether or
     * not this layer acts on it itself (RFC 9000 section 13.2.1). */
    case WT_QUIC_FRAME_KIND_PING:
    case WT_QUIC_FRAME_KIND_CRYPTO:
    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      return deliver_to_handler(connection, visit, frame);
  }
  /* A kind this layer does not know cannot come from the decoder, which refuses unknown types, so
   * this is a header/library mismatch rather than peer data. */
  return WT_ERR_STATE;
}
static wt_status_t process_packet(wt_quic_connection_t *connection, wt_quic_space_t space,
                                  const uint8_t *payload, size_t payload_length, int *out_ack_eliciting,
                                  uint64_t now, uint64_t destination_sequence) {
  wt_quic_visit_t visit;
  wt_quic_error_t error = WT_QUIC_NO_ERROR;
  wt_status_t status;

  visit.connection = connection;
  visit.space = space;
  visit.now = now;
  visit.ack_eliciting = 0;
  visit.saw_close = 0;
  visit.destination_sequence = destination_sequence;

  status = wt_quic_frames_decode(payload, payload_length, visit_frame, &visit, &error);
  if (status != WT_OK) {
    /* RFC 9000 section 12.4: a frame that cannot be decoded is a connection error, and the per-frame
     * rules name the code -- the decoder reports it in `error` where the failure is one of those, and a
     * truncated frame (also a FRAME_ENCODING_ERROR by the same section) comes back as WT_ERR_TRUNCATED
     * from the cursor helpers without a code. Closing here is what TELLS the peer: returning the status
     * instead left the connection open, the peer uninformed, and the failure visible only to whoever
     * called `wt_quic_connection_receive` (WT-83). A status from the visitor is left alone, because the
     * paths that raise one have already closed the connection with the code they chose. */
    if (!wt_quic_connection_is_closed(connection) &&
        (status == WT_ERR_PROTOCOL || status == WT_ERR_TRUNCATED)) {
      uint64_t code = error == WT_QUIC_NO_ERROR ? (uint64_t)WT_QUIC_FRAME_ENCODING_ERROR
                                                : (uint64_t)error;
      (void)close_with(connection, code, 0U, now);
    }
    if (wt_quic_connection_is_closed(connection)) {
      if (out_ack_eliciting != NULL) *out_ack_eliciting = visit.ack_eliciting;
      return WT_OK;
    }
    return status;
  }
  if (out_ack_eliciting != NULL) *out_ack_eliciting = visit.ack_eliciting;
  return WT_OK;
}
static wt_status_t read_application_packet(wt_quic_connection_t *connection, uint8_t *packet, size_t length,
                                           uint64_t largest_received, size_t local_connection_id_len,
                                           wt_quic_received_packet_t *out, uint64_t now) {
  uint8_t saved[WT_QUIC_MAX_PACKET];
  size_t total_len = 0U;
  size_t pn_offset = 0U;
  size_t pn_len = 0U;
  int short_header = 0;
  int phase;
  uint64_t truncated = 0U;
  uint64_t packet_number;
  int has_reference;
  size_t i;
  wt_status_t status;

  status = wt_quic_packet_unprotect_header(packet, length,
                                           &connection->keys_in[WT_QUIC_SPACE_APPLICATION],
                                           local_connection_id_len, &pn_offset, &total_len, &pn_len,
                                           &short_header);
  if (status != WT_OK) return status;
  phase = (packet[0] & WT_QUIC_KEY_PHASE_BIT) != 0U ? 1 : 0;

  if (phase == connection->key_phase_in) {
    status = wt_quic_packet_open(packet, total_len, pn_len,
                                 &connection->keys_in[WT_QUIC_SPACE_APPLICATION], largest_received,
                                 local_connection_id_len, out);
    if (status != WT_OK) return status;
    if (connection->key_phase_in_first_pn_set == 0) {
      connection->key_phase_in_first_pn = out->packet_number;
      connection->key_phase_in_first_pn_set = 1;
    }
    return WT_OK;
  }

  /* The packet number decides between the two phases that share this bit: lower than any number of the current
   * phase is a delayed packet from the one being retired, higher is the start of the next. */
  for (i = 0U; i < pn_len; i++) truncated = (truncated << 8) | (uint64_t)packet[pn_offset + i];
  packet_number = wt_quic_packet_number_decode(truncated, pn_len, largest_received);
  has_reference = connection->key_phase_in_first_pn_set != 0;

  if (has_reference && packet_number < connection->key_phase_in_first_pn) {
    if (connection->previous_keys_in_ready == 0) return WT_ERR_AUTHENTICATION;
    return wt_quic_packet_open(packet, total_len, pn_len, &connection->previous_keys_in, largest_received,
                               local_connection_id_len, out);
  }

  /* The peer's next phase. Whether the packet is remembered for a second attempt depends on whether there is
   * another key set it could belong to: with no packet of the current phase seen yet, a delayed packet from the
   * retired phase is just as likely as the start of the next, and section 6.5's comparison has nothing to compare
   * against. */
  {
    int keep_copy = connection->previous_keys_in_ready != 0 && total_len <= sizeof(saved);
    if (keep_copy) memcpy(saved, packet, total_len);

    status = ensure_next_keys_in(connection);
    if (status != WT_OK) return status;
    status = wt_quic_packet_open(packet, total_len, pn_len, &connection->next_keys_in, largest_received,
                                 local_connection_id_len, out);
    if (status == WT_OK) {
      /* The packet authenticated in the phase after this endpoint's: the peer has updated, and it has to be
       * answered in the new keys. */
      return key_update_respond(connection, now);
    }
    if (status != WT_ERR_AUTHENTICATION || keep_copy == 0) return status;

    /* The retired keys are the only other possibility. If THEY open it, one of two things is true: the packet was
     * delayed and its number is below the current phase's first (handled above, so this is the no-reference
     * case), or the peer protected a HIGHER-numbered packet with the older keys -- which section 6.4 makes
     * KEY_UPDATE_ERROR. */
    memcpy(packet, saved, total_len);
    status = wt_quic_packet_open(packet, total_len, pn_len, &connection->previous_keys_in, largest_received,
                                 local_connection_id_len, out);
    if (status != WT_OK) return WT_ERR_AUTHENTICATION;
    if (has_reference) {
      connection->key_update_errors++;
      return close_with(connection, WT_QUIC_KEY_UPDATE_ERROR, 0U, now);
    }
    return WT_OK;
  }
}
wt_status_t wt_quic_connection_receive(wt_quic_connection_t *connection, uint64_t now) {
  uint8_t datagram[WT_UDP_MAX_DATAGRAM];
  wt_udp_address_t from;
  size_t offset = 0U;
  size_t datagram_length = 0U;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (connection->socket.fd < 0) return WT_ERR_STATE;

  memset(&from, 0, sizeof(from));
  status = wt_udp_receive(&connection->socket, datagram, sizeof(datagram), &datagram_length, &from);
  if (status != WT_OK) return status;

  /* A server learns its peer from the first packet and keeps it: RFC 9000 section 7.2's server has no
   * address until the client's first Initial arrives. A packet from anywhere else is discarded rather
   * than answered, because answering would be a way to make this endpoint send to an arbitrary
   * address. */
  if (!connection->has_peer) {
    connection->peer = from;
    connection->has_peer = 1;
  } else if (!wt_udp_address_equal(&from, &connection->peer)) {
    connection->packets_discarded++;
    return WT_OK;
  }

  if (datagram_length == 0U) {
    /* An empty datagram is legal UDP and carries no packet. */
    connection->packets_discarded++;
    return WT_OK;
  }

  connection->packets_received++;
  connection->bytes_received += (uint64_t)datagram_length;
  connection->last_activity = now;

  /* A datagram is a sequence of coalesced packets (RFC 9000 section 12.2), each with its own
   * encryption level, so the loop advances by the packet's own length rather than by the datagram's. */
  while (offset < datagram_length) {
    wt_quic_received_packet_t packet;
    wt_quic_space_t space;
    int ack_eliciting = 0;
    uint64_t largest_received = 0U;

    /* The space has to be known before the packet can be read, because it selects the keys AND the
     * largest received packet number that reconstructs this packet's truncated number. The type bits
     * of a long header are not masked (the mask covers the low four), so reading the first byte here
     * is reading the wire and not the mask. */
    {
      wt_quic_packet_kind_t kind;
      uint8_t first = datagram[offset];

      status = wt_quic_packet_kind(datagram + offset, datagram_length - offset, &kind);
      if (status == WT_ERR_TRUNCATED) {
        connection->packets_discarded++;
        return WT_OK;
      }
      if (status != WT_OK) return status;
      if (kind == WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION) {
        /* A list of versions rather than a packet. The response to one is the connection's business
         * rather than this loop's. */
        connection->packets_discarded++;
        return WT_OK;
      }
      if (kind == WT_QUIC_PACKET_KIND_SHORT) {
        space = WT_QUIC_SPACE_APPLICATION;
      } else {
        uint32_t type_bits = (uint32_t)((first >> 4) & 0x03U);
        /* RFC 9000 section 5.2.2: "an endpoint MUST discard packets with a version it does not support". The type
         * bits are not version-specific in the two versions this build knows, so a long header carrying version 2
         * (or anything else) was parsed with version 1's semantics, with the masking, the packet-number encoding
         * and the key derivation that go with it. Keys still had to match, so this was never exploitable -- it was
         * a frame from a version this endpoint does not speak being answered in the version it does. Checked here,
         * before the space is chosen, so nothing downstream sees it. */
        {
          uint32_t version = 0U;
          if (datagram_length - offset >= 5U) {
            version = ((uint32_t)datagram[offset + 1U] << 24) | ((uint32_t)datagram[offset + 2U] << 16) |
                      ((uint32_t)datagram[offset + 3U] << 8) | (uint32_t)datagram[offset + 4U];
          }
          if (version != connection->config.version) {
            connection->packets_discarded++;
            return WT_OK;
          }
        }
        if (type_bits == (uint32_t)WT_QUIC_PACKET_INITIAL) {
          space = WT_QUIC_SPACE_INITIAL;
        } else if (type_bits == (uint32_t)WT_QUIC_PACKET_HANDSHAKE) {
          space = WT_QUIC_SPACE_HANDSHAKE;
        } else if (type_bits == (uint32_t)WT_QUIC_PACKET_RETRY) {
          /* RFC 9000 section 17.2.5: a Retry is not READ -- it is answered, and answering it changes the
           * destination connection ID and the Initial keys. It occupies the whole datagram, so the loop ends
           * here either way. */
          return on_retry_packet(connection, datagram + offset, datagram_length - offset, now);
        } else {
          /* 0-RTT shares the Application packet number space but not its keys, and this runtime has one
           * key set per space: reading a 0-RTT packet with the 1-RTT keys would report an
           * authentication failure for a packet that is correctly protected. It is discarded by name rather
           * than through a confusing failure (WT-71 records the 0-RTT keys). */
          connection->packets_discarded++;
          return WT_OK;
        }
      }
      /* RFC 9000 section 14.1: a server MUST discard an Initial packet carried in a UDP datagram whose
       * payload is smaller than 1200 bytes. The rule is about the datagram, so the rest of it goes too:
       * a coalesced packet after a short Initial would be located only from a datagram the peer built
       * against a different rule. */
      if (space == WT_QUIC_SPACE_INITIAL && connection->config.role == WT_QUIC_ROLE_SERVER &&
          datagram_length < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE) {
        connection->packets_discarded++;
        return WT_OK;
      }
    }
    if (!connection->has_keys_in[space]) {
      /* A packet for a key this endpoint does not have is discarded (RFC 9000 section 5.2): during a
       * handshake it is ordinary, and after one it means a peer that is sending at a level this
       * endpoint has already forgotten. */
      connection->packets_discarded++;
      return WT_OK;
    }
    if (connection->spaces[space].received.has_largest) {
      largest_received = connection->spaces[space].received.largest_received;
    }

    memset(&packet, 0, sizeof(packet));
    if (space == WT_QUIC_SPACE_APPLICATION) {
      /* The Application space is the one that can be key-updated, so its keys are chosen AFTER the header
       * protection comes off: the Key Phase bit is inside the mask (RFC 9001 sections 5.4 and 6.2). */
      status = read_application_packet(connection, datagram + offset, datagram_length - offset,
                                       largest_received, connection->local_connection_id_length, &packet,
                                       now);
    } else {
      status = wt_quic_packet_read(datagram + offset, datagram_length - offset,
                                   &connection->keys_in[space], largest_received,
                                   connection->local_connection_id_length, &packet);
    }
    if (status == WT_ERR_AUTHENTICATION) {
      /* RFC 9001 section 5.3: a packet that does not authenticate is discarded. So is the rest of the
       * datagram, because the next coalesced packet's position is only known from a header this one did
       * not authenticate.
       *
       * And section 6.6 counts them: "endpoints MUST count the number of received packets that fail
       * authentication during the lifetime of a connection... If the total... exceeds the integrity limit for
       * the selected AEAD, the endpoint MUST immediately close the connection with a connection error of type
       * AEAD_LIMIT_REACHED and not process any more packets." A QUIC endpoint ignores unauthenticated packets
       * rather than closing on the first, which is exactly why the count exists (WT-169). */
      connection->aead_failed++;
      if (connection->aead_failed > connection->aead_integrity_limit) {
        return close_with(connection, WT_QUIC_AEAD_LIMIT_REACHED, 0U, now);
      }
      connection->packets_discarded++;
      return WT_OK;
    }
    if (status == WT_ERR_TRUNCATED) {
      connection->packets_discarded++;
      return WT_OK;
    }
    if (status != WT_OK) return status;

    /* RFC 9000 section 7.2: a packet whose destination connection ID is not this endpoint's is not for
     * this connection, which is ordinary during a handshake and not an error. Every ID this endpoint
     * issued and has not retired counts as its own. */
    {
      uint64_t destination_sequence = 0U;
      if (!local_connection_id_sequence(connection, packet.destination_connection_id,
                                        packet.destination_connection_id_len,
                                        &destination_sequence)) {
        connection->packets_discarded++;
        return WT_OK;
      }
      /* RFC 9000 section 7.3: "Endpoints MUST validate that received transport parameters match received
       * connection ID values", where the value for `initial_source_connection_id` is "the value that an
       * endpoint used in the ... Source Connection ID fields of Initial packets that it sent". The parameters
       * arrive in CRYPTO frames carried by these very packets, so the SCID is recorded from the first
       * authenticated long-header packet addressed to this endpoint, and `set_peer_parameters` compares the
       * parameter with it before adopting it as this connection's destination. A short header carries no
       * SCID, and a packet for another connection proves nothing about this one, which is why this sits
       * after the destination check. */
      if (packet.short_header == 0 && connection->peer_source_connection_id_set == 0 &&
          packet.source_connection_id_len <= (size_t)WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
        if (packet.source_connection_id_len > 0U) {
          memcpy(connection->peer_source_connection_id, packet.source_connection_id,
                 packet.source_connection_id_len);
        }
        connection->peer_source_connection_id_length = packet.source_connection_id_len;
        connection->peer_source_connection_id_set = 1;
      }
      status = process_packet(connection, space, packet.payload, packet.payload_len, &ack_eliciting,
                              now, destination_sequence);
    }
    if (status != WT_OK) return status;
    /* RFC 9000 section 17.2.5.2: after the client has received and PROCESSED a packet from the server, every later
     * Retry is discarded. This is the moment that becomes true. */
    if (space == WT_QUIC_SPACE_INITIAL && connection->config.role == WT_QUIC_ROLE_CLIENT) {
      connection->server_packet_received = 1;
    }

    /* RFC 9001 section 4.9.1: the Initial keys are discarded when the first Handshake packet is
     * successfully processed. Both ends can derive them from a connection ID either can see, so keeping
     * them would leave the connection readable by anyone who saw its first packet -- and the packet
     * that proves the peer has the handshake keys is that first Handshake packet, which is why this is
     * the moment and not the moment the keys were installed. */
    if (space == WT_QUIC_SPACE_HANDSHAKE) {
      (void)wt_quic_connection_discard_keys(connection, WT_QUIC_SPACE_INITIAL);
    }

    /* The received set is updated after the frames are processed, because whether the acknowledgement
     * is urgent depends on what they carried. A packet that turned out not to be ack-eliciting is still
     * recorded, so a later acknowledgement covers it. */
    status = wt_quic_ack_record(&connection->spaces[space].received, packet.packet_number,
                                ack_eliciting);
    if (status != WT_OK) return status;
    connection->received_at[space] = now;

    if (packet.total_len == 0U || packet.total_len > datagram_length - offset) {
      /* A decoder that reported a packet longer than what is left would make this loop spin. */
      return WT_ERR_STATE;
    }
    offset += packet.total_len;
  }
  return WT_OK;
}
