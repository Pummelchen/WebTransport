/* The send path: frame encoding into slots, one packet out, the control-frame retention
 * RFC 9000 section 13.3 obliges, and the flush that drives both. */

#include "connection_internal.h"

static size_t packet_number_length_for(uint64_t next, const wt_quic_pn_space_t *space) {
  uint64_t difference = space->has_largest_acked ? next - space->largest_acked : next + 1U;

  if (difference < 0x80U) return 1U;
  if (difference < 0x8000U) return 2U;
  if (difference < 0x800000U) return 3U;
  return 4U;
}
static size_t sample_minimum(size_t packet_number_length) {
  return packet_number_length >= 4U ? 0U : 4U - packet_number_length;
}
static int alloc_frame(wt_quic_connection_t *connection, wt_quic_space_t space, int is_crypto,
                       uint64_t stream_id, uint64_t offset, size_t length) {
  size_t i;
  for (i = 0U; i < WT_QUIC_CONNECTION_FRAMES_MAX; i++) {
    if (!connection->frames[i].in_use) {
      connection->frames[i].in_use = 1;
      connection->frames[i].space = space;
      connection->frames[i].is_crypto = is_crypto;
      connection->frames[i].stream_id = stream_id;
      connection->frames[i].offset = offset;
      connection->frames[i].length = length;
      return (int)i;
    }
  }
  return -1;
}
void free_frame(wt_quic_connection_t *connection, uint64_t tag) {
  if (tag < (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) {
    connection->frames[tag].in_use = 0;
  }
}
int probe_time(const wt_quic_connection_t *connection, wt_quic_space_t space, uint64_t *out_time) {
  const wt_quic_pn_space_t *space_state = &connection->spaces[space];
  uint64_t earliest = 0U;
  uint64_t backoff;
  size_t i;
  int found = 0;

  if (wt_quic_loss_pto(&connection->loss, (uint8_t)space, &space_state->rtt,
                       max_ack_delay_for(connection, space), out_time) == WT_OK) {
    return 1;
  }
  /* Nothing to probe for unless something ack-eliciting is outstanding. */
  if (wt_quic_loss_ack_eliciting_in_flight(&connection->loss) == 0U) return 0;
  for (i = 0U; i < connection->loss.count; i++) {
    if (!connection->loss.sent[i].ack_eliciting) continue;
    if (!found || connection->loss.sent[i].time_sent < earliest) {
      earliest = connection->loss.sent[i].time_sent;
      found = 1;
    }
  }
  if (!found) return 0;
  /* The backoff is clamped: the loss module bounds its own count, and a shift of a large count would
   * be undefined rather than merely large. */
  backoff = WT_QUIC_CONNECTION_INITIAL_PTO *
            (1ULL << (connection->loss.pto_count > 8U ? 8U : connection->loss.pto_count));
  *out_time = earliest + backoff;
  return 1;
}
uint64_t tag_for_control(wt_quic_connection_t *connection, size_t slot) {
  int index =
      alloc_frame(connection, connection->control_frames[slot].space, 0, WT_QUIC_CONTROL_STREAM_ID,
                  (uint64_t)slot, connection->control_frames[slot].wire_length);
  return index < 0 ? (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX : (uint64_t)index;
}
static wt_status_t send_packet(wt_quic_connection_t *connection, wt_quic_space_t space,
                               const uint8_t *payload, size_t payload_length, int ack_eliciting,
                               uint64_t tag, uint64_t now) {
  wt_quic_packet_build_t build;
  wt_quic_sent_packet_t sent;
  wt_quic_pn_space_t *space_state = &connection->spaces[space];
  uint8_t packet[WT_QUIC_CONNECTION_PAYLOAD_MAX];
  size_t packet_length = 0U;
  size_t packet_number_length;
  uint64_t packet_number = 0U;
  wt_status_t status;

  if (!connection->has_keys_out[space]) return WT_ERR_STATE;
  if (connection->has_peer == 0 && connection->config.role == WT_QUIC_ROLE_CLIENT) {
    return WT_ERR_STATE;
  }
  /* The header and the tag are the only things the payload does not account for, and 128 bytes is
   * more than either form needs. */
  if (payload_length > sizeof(packet) - 128U) return WT_ERR_LIMIT;

  /* RFC 9001 section 6.6: an endpoint MUST initiate a key update before sending more protected packets than the
   * confidentiality limit permits, and MUST stop using the connection when an update is not possible. The check
   * is BEFORE the packet is protected, so the limit is never exceeded -- and for the Application space an update
   * is attempted first, because that is what the section asks for rather than closing. */
  if (connection->aead_encrypted[space] >= connection->aead_confidentiality_limit) {
    if (space == WT_QUIC_SPACE_APPLICATION &&
        wt_quic_connection_key_update_allowed(connection) != 0) {
      wt_status_t updated_keys = wt_quic_connection_initiate_key_update(connection, now);
      if (updated_keys != WT_OK) return updated_keys;
    } else {
      return close_with(connection, WT_QUIC_AEAD_LIMIT_REACHED, 0U, now);
    }
  }

  /* Room to remember the packet, because a packet that is not remembered is never retransmitted.
   * Declaring what is already lost by the time threshold is the way to make room, and if that is not
   * enough the packet is not sent: the caller tries again, and nothing has been put on the wire. */
  if (connection->loss.count >= WT_QUIC_SENT_PACKETS_MAX) {
    status = wt_quic_loss_detect(&connection->loss, (uint8_t)space, &space_state->rtt, now,
                                 space_state->has_largest_acked ? space_state->largest_acked : 0U,
                                 on_lost, connection);
    if (status != WT_OK) return status;
    if (connection->loss.count >= WT_QUIC_SENT_PACKETS_MAX) return WT_ERR_LIMIT;
  }

  packet_number_length = packet_number_length_for(space_state->next_send, space_state);
  if (!wt_quic_congestion_can_send(&connection->congestion,
                                   wt_quic_loss_bytes_in_flight(&connection->loss))) {
    return WT_ERR_AGAIN;
  }

  status = wt_quic_pn_space_next(space_state, &packet_number);
  if (status != WT_OK) return status;

  memset(&build, 0, sizeof(build));
  /* The type is what a long header carries. A short header has none, and the builder ignores this
   * field for one -- which is why the Application space borrows a value rather than inventing one. */
  build.type =
      space == WT_QUIC_SPACE_INITIAL
          ? WT_QUIC_PACKET_INITIAL
          : (space == WT_QUIC_SPACE_HANDSHAKE ? WT_QUIC_PACKET_HANDSHAKE : WT_QUIC_PACKET_INITIAL);
  build.short_header = space == WT_QUIC_SPACE_APPLICATION ? 1 : 0;
  build.version = connection->config.version;
  build.destination_connection_id = connection->config.peer_connection_id;
  build.destination_connection_id_len = connection->config.peer_connection_id_length;
  if (build.short_header == 0) {
    /* The source connection ID and the token are long header fields. A short header has neither, and
     * the builder refuses a packet that claims one -- which is what a caller that set them
     * unconditionally would discover only when it first sent a 1-RTT packet. */
    build.source_connection_id = connection->config.local_connection_id;
    build.source_connection_id_len = connection->config.local_connection_id_length;
    /* RFC 9000 section 17.2.5.3: once a Retry has been accepted, EVERY Initial carries its token. */
    if (space == WT_QUIC_SPACE_INITIAL && connection->retry_accepted != 0) {
      build.token = connection->retry_token;
      build.token_len = connection->retry_token_length;
    }
  }
  if (space == WT_QUIC_SPACE_INITIAL && connection->retry_pending_keys != 0) {
    /* The keys no longer match the connection ID a Retry named, and a packet protected with the old ones is
     * indistinguishable from a client that ignored the Retry. The runtime session derives them again on the pump
     * that read the Retry, and WT_ERR_AGAIN is what tells the flush to try later rather than to fail. */
    return WT_ERR_AGAIN;
  }
  build.packet_number = packet_number;
  build.packet_number_length = packet_number_length;
  /* RFC 9001 section 6.1's Key Phase bit: what a peer reads to know which keys protect this packet. It is only
   * meaningful for the Application space, and the builder ignores it for the longer headers. */
  build.key_phase = connection->key_phase;
  build.payload = payload;
  build.payload_len = payload_length;
  build.keys = &connection->keys_out[space];

  status = wt_quic_packet_build(&build, packet, sizeof(packet), &packet_length);
  if (status != WT_OK) return status;
  if (space == WT_QUIC_SPACE_INITIAL && connection->config.role == WT_QUIC_ROLE_CLIENT &&
      packet_length < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE) {
    /* RFC 9000 section 14.1: a client MUST expand every UDP datagram carrying an Initial packet to at
     * least 1200 bytes, because a server discards an Initial datagram smaller than that -- so an
     * unpadded client Initial cannot start a connection against a conformant server. This runtime puts
     * one packet in a datagram, so the packet is what is expanded, with PADDING frames ahead of the
     * tag (RFC 9000 section 19.1).
     *
     * The padding is added by rebuilding rather than computed ahead of the build because the packet's
     * own header length depends on the padded length: the long header's Length field is a varint whose
     * width grows with the value it carries, so a size computed from the unpadded payload can land one
     * byte short. Each pass adds the shortfall the previous pass measured, which converges immediately
     * in practice and is bounded here rather than assumed. */
    uint8_t padded[WT_QUIC_CONNECTION_PAYLOAD_MAX];
    size_t padding = 0U;
    size_t pass;

    if (payload_length > sizeof(padded)) return WT_ERR_LIMIT;
    if (payload_length != 0U) memcpy(padded, payload, payload_length);
    for (pass = 0U; pass < 4U; pass++) {
      if (packet_length == WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE) break;
      if (packet_length < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE) {
        padding += (size_t)WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE - packet_length;
      } else {
        /* Adding the shortfall can also widen the header, because the long header's Length field is a
         * varint whose width grows with the value it carries: a pass that lands one byte over is
         * corrected by trimming a byte of padding rather than by sending a datagram above the path's
         * limit, which is what the caller's `max_datagram_size` would then refuse. */
        size_t excess = packet_length - WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE;
        if (excess > padding) break;
        padding -= excess;
      }
      if (payload_length + padding > sizeof(padded)) return WT_ERR_LIMIT;
      memset(padded + payload_length, 0, padding);
      build.payload = padded;
      build.payload_len = payload_length + padding;
      status = wt_quic_packet_build(&build, packet, sizeof(packet), &packet_length);
      if (status != WT_OK) return status;
    }
    if (packet_length < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE) return WT_ERR_STATE;
  }
  if (packet_length > connection->config.max_datagram_size) {
    /* The path's limit is the caller's, and a packet above it is refused here rather than fragmented
     * or dropped somewhere the caller cannot see. */
    return WT_ERR_LIMIT;
  }

  /* Counted once the AEAD has been applied: the limit bounds ENCRYPTIONS with one key, which is what the retry
   * loop above may have attempted more than once for padding (WT-169). */
  connection->aead_encrypted[space]++;
  if (space == WT_QUIC_SPACE_APPLICATION) {
    if (connection->key_phase_first_pn_set == 0) {
      /* The FIRST packet of this phase, which is the number section 6.1's test compares an acknowledgement
       * against: "tracking the lowest packet number sent with each key phase and the highest acknowledged
       * packet number in the 1-RTT space". */
      connection->key_phase_first_pn = packet_number;
      connection->key_phase_first_pn_set = 1;
    }
    /* Anything sent in the new phase is what section 6.2 asks for after responding to a peer's update -- "the
     * next packet that contains an acknowledgment will cause the key update to be completed" -- so the flag
     * that detects a peer updating twice without waiting is cleared by SENDING, not by acknowledging. */
    connection->key_update_response_pending = 0;
  }
  status = wt_udp_send(&connection->socket, &connection->peer, packet, packet_length);
  if (status != WT_OK) return status;

  memset(&sent, 0, sizeof(sent));
  /* The space travels with the packet because a packet number is only unique within one (RFC 9000
   * section 12.3), and the loss list is one list for the connection. */
  sent.packet_number_space = (uint8_t)space;
  sent.packet_number = packet_number;
  sent.time_sent = now;
  sent.size = (uint64_t)packet_length;
  sent.tag = tag;
  sent.ack_eliciting = ack_eliciting;
  sent.in_flight = 1;
  status = wt_quic_loss_on_sent(&connection->loss, &sent);
  if (status != WT_OK) {
    /* The list is full: the packet is on the wire and cannot be remembered. That is the one case this
     * function's ordering cannot prevent -- the count was checked above, and a concurrent change to it
     * is impossible in a single-threaded runtime -- so it is reported rather than hidden. */
    return status;
  }

  /* A DIAGNOSTIC, gated by WT_QUIC_PACKET_LOG: what this endpoint ACTUALLY sent, byte for byte, because a
   * third-party peer that holds the right keys still could not read our Handshake packets (WT-135). The type
   * bits of a long header are NOT covered by header protection (RFC 9001 section 5.4.1), so the first byte says
   * which packet this is even after it is protected. */
  {
    const char *packet_log_path = getenv("WT_QUIC_PACKET_LOG");
    if (packet_log_path != NULL && packet_length > 0U) {
      FILE *packet_log = fopen(packet_log_path, "a");
      if (packet_log != NULL) {
        size_t dump_limit = packet_length < 1300U
                                ? packet_length
                                : 1300U; /* an Initial is 1200 and has to be whole to open */
        size_t dump_index;
        fprintf(packet_log,
                "sent space=%d type_bits=%u first=0x%02x length=%zu pn=%llu bytes=", (int)space,
                (unsigned)((packet[0] >> 4) & 0x03U), (unsigned)packet[0], packet_length,
                (unsigned long long)packet_number);
        for (dump_index = 0U; dump_index < dump_limit; dump_index++) {
          fprintf(packet_log, "%02x", packet[dump_index]);
        }
        fprintf(packet_log, "\n");
        (void)fclose(packet_log);
      }
    }
  }

  connection->packets_sent++;
  if (space < WT_QUIC_SPACE_COUNT) connection->packets_sent_by_space[space]++;
  connection->bytes_sent += (uint64_t)packet_length;
  connection->last_activity = now;
  return WT_OK;
}
int control_frame_is_retained(wt_quic_frame_type_t kind) {
  switch (kind) {
    case WT_QUIC_FRAME_KIND_RESET_STREAM:
    case WT_QUIC_FRAME_KIND_RESET_STREAM_AT:
    case WT_QUIC_FRAME_KIND_STOP_SENDING:
    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
    case WT_QUIC_FRAME_KIND_MAX_DATA:
    case WT_QUIC_FRAME_KIND_MAX_STREAM_DATA:
    case WT_QUIC_FRAME_KIND_MAX_STREAMS:
    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
    case WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED:
    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
    case WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID:
    case WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID:
    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
      return 1;
    case WT_QUIC_FRAME_KIND_PADDING:
    case WT_QUIC_FRAME_KIND_PING:
    case WT_QUIC_FRAME_KIND_ACK:
    case WT_QUIC_FRAME_KIND_CRYPTO:
    case WT_QUIC_FRAME_KIND_STREAM:
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      return 0;
  }
  return 0;
}
wt_status_t send_control_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                               const wt_quic_frame_t *frame, int ack_eliciting, int *out_sent,
                               uint64_t now) {
  uint8_t wire[WT_QUIC_CONTROL_WIRE_MAX];
  wt_writer_t kept = wt_writer_init(wire, sizeof(wire));
  size_t slot = WT_QUIC_CONTROL_FRAMES_MAX;
  size_t i;

  if (out_sent != NULL) *out_sent = 0;
  if (!control_frame_is_retained(frame->kind)) {
    /* No slot, by design -- and NOT counted, because nothing about this frame was promised: see the kinds above. */
    return send_one_frame(connection, space, frame, ack_eliciting, 0, 0, 0U, 0U, 0U, out_sent, now);
  }
  for (i = 0U; i < WT_QUIC_CONTROL_FRAMES_MAX; i++) {
    if (!connection->control_frames[i].in_use) {
      slot = i;
      break;
    }
  }
  if (slot == WT_QUIC_CONTROL_FRAMES_MAX || wt_quic_frame_encode(&kept, frame) != WT_OK ||
      !wt_writer_ok(&kept)) {
    /* No room to keep it, or it is bigger than a slot holds: it goes out, and a loss of it is not answered. */
    connection->control_frames_unretained++;
    return send_one_frame(connection, space, frame, ack_eliciting, 0, 0, 0U, 0U, 0U, out_sent, now);
  }

  connection->control_frames[slot].in_use = 1;
  connection->control_frames[slot].resend_pending = 0;
  connection->control_frames[slot].space = space;
  connection->control_frames[slot].wire_length = wt_writer_offset(&kept);
  memcpy(connection->control_frames[slot].wire, wire, wt_writer_offset(&kept));
  {
    wt_status_t status =
        send_one_frame(connection, space, frame, ack_eliciting, 1, 0, WT_QUIC_CONTROL_STREAM_ID,
                       (uint64_t)slot, wt_writer_offset(&kept), out_sent, now);
    if (status != WT_OK) connection->control_frames[slot].in_use = 0;
    return status;
  }
}
wt_status_t send_one_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                           const wt_quic_frame_t *frame, int ack_eliciting, int has_descriptor,
                           int is_crypto, uint64_t stream_id, uint64_t offset, size_t length,
                           int *out_sent, uint64_t now) {
  uint8_t payload[WT_QUIC_CONNECTION_PAYLOAD_MAX];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t packet_number_length;
  size_t minimum;
  uint64_t tag = (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX;
  size_t payload_length;
  wt_status_t status;

  if (out_sent != NULL) *out_sent = 0;
  if (!connection->has_keys_out[space]) return WT_ERR_STATE;

  status = wt_quic_frame_encode(&w, frame);
  if (status != WT_OK) return status;
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;

  /* The padding WT-72 asks for, applied before anything is sent: a packet whose payload is too short
   * to carry a header protection sample cannot be protected at all, so the runtime pads rather than
   * leaving the caller with a failure it cannot act on. PADDING is not ack-eliciting, so this does not
   * change what the peer owes. */
  packet_number_length =
      packet_number_length_for(connection->spaces[space].next_send, &connection->spaces[space]);
  minimum = sample_minimum(packet_number_length);
  while (wt_writer_offset(&w) < minimum)
    wt_writer_u8(&w, 0U);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;
  payload_length = wt_writer_offset(&w);

  if (has_descriptor) {
    int index = alloc_frame(connection, space, is_crypto, stream_id, offset, length);
    if (index < 0) return WT_ERR_LIMIT;
    tag = (uint64_t)index;
  }
  return send_encoded_frame(connection, space, payload, payload_length, ack_eliciting, tag,
                            out_sent, now);
}
wt_status_t send_encoded_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                               const uint8_t *payload, size_t payload_length, int ack_eliciting,
                               uint64_t tag, int *out_sent, uint64_t now) {
  wt_status_t status;

  if (out_sent != NULL) *out_sent = 0;
  status = send_packet(connection, space, payload, payload_length, ack_eliciting, tag, now);
  if (status != WT_OK) {
    if (tag != (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) free_frame(connection, tag);
    return status;
  }
  if (out_sent != NULL) *out_sent = 1;
  return WT_OK;
}
wt_status_t wt_quic_connection_send_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame, int ack_eliciting,
                                          uint64_t now) {
  int sent = 0;
  wt_status_t status;

  if (connection == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_connection_is_closed(connection)) return WT_ERR_STATE;

  /* The frame's KIND decides whether this layer answers for its loss (see `control_frame_is_retained`): a
   * HANDSHAKE_DONE sent by the handshake is kept and re-sent, a caller's PATH_RESPONSE or DATAGRAM is not. */
  status = send_control_frame(connection, space, frame, ack_eliciting, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}
static void resume_control_frame(wt_quic_connection_t *connection, size_t slot, uint64_t now) {
  wt_quic_control_frame_t *kept = &connection->control_frames[slot];
  uint64_t tag = tag_for_control(connection, slot);

  if (tag >= (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) {
    connection->control_frames_resend_deferred++;
    return;
  }
  if (send_encoded_frame(connection, kept->space, kept->wire, kept->wire_length, 1, tag, NULL,
                         now) != WT_OK) {
    connection->control_frames_resend_deferred++;
    return;
  }
  kept->resend_pending = 0;
}
static void resume_pending_control_frames(wt_quic_connection_t *connection, uint64_t now) {
  size_t slot;

  for (slot = 0U; slot < WT_QUIC_CONTROL_FRAMES_MAX; slot++) {
    if (connection->control_frames[slot].in_use &&
        connection->control_frames[slot].resend_pending != 0) {
      resume_control_frame(connection, slot, now);
    }
  }
}
wt_status_t flush_space(wt_quic_connection_t *connection, wt_quic_space_t space, int probe,
                        int force, uint64_t now) {
  wt_quic_pn_space_t *space_state = &connection->spaces[space];
  uint8_t range_bytes[WT_QUIC_CONNECTION_ACK_RANGES_MAX];
  size_t range_length = 0U;
  wt_quic_frame_t frame;
  uint64_t delay;
  int sent = 0;
  wt_status_t status;

  if (!connection->has_keys_out[space]) return WT_OK;
  if (wt_quic_connection_is_closed(connection)) return WT_OK;

  if (probe) {
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
    return send_control_frame(connection, space, &frame, 1, &sent, now);
  }

  if (!space_state->received.ack_pending) return WT_OK;
  if (space_state->received.ack_eliciting_since_ack == 0U) {
    /* Nothing ack-eliciting has arrived since the last acknowledgement. Responding to a packet that
     * asked for nothing with a packet that asks for nothing is the acknowledgement storm RFC 9000
     * section 13.2.1 exists to prevent; the packet stays in the received set, so the next
     * acknowledgement covers it. */
    return WT_OK;
  }
  /* An acknowledgement may be delayed up to this endpoint's own limit (RFC 9000 section 13.2.1), and
   * `force` is the timer having reached it. Before that, the module's own rule decides: two
   * ack-eliciting packets, or a gap that a sender is waiting on, are acknowledged at once. */
  if (!force && !wt_quic_ack_should_send(&space_state->received) &&
      now < connection->received_at[space] + ack_delay_for(connection, space)) {
    return WT_OK;
  }

  delay = now >= connection->received_at[space] ? now - connection->received_at[space] : 0U;
  memset(&frame, 0, sizeof(frame));
  status = wt_quic_ack_build(&space_state->received, delay, range_bytes, sizeof(range_bytes),
                             &range_length, &frame);
  if (status != WT_OK) return status;
  frame.as.ack.ranges = range_bytes;
  frame.as.ack.ranges_len = range_length;

  status = send_control_frame(connection, space, &frame, 0, &sent, now);
  if (status != WT_OK) return status;
  if (sent) {
    wt_quic_ack_sent(&space_state->received);
    if (space < WT_QUIC_SPACE_COUNT) {
      connection->acks_sent[space]++;
      connection->ack_largest[space] = frame.as.ack.largest;
    }
  }
  return WT_OK;
}
wt_status_t wt_quic_connection_flush(wt_quic_connection_t *connection, uint64_t now) {
  size_t i;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* A close that has not gone out is owed a packet before anything else: it is the last thing this
   * endpoint says, and RFC 9000 section 10.2.3 sends it in the highest space that has keys. */
  if (wt_quic_connection_is_closed(connection) && connection->close_sent == 0 &&
      !connection->peer_closed) {
    for (i = WT_QUIC_SPACE_COUNT; i > 0U; i--) {
      wt_quic_space_t space = (wt_quic_space_t)(i - 1U);
      wt_quic_frame_t frame;
      int sent = 0;
      if (!connection->has_keys_out[space]) continue;
      memset(&frame, 0, sizeof(frame));
      status = wt_quic_close_frame(&connection->close, &frame);
      if (status != WT_OK) return status;
      status = send_control_frame(connection, space, &frame, 0, &sent, now);
      if (status != WT_OK) return status;
      if (sent) {
        connection->close_sent = 1;
        connection->close_frame_sent = 1;
        return WT_OK;
      }
    }
    return WT_OK;
  }
  if (wt_quic_connection_is_closed(connection)) return WT_OK;

  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    status = flush_space(connection, (wt_quic_space_t)i, 0, 0, now);
    if (status != WT_OK) return status;
  }
  /* A retained control frame whose re-send failed is still owed, and no loss event names it: re-drive it before
   * the path challenge, because it is the connection's own frame and the challenge is a question, not an
   * obligation. */
  resume_pending_control_frames(connection, now);
  /* And a PATH_CHALLENGE this connection owes (WT-172), after the spaces: a challenge is a probe, not a
   * handshake message, and a flush that sent it before an owed acknowledgement would delay the peer's own
   * progress to ask it a question of our own. */
  return flush_path_challenge(connection, now);
}
