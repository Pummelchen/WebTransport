/* Loss recovery: the probe timeout, time-threshold loss, ACK processing and the timers
 * RFC 9002 arms and fires. */

#include "connection_internal.h"

/* Defined below in this file; declared here because the callers come first. */
static int ack_covers(const wt_quic_frame_t *frame, uint64_t packet_number);

uint64_t max_ack_delay_for(const wt_quic_connection_t *connection, wt_quic_space_t space) {
  return space == WT_QUIC_SPACE_APPLICATION ? connection->config.max_ack_delay : 0U;
}
uint64_t ack_delay_for(const wt_quic_connection_t *connection, wt_quic_space_t space) {
  return space == WT_QUIC_SPACE_APPLICATION ? connection->config.local_max_ack_delay : 0U;
}
uint64_t pto_of(const wt_quic_connection_t *connection) {
  static const wt_quic_space_t order[WT_QUIC_SPACE_COUNT] = {
      WT_QUIC_SPACE_APPLICATION, WT_QUIC_SPACE_HANDSHAKE, WT_QUIC_SPACE_INITIAL};
  size_t i;

  for (i = 0U; i < sizeof(order) / sizeof(order[0]); i++) {
    uint64_t pto = 0U;
    wt_quic_space_t space = order[i];
    if (wt_quic_rtt_pto(&connection->spaces[space].rtt, max_ack_delay_for(connection, space),
                        &pto) == WT_OK) {
      return pto;
    }
  }
  return WT_QUIC_CONNECTION_INITIAL_PTO;
}
void on_lost(void *context, const wt_quic_sent_packet_t *packet) {
  wt_quic_connection_t *connection = context;
  uint64_t tag = packet->tag;

  if (packet->packet_number_space < (uint8_t)WT_QUIC_SPACE_COUNT) {
    connection->packets_declared_lost[packet->packet_number_space]++;
  }
  if (tag >= (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX || !connection->frames[tag].in_use) {
    connection->lost_without_descriptor++;
    return;
  }
  if (tag < (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX && connection->frames[tag].in_use) {
    const wt_quic_tx_frame_t descriptor = connection->frames[tag];
    connection->frames[tag].in_use = 0;
    if (descriptor.stream_id == WT_QUIC_CONTROL_STREAM_ID) {
      /* The connection's OWN frame: it is re-sent from the slot the descriptor names, because this layer is what
       * decided to send it and the bytes are what the frame was (RFC 9000 section 13.3). The slot stays in_use:
       * the re-sent packet answers for the same obligation. */
      size_t slot = (size_t)descriptor.offset;
      if (slot < WT_QUIC_CONTROL_FRAMES_MAX && connection->control_frames[slot].in_use) {
        wt_quic_control_frame_t *kept = &connection->control_frames[slot];
        /* The re-sent packet has to be ANSWERABLE: the descriptor is what a later loss names this obligation
         * by, and `send_encoded_frame` frees the one it was given when the send fails. A discarded failure
         * would therefore drop the frame for the life of the connection AND leave the slot occupied forever --
         * nothing later names it. The slot is flagged instead, and `wt_quic_connection_flush` re-drives it (the
         * bytes are still the frame, which is why the slot is kept at all). */
        wt_status_t resent =
            send_encoded_frame(connection, kept->space, kept->wire, kept->wire_length, 1,
                               tag_for_control(connection, slot), NULL, connection->last_activity);
        if (resent != WT_OK) {
          kept->resend_pending = 1;
          connection->control_frames_resend_deferred++;
        }
      }
    } else if (connection->lost_handler != NULL) {
      connection->lost_handler(connection->lost_context, &descriptor);
    }
  }
  wt_quic_congestion_on_loss(&connection->congestion, packet->time_sent, packet->time_sent);
}
static wt_status_t validate_ack(const wt_quic_frame_t *frame) {
  wt_cursor_t c = wt_cursor_init(frame->as.ack.ranges, frame->as.ack.ranges_len);
  uint64_t largest = frame->as.ack.largest;
  uint64_t smallest;
  uint64_t i;

  if (frame->as.ack.first_range > largest) return WT_ERR_PROTOCOL;
  smallest = largest - frame->as.ack.first_range;
  /* ONE pass over the range list, not one pass PER range: `wt_quic_frame_ack_range_at` re-parses the list from
   * its first byte for every index, so a peer-supplied range count made this loop quadratic -- an audit measured
   * 2.2 seconds for a single 16,000-range ACK and a 64 KB datagram carries twice that, before the per-packet
   * `ack_covers` sweep multiplies it. The cursor walks the list once; the arithmetic below is the same section
   * 19.3.1 chain it always was. */
  for (i = 0U; i < frame->as.ack.range_count; i++) {
    wt_quic_ack_range_t range;
    if (wt_quic_varint_decode(&c, &range.gap) != WT_OK ||
        wt_quic_varint_decode(&c, &range.length) != WT_OK) {
      return WT_ERR_PROTOCOL;
    }
    if (range.length == 0U) return WT_ERR_PROTOCOL;
    if (smallest < range.gap + 2U) return WT_ERR_PROTOCOL;
    largest = smallest - range.gap - 2U;
    if (range.length - 1U > largest) return WT_ERR_PROTOCOL;
    smallest = largest - (range.length - 1U);
    if (smallest == 0U) return WT_OK;
  }
  return WT_OK;
}
static int ack_covers(const wt_quic_frame_t *frame, uint64_t packet_number) {
  wt_cursor_t c = wt_cursor_init(frame->as.ack.ranges, frame->as.ack.ranges_len);
  uint64_t largest = frame->as.ack.largest;
  uint64_t smallest = largest - frame->as.ack.first_range;
  uint64_t i;

  if (packet_number > largest) return 0;
  if (packet_number >= smallest) return 1;
  /* The same single pass as `validate_ack`, and for the same reason: this runs once per in-flight packet, so a
   * quadratic range walk here was multiplied by the number of them. */
  for (i = 0U; i < frame->as.ack.range_count; i++) {
    wt_quic_ack_range_t range;
    if (wt_quic_varint_decode(&c, &range.gap) != WT_OK ||
        wt_quic_varint_decode(&c, &range.length) != WT_OK) {
      return 0;
    }
    largest = smallest - range.gap - 2U;
    smallest = largest - (range.length - 1U);
    if (packet_number > largest) return 0;
    if (packet_number >= smallest) return 1;
    if (smallest == 0U) return 0;
  }
  return 0;
}
wt_status_t handle_ack(wt_quic_connection_t *connection, wt_quic_space_t space,
                       const wt_quic_frame_t *frame, uint64_t now) {
  wt_quic_pn_space_t *space_state = &connection->spaces[space];
  uint64_t largest = frame->as.ack.largest;
  wt_quic_sent_packet_t snapshot[WT_QUIC_SENT_PACKETS_MAX];
  size_t count = connection->loss.count;
  size_t i;
  int has_largest = 0;
  uint64_t largest_newly_acked = 0U;
  uint64_t largest_time_sent = 0U;
  wt_status_t status;

  status = validate_ack(frame);
  if (status != WT_OK) {
    return close_with(connection, WT_QUIC_FRAME_ENCODING_ERROR, WT_QUIC_FRAME_ACK, now);
  }
  /* RFC 9000 section 13.1: an acknowledgement of a packet this endpoint never sent is a protocol
   * violation, and it is the one thing that makes the reconstruction below meaningful -- the largest
   * acknowledged bounds every packet number in the ranges. */
  if (!space_state->has_sent || largest >= space_state->next_send) {
    return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, WT_QUIC_FRAME_ACK, now);
  }

  memcpy(snapshot, connection->loss.sent, count * sizeof(snapshot[0]));
  for (i = 0U; i < count; i++) {
    int newly_acked = 0;
    if (!ack_covers(frame, snapshot[i].packet_number)) continue;
    status = wt_quic_loss_on_ack(&connection->loss, (uint8_t)space, snapshot[i].packet_number,
                                 &space_state->rtt, now, max_ack_delay_for(connection, space),
                                 &newly_acked);
    if (status != WT_OK) return status;
    if (newly_acked == 0) continue;
    if (snapshot[i].in_flight) {
      /* RFC 9002 section 7.3: each newly acknowledged packet moves the window, and the recovery check
       * is that packet's own send time. */
      status = wt_quic_congestion_on_ack(&connection->congestion, snapshot[i].size,
                                         snapshot[i].time_sent);
      if (status != WT_OK) return status;
    }
    /* Counted HERE, at the one place a packet is found to be covered by an acknowledgement, because the peer's
     * ACK is the only evidence that it READ what this endpoint sent. `wt_quic_loss_on_ack` above has already
     * refused a packet that was acknowledged before, so each packet is counted once and a repeated acknowledgement
     * of the same range changes nothing (WT-145). */
    connection->packets_acked[space]++;
    /* And the packet's RETRANSMISSION DESCRIPTOR comes back here. `on_lost` releases one for a packet that is
     * declared lost, and an acknowledged packet never is -- so this is the only place that can, and without it
     * the table filled at sixteen retransmittable packets net of losses: every later send that needed a
     * descriptor was refused with WT_ERR_LIMIT, which is a session that stops after sixteen messages and names
     * nothing (WT-170). */
    if (snapshot[i].tag < (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) {
      /* A control frame that has been acknowledged is DONE: the peer has it, so the slot is free and the frame
       * is never sent again (RFC 9000 section 13.3's "until acknowledged"). */
      if (connection->frames[snapshot[i].tag].stream_id == WT_QUIC_CONTROL_STREAM_ID &&
          connection->frames[snapshot[i].tag].offset < (uint64_t)WT_QUIC_CONTROL_FRAMES_MAX) {
        connection->control_frames[connection->frames[snapshot[i].tag].offset].in_use = 0;
        connection->control_frames[connection->frames[snapshot[i].tag].offset].resend_pending = 0;
      }
      free_frame(connection, snapshot[i].tag);
    }
    if (!has_largest || snapshot[i].packet_number > largest_newly_acked) {
      has_largest = 1;
      largest_newly_acked = snapshot[i].packet_number;
      largest_time_sent = snapshot[i].time_sent;
    }
  }

  if (has_largest) {
    /* One round trip sample per acknowledgement, from the largest newly acknowledged packet
     * (RFC 9002 section 5.1). */
    status =
        wt_quic_rtt_update(&space_state->rtt, now - largest_time_sent, frame->as.ack.delay,
                           max_ack_delay_for(connection, space), connection->handshake_confirmed);
    if (status != WT_OK) return status;
    status = wt_quic_pn_space_on_ack(space_state, largest_newly_acked);
    if (status != WT_OK) return status;
    /* RFC 9001 section 6.1: an acknowledgement that reaches the first packet sent in the current key phase is
     * what CONFIRMS the update -- and what makes the next one allowed. */
    if (space == WT_QUIC_SPACE_APPLICATION && connection->key_phase_first_pn_set != 0 &&
        largest_newly_acked >= connection->key_phase_first_pn) {
      connection->key_update_awaiting_confirmation = 0;
      /* The phase being retired has done its job: a packet protected with the current keys has been
       * acknowledged, so the peer holds them and a reordered packet from before the update is no longer worth
       * retaining (sections 6.1 and 6.3). */
      connection->previous_keys_in_ready = 0;
    }
  }

  /* Anything the acknowledgement put beyond the thresholds is lost now rather than at the next timer,
   * which is what keeps a loss from waiting for a probe timeout. */
  return wt_quic_loss_detect(&connection->loss, (uint8_t)space, &space_state->rtt, now, largest,
                             on_lost, connection);
}
wt_status_t wt_quic_connection_next_timeout(wt_quic_connection_t *connection, uint64_t now,
                                            uint64_t *out_micros) {
  uint64_t earliest = 0U;
  int armed = 0;
  size_t i;

  if (connection == NULL || out_micros == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_micros = 0U;

  if (wt_quic_close_is_closed(&connection->close)) {
    if (!wt_quic_close_draining_expired(&connection->close, now)) {
      *out_micros = connection->close.draining_until - now;
    }
    return WT_OK;
  }

  /* The idle timeout is armed whether or not anything is in flight (RFC 9000 section 10.1). */
  if (idle_timeout_of(connection) != 0U) {
    uint64_t idle_deadline = connection->last_activity + idle_timeout_of(connection);
    if (idle_deadline > now) {
      earliest = idle_deadline - now;
      armed = 1;
    } else {
      *out_micros = 0U;
      return WT_OK;
    }
  }

  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_space_t space = (wt_quic_space_t)i;
    const wt_quic_pn_space_t *space_state = &connection->spaces[space];
    uint64_t largest_acked = space_state->has_largest_acked ? space_state->largest_acked : 0U;
    uint64_t loss_time =
        wt_quic_loss_time(&connection->loss, (uint8_t)space, &space_state->rtt, largest_acked);
    uint64_t pto = 0U;

    /* An acknowledgement that is owed and delayed is a deadline like any other: the peer is waiting
     * for it, and RFC 9000 section 13.2.1 bounds how long it may wait. */
    if (space_state->received.ack_pending && space_state->received.ack_eliciting_since_ack != 0U) {
      uint64_t ack_deadline = connection->received_at[space] + ack_delay_for(connection, space);
      if (ack_deadline <= now) {
        *out_micros = 0U;
        return WT_OK;
      }
      if (!armed || ack_deadline - now < earliest) {
        earliest = ack_deadline - now;
        armed = 1;
      }
    }

    if (loss_time != 0U && loss_time > now) {
      uint64_t delay = loss_time - now;
      if (!armed || delay < earliest) {
        earliest = delay;
        armed = 1;
      }
    } else if (loss_time != 0U) {
      *out_micros = 0U;
      return WT_OK;
    }

    if (probe_time(connection, space, &pto) && pto > now) {
      uint64_t delay = pto - now;
      if (!armed || delay < earliest) {
        earliest = delay;
        armed = 1;
      }
    }
  }

  if (!armed) return WT_ERR_STATE;
  *out_micros = earliest;
  return WT_OK;
}
wt_status_t wt_quic_connection_on_timeout(wt_quic_connection_t *connection, uint64_t now) {
  uint64_t earliest_pto = 0U;
  wt_quic_space_t probe_space = WT_QUIC_SPACE_COUNT;
  size_t i;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (wt_quic_close_is_closed(&connection->close)) {
    /* Nothing to do: the draining period is the caller's timer, and `is_drained` is the question. */
    return WT_OK;
  }

  /* The idle timeout is a silent close (RFC 9000 section 10.1): the connection is gone and nothing is
   * sent, because the peer is presumed gone too. */
  if (idle_timeout_of(connection) != 0U &&
      now >= connection->last_activity + idle_timeout_of(connection)) {
    (void)wt_quic_close_transport(&connection->close, WT_QUIC_NO_ERROR, 0U, NULL, 0U, now,
                                  pto_of(connection));
    connection->close_sent = 1;
    return WT_OK;
  }

  /* The loss timer is per space -- each has its own round trip estimate and its own largest
   * acknowledged -- so every space that is due is checked. */
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_space_t space = (wt_quic_space_t)i;
    wt_quic_pn_space_t *space_state = &connection->spaces[space];
    uint64_t largest_acked = space_state->has_largest_acked ? space_state->largest_acked : 0U;
    uint64_t loss_time =
        wt_quic_loss_time(&connection->loss, (uint8_t)space, &space_state->rtt, largest_acked);

    if (loss_time != 0U && now >= loss_time) {
      status = wt_quic_loss_detect(&connection->loss, (uint8_t)space, &space_state->rtt, now,
                                   largest_acked, on_lost, connection);
      if (status != WT_OK) return status;
    }
  }

  /* An acknowledgement whose delay has passed goes out, in every space that owes one. */
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_space_t space = (wt_quic_space_t)i;
    if (!connection->spaces[space].received.ack_pending) continue;
    if (connection->spaces[space].received.ack_eliciting_since_ack == 0U) continue;
    if (now >= connection->received_at[space] + ack_delay_for(connection, space)) {
      status = flush_space(connection, space, 0, 1, now);
      if (status != WT_OK) return status;
    }
  }

  /* The path-validation timer (WT-172) before the probe timeout: a challenge that is due is a question this
   * endpoint asked, and re-asking it is cheaper than a probe. */
  status = path_validation_on_timeout(connection, now);
  if (status != WT_OK) return status;

  /* The probe timeout is one timer for the connection (RFC 9002 section 6.2.2), armed for the space
   * whose deadline comes first. The backoff is advanced once, because the timer that fired is one. */
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_space_t space = (wt_quic_space_t)i;
    uint64_t pto = 0U;

    if (!connection->has_keys_out[space]) continue;
    if (!probe_time(connection, space, &pto)) continue;
    if (now >= pto && (probe_space == WT_QUIC_SPACE_COUNT || pto < earliest_pto)) {
      earliest_pto = pto;
      probe_space = space;
    }
  }

  if (probe_space != WT_QUIC_SPACE_COUNT) {
    /* RFC 9002 section 6.2.4: a probe timeout MUST send new frames OR RETRANSMIT unacknowledged data. The probe
     * packet itself is a PING (see the acknowledgement path), so without this the DATA is never resent -- which
     * is what a third-party peer showed and a relayed packet drop reproduces: the CONNECT went out once, the
     * peer could not read it, and nothing ever sent it again (WT-135).
     *
     * The oldest outstanding ack-eliciting packet's descriptor is handed to the owner, and the descriptor is NOT
     * freed: the packet is still in flight, and a later acknowledgement is what retires it. The owner -- the
     * layer that kept the bytes -- is what resends them. */
    size_t oldest = connection->loss.count;
    for (i = 0U; i < connection->loss.count; i++) {
      const wt_quic_sent_packet_t *sent_packet = &connection->loss.sent[i];
      uint64_t tag = sent_packet->tag;
      if (sent_packet->packet_number_space != (uint8_t)probe_space) continue;
      if (!sent_packet->ack_eliciting) continue;
      if (tag >= (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) continue;
      if (!connection->frames[tag].in_use) continue;
      if (oldest == connection->loss.count ||
          sent_packet->time_sent < connection->loss.sent[oldest].time_sent) {
        oldest = i;
      }
    }
    if (probe_space < WT_QUIC_SPACE_COUNT) connection->probes_sent[probe_space]++;
    if (oldest < connection->loss.count) {
      connection->probes_with_data++;
      if (connection->lost_handler != NULL) {
        connection->lost_handler(connection->lost_context,
                                 &connection->frames[connection->loss.sent[oldest].tag]);
      }
    }
    wt_quic_loss_on_pto(&connection->loss);
    return flush_space(connection, probe_space, 1, 0, now);
  }
  return WT_OK;
}
