/* One connection: its packet number spaces, its timer and its socket. See webtransport/quic/connection.h.
 *
 * The shape of the receive path is the part worth reading first. A datagram is a sequence of coalesced
 * packets (RFC 9000 section 12.2); each is unprotected, authenticated and decrypted by packet_io, and
 * its frames are walked by the frame decoder with a visitor that acts on the ones this layer owns and
 * hands the rest to the caller's handler. Only after the walk does this file decide whether the packet
 * was ack-eliciting, because that is a property of the frames it carried and not of its header: a
 * packet of PADDING alone is not, and neither is an acknowledgement (RFC 9000 section 13.2.1).
 *
 * The send path is the mirror image, and the order the two protections impose is packet_io's business,
 * not this file's. What this file adds is the three refusals that must happen BEFORE a packet reaches
 * the wire: the congestion window has to have room, the sent-packet list has to have room to remember
 * it (a packet that is not remembered is one that is never retransmitted, so sending it is worse than
 * not sending it), and a retransmission descriptor has to exist for anything worth sending again.
 */

#include "webtransport/quic/connection.h"

#include <string.h>

#include "webtransport/quic/packet_io.h"
#include "webtransport/writer.h"

/* RFC 9002 section 6.2.1's kInitialRtt is 333ms, which makes the first probe timeout 1333ms: it is
 * the value a connection uses before it has a round trip sample, and it exists so that a probe is
 * never armed at zero. */
#define WT_QUIC_CONNECTION_INITIAL_PTO 1333000U

/* The payload buffer one packet's frames are encoded into. A caller's maximum datagram size bounds
 * the packet; this is the room above it that the header and the tag take. */
#define WT_QUIC_CONNECTION_PAYLOAD_MAX (WT_QUIC_MAX_PACKET + 64U)

/* How many bytes of the peer's close reason are kept. Bounded because it is peer data and the length
 * is the peer's to choose. */
#define WT_QUIC_CONNECTION_REASON_MAX 64U

const char *wt_quic_space_name(wt_quic_space_t space) {
  switch (space) {
    case WT_QUIC_SPACE_INITIAL:
      return "initial";
    case WT_QUIC_SPACE_HANDSHAKE:
      return "handshake";
    case WT_QUIC_SPACE_APPLICATION:
      return "application";
    case WT_QUIC_SPACE_COUNT:
      break;
  }
  return "unknown";
}

/* RFC 9002 section 5.3: an acknowledgement delay is only subtracted in the Application space, and only
 * once the handshake is confirmed. Everywhere else the peer's delay is zero by definition. */
static uint64_t max_ack_delay_for(const wt_quic_connection_t *connection, wt_quic_space_t space) {
  return space == WT_QUIC_SPACE_APPLICATION ? connection->config.max_ack_delay : 0U;
}

/* How long this endpoint may delay an acknowledgement in a space. RFC 9000 section 13.2.1 does not
 * delay the Initial or Handshake spaces -- they are what the handshake itself depends on -- so only
 * the Application space has a delay at all. */
static uint64_t ack_delay_for(const wt_quic_connection_t *connection, wt_quic_space_t space) {
  return space == WT_QUIC_SPACE_APPLICATION ? connection->config.local_max_ack_delay : 0U;
}

/* The probe timeout the close paths need, which has to exist before the estimator has a sample: the
 * Initial space's estimator first, then the Handshake's, then RFC 9002 section 6.2.1's constant. */
static uint64_t pto_of(const wt_quic_connection_t *connection) {
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

/* RFC 9000 section 17.1: the packet number is encoded in as few bytes as will let the peer
 * reconstruct it, which depends on how far ahead of the largest it has acknowledged this one is. */
static size_t packet_number_length_for(uint64_t next, const wt_quic_pn_space_t *space) {
  uint64_t difference = space->has_largest_acked ? next - space->largest_acked : next + 1U;

  if (difference < 0x80U) return 1U;
  if (difference < 0x8000U) return 2U;
  if (difference < 0x800000U) return 3U;
  return 4U;
}

/* The smallest payload a packet can carry and still be header-protected: the sample starts four bytes
 * after the packet number and is sixteen bytes long (RFC 9001 section 5.4.2), so a packet with a
 * one-byte packet number needs three bytes of payload before the tag. This is why the runtime pads,
 * and it is the answer WT-72 asks for: the padding is this layer's decision, made explicitly, and not
 * a builder inventing bytes. */
static size_t sample_minimum(size_t packet_number_length) {
  return packet_number_length >= 4U ? 0U : 4U - packet_number_length;
}

/* A descriptor for a retransmittable payload, or -1 when every slot is taken. Slots are indexed by
 * the loss list's `tag`, so a lost packet finds its own descriptor without a search. */
static int alloc_frame(wt_quic_connection_t *connection, wt_quic_space_t space, int is_crypto,
                       uint64_t offset, size_t length) {
  size_t i;
  for (i = 0U; i < WT_QUIC_CONNECTION_FRAMES_MAX; i++) {
    if (!connection->frames[i].in_use) {
      connection->frames[i].in_use = 1;
      connection->frames[i].space = space;
      connection->frames[i].is_crypto = is_crypto;
      connection->frames[i].offset = offset;
      connection->frames[i].length = length;
      return (int)i;
    }
  }
  return -1;
}

static void free_frame(wt_quic_connection_t *connection, uint64_t tag) {
  if (tag < (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) {
    connection->frames[tag].in_use = 0;
  }
}

/* The probe timeout of one space. RFC 9002 section 6.2.1 uses kInitialRtt until the estimator has a
 * sample, and that is the case that matters most: a client whose first Initial is lost has no sample
 * BY DEFINITION, so a connection that armed no probe until one arrived would wait forever and never
 * retransmit the very packet that would produce the sample. The estimator refuses to answer before its
 * first sample, which is why the fallback is here. */
static int probe_time(const wt_quic_connection_t *connection, wt_quic_space_t space,
                      uint64_t *out_time) {
  const wt_quic_pn_space_t *space_state = &connection->spaces[space];
  uint64_t earliest = 0U;
  uint64_t backoff;
  size_t i;
  int found = 0;

  if (wt_quic_loss_pto(&connection->loss, &space_state->rtt, max_ack_delay_for(connection, space),
                       out_time) == WT_OK) {
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

/* A packet that was declared lost: the descriptor goes back to the pool and the owner is told, which
 * is what lets it send the bytes again. A packet with no descriptor carried nothing worth resending. */
static void on_lost(void *context, const wt_quic_sent_packet_t *packet) {
  wt_quic_connection_t *connection = context;
  uint64_t tag = packet->tag;

  if (tag < (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX && connection->frames[tag].in_use) {
    const wt_quic_tx_frame_t descriptor = connection->frames[tag];
    connection->frames[tag].in_use = 0;
    if (connection->lost_handler != NULL) {
      connection->lost_handler(connection->lost_context, &descriptor);
    }
  }
  wt_quic_congestion_on_loss(&connection->congestion, packet->time_sent, packet->time_sent);
}

/* Send one packet carrying `payload`. `tag` is the retransmission descriptor's index, or
 * WT_QUIC_CONNECTION_FRAMES_MAX for a packet with nothing to retransmit. */
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

  /* Room to remember the packet, because a packet that is not remembered is never retransmitted.
   * Declaring what is already lost by the time threshold is the way to make room, and if that is not
   * enough the packet is not sent: the caller tries again, and nothing has been put on the wire. */
  if (connection->loss.count >= WT_QUIC_SENT_PACKETS_MAX) {
    status = wt_quic_loss_detect(&connection->loss, &space_state->rtt, now,
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
  build.type = space == WT_QUIC_SPACE_INITIAL
                   ? WT_QUIC_PACKET_INITIAL
                   : (space == WT_QUIC_SPACE_HANDSHAKE ? WT_QUIC_PACKET_HANDSHAKE
                                                       : WT_QUIC_PACKET_INITIAL);
  build.short_header = space == WT_QUIC_SPACE_APPLICATION ? 1 : 0;
  build.version = connection->config.version;
  build.destination_connection_id = connection->config.peer_connection_id;
  build.destination_connection_id_len = connection->config.peer_connection_id_length;
  build.source_connection_id = connection->config.local_connection_id;
  build.source_connection_id_len = connection->config.local_connection_id_length;
  build.packet_number = packet_number;
  build.packet_number_length = packet_number_length;
  build.key_phase = 0;
  build.payload = payload;
  build.payload_len = payload_length;
  build.keys = &connection->keys_out[space];

  status = wt_quic_packet_build(&build, packet, sizeof(packet), &packet_length);
  if (status != WT_OK) return status;
  if (packet_length > connection->config.max_datagram_size) {
    /* The path's limit is the caller's, and a packet above it is refused here rather than fragmented
     * or dropped somewhere the caller cannot see. */
    return WT_ERR_LIMIT;
  }

  status = wt_udp_send(&connection->socket, &connection->peer, packet, packet_length);
  if (status != WT_OK) return status;

  memset(&sent, 0, sizeof(sent));
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

  connection->packets_sent++;
  connection->bytes_sent += (uint64_t)packet_length;
  connection->last_activity = now;
  return WT_OK;
}

/* Encode one frame into a payload, pad it to what header protection needs, and send it. `*out_sent`
 * says whether a packet went out, because WT_OK with nothing sent is the ordinary case for a flush
 * that had nothing to acknowledge. */
static wt_status_t send_one_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                                  const wt_quic_frame_t *frame, int ack_eliciting,
                                  int has_descriptor, int is_crypto, uint64_t offset, size_t length,
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
  packet_number_length = packet_number_length_for(connection->spaces[space].next_send,
                                                  &connection->spaces[space]);
  minimum = sample_minimum(packet_number_length);
  while (wt_writer_offset(&w) < minimum) wt_writer_u8(&w, 0U);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;
  payload_length = wt_writer_offset(&w);

  if (has_descriptor) {
    int index = alloc_frame(connection, space, is_crypto, offset, length);
    if (index < 0) return WT_ERR_LIMIT;
    tag = (uint64_t)index;
  }

  status = send_packet(connection, space, payload, payload_length, ack_eliciting, tag, now);
  if (status != WT_OK) {
    if (tag != (uint64_t)WT_QUIC_CONNECTION_FRAMES_MAX) free_frame(connection, tag);
    return status;
  }
  if (out_sent != NULL) *out_sent = 1;
  return WT_OK;
}

/* RFC 9000 section 19.3.1: an ACK frame's ranges are a descending chain. The first is
 * [largest - first_range, largest], and then each of the `range_count` ADDITIONAL ranges -- the wire's
 * "ACK Range Count" counts only those, which is why the loop below starts at zero and the first range
 * is handled before it -- describes the next range lower down: its largest is two below the previous
 * smallest less the gap, and it covers `length` packets. A pair that would take the chain below zero is
 * a malformed frame and not something to clamp. */
static wt_status_t validate_ack(const wt_quic_frame_t *frame) {
  uint64_t largest = frame->as.ack.largest;
  uint64_t smallest;
  uint64_t i;

  if (frame->as.ack.first_range > largest) return WT_ERR_PROTOCOL;
  smallest = largest - frame->as.ack.first_range;
  for (i = 0U; i < frame->as.ack.range_count; i++) {
    wt_quic_ack_range_t range;
    if (wt_quic_frame_ack_range_at(frame, i, &range) != WT_OK) return WT_ERR_PROTOCOL;
    if (range.length == 0U) return WT_ERR_PROTOCOL;
    if (smallest < range.gap + 2U) return WT_ERR_PROTOCOL;
    largest = smallest - range.gap - 2U;
    if (range.length - 1U > largest) return WT_ERR_PROTOCOL;
    smallest = largest - (range.length - 1U);
    if (smallest == 0U) return WT_OK;
  }
  return WT_OK;
}

/* Whether the frame acknowledges one packet number. Assumes `validate_ack` passed. */
static int ack_covers(const wt_quic_frame_t *frame, uint64_t packet_number) {
  uint64_t largest = frame->as.ack.largest;
  uint64_t smallest = largest - frame->as.ack.first_range;
  uint64_t i;

  if (packet_number > largest) return 0;
  if (packet_number >= smallest) return 1;
  for (i = 0U; i < frame->as.ack.range_count; i++) {
    wt_quic_ack_range_t range;
    if (wt_quic_frame_ack_range_at(frame, i, &range) != WT_OK) return 0;
    largest = smallest - range.gap - 2U;
    smallest = largest - (range.length - 1U);
    if (packet_number > largest) return 0;
    if (packet_number >= smallest) return 1;
    if (smallest == 0U) return 0;
  }
  return 0;
}

static wt_status_t close_with(wt_quic_connection_t *connection, uint64_t error_code,
                              uint64_t frame_type, uint64_t now) {
  return wt_quic_connection_close(connection, error_code, frame_type, NULL, 0U, now);
}

/* An acknowledgement. Everything this endpoint has in flight is checked against the frame's ranges --
 * the sent list is walked rather than the ranges, because a range is a peer's number and iterating one
 * would let a peer choose how much work this endpoint does. */
static wt_status_t handle_ack(wt_quic_connection_t *connection, wt_quic_space_t space,
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
    status = wt_quic_loss_on_ack(&connection->loss, snapshot[i].packet_number, &space_state->rtt,
                                 now, max_ack_delay_for(connection, space), &newly_acked);
    if (status != WT_OK) return status;
    if (newly_acked == 0) continue;
    if (snapshot[i].in_flight) {
      /* RFC 9002 section 7.3: each newly acknowledged packet moves the window, and the recovery check
       * is that packet's own send time. */
      status = wt_quic_congestion_on_ack(&connection->congestion, snapshot[i].size,
                                         snapshot[i].time_sent);
      if (status != WT_OK) return status;
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
    status = wt_quic_rtt_update(&space_state->rtt, now - largest_time_sent, frame->as.ack.delay,
                                max_ack_delay_for(connection, space),
                                connection->handshake_confirmed);
    if (status != WT_OK) return status;
    status = wt_quic_pn_space_on_ack(space_state, largest_newly_acked);
    if (status != WT_OK) return status;
  }

  /* Anything the acknowledgement put beyond the thresholds is lost now rather than at the next timer,
   * which is what keeps a loss from waiting for a probe timeout. */
  return wt_quic_loss_detect(&connection->loss, &space_state->rtt, now, largest, on_lost, connection);
}

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

/* One packet's frames. */
typedef struct wt_quic_visit {
  wt_quic_connection_t *connection;
  wt_quic_space_t space;
  uint64_t now;
  /* Set by any frame that is not ACK, PADDING or CONNECTION_CLOSE, which is what makes the packet
   * ack-eliciting (RFC 9000 section 13.2.1). */
  int ack_eliciting;
  int saw_close;
} wt_quic_visit_t;

static wt_status_t visit_frame(void *context, const wt_quic_frame_t *frame) {
  wt_quic_visit_t *visit = context;
  wt_quic_connection_t *connection = visit->connection;
  wt_status_t status;

  switch (frame->kind) {
    case WT_QUIC_FRAME_KIND_PADDING:
      return WT_OK;
    case WT_QUIC_FRAME_KIND_ACK:
      return handle_ack(connection, visit->space, frame, visit->now);
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT:
    case WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION:
      visit->saw_close = 1;
      return handle_connection_close(connection, frame, visit->now);
    case WT_QUIC_FRAME_KIND_PING:
    case WT_QUIC_FRAME_KIND_CRYPTO:
    case WT_QUIC_FRAME_KIND_STREAM:
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
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
    case WT_QUIC_FRAME_KIND_HANDSHAKE_DONE:
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      /* Everything that is not PADDING, an acknowledgement or a close makes the packet
       * ack-eliciting, whether or not this layer acts on it itself (RFC 9000 section 13.2.1). */
      visit->ack_eliciting = 1;
      if (connection->handler == NULL) return WT_OK;
      status = connection->handler(connection->handler_context, visit->space, frame);
      if (status != WT_OK) {
        /* A handler that refuses a frame is refusing the connection: there is no way to accept a
         * packet that its owner could not process. */
        (void)close_with(connection, WT_QUIC_INTERNAL_ERROR, 0U, visit->now);
        return status;
      }
      return WT_OK;
  }
  /* A kind this layer does not know cannot come from the decoder, which refuses unknown types, so
   * this is a header/library mismatch rather than peer data. */
  return WT_ERR_STATE;
}

/* One packet, already read. */
static wt_status_t process_packet(wt_quic_connection_t *connection, wt_quic_space_t space,
                                  const uint8_t *payload, size_t payload_length, int *out_ack_eliciting,
                                  uint64_t now) {
  wt_quic_visit_t visit;
  wt_quic_error_t error = WT_QUIC_NO_ERROR;
  wt_status_t status;

  visit.connection = connection;
  visit.space = space;
  visit.now = now;
  visit.ack_eliciting = 0;
  visit.saw_close = 0;

  status = wt_quic_frames_decode(payload, payload_length, visit_frame, &visit, &error);
  if (status != WT_OK) return status;
  if (out_ack_eliciting != NULL) *out_ack_eliciting = visit.ack_eliciting;
  return WT_OK;
}

wt_status_t wt_quic_connection_init(wt_quic_connection_t *connection,
                                    const wt_quic_connection_config_t *config) {
  size_t i;

  if (connection == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (config->local_connection_id_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH ||
      config->peer_connection_id_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->max_datagram_size < WT_QUIC_MAX_PACKET) return WT_ERR_INVALID_ARGUMENT;

  memset(connection, 0, sizeof(*connection));
  connection->config = *config;
  /* The IDs are copied, and the configuration kept in the connection is then pointed at the copies:
   * a caller may let its own buffers go, and every later read of `config` -- the send path reads the
   * peer's ID from it -- describes this connection rather than the caller's memory. */
  memcpy(connection->local_connection_id, config->local_connection_id,
         config->local_connection_id_length);
  memcpy(connection->peer_connection_id, config->peer_connection_id,
         config->peer_connection_id_length);
  connection->local_connection_id_length = config->local_connection_id_length;
  connection->peer_connection_id_length = config->peer_connection_id_length;
  connection->config.local_connection_id = connection->local_connection_id;
  connection->config.peer_connection_id = connection->peer_connection_id;

  connection->socket.fd = -1;
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_pn_space_init(&connection->spaces[i]);
  }
  wt_quic_loss_init(&connection->loss);
  wt_quic_congestion_init(&connection->congestion, (uint64_t)config->max_datagram_size);
  wt_quic_close_state_init(&connection->close);
  return WT_OK;
}

wt_status_t wt_quic_connection_attach(wt_quic_connection_t *connection,
                                      const wt_udp_socket_t *socket,
                                      const wt_udp_address_t *peer) {
  if (connection == NULL || socket == NULL) return WT_ERR_INVALID_ARGUMENT;
  connection->socket = *socket;
  if (peer != NULL) {
    connection->peer = *peer;
    connection->has_peer = 1;
  }
  return WT_OK;
}

wt_status_t wt_quic_connection_set_keys(wt_quic_connection_t *connection, wt_quic_space_t space,
                                        int inbound, const wt_quic_packet_keys_t *keys) {
  if (connection == NULL || keys == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (inbound) {
    connection->keys_in[space] = *keys;
    connection->has_keys_in[space] = 1;
  } else {
    connection->keys_out[space] = *keys;
    connection->has_keys_out[space] = 1;
  }
  return WT_OK;
}

void wt_quic_connection_set_handlers(wt_quic_connection_t *connection,
                                     wt_quic_frame_handler_fn handler, void *handler_context,
                                     wt_quic_frame_lost_fn lost_handler, void *lost_context) {
  if (connection == NULL) return;
  connection->handler = handler;
  connection->handler_context = handler_context;
  connection->lost_handler = lost_handler;
  connection->lost_context = lost_context;
}

wt_status_t wt_quic_connection_send_crypto(wt_quic_connection_t *connection, wt_quic_space_t space,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           uint64_t now) {
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U) return WT_ERR_INVALID_ARGUMENT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CRYPTO);
  frame.as.crypto.offset = offset;
  frame.as.crypto.data = data;
  frame.as.crypto.length = length;

  status = send_one_frame(connection, space, &frame, 1, 1, 1, offset, length, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}

/* An acknowledgement for a space, if one is owed. `probe` asks for an ack-eliciting PING instead,
 * which is what a probe timeout sends: something the peer must acknowledge, so that the round trip
 * estimate can recover. */
static wt_status_t flush_space(wt_quic_connection_t *connection, wt_quic_space_t space, int probe,
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
    return send_one_frame(connection, space, &frame, 1, 0, 0, 0U, 0U, &sent, now);
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

  status = send_one_frame(connection, space, &frame, 0, 0, 0, 0U, 0U, &sent, now);
  if (status != WT_OK) return status;
  if (sent) wt_quic_ack_sent(&space_state->received);
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
      status = send_one_frame(connection, space, &frame, 0, 0, 0, 0U, 0U, &sent, now);
      if (status != WT_OK) return status;
      if (sent) {
        connection->close_sent = 1;
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
  return WT_OK;
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
        /* A list of versions rather than a packet, and the response to one is the connection's
         * business rather than this loop's. */
        connection->packets_discarded++;
        return WT_OK;
      }
      if (kind == WT_QUIC_PACKET_KIND_SHORT) {
        space = WT_QUIC_SPACE_APPLICATION;
      } else {
        uint32_t type_bits = (uint32_t)((first >> 4) & 0x03U);
        if (type_bits == (uint32_t)WT_QUIC_PACKET_INITIAL) {
          space = WT_QUIC_SPACE_INITIAL;
        } else if (type_bits == (uint32_t)WT_QUIC_PACKET_HANDSHAKE) {
          space = WT_QUIC_SPACE_HANDSHAKE;
        } else {
          /* 0-RTT shares the Application packet number space but not its keys, and this runtime has
           * one key set per space: reading a 0-RTT packet with the 1-RTT keys would report an
           * authentication failure for a packet that is correctly protected. A Retry is not read here
           * either. Both are refused by name rather than by a confusing failure (WT-71 records the
           * 0-RTT keys). */
          connection->packets_discarded++;
          return WT_OK;
        }
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
    status = wt_quic_packet_read(datagram + offset, datagram_length - offset,
                                 &connection->keys_in[space], largest_received,
                                 connection->local_connection_id_length, &packet);
    if (status == WT_ERR_AUTHENTICATION) {
      /* RFC 9001 section 5.3: a packet that does not authenticate is discarded. So is the rest of the
       * datagram, because the next coalesced packet's position is only known from a header this one
       * did not authenticate. */
      connection->packets_discarded++;
      return WT_OK;
    }
    if (status == WT_ERR_TRUNCATED) {
      connection->packets_discarded++;
      return WT_OK;
    }
    if (status != WT_OK) return status;

    /* RFC 9000 section 7.2: a packet whose destination connection ID is not this endpoint's is not
     * for this connection, which is ordinary during a handshake and not an error. */
    if (packet.destination_connection_id_len != connection->local_connection_id_length ||
        (packet.destination_connection_id_len != 0U &&
         memcmp(packet.destination_connection_id, connection->local_connection_id,
                packet.destination_connection_id_len) != 0)) {
      connection->packets_discarded++;
      return WT_OK;
    }

    status = process_packet(connection, space, packet.payload, packet.payload_len, &ack_eliciting,
                            now);
    if (status != WT_OK) return status;

    /* The received set is updated after the frames are processed, because whether the acknowledgement
     * is urgent depends on what they carried. A packet that turned out not to be ack-eliciting is
     * still acknowledged eventually. */
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
  if (connection->config.idle_timeout != 0U) {
    uint64_t idle_deadline = connection->last_activity + connection->config.idle_timeout;
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
    uint64_t loss_time = wt_quic_loss_time(&connection->loss, &space_state->rtt, largest_acked);
    uint64_t pto = 0U;

    /* An acknowledgement that is owed and delayed is a deadline like any other: the peer is waiting
     * for it, and RFC 9000 section 13.2.1 bounds how long it may wait. */
    if (space_state->received.ack_pending &&
        space_state->received.ack_eliciting_since_ack != 0U) {
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
  if (connection->config.idle_timeout != 0U &&
      now >= connection->last_activity + connection->config.idle_timeout) {
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
    uint64_t loss_time = wt_quic_loss_time(&connection->loss, &space_state->rtt, largest_acked);

    if (loss_time != 0U && now >= loss_time) {
      status = wt_quic_loss_detect(&connection->loss, &space_state->rtt, now, largest_acked, on_lost,
                                   connection);
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
    wt_quic_loss_on_pto(&connection->loss);
    return flush_space(connection, probe_space, 1, 0, now);
  }
  return WT_OK;
}

wt_status_t wt_quic_connection_close(wt_quic_connection_t *connection, uint64_t error_code,
                                     uint64_t frame_type, const uint8_t *reason, size_t reason_length,
                                     uint64_t now) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (reason == NULL && reason_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_connection_is_closed(connection)) return WT_OK;

  return wt_quic_close_transport(&connection->close, error_code, frame_type, reason, reason_length,
                                 now, pto_of(connection));
}

int wt_quic_connection_is_closed(const wt_quic_connection_t *connection) {
  if (connection == NULL) return 0;
  return connection->peer_closed != 0 || wt_quic_close_is_closed(&connection->close) != 0;
}

int wt_quic_connection_is_drained(const wt_quic_connection_t *connection, uint64_t now) {
  if (connection == NULL) return 0;
  if (!wt_quic_connection_is_closed(connection)) return 0;
  return wt_quic_close_draining_expired(&connection->close, now);
}

void wt_quic_connection_clear(wt_quic_connection_t *connection) {
  size_t i;
  if (connection == NULL) return;
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_packet_keys_clear(&connection->keys_in[i]);
    wt_quic_packet_keys_clear(&connection->keys_out[i]);
  }
  connection->has_peer = 0;
  connection->socket.fd = -1;
}
