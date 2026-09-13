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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webtransport/quic/frame.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/transport_parameters.h"
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

/* The idle timeout this connection enforces: the smaller of its own and the peer's, because RFC 9000
 * section 10.1 makes the effective value the minimum of the two nonzero ones. Zero means neither end
 * limited it. */
static uint64_t idle_timeout_of(const wt_quic_connection_t *connection) {
  uint64_t local = connection->config.idle_timeout;
  uint64_t peer = connection->peer_limits.max_idle_timeout;

  if (local == 0U) return peer;
  if (peer == 0U) return local;
  return local < peer ? local : peer;
}

/* One integer parameter, or `fallback` when the peer did not send it: absent and zero are different
 * answers (RFC 9000 section 18.2 gives an absent flow control limit the value zero, which is the same
 * number but a different fact), and this is where the RFC's default is applied. */
static uint64_t parameter_or(const wt_quic_transport_parameters_t *params, uint64_t id,
                             uint64_t fallback) {
  uint64_t value = 0U;
  if (wt_quic_transport_parameters_integer(params, id, &value) != WT_OK) return fallback;
  return value;
}

wt_status_t wt_quic_connection_set_peer_parameters(wt_quic_connection_t *connection,
                                                   const uint8_t *data, size_t length) {
  wt_quic_transport_parameters_t params;
  wt_quic_error_t error = WT_QUIC_NO_ERROR;
  uint64_t offender = 0U;
  wt_quic_peer_limits_t limits;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  wt_quic_transport_parameters_init(&params);
  status = wt_quic_transport_parameters_decode(data, length, &params, &error);
  if (status != WT_OK) return status;
  /* RFC 9000 section 18.2's own rules -- a max_udp_payload_size below 1200, an ack delay exponent
   * above 20, a stream limit above 2^60 -- are an error rather than something to clamp. */
  status = wt_quic_transport_parameters_check(&params, &error, &offender);
  if (status != WT_OK) return status;

  memset(&limits, 0, sizeof(limits));
  limits.max_idle_timeout = parameter_or(&params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 0U);
  limits.max_udp_payload_size = parameter_or(&params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                                            WT_QUIC_DEFAULT_MAX_UDP_PAYLOAD_SIZE);
  limits.initial_max_data = parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_DATA, 0U);
  limits.initial_max_stream_data_bidi_local =
      parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0U);
  limits.initial_max_stream_data_bidi_remote =
      parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0U);
  limits.initial_max_stream_data_uni =
      parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 0U);
  limits.initial_max_streams_bidi = parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 0U);
  limits.initial_max_streams_uni = parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 0U);
  /* RFC 9000 section 18.2's default is 2, not zero: a peer that says nothing still allows the two
   * connection IDs the handshake itself needs. */
  limits.active_connection_id_limit =
      parameter_or(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2U);
  limits.max_datagram_frame_size = parameter_or(&params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 0U);
  limits.set = 1;
  connection->peer_limits = limits;
  connection->flow.peer_max_data = limits.initial_max_data;
  return WT_OK;
}

const wt_quic_peer_limits_t *wt_quic_connection_peer_limits(const wt_quic_connection_t *connection) {
  return connection == NULL ? NULL : &connection->peer_limits;
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

/* A packet that was declared lost: the descriptor goes back to the pool and the owner is told, which
 * is what lets it send the bytes again. A packet with no descriptor carried nothing worth resending. */
static void on_lost(void *context, const wt_quic_sent_packet_t *packet) {
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
  build.type = space == WT_QUIC_SPACE_INITIAL
                   ? WT_QUIC_PACKET_INITIAL
                   : (space == WT_QUIC_SPACE_HANDSHAKE ? WT_QUIC_PACKET_HANDSHAKE
                                                       : WT_QUIC_PACKET_INITIAL);
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
  }
  build.packet_number = packet_number;
  build.packet_number_length = packet_number_length;
  build.key_phase = 0;
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
        size_t dump_limit = packet_length < 1300U ? packet_length : 1300U;  /* an Initial is 1200 and has to be whole to open */
        size_t dump_index;
        fprintf(packet_log, "sent space=%d type_bits=%u first=0x%02x length=%zu pn=%llu bytes=", (int)space,
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

/* Encode one frame into a payload, pad it to what header protection needs, and send it. `*out_sent`
 * says whether a packet went out, because WT_OK with nothing sent is the ordinary case for a flush
 * that had nothing to acknowledge. */
static wt_status_t send_one_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                                  const wt_quic_frame_t *frame, int ack_eliciting,
                                  int has_descriptor, int is_crypto, uint64_t stream_id,
                                  uint64_t offset, size_t length, int *out_sent, uint64_t now) {
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
    int index = alloc_frame(connection, space, is_crypto, stream_id, offset, length);
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

wt_status_t wt_quic_connection_discard_keys(wt_quic_connection_t *connection, wt_quic_space_t space) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  /* Zeroed rather than marked unused: the key material must not be left in memory a caller can read,
   * and `has_keys` is what makes the layer treat the space as gone. A packet for a discarded space is
   * then discarded by the receive path, which is what RFC 9001 section 4.9.3 asks for. Idempotent, so
   * the two places that discard the Initial keys -- a Handshake packet in either direction -- cannot
   * disagree. */
  wt_quic_packet_keys_clear(&connection->keys_in[space]);
  wt_quic_packet_keys_clear(&connection->keys_out[space]);
  connection->has_keys_in[space] = 0;
  connection->has_keys_out[space] = 0;
  return WT_OK;
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
  return wt_quic_loss_detect(&connection->loss, (uint8_t)space, &space_state->rtt, now, largest,
                             on_lost, connection);
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
  /* The sequence of this endpoint's connection ID that the packet was addressed to: 0 for the ID the
   * handshake used, or the sequence of an issued one. RFC 9000 section 19.16 needs it -- the peer cannot
   * retire the ID it addressed the packet to -- and it is not always 0, because a peer that has moved
   * onto one of the IDs this endpoint issued sends its frames there. */
  uint64_t destination_sequence;
  /* Set by any frame that is not ACK, PADDING or CONNECTION_CLOSE, which is what makes the packet
   * ack-eliciting (RFC 9000 section 13.2.1). */
  int ack_eliciting;
  int saw_close;
} wt_quic_visit_t;

/* The wire type of a decoded frame kind, which is what the rules that speak in wire terms ask about
 * (the close rule and the frame-permission rule of RFC 9000 section 12.4). One map rather than one per
 * rule: a second copy is a second thing to keep in step with the codec. */
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

/* RFC 9000 section 12.4: a frame that is not permitted in the packet type it arrived in is a
 * PROTOCOL_VIOLATION. Section 12.5's table, as the two facts this runtime can tell: the frames that are
 * allowed in any space, and the frames that are allowed only where the application level is (0-RTT and
 * 1-RTT, which this runtime treats as one space because it refuses 0-RTT packets by name). CRYPTO is the
 * one frame that is the other way round: it belongs to the handshake's own spaces and must not appear
 * once the handshake is over. */
static int frame_forbidden_in_space(wt_quic_frame_type_t kind, wt_quic_space_t space) {
  if (kind == WT_QUIC_FRAME_KIND_PADDING || kind == WT_QUIC_FRAME_KIND_PING ||
      kind == WT_QUIC_FRAME_KIND_ACK || kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT ||
      kind == WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION) {
    return 0; /* section 12.5 allows these in every packet type */
  }
  if (kind == WT_QUIC_FRAME_KIND_CRYPTO) return space == WT_QUIC_SPACE_APPLICATION;
  return space != WT_QUIC_SPACE_APPLICATION;
}

/* The stream a received frame is about, opening it if this is the first frame that mentions it.
 *
 * RFC 9000 section 3.2: a stream is created by its first frame, so a frame for a peer-initiated stream
 * this endpoint has never seen OPENS it -- no separate message announces a stream. Two rules decide
 * whether that is allowed, and both are the peer's fault when it is not: a frame for a LOCALLY-initiated
 * stream that was never opened is the STREAM_STATE_ERROR of section 19.8, and a peer-initiated stream
 * beyond the count this endpoint granted is the STREAM_LIMIT_ERROR of section 4.6. A full table is
 * neither -- it is this endpoint's own bound -- so it is reported as a limit for the caller to act on.
 */
static wt_status_t ensure_peer_stream(wt_quic_connection_t *connection, uint64_t stream_id,
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

/* A NEW_CONNECTION_ID from the peer (RFC 9000 section 19.15): store it, bounded by what this endpoint
 * said it would store, and refuse what the section makes an error rather than something to ignore. */
static wt_status_t handle_new_connection_id(wt_quic_connection_t *connection,
                                            const wt_quic_frame_t *frame, uint64_t now) {
  const uint8_t *id = frame->as.new_connection_id.connection_id;
  size_t length = frame->as.new_connection_id.connection_id_length;
  uint64_t sequence = frame->as.new_connection_id.sequence;
  size_t slot = WT_QUIC_PEER_CONNECTION_IDS_MAX;
  size_t i;
  uint64_t allowed;

  /* A length outside 1..20 is a FRAME_ENCODING_ERROR, and a retire_prior_to above the sequence it
   * arrives with is one too (section 19.15). */
  if (length == 0U || length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return close_with(connection, WT_QUIC_FRAME_ENCODING_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }
  if (frame->as.new_connection_id.retire_prior_to > sequence) {
    return close_with(connection, WT_QUIC_FRAME_ENCODING_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }

  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    const wt_quic_peer_connection_id_t *known = &connection->peer_ids[i];
    if (!known->in_use) {
      if (slot == WT_QUIC_PEER_CONNECTION_IDS_MAX) slot = i;
      continue;
    }
    if (known->sequence == sequence) {
      /* The same sequence twice: the section makes a DIFFERENT connection ID or token for it a
       * PROTOCOL_VIOLATION, and the same one again merely a duplicate. */
      if (known->length != length || memcmp(known->id, id, length) != 0 ||
          memcmp(known->reset_token, frame->as.new_connection_id.stateless_reset_token, 16U) != 0) {
        return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION,
                          WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
      }
      return WT_OK;
    }
    /* A retire_prior_to retires everything below it, which is how a peer asks for the old ones back. */
    if (known->sequence < frame->as.new_connection_id.retire_prior_to) {
      connection->peer_ids[i].in_use = 0;
      connection->peer_id_count--;
    }
  }
  if (slot == WT_QUIC_PEER_CONNECTION_IDS_MAX) {
    /* Every slot is taken by an ID that is still active, which is more than this endpoint said it would
     * store: section 5.1.1 makes that a CONNECTION_ID_LIMIT_ERROR. */
    return close_with(connection, WT_QUIC_CONNECTION_ID_LIMIT_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }
  allowed = connection->config.local_active_connection_id_limit;
  /* Zero means a caller that did not say, and the RFC's own default is two -- counting the handshake's
   * ID, which leaves room for one spare. A limit of zero would otherwise refuse every NEW_CONNECTION_ID,
   * which is a policy no caller asked for. */
  if (allowed == 0U) allowed = 2U;
  allowed -= 1U;
  if ((uint64_t)connection->peer_id_count >= allowed) {
    return close_with(connection, WT_QUIC_CONNECTION_ID_LIMIT_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }

  connection->peer_ids[slot].in_use = 1;
  connection->peer_ids[slot].sequence = sequence;
  memcpy(connection->peer_ids[slot].id, id, length);
  connection->peer_ids[slot].length = length;
  memcpy(connection->peer_ids[slot].reset_token,
         frame->as.new_connection_id.stateless_reset_token, 16U);
  connection->peer_id_count++;
  return WT_OK;
}

/* Hand one frame to the caller's handler, which is where everything this layer does not own goes. A
 * handler that refuses a frame is refusing the connection, and the code it named -- if it named one --
 * is what the peer is told. */
static wt_status_t deliver_to_handler(wt_quic_connection_t *connection, wt_quic_visit_t *visit,
                                      const wt_quic_frame_t *frame) {
  connection->frames_delivered++;
  wt_status_t status;

  visit->ack_eliciting = 1;
  if (connection->handler == NULL) return WT_OK;
  status = connection->handler(connection->handler_context, visit->space, frame);
  if (status == WT_OK) return WT_OK;
  {
    uint64_t code = connection->close_code_set ? connection->close_code : WT_QUIC_INTERNAL_ERROR;
    uint64_t type = connection->close_code_set ? connection->close_frame_type : 0U;
    connection->close_code_set = 0;
    (void)close_with(connection, code, type, visit->now);
  }
  return status;
}

/* A RETIRE_CONNECTION_ID from the peer (RFC 9000 section 19.16): give up an ID this endpoint issued.
 *
 * Section 19.16 makes two sequences a PROTOCOL_VIOLATION: one that was never issued, and the one the peer
 * used as the Destination Connection ID of the packet that carried the frame -- the peer cannot ask for
 * the ID it is addressing. Which sequence that is comes from the receive path, because a peer may be
 * addressing any ID this endpoint issued rather than the handshake's.
 *
 * A repeat of a sequence that was already retired is not an error: RETIRE_CONNECTION_ID is retransmitted
 * when it is lost, so the second copy describes a state the endpoint is already in. The frame still
 * reaches the handler either way, because replacing a retired ID needs a fresh ID and reset token that
 * only the caller can produce (section 5.1.2 asks the endpoint to keep one available).
 */
static wt_status_t handle_retire_connection_id(wt_quic_connection_t *connection,
                                               const wt_quic_frame_t *frame,
                                               wt_quic_visit_t *visit) {
  uint64_t sequence = frame->as.retire_connection_id.sequence;
  size_t i;

  if (sequence == visit->destination_sequence || sequence >= connection->next_issued_sequence) {
    return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, WT_QUIC_FRAME_RETIRE_CONNECTION_ID,
                      visit->now);
  }
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use && connection->issued_ids[i].sequence == sequence) {
      connection->issued_ids[i].in_use = 0;
      /* `issued_count` was incremented only for an entry that is in use, so it cannot underflow here. */
      connection->issued_count--;
      break;
    }
  }
  return deliver_to_handler(connection, visit, frame);
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
    case WT_QUIC_FRAME_KIND_PING:
    case WT_QUIC_FRAME_KIND_CRYPTO:
    case WT_QUIC_FRAME_KIND_NEW_TOKEN:
    case WT_QUIC_FRAME_KIND_DATA_BLOCKED:
    case WT_QUIC_FRAME_KIND_STREAMS_BLOCKED:
    case WT_QUIC_FRAME_KIND_PATH_CHALLENGE:
    case WT_QUIC_FRAME_KIND_PATH_RESPONSE:
    case WT_QUIC_FRAME_KIND_DATAGRAM:
      /* Everything that is not PADDING, an acknowledgement or a close makes the packet
       * ack-eliciting, whether or not this layer acts on it itself (RFC 9000 section 13.2.1). */
      return deliver_to_handler(connection, visit, frame);
  }
  /* A kind this layer does not know cannot come from the decoder, which refuses unknown types, so
   * this is a header/library mismatch rather than peer data. */
  return WT_ERR_STATE;
}

/* Which of this endpoint's connection IDs a packet was addressed to (RFC 9000 section 5.1).
 *
 * The handshake's connection ID is sequence 0 (section 5.1.1), and every ID this endpoint has issued and
 * not retired is one of ours too -- which is the whole reason to issue them: they are what a peer can use
 * when it moves to a new path. A retired ID is not in the table any more, so a packet addressed to one is
 * discarded like any other packet that belongs to a connection this endpoint does not have, which is this
 * side's half of section 10.2's rule that a retired connection ID is not used again.
 *
 * Returns 1 and writes the sequence when the ID is ours. */
static int local_connection_id_sequence(const wt_quic_connection_t *connection, const uint8_t *id,
                                        size_t length, uint64_t *out_sequence) {
  size_t i;

  if (length == connection->local_connection_id_length &&
      (length == 0U || memcmp(id, connection->local_connection_id, length) == 0)) {
    *out_sequence = 0U;
    return 1;
  }
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use && connection->issued_ids[i].length == length &&
        (length == 0U || memcmp(id, connection->issued_ids[i].id, length) == 0)) {
      *out_sequence = connection->issued_ids[i].sequence;
      return 1;
    }
  }
  return 0;
}

/* One packet, already read. */
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

  connection->socket.fd = WT_UDP_INVALID_FD;
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_pn_space_init(&connection->spaces[i]);
  }
  wt_quic_loss_init(&connection->loss);
  wt_quic_datagram_queue_init(&connection->datagrams);
  wt_quic_stream_table_init(&connection->streams);
  /* Both limits are zero until a caller that knows what it can buffer grants them: an endpoint that
   * advertises nothing cannot receive (RFC 9000 section 4.1), which is the honest default. */
  wt_quic_flow_init(&connection->flow, 0U, 0U);
  wt_quic_congestion_init(&connection->congestion, (uint64_t)config->max_datagram_size);
  wt_quic_close_state_init(&connection->close);
  /* Sequence 0 belongs to the connection ID the handshake used (RFC 9000 section 5.1.1), so the first ID
   * this endpoint announces to the peer is sequence 1. */
  connection->next_issued_sequence = 1U;
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

  status = send_one_frame(connection, space, &frame, 1, 1, 1, 0U, offset, length, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}

/* The packet overhead a DATAGRAM frame's payload has to leave room for: the short header with the
 * longest connection ID and packet number this endpoint may use, the frame's own type and length field,
 * and the tag. Being generous here costs a few bytes of payload and never a packet that does not fit. */
#define WT_QUIC_DATAGRAM_PACKET_OVERHEAD 64U

wt_status_t wt_quic_connection_issue_connection_id(wt_quic_connection_t *connection,
                                                   const uint8_t *id, size_t length,
                                                   const uint8_t reset_token[16], uint64_t now) {
  wt_quic_frame_t frame;
  size_t slot = WT_QUIC_CONNECTION_IDS_MAX;
  size_t i;
  uint64_t allowed;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL || id == NULL || reset_token == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U || length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) return WT_ERR_INVALID_ARGUMENT;
  /* A short header does not carry the length of its Destination Connection ID (RFC 9000 section 17.2),
   * so this endpoint can only recognise the IDs it issued if they are the length it already uses: the
   * receive path parses with one length for the whole connection. Issuing one of another length would
   * hand the peer an ID whose packets would be discarded as somebody else's, which is worse than
   * refusing it here. */
  if (length != connection->local_connection_id_length) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;

  /* A caller that hands the same ID twice has made a mistake whether or not there is room, so the
   * duplicate is reported before the limit: the two are different answers and the first is the one that
   * describes what the caller did. */
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use) {
      if (connection->issued_ids[i].length == length &&
          memcmp(connection->issued_ids[i].id, id, length) == 0) {
        /* The same ID twice is a new sequence number for an ID the peer already has, which is not what a
         * caller means and would waste the peer's storage. */
        return WT_ERR_STATE;
      }
      continue;
    }
    if (slot == WT_QUIC_CONNECTION_IDS_MAX) slot = i;
  }
  if (slot == WT_QUIC_CONNECTION_IDS_MAX) return WT_ERR_LIMIT;

  /* RFC 9000 section 5.1.1: the peer's limit counts the connection ID the handshake used, so this
   * endpoint may have one fewer than the limit outstanding. A peer that granted the minimum (two, the
   * default) therefore allows exactly one spare. */
  allowed = connection->peer_limits.active_connection_id_limit;
  if (allowed > 0U) allowed -= 1U;
  if ((uint64_t)connection->issued_count >= allowed) return WT_ERR_LIMIT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
  frame.as.new_connection_id.sequence = connection->next_issued_sequence;
  frame.as.new_connection_id.retire_prior_to = 0U;
  frame.as.new_connection_id.connection_id = id;
  frame.as.new_connection_id.connection_id_length = length;
  frame.as.new_connection_id.stateless_reset_token = reset_token;
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 0, 0, 0U, 0U, 0U, &sent,
                          now);
  if (status != WT_OK) return status;
  if (!sent) return WT_ERR_STATE;

  connection->issued_ids[slot].in_use = 1;
  connection->issued_ids[slot].sequence = frame.as.new_connection_id.sequence;
  memcpy(connection->issued_ids[slot].id, id, length);
  connection->issued_ids[slot].length = length;
  memcpy(connection->issued_ids[slot].reset_token, reset_token, 16U);
  connection->issued_count++;
  /* The sequence is spent whether or not this ID is ever retired: RFC 9000 section 5.1.1 keys every
   * reference to an ID by its sequence, so a number is never reused. */
  connection->next_issued_sequence++;
  return WT_OK;
}

const wt_quic_issued_connection_id_t *wt_quic_connection_issued_id(
    const wt_quic_connection_t *connection, uint64_t sequence) {
  size_t i;
  if (connection == NULL) return NULL;
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use && connection->issued_ids[i].sequence == sequence) {
      return &connection->issued_ids[i];
    }
  }
  return NULL;
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
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 0, 0, 0U, 0U, 0U, &sent, now);
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
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 0, 0, 0U, 0U, 0U, &sent, now);
  if (status != WT_OK) return status;
  if (sent) connection->local_max_streams[index] = maximum;
  return sent ? WT_OK : WT_ERR_STATE;
}

/* Whether `stream_id` is one this endpoint is allowed to open, given what the peer granted. A stream
 * number is four fields in one (RFC 9000 section 2.1): the least significant bit is the initiator and
 * the next one is the directionality, so whether a limit applies at all depends on who opened the
 * stream. Sending on a stream the PEER opened is always allowed -- it is theirs to send on -- and only
 * a stream this endpoint opens is bounded by the count the peer granted. */
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
  /* Only the receiver of a stream's data may ask for it to stop, and only once: RFC 9000 section 19.5
   * makes a second one a STREAM_STATE_ERROR rather than something to ignore. The field is the stream
   * machine's own record of having asked, which is why it is set here rather than kept beside it. */
  if (wt_quic_stream_id_from_client(stream_id) !=
          (connection->config.role == WT_QUIC_ROLE_CLIENT) &&
      !wt_quic_stream_id_is_bidirectional(stream_id)) {
    return WT_ERR_STATE;
  }
  if (stream->sent_stop_sending) return WT_ERR_STATE;
  if (wt_quic_stream_recv_finished(stream)) return WT_ERR_STATE;
  stream->sent_stop_sending = 1;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STOP_SENDING);
  frame.as.stop_sending.id = stream_id;
  frame.as.stop_sending.application_error_code = error_code;
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 0, 0, 0U, 0U, 0U, &sent,
                          now);
  if (status != WT_OK) {
    /* A frame that could not be sent leaves the stream as it was, so a caller that retries is not told it
     * has already asked. */
    stream->sent_stop_sending = 0;
    return status;
  }
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
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 0, 0, 0U, 0U, 0U, &sent,
                          now);
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
  /* No descriptor: a DATAGRAM frame is never sent again, which is the whole point of it. */
  status = send_one_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, 0, 0, 0U, 0U, 0U, &sent, now);
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

wt_status_t wt_quic_connection_send_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame, int ack_eliciting,
                                          uint64_t now) {
  int sent = 0;
  wt_status_t status;

  if (connection == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_connection_is_closed(connection)) return WT_ERR_STATE;

  /* A frame with nothing to retransmit carries no descriptor, so a loss of its packet costs the
   * congestion controller but asks nobody to send it again -- which is right for a HANDSHAKE_DONE and
   * wrong for a STREAM frame, whose caller has its own retransmission to do. */
  status = send_one_frame(connection, space, frame, ack_eliciting, 0, 0, 0U, 0U, 0U, &sent, now);
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
    return send_one_frame(connection, space, &frame, 1, 0, 0, 0U, 0U, 0U, &sent, now);
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

  status = send_one_frame(connection, space, &frame, 0, 0, 0, 0U, 0U, 0U, &sent, now);
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
      status = send_one_frame(connection, space, &frame, 0, 0, 0, 0U, 0U, 0U, &sent, now);
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
        if (type_bits == (uint32_t)WT_QUIC_PACKET_INITIAL) {
          space = WT_QUIC_SPACE_INITIAL;
        } else if (type_bits == (uint32_t)WT_QUIC_PACKET_HANDSHAKE) {
          space = WT_QUIC_SPACE_HANDSHAKE;
        } else {
          /* 0-RTT shares the Application packet number space but not its keys, and this runtime has one
           * key set per space: reading a 0-RTT packet with the 1-RTT keys would report an
           * authentication failure for a packet that is correctly protected. A Retry is not read here
           * either. Both are discarded by name rather than through a confusing failure (WT-71 records
           * the 0-RTT keys). */
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
    status = wt_quic_packet_read(datagram + offset, datagram_length - offset,
                                 &connection->keys_in[space], largest_received,
                                 connection->local_connection_id_length, &packet);
    if (status == WT_ERR_AUTHENTICATION) {
      /* RFC 9001 section 5.3: a packet that does not authenticate is discarded. So is the rest of the
       * datagram, because the next coalesced packet's position is only known from a header this one did
       * not authenticate. */
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
      status = process_packet(connection, space, packet.payload, packet.payload_len, &ack_eliciting,
                              now, destination_sequence);
    }
    if (status != WT_OK) return status;

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
    uint64_t loss_time = wt_quic_loss_time(&connection->loss, (uint8_t)space, &space_state->rtt,
                                           largest_acked);
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
    uint64_t loss_time = wt_quic_loss_time(&connection->loss, (uint8_t)space, &space_state->rtt,
                                           largest_acked);

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
      if (oldest == connection->loss.count || sent_packet->time_sent < connection->loss.sent[oldest].time_sent) {
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
  connection->socket.fd = WT_UDP_INVALID_FD;
}
