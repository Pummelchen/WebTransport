/* Declarations shared across the connection runtime's translation units.
 *
 * These were `static` in the single connection.c. They are `internal` linkage rather than static
 * because the file is now several, and this is the only place their prototypes live: a future
 * reader must not tighten one back to `static` without moving its callers too. Nothing here is
 * part of the installed API (see webtransport/quic/connection.h). */

#include "webtransport/quic/connection.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webtransport/crypto/crypto.h"
#include "webtransport/quic/frame.h"
#include "webtransport/quic/packet_number.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/writer.h"

#define WT_QUIC_CONNECTION_INITIAL_PTO 1333000U
#define WT_QUIC_CONNECTION_PAYLOAD_MAX (WT_QUIC_MAX_PACKET + 64U)
#define WT_QUIC_CONNECTION_REASON_MAX 64U
#define WT_QUIC_DATAGRAM_PACKET_OVERHEAD 64U

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

uint64_t idle_timeout_of(const wt_quic_connection_t *connection);
void adopt_peer_connection_id(wt_quic_connection_t *connection, const uint8_t *id, size_t length);
uint64_t max_ack_delay_for(const wt_quic_connection_t *connection, wt_quic_space_t space);
uint64_t ack_delay_for(const wt_quic_connection_t *connection, wt_quic_space_t space);
uint64_t pto_of(const wt_quic_connection_t *connection);
void free_frame(wt_quic_connection_t *connection, uint64_t tag);
int probe_time(const wt_quic_connection_t *connection, wt_quic_space_t space,
               uint64_t *out_time);
uint64_t tag_for_control(wt_quic_connection_t *connection, size_t slot);
void on_lost(void *context, const wt_quic_sent_packet_t *packet);
int control_frame_is_retained(wt_quic_frame_type_t kind);
wt_status_t send_control_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                               const wt_quic_frame_t *frame, int ack_eliciting, int *out_sent,
                               uint64_t now);
wt_status_t send_one_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                           const wt_quic_frame_t *frame, int ack_eliciting,
                           int has_descriptor, int is_crypto, uint64_t stream_id,
                           uint64_t offset, size_t length, int *out_sent, uint64_t now);
wt_status_t send_encoded_frame(wt_quic_connection_t *connection, wt_quic_space_t space,
                               const uint8_t *payload, size_t payload_length, int ack_eliciting,
                               uint64_t tag, int *out_sent, uint64_t now);
wt_status_t close_with(wt_quic_connection_t *connection, uint64_t error_code,
                       uint64_t frame_type, uint64_t now);
wt_status_t handle_ack(wt_quic_connection_t *connection, wt_quic_space_t space,
                       const wt_quic_frame_t *frame, uint64_t now);
wt_status_t ensure_peer_stream(wt_quic_connection_t *connection, uint64_t stream_id,
                               uint64_t frame_type, uint64_t now,
                               wt_quic_stream_t **out_stream);
wt_status_t handle_new_connection_id(wt_quic_connection_t *connection,
                                     const wt_quic_frame_t *frame, uint64_t now);
wt_status_t deliver_to_handler(wt_quic_connection_t *connection, wt_quic_visit_t *visit,
                               const wt_quic_frame_t *frame);
wt_status_t handle_retire_connection_id(wt_quic_connection_t *connection,
                                        const wt_quic_frame_t *frame,
                                        wt_quic_visit_t *visit);
wt_status_t flush_path_challenge(wt_quic_connection_t *connection, uint64_t now);
wt_status_t path_validation_on_timeout(wt_quic_connection_t *connection, uint64_t now);
int local_connection_id_sequence(const wt_quic_connection_t *connection, const uint8_t *id,
                                 size_t length, uint64_t *out_sequence);
wt_status_t flush_space(wt_quic_connection_t *connection, wt_quic_space_t space, int probe,
                        int force, uint64_t now);
wt_status_t on_retry_packet(wt_quic_connection_t *connection, const uint8_t *packet, size_t length,
                            uint64_t now);
void aead_limits_for(wt_aead_t aead, uint64_t *out_confidentiality, uint64_t *out_integrity);
wt_status_t ensure_next_keys_in(wt_quic_connection_t *connection);
wt_status_t key_update_respond(wt_quic_connection_t *connection, uint64_t now);
