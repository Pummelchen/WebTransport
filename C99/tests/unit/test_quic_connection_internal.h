/* Shared fixtures and prototypes for the split `test_quic_connection` translation units.
 *
 * The single test file became several so a reader can find a topic's fixtures with its tests.
 * Everything shared lives here: the recorded-frame and connection-pair fixtures, the helpers
 * that build and deliver packets, and every test entry point `main` calls. Definitions are in
 * test_quic_connection_support.c and the topic files; the harness counters they use are shared
 * by tests/wt_test.c, because a translation unit no longer owns its own tally. */

#ifndef WT_TEST_QUIC_CONNECTION_INTERNAL_H
#define WT_TEST_QUIC_CONNECTION_INTERNAL_H

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/connection.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/protection.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/udp.h"

/* What a handler was told, recorded rather than acted on: the frame bytes, the space and the count. */
#define RECORDED_MAX 8

typedef struct recorded_frame {
  wt_quic_space_t space;
  wt_quic_frame_type_t kind;
  uint64_t offset;
  size_t length;
  uint8_t data[64];
} recorded_frame_t;

typedef struct fs_witness {
  recorded_frame_t frames[RECORDED_MAX];
  size_t count;
  /* The packet numbers the loss handler was told about, by descriptor offset. */
  uint64_t lost_offsets[RECORDED_MAX];
  size_t lost_count;
} fs_witness_t;

/* Two connections, two sockets, one family, both with Initial keys derived from the same connection ID
 * in the RFC 9001 section 5.2 way. The client is the one that opens the exchange, so its send keys are
 * the client's and its receive keys are the server's. */
typedef struct connection_pair {
  wt_quic_connection_t client;
  wt_quic_connection_t server;
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  fs_witness_t client_witness;
  fs_witness_t server_witness;
} connection_pair_t;

/* What a lost STREAM packet tells its owner: RFC 9002 section 6.1 hands a lost packet back to whoever
 * can send it again, and for a stream that is the layer that keeps the bytes. This checks the
 * descriptor the connection reports -- the stream, the offset and the length -- because a descriptor
 * that named the wrong range would resend the wrong bytes just as silently as no descriptor at all. */
typedef struct lost_witness {
  size_t count;
  uint64_t stream_id;
  uint64_t offset;
  size_t length;
  int is_crypto;
} lost_witness_t;

/* What the send path put on the wire, recorded rather than inferred: "the frame was sent" and "the frame the
 * peer needs was sent" are different claims, and the difference is what WT-162 is about. */
typedef struct reset_at_witness {
  unsigned seen;
  unsigned walked;
  uint64_t last_kind;
  uint64_t last_length;
  uint64_t id;
  uint64_t error_code;
  uint64_t final_size;
  uint64_t reliable_size;
} reset_at_witness_t;

extern const uint8_t k_dcid[8];
extern const uint8_t k_server_scid[4];
extern const uint8_t k_retry_odcid[8];
extern const uint8_t k_retry_scid[10];
extern const uint8_t k_retry_token[12];

wt_status_t record_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
void record_lost(void *context, const wt_quic_tx_frame_t *frame);
void open_pair(wt_udp_family_t family, connection_pair_t *pair);
void receive_on(wt_quic_connection_t *connection, const wt_udp_socket_t *socket, uint64_t now);
void close_pair(connection_pair_t *pair);
void send_raw_payload_with_dcid(const connection_pair_t *pair, const uint8_t *payload,
                                size_t payload_length, const uint8_t *dcid, size_t dcid_length,
                                const wt_quic_packet_keys_t *keys, uint64_t packet_number);
void send_raw_payload_to(const connection_pair_t *pair, const uint8_t *payload,
                         size_t payload_length, const wt_quic_packet_keys_t *keys,
                         uint64_t packet_number);
void send_frame_to(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                   const wt_quic_packet_keys_t *keys, uint64_t packet_number, uint64_t now);
void record_stream_loss(void *context, const wt_quic_tx_frame_t *frame);
void send_application_frame(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                            const wt_quic_packet_keys_t *keys, uint64_t packet_number);
void send_short_initial_frame(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                              const wt_quic_packet_keys_t *keys, uint64_t packet_number);
wt_status_t refuse_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
wt_status_t refuse_frame_with_code(void *context, wt_quic_space_t space,
                                   const wt_quic_frame_t *frame);
wt_status_t refuse_with_h3_error(void *context, wt_quic_space_t space,
                                 const wt_quic_frame_t *frame);
wt_status_t record_reset_at(void *context, const wt_quic_frame_t *frame);
void install_application_keys(connection_pair_t *pair, uint8_t base);
void deliver_to(connection_pair_t *pair, int to_server, const uint8_t *packet, size_t length,
                uint64_t now);
void retry_client(connection_pair_t *pair);
size_t build_retry(uint8_t *out, size_t capacity, const uint8_t *source, size_t source_len,
                   const uint8_t *token, size_t token_len);
void arm_application(connection_pair_t *pair, uint8_t seed);
void update_keys_keeping_hp(const wt_quic_packet_keys_t *current, wt_quic_packet_keys_t *out);
size_t build_application_packet(const wt_quic_packet_keys_t *keys, uint64_t packet_number,
                                int key_phase, uint8_t *out, size_t capacity,
                                size_t payload_offset);
void deliver_to_peer(connection_pair_t *pair, int to_server, const uint8_t *packet, size_t length,
                     uint64_t now);
void send_frame_from_side(connection_pair_t *pair, int to_client, const wt_quic_frame_t *frame,
                          const wt_quic_packet_keys_t *keys, uint64_t packet_number,
                          const uint8_t *dcid, size_t dcid_len);
void discard_one_datagram(wt_udp_socket_t *socket);
void arm_for_connection_ids(connection_pair_t *pair, uint8_t seed);
unsigned witness_frames_of(const fs_witness_t *witness, wt_quic_frame_type_t kind);
void arm_path_pair(connection_pair_t *pair, uint8_t seed);
const recorded_frame_t *witness_frame(const fs_witness_t *witness, wt_quic_frame_type_t kind,
                                      unsigned occurrence);
void send_two_frames_from_side(connection_pair_t *pair, const wt_quic_frame_t *first,
                               const wt_quic_frame_t *second, const wt_quic_packet_keys_t *keys,
                               uint64_t packet_number, const uint8_t *dcid, size_t dcid_len);
void test_round_trip(wt_udp_family_t family);
void test_short_packet_is_padded(wt_udp_family_t family);
void test_packet_threshold_loss(void);
void test_ack_for_unsent_packet(void);
void test_close_paths(void);
void test_discards(void);
void test_garbage(wt_udp_family_t family);
void test_key_discard(void);
void test_handshake_done_role(void);
void test_frame_permission(void);
void test_open_stream(void);
void test_peer_opens_stream(void);
void test_reset_and_stop(void);
void test_limit_extension(void);
void test_reset_stream_send(void);
void test_stream_retransmit_descriptor(void);
void test_stop_sending_send(void);
void test_issue_connection_id(void);
void test_peer_connection_ids(void);
void test_retire_connection_id(void);
void test_retire_handshake_connection_id(void);
void test_client_initial_datagram_is_padded(void);
void test_short_initial_datagram_is_discarded(void);
void test_new_connection_id_retire_prior_to_is_refused(void);
void test_packets_to_issued_connection_ids(void);
void test_a_refusal_leaves_a_readable_close(wt_udp_family_t family);
void test_a_handler_can_name_the_code_it_refused_with(wt_udp_family_t family);
void test_crypto_is_permitted_in_the_application_space(void);
void test_a_server_answers_to_the_clients_chosen_id(void);
void test_an_http3_refusal_is_an_application_close(wt_udp_family_t family);
void test_the_reliable_stream_reset_is_sent_and_applied(void);
void test_the_reliable_stream_reset_rules(void);
void test_a_retry_is_accepted_and_answered(void);
void test_a_retry_that_breaks_a_rule_is_discarded(void);
void test_an_unauthenticable_packet_is_discarded(void);
void test_a_key_update_moves_both_directions(void);
void test_an_acknowledgement_confirms_the_update(void);
void test_a_reordered_packet_is_read_with_the_retained_keys(void);
void test_a_reordered_packet_with_no_reference_is_read(void);
void test_a_second_update_without_an_answer_is_refused(void);
void test_the_confidentiality_limit_rotates_the_keys(void);
void test_a_limit_with_no_update_possible_closes(void);
void test_the_integrity_limit_closes_the_connection(void);
void test_the_limits_follow_the_suite(void);
void test_using_an_issued_connection_id(void);
void test_a_retire_prior_to_replaces_the_id_in_use(void);
void test_a_retransmission_descriptor_is_released_on_acknowledgement(void);
void test_a_lost_control_frame_is_sent_again(void);
void test_an_acknowledged_control_frame_is_not_sent_again(void);
void test_a_failed_control_resend_is_redriven_by_flush(void);
void test_only_retransmittable_frames_keep_a_slot(void);
void test_a_frame_that_is_not_a_challenge_is_not_handled_as_one(void);
void test_a_path_challenge_is_echoed_immediately(void);
void test_a_path_is_validated_by_its_own_response(void);
void test_a_path_that_does_not_answer_is_given_up_on(void);
void test_quic_space_names(void);

#endif /* WT_TEST_QUIC_CONNECTION_INTERNAL_H */
