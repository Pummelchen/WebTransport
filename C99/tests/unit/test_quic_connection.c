/* The connection runtime: two real connections over two real sockets.
 *
 * THIS IS THE TEST THAT MAKES THE PHASE-4 COMPLETION CRITERION REACHABLE: packets are built, protected,
 * sent over a loopback UDP socket, received, unprotected, walked frame by frame, acknowledged, and
 * accounted for -- on IPv4 and on IPv6 -- without a synthetic transport anywhere in the path. What it
 * deliberately does not do is complete a TLS handshake: the handshake needs the CRYPTO handler that
 * Phase 4's next part brings, so the keys here are the Initial keys both ends derive from the same
 * connection ID, which is exactly what RFC 9001 section 5.2 lets two ends of a connection do before
 * any handshake has happened.
 *
 * THE CLOCK IS A PARAMETER, WHICH IS WHAT MAKES THE TIMERS TESTABLE. Every call takes `now`, so a
 * probe timeout, a time-threshold loss and an idle timeout are all tested by moving a number rather
 * than by sleeping: a test that slept would be testing the machine's load, and the values it would
 * assert on would be the ones that happen to be slow enough to be stable.
 */

#include "test_quic_connection_internal.h"

int main(void) {
  test_quic_space_names();
  test_frame_permission();
  test_a_frame_that_is_not_a_challenge_is_not_handled_as_one();
  test_a_path_challenge_is_echoed_immediately();
  test_a_path_is_validated_by_its_own_response();
  test_a_path_that_does_not_answer_is_given_up_on();
  test_handshake_done_role();
  test_key_discard();
  test_round_trip(WT_UDP_IPV4);
  test_round_trip(WT_UDP_IPV6);
  test_short_packet_is_padded(WT_UDP_IPV4);
  test_client_initial_datagram_is_padded();
  test_short_initial_datagram_is_discarded();
  test_packet_threshold_loss();
  test_ack_for_unsent_packet();
  test_close_paths();
  test_a_refusal_leaves_a_readable_close(WT_UDP_IPV4);
  test_a_refusal_leaves_a_readable_close(WT_UDP_IPV6);
  test_a_handler_can_name_the_code_it_refused_with(WT_UDP_IPV4);
  test_crypto_is_permitted_in_the_application_space();
  test_discards();
  test_garbage(WT_UDP_IPV4);
  test_garbage(WT_UDP_IPV6);
  test_a_retry_is_accepted_and_answered();
  test_a_retry_that_breaks_a_rule_is_discarded();
  test_an_unauthenticable_packet_is_discarded();
  test_a_key_update_moves_both_directions();
  test_an_acknowledgement_confirms_the_update();
  test_a_reordered_packet_with_no_reference_is_read();
  test_a_reordered_packet_is_read_with_the_retained_keys();
  test_a_second_update_without_an_answer_is_refused();
  test_the_confidentiality_limit_rotates_the_keys();
  test_a_limit_with_no_update_possible_closes();
  test_the_integrity_limit_closes_the_connection();
  test_the_limits_follow_the_suite();
  test_using_an_issued_connection_id();
  test_a_retire_prior_to_replaces_the_id_in_use();
  test_a_retransmission_descriptor_is_released_on_acknowledgement();
  test_a_lost_control_frame_is_sent_again();
  test_an_acknowledged_control_frame_is_not_sent_again();
  test_a_failed_control_resend_is_redriven_by_flush();
  test_only_retransmittable_frames_keep_a_slot();

  test_open_stream();
  test_peer_opens_stream();
  test_the_reliable_stream_reset_is_sent_and_applied();
  test_the_reliable_stream_reset_rules();
  test_reset_and_stop();
  test_limit_extension();
  test_reset_stream_send();
  test_stream_retransmit_descriptor();
  test_stop_sending_send();
  test_issue_connection_id();
  test_peer_connection_ids();
  test_a_server_answers_to_the_clients_chosen_id();
  test_an_http3_refusal_is_an_application_close(WT_UDP_IPV4);
  test_retire_connection_id();
  test_retire_handshake_connection_id();
  test_new_connection_id_retire_prior_to_is_refused();
  test_packets_to_issued_connection_ids();
  WT_TEST_MAIN_END("wt_quic_connection");
}
