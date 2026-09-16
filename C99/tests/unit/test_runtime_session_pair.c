/* Two packet sessions over loopback: a QUIC handshake, then a WebTransport exchange (Phase 9).
 *
 * The suite is now one topic file per seam, all compiled into this one executable so the CTest name
 * `test_runtime_session_pair` is unchanged: the loopback exchange, packet loss, the frames that
 * cross a real handshake, connection-ID retirement, the runtime session's shutdown and cancellation
 * paths, a terminated session's stream resets, and early-stream buffering. The shared pair, its
 * fixtures and its pump live in test_runtime_session_pair_support.c, declared by
 * test_runtime_session_pair_internal.h.
 *
 * `main` runs them in the order below, which is the order this file used when the whole suite was
 * one translation unit: a test whose ORDER is its subject should stay readable in one sitting.
 */

#include "test_runtime_session_pair_internal.h"

int main(void) {
  test_a_handshake_completes_over_loopback();
  test_a_terminated_session_resets_its_streams();
  test_an_early_stream_is_parked_and_rejected_over_the_bound();
  test_clearing_a_session_that_never_started_is_safe();
  test_a_session_survives_being_cleared_twice_and_can_start_again();
  test_cancelling_a_handshake_is_safe();
  test_a_peer_that_closes_is_noticed_without_waiting_the_clock();
  test_a_retired_connection_id_is_replaced();
  test_a_retire_flood_is_rate_limited();
  test_a_refusal_reaches_the_peer_as_an_application_close();
  test_a_reliable_stream_reset_crosses_the_connection();
  test_a_lost_packet_is_retransmitted();
  test_a_connect_and_its_response_cross_the_connection();
  WT_TEST_MAIN_END("wt_runtime_session_pair");
}
