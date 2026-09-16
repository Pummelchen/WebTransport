/* Driving an HTTP/3 endpoint from a connection (Phase 9).
 *
 * The driver exists for one reason: a stream's type prefix is a varint and a varint can be
 * split across frames. These tests are that fact and its consequences -- the prefix
 * reassembles across frames, the payload after it is a view into the frame that completed it,
 * a prefix that does not start at offset zero is the caller's accounting rather than the
 * peer's, an incomplete prefix is never classified, the pending table is a fixed bound, and a
 * stream that ends before its prefix is complete is dropped without ever becoming a stream of
 * any type.
 *
 * The suite is now one topic file per seam, all compiled into this one executable so the CTest name
 * `test_http3_driver` is unchanged: reassembling a prefix, HTTP/3 frame boundaries and the capsule
 * mark, the outbound half, and the routing of a connection's frames. The shared recording sinks
 * live in test_http3_driver_support.c, declared by test_http3_driver_internal.h.
 *
 * `main` runs them in the order below, which is the order this file used when the whole suite was
 * one translation unit. */

#include "test_http3_driver_internal.h"

int main(void) {
  test_a_prefix_split_across_frames();
  test_a_complete_prefix_in_one_frame();
  test_control_and_qpack_reach_the_endpoint();
  test_starting_our_own_streams();
  test_frame_boundaries_on_a_stream();
  test_settling_a_capsule_stream_leaves_the_other_streams_framing();
  test_a_connection_frame_is_routed();
  test_a_duplicate_settings_identifier_is_refused();
  test_the_outbound_half_sends_what_it_should();
  test_the_quic_transport_forwards();
  test_the_bidi_classifier();
  test_a_bidi_stream_is_routed_by_its_prefix();
  test_a_bidirectional_prefix_split_across_frames();
  test_the_pending_table_is_bounded();
  test_a_data_stream_knows_its_session();
  test_a_webtransport_uni_prefix_split_after_the_type();
  WT_TEST_MAIN_END("wt_http3_driver");
}
