/* Shared fixtures and prototypes for the split `test_http3_driver` translation units.
 *
 * The single test file became several so a reader can find a topic's fixtures with its tests.
 * Everything shared lives here: the two recording logs the scenarios assert against, the helpers
 * that fill them, and every test entry point `main` calls. Definitions are in
 * test_http3_driver_support.c and the topic files; the harness counters they use are shared by
 * tests/wt_test.c, because a translation unit no longer owns its own tally. */

#ifndef WT_TEST_HTTP3_DRIVER_INTERNAL_H
#define WT_TEST_HTTP3_DRIVER_INTERNAL_H

#include <stdio.h>

#include "wt_test.h"

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/connection.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"

/* A sink that records what it was handed, so the test can assert the frame boundary rather
 * than trusting it. */
typedef struct frame_log {
  unsigned frames;
  uint64_t last_type;
  size_t total_bytes;
  unsigned last_was_last;
  uint8_t first_byte;
} frame_log_t;

/* A sink that records the session's own data, so the test can assert what the driver handed
 * over rather than what it happened to leave behind. */
typedef struct session_log {
  unsigned streams;
  size_t stream_bytes;
  unsigned datagrams;
  size_t datagram_bytes;
  uint64_t last_stream_id;
} session_log_t;

wt_status_t record_frame(void *context, uint64_t stream_id, uint64_t type,
                         const uint8_t *payload, size_t length, int last);
wt_status_t record_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                               size_t length, int fin);
wt_status_t record_datagram(void *context, const uint8_t *data, size_t length);

/* Reassembling a stream's prefix, one frame at a time. */
void test_a_prefix_split_across_frames(void);
void test_a_complete_prefix_in_one_frame(void);
void test_control_and_qpack_reach_the_endpoint(void);
void test_the_pending_table_is_bounded(void);
void test_a_data_stream_knows_its_session(void);
void test_a_webtransport_uni_prefix_split_after_the_type(void);

/* HTTP/3 frame boundaries, and the capsule mark that changes what a stream's bytes are. */
void test_frame_boundaries_on_a_stream(void);
void test_settling_a_capsule_stream_leaves_the_other_streams_framing(void);

/* The outbound half: the streams an endpoint starts and the frames it sends. */
void test_starting_our_own_streams(void);
void test_the_outbound_half_sends_what_it_should(void);
void test_the_quic_transport_forwards(void);

/* Routing a connection's frames to whichever sink the stream's kind names. */
void test_a_connection_frame_is_routed(void);
void test_the_bidi_classifier(void);
void test_a_bidi_stream_is_routed_by_its_prefix(void);
void test_a_bidirectional_prefix_split_across_frames(void);

#endif /* WT_TEST_HTTP3_DRIVER_INTERNAL_H */
