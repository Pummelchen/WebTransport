/* Shared fixtures and prototypes for the split `test_runtime_session_pair` translation units.
 *
 * The single test file became several so a reader can find a topic's fixtures with its tests.
 * Everything shared lives here: the loopback pair and the HTTP/3 sides it carries, the helpers that
 * arm the pair and pump it, and every test entry point `main` calls. Definitions are in
 * test_runtime_session_pair_support.c and the topic files; the harness counters they use are shared
 * by tests/wt_test.c, because a translation unit no longer owns its own tally. */

#ifndef WT_TEST_RUNTIME_SESSION_PAIR_INTERNAL_H
#define WT_TEST_RUNTIME_SESSION_PAIR_INTERNAL_H

#include <stdio.h>
#include <string.h>

#include "wt_test.h"

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/session.h"
#include "webtransport/webtransport/buffered.h"
#include "webtransport/webtransport/error.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

/* ---- the trust fixtures: a real leaf, a real CA and a real signature ------------------------- */

typedef struct fixtures {
  uint8_t leaf[4096];
  size_t leaf_len;
  uint8_t ca_bundle[8192];
  size_t ca_bundle_len;
  uint8_t private_key[4096];
  size_t private_key_len;
} fixtures_t;

/* ---- the pair -------------------------------------------------------------------------------- */

typedef struct http3_side {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  /* The field section this side assembles: the driver reports a frame's payload in PIECES and buffers
   * nothing, so the side that owns the memory (this test) is the side that assembles it. */
  uint8_t section[2048];
  size_t section_length;
  int section_complete;
  uint64_t request_stream_id;
  unsigned frames_seen;
  unsigned control_frames;
  uint64_t last_control_type;
  /* The session's own bytes, which arrive on a WebTransport stream rather than as HTTP/3 frames: the draft's
   * stream types are the layer above's, and the unidirectional path is the one that already classifies them. */
  uint8_t stream_data[64];
  size_t stream_bytes;
  uint64_t last_stream_id;
  /* The session's datagrams, which arrive whole and are the draft's own framing: a quarter stream ID and then
   * the payload. The driver hands them over uninterpreted, so this test parses them the way the session layer
   * does. */
  uint8_t datagram[128];
  size_t datagram_bytes;
  unsigned datagrams;
  /* The RESET frames this side was told about, and the code the last one carried: what a peer's termination of a
   * session looks like from the other end (WT-182). */
  unsigned resets;
  uint64_t last_reset_code;
  /* The STOP_SENDING frames this side was told about, and the code the last one carried: for a stream this
   * endpoint cannot send on -- a peer's unidirectional stream -- section 4.6's "and/or" picks this one. */
  unsigned stops;
  uint64_t last_stop_code;
} http3_side_t;

typedef struct pair {
  fixtures_t fixtures;
  wt_tls_server_identity_t server_identity; /* kept alive for the whole pair: the handshake keeps the pointer */
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  wt_runtime_session_t client;
  wt_runtime_session_t server;
  /* The configurations and the TLS settings are kept on the PAIR rather than in the arming function's frame,
   * because a test that cancels a session and starts again needs the same ones -- and rebuilding them would be a
   * second description of the same connection (WT-178). */
  wt_quic_connection_config_t client_connection;
  wt_quic_connection_config_t server_connection;
  wt_tls_client_config_t client_tls;
  wt_tls_server_config_t server_tls;
  http3_side_t *server_side;
  uint64_t now;
} pair_t;

/* The connection ID both ends use, and the one the Initial keys are derived from. */
extern const uint8_t k_connection_id[8];

void open_socket(wt_udp_socket_t *socket, wt_udp_address_t *address);
void arm_pair_to(pair_t *pair, const wt_udp_address_t *client_peer,
                 const wt_udp_address_t *server_peer);
void arm_pair(pair_t *pair);
int both_established(const pair_t *pair);
int connect_arrived(const pair_t *pair);
unsigned pump_pair(pair_t *pair, unsigned rounds, int (*done)(const pair_t *));
wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
void init_side(http3_side_t *side, wt_http3_role_t role);

/* The test entry points, one per topic file, in the order `main` runs them. */
void test_a_handshake_completes_over_loopback(void);
void test_a_terminated_session_resets_its_streams(void);
void test_an_early_stream_is_parked_and_rejected_over_the_bound(void);
void test_clearing_a_session_that_never_started_is_safe(void);
void test_a_session_survives_being_cleared_twice_and_can_start_again(void);
void test_cancelling_a_handshake_is_safe(void);
void test_a_peer_that_closes_is_noticed_without_waiting_the_clock(void);
void test_a_retired_connection_id_is_replaced(void);
void test_a_retire_flood_is_rate_limited(void);
void test_a_refusal_reaches_the_peer_as_an_application_close(void);
void test_a_reliable_stream_reset_crosses_the_connection(void);
void test_a_lost_packet_is_retransmitted(void);
void test_a_connect_and_its_response_cross_the_connection(void);

#endif /* WT_TEST_RUNTIME_SESSION_PAIR_INTERNAL_H */
