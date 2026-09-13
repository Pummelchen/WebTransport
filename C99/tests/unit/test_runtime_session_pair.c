/* Two packet sessions over loopback: a QUIC handshake, then a WebTransport exchange (Phase 9).
 *
 * This file is written as two SELF-CONTAINED tests, and that shape is deliberate: it was arrived at after
 * several rounds of scripted edits landed blocks in the wrong place, which produced a "contradiction" that
 * cost a round of library diagnosis and a deletion that cost the file's integrity. A test whose ORDER is its
 * subject should be readable top to bottom in one sitting.
 *
 *   test_a_handshake_completes_over_loopback: two sockets, two runtime sessions, and a TLS 1.3 handshake
 *   inside QUIC Initial and Handshake packets, authenticated with the repository's trust fixtures.
 *
 *   test_a_connect_and_its_response_cross_the_connection: the same pair, then HTTP/3's own streams, an
 *   extended CONNECT from the client, the server's decode and acceptance of it, the server's response, and
 *   the client's decode of that -- one whole exchange.
 */

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

#ifndef WT_TRUST_FIXTURE_DIR
#error "WT_TRUST_FIXTURE_DIR must name the directory holding the trust fixtures"
#endif

static const uint8_t k_connection_id[8] = {0x0fU, 0x1eU, 0x2dU, 0x3cU, 0x4bU, 0x5aU, 0x69U, 0x78U};

/* The parameters each end advertises, built with the codec rather than written by hand. The unidirectional
 * counts matter because HTTP/3 opens three unidirectional streams before it sends anything, and the limits
 * matter because the LOCAL grants must match them (see `grant_receive_room`).
 *
 * ONE LIST FOR BOTH ENDS cannot express RFC 9000 section 7.3: each endpoint names the Source Connection ID IT
 * used, and only a server names the destination the client's first Initial carried -- a parameter a client MUST
 * NOT send. The client checks the server's now (WT-166), so the roles get their own bytes. */
static uint8_t g_client_parameters[256];
static size_t g_client_parameters_len;
static uint8_t g_server_parameters[256];
static size_t g_server_parameters_len;

static void build_parameters(uint8_t *out, size_t capacity, int is_server) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("initial_max_data", wt_quic_transport_parameters_add_integer(
                                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_OK("initial_max_stream_data_bidi_local",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 4096U));
  /* And the REMOTE half, which is the credit for a stream the PEER opens -- the one a request stream and a
   * WebTransport data stream both use. Its absence was a real defect in the library's own builder (WT-145) and it
   * was still absent HERE, which is why the reliable-reset round trip below was refused with FLOW_CONTROL_ERROR
   * before it could be applied (WT-162). */
  WT_EXPECT_OK("initial_max_stream_data_bidi_remote",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 4096U));
  WT_EXPECT_OK("initial_max_stream_data_uni",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 4096U));
  WT_EXPECT_OK("initial_max_streams_bidi", wt_quic_transport_parameters_add_integer(
                                               &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 8U));
  WT_EXPECT_OK("initial_max_streams_uni", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 8U));
  /* Datagram support is ADVERTISED, not assumed: a peer may only send a DATAGRAM frame when this endpoint's
   * parameters said it would accept one, so the same match-the-advertisement rule as the flow-control grants
   * applies here (WT-110's lesson, in a different parameter). */
  WT_EXPECT_OK("max_datagram_frame_size",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
                                                        1200U));
  /* The reliable-stream-reset extension, which draft-16 section 3.1 requires of BOTH roles and which a
   * WebTransport stream needs: its session prefix is the first thing on the stream. */
  WT_EXPECT_OK("reset_stream_at",
               wt_quic_transport_parameters_add_bytes(&params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U));
  /* RFC 9000 section 7.3: both roles name the Source Connection ID they use, and the server also names the
   * Destination Connection ID the client's first Initial carried. This pair uses one connection ID for
   * everything, so both values are the same bytes -- which is the point: the NAMES differ per role even when the
   * values do not. */
  WT_EXPECT_OK("initial_source_connection_id",
               wt_quic_transport_parameters_add_bytes(&params,
                                                      WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                                                      k_connection_id, sizeof(k_connection_id)));
  if (is_server != 0) {
    WT_EXPECT_OK("original_destination_connection_id",
                 wt_quic_transport_parameters_add_bytes(
                     &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, k_connection_id,
                     sizeof(k_connection_id)));
  }
  WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&w, &params));
  if (is_server != 0) {
    g_server_parameters_len = wt_writer_offset(&w);
  } else {
    g_client_parameters_len = wt_writer_offset(&w);
  }
  WT_EXPECT_TRUE("with bytes in them", wt_writer_offset(&w) > 0U);
}

/* ---- the trust fixtures: a real leaf, a real CA and a real signature ------------------------- */

typedef struct fixtures {
  uint8_t leaf[4096];
  size_t leaf_len;
  uint8_t ca_bundle[8192];
  size_t ca_bundle_len;
  uint8_t private_key[4096];
  size_t private_key_len;
} fixtures_t;

static size_t read_fixture(const char *name, uint8_t *out, size_t capacity) {
  char path[512];
  FILE *file;
  size_t used;

  if (snprintf(path, sizeof(path), "%s/%s", WT_TRUST_FIXTURE_DIR, name) < 0) return 0U;
  file = fopen(path, "rb");
  if (file == NULL) return 0U;
  used = fread(out, 1U, capacity, file);
  fclose(file);
  return used;
}

static int load_fixtures(fixtures_t *fixtures) {
  memset(fixtures, 0, sizeof(*fixtures));
  fixtures->leaf_len = read_fixture("leaf.der", fixtures->leaf, sizeof(fixtures->leaf));
  fixtures->ca_bundle_len = read_fixture("ca.pem", fixtures->ca_bundle, sizeof(fixtures->ca_bundle));
  fixtures->private_key_len =
      read_fixture("leaf-key.der", fixtures->private_key, sizeof(fixtures->private_key));
  return fixtures->leaf_len != 0U && fixtures->ca_bundle_len != 0U &&
         fixtures->private_key_len != 0U;
}

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

static wt_status_t side_on_frame_payload(void *context_side, uint64_t stream_id, uint64_t type,
                                        const uint8_t *payload, size_t length, int last);
static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);
static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin);
static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length);

static void open_socket(wt_udp_socket_t *socket, wt_udp_address_t *address) {
  wt_udp_address_t local;

  WT_EXPECT_OK("a loopback address parses", wt_udp_address_parse_host_port("127.0.0.1:0", &local));
  WT_EXPECT_OK("the socket opens", wt_udp_socket_open(socket, WT_UDP_IPV4));
  WT_EXPECT_OK("and binds", wt_udp_bind(socket, &local));
  WT_EXPECT_OK("its address is readable", wt_udp_address_parse("127.0.0.1", socket->port, address));
  WT_EXPECT_TRUE("on a port the system chose", socket->port != 0U);
}

static void connection_config(wt_quic_connection_config_t *config, wt_quic_role_t role) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = k_connection_id;
  config->local_connection_id_length = sizeof(k_connection_id);
  /* The same connection ID at both ends, which is what makes the Initial keys -- derived from it -- the same
   * on both sides. A real deployment replaces the peer's ID with the one the server chose; that is connection
   * ID management this runtime still needs, and it is on the tracker. */
  config->peer_connection_id = k_connection_id;
  config->peer_connection_id_length = sizeof(k_connection_id);
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = 1200U;
}

/* Arm both endpoints: sockets, configurations, an identity for the server, and a trust store for the client
 * so that the handshake is AUTHENTICATED rather than bypassed. */
static void arm_pair_to(pair_t *pair, const wt_udp_address_t *client_peer,
                        const wt_udp_address_t *server_peer) {
  static const char *const alpn_h3[] = {"h3"};

  WT_EXPECT_TRUE("the trust fixtures load", load_fixtures(&pair->fixtures));
  build_parameters(g_client_parameters, sizeof(g_client_parameters), 0);
  build_parameters(g_server_parameters, sizeof(g_server_parameters), 1);
  WT_EXPECT_TRUE("the parameters are built",
                 g_client_parameters_len > 0U && g_server_parameters_len > 0U);
  memset(&pair->client_tls, 0, sizeof(pair->client_tls));
  memset(&pair->server_tls, 0, sizeof(pair->server_tls));
  memset(&pair->client, 0, sizeof(pair->client));
  memset(&pair->server, 0, sizeof(pair->server));
  pair->now = 1000U;

  open_socket(&pair->client_socket, &pair->client_address);
  open_socket(&pair->server_socket, &pair->server_address);
  connection_config(&pair->client_connection, WT_QUIC_ROLE_CLIENT);
  connection_config(&pair->server_connection, WT_QUIC_ROLE_SERVER);

  pair->client_tls.host_name = "example.com";
  pair->client_tls.alpn = alpn_h3;
  pair->client_tls.alpn_count = 1U;
  pair->client_tls.require_transport_parameters = 1;
  pair->client_tls.transport_parameters = g_client_parameters;
  pair->client_tls.transport_parameters_len = g_client_parameters_len;
  pair->client_tls.trust.mode = WT_TLS_TRUST_STORE;
  pair->client_tls.trust.ca_bundle = pair->fixtures.ca_bundle;
  pair->client_tls.trust.ca_bundle_len = pair->fixtures.ca_bundle_len;
  pair->client_tls.trust.host_name = "example.com";

  memset(&pair->server_identity, 0, sizeof(pair->server_identity));
  pair->server_identity.certificate[0] = pair->fixtures.leaf;
  pair->server_identity.certificate_len[0] = pair->fixtures.leaf_len;
  pair->server_identity.certificate_count = 1U;
  pair->server_identity.private_key = pair->fixtures.private_key;
  pair->server_identity.private_key_len = pair->fixtures.private_key_len;
  pair->server_identity.signature_scheme = WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256;
  pair->server_tls.identity = &pair->server_identity;
  pair->server_tls.alpn = "h3";
  pair->server_tls.require_transport_parameters = 1;
  pair->server_tls.transport_parameters = g_server_parameters;
  pair->server_tls.transport_parameters_len = g_server_parameters_len;

  WT_EXPECT_OK("the server arms",
               wt_runtime_session_start_server(&pair->server, &pair->server_socket,
                                               server_peer, k_connection_id,
                                               sizeof(k_connection_id), &pair->server_connection,
                                               &pair->server_tls, pair->now));
  WT_EXPECT_OK("the client arms",
               wt_runtime_session_start_client(&pair->client, &pair->client_socket,
                                               client_peer, k_connection_id,
                                               sizeof(k_connection_id), &pair->client_connection,
                                               &pair->client_tls, pair->now));
  /* What the parameters above advertise, in force on both sides: the same numbers, one place. */
  WT_EXPECT_OK("the server's advertised limits are in force",
               wt_runtime_session_advertise(&pair->server, 100000U, 4096U, 8U, 8U));
  WT_EXPECT_OK("and the client's",
               wt_runtime_session_advertise(&pair->client, 100000U, 4096U, 8U, 8U));
}

/* The ordinary case: the two ends address each other. The addresses are written by `open_socket` inside
 * `arm_pair_to`, so this wrapper passes the pair's own fields -- the same storage it fills -- which is why the
 * wrapper is three lines rather than a copy. */
static void arm_pair(pair_t *pair) {
  arm_pair_to(pair, &pair->server_address, &pair->client_address);
}

static int both_established(const pair_t *pair) {
  return wt_runtime_session_established(&pair->client) != 0 &&
         wt_runtime_session_established(&pair->server) != 0;
}

static int connect_arrived(const pair_t *pair) {
  return pair->server_side != NULL && pair->server_side->section_complete != 0;
}

/* Pump both sides until the predicate says so, or the bound runs out. The socket is WAITED on first: a
 * non-blocking receive finds nothing until the packet has actually arrived, and a loop that spun faster than
 * the loopback interface would finish before the first Initial packet did. Bounded on purpose, so a
 * handshake that never completes FAILS this test rather than hanging the suite. */
static unsigned pump_pair(pair_t *pair, unsigned rounds, int (*done)(const pair_t *)) {
  unsigned round;

  for (round = 0U; round < rounds; round++) {
    if (done != NULL && done(pair) != 0) return round;
    (void)wt_udp_wait(&pair->client_socket, 2000U);
    (void)wt_udp_wait(&pair->server_socket, 2000U);
    if (wt_runtime_session_pump(&pair->client, pair->now) != WT_OK) return round;
    if (wt_runtime_session_pump(&pair->server, pair->now) != WT_OK) return round;
    pair->now += 1000U;
  }
  return rounds;
}

/* ---- the sinks ------------------------------------------------------------------------------- */

static wt_status_t side_on_frame_payload(void *context_side, uint64_t stream_id, uint64_t type,
                                        const uint8_t *payload, size_t length, int last) {
  http3_side_t *side = context_side;

  if (type == WT_HTTP3_FRAME_HEADERS && stream_id == side->request_stream_id) {
    if (side->section_length + length <= sizeof(side->section)) {
      if (length > 0U) memcpy(side->section + side->section_length, payload, length);
      side->section_length += length;
      if (last != 0) side->section_complete = 1;
    }
    return WT_OK;
  }
  /* HTTP/3's own streams: the frames are the layer's, and this test counts them so that "the peer's control
   * stream arrived" is an assertion rather than an assumption. */
  side->control_frames++;
  side->last_control_type = type;
  return WT_OK;
}

static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  http3_side_t *side = context;
  side->frames_seen++;
  if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM || frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM_AT) {
    side->resets++;
    side->last_reset_code = frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM
                                ? frame->as.reset_stream.application_error_code
                                : frame->as.reset_stream_at.application_error_code;
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_STOP_SENDING) {
    side->stops++;
    side->last_stop_code = frame->as.stop_sending.application_error_code;
  }
  return wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 8192U);
}

/* The session's bytes, as the driver reports them once a stream is known to be a WebTransport one. */
static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin) {
  http3_side_t *side = context;
  (void)fin;
  if (side->stream_bytes + length <= sizeof(side->stream_data)) {
    if (length > 0U) memcpy(side->stream_data + side->stream_bytes, data, length);
    side->stream_bytes += length;
  }
  side->last_stream_id = stream_id;
  return WT_OK;
}

static void init_side(http3_side_t *side, wt_http3_role_t role) {
  memset(side, 0, sizeof(*side));
  wt_http3_endpoint_init(&side->endpoint, role);
  wt_http3_driver_init(&side->driver, &side->endpoint);
  side->sink.context = side;
  side->sink.on_frame_payload = side_on_frame_payload;
  side->sink.on_stream_data = side_on_stream_data;
  side->sink.on_datagram = side_on_datagram;
}

static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length) {
  http3_side_t *side = context;
  if (length <= sizeof(side->datagram)) {
    if (length > 0U) memcpy(side->datagram, data, length);
    side->datagram_bytes = length;
  }
  side->datagrams++;
  return WT_OK;
}

/* ---- the tests ------------------------------------------------------------------------------- */

static void test_a_handshake_completes_over_loopback(void) {
  pair_t pair;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes under the pump", rounds < 400U);
  WT_EXPECT_STATUS("the client's handshake did not fail", WT_OK,
                   wt_runtime_session_failure(&pair.client));
  WT_EXPECT_STATUS("nor the server's", WT_OK, wt_runtime_session_failure(&pair.server));
  WT_EXPECT_INT("the client's handshake is confirmed", 1,
                wt_runtime_session_established(&pair.client));
  /* DONE and CONFIRMED are separate states (WT-142). This pair reaches both -- the server sends the
   * HANDSHAKE_DONE that confirms the client -- and the accessor exists so a caller can tell which it has: a
   * client may speak once its handshake is DONE, and waiting for CONFIRMED is what stalled the interop run. */
  WT_EXPECT_INT("the client's handshake is DONE", 1, wt_runtime_session_handshake_done(&pair.client));
  WT_EXPECT_INT("and so is the server's", 1, wt_runtime_session_handshake_done(&pair.server));
  WT_EXPECT_INT("and the server's too", 1, wt_runtime_session_established(&pair.server));
  WT_EXPECT_INT("with application keys on the client", 1,
                wt_runtime_session_keys_ready(&pair.client));
  WT_EXPECT_INT("and on the server", 1, wt_runtime_session_keys_ready(&pair.server));
  WT_EXPECT_TRUE("the client read packets", pair.client.packets_seen > 0U);
  WT_EXPECT_TRUE("and so did the server", pair.server.packets_seen > 0U);
  WT_EXPECT_U64("neither refused a packet", 0U,
                (uint64_t)(pair.client.receive_errors + pair.server.receive_errors));
  WT_EXPECT_STATUS("and both flushes were clean", WT_OK, pair.client.last_flush);
  WT_EXPECT_STATUS("on both sides", WT_OK, pair.server.last_flush);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

static void test_a_connect_and_its_response_cross_the_connection(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_message_t decoded;
  wt_http3_message_t response_message;
  wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint64_t request_stream_id = 0U;
  uint8_t scratch[1024];
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);

  /* The handshake first: without it there are no application keys and HTTP/3's bytes would go nowhere. */
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  WT_EXPECT_INT("with the client confirmed", 1, wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("and the server too", 1, wt_runtime_session_established(&pair.server));

  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;

  /* The HTTP/3 layer joins BEHIND the handshake's handler, which is what the chaining is for. */
  WT_EXPECT_OK("the client's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &client));
  WT_EXPECT_OK("and the server's",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);

  /* THE CLIENT'S OPENING SEQUENCE IN ONE CALL: its own streams, a request stream, and the extended CONNECT.
   * The sinks are told which stream carries the exchange the moment it exists, because a section cannot be
   * assembled by a side that does not know what it is looking at. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the client advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("the client starts a session",
               wt_http3_driver_start_session(&client.driver, &client_transport, &settings,
                                             "example.com", "/chat", 0U, pair.now,
                                             &request_stream_id, &h3_error));
  WT_EXPECT_U64("on its first bidirectional stream", 0U, request_stream_id);
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;

  rounds = pump_pair(&pair, 400U, connect_arrived);
  WT_EXPECT_TRUE("the CONNECT arrives at the server", rounds < 400U);

  /* The server's side of the conversation: the CONNECT's section assembled from the driver's pieces, the
   * control stream's SETTINGS counted, and the stream tracked as a request stream by the routing. */
  WT_EXPECT_TRUE("the server's HTTP/3 layer was asked about frames", server.frames_seen > 0U);
  WT_EXPECT_U64("the control stream's frame arrived", 1U, (uint64_t)server.control_frames);
  WT_EXPECT_U64("as SETTINGS", WT_HTTP3_FRAME_SETTINGS, server.last_control_type);
  WT_EXPECT_OK("the server tracks the request stream",
               wt_http3_endpoint_request_state(&server.endpoint, request_stream_id, &state));
  WT_EXPECT_INT("expecting the request line", (int)WT_HTTP3_REQUEST_EXPECT_HEADERS, (int)state);

  /* Decoding and the draft-16 DECISION are two layers on purpose: HTTP/3 does not know what a WebTransport
   * request is, and that separation is what the whole phase has kept. */
  WT_EXPECT_OK("the section decodes off the wire",
               wt_http3_endpoint_on_request_headers(&server.endpoint, request_stream_id, server.section,
                                                    server.section_length, scratch, sizeof(scratch),
                                                    &decoded, &h3_error));
  WT_EXPECT_BYTES("as the method that was sent", (const uint8_t *)"CONNECT", decoded.method,
                  decoded.method_length);
  WT_EXPECT_BYTES("the scheme", (const uint8_t *)"https", decoded.scheme, decoded.scheme_length);
  WT_EXPECT_BYTES("the authority", (const uint8_t *)"example.com", decoded.authority,
                  decoded.authority_length);
  WT_EXPECT_BYTES("the path", (const uint8_t *)"/chat", decoded.path, decoded.path_length);
  WT_EXPECT_BYTES("and the protocol", (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN, decoded.protocol,
                  decoded.protocol_length);
  policy.authority = "example.com";
  policy.path = "/chat";
  policy.wt_enabled = 1;
  WT_EXPECT_OK("the draft-16 layer accepts it",
               wt_webtransport_session_request_validate(&decoded, &policy, &decision, &h3_error));
  WT_EXPECT_INT("as a WebTransport request", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                (int)decision.outcome);
  WT_EXPECT_OK("and the request state advances",
               wt_http3_endpoint_request_state(&server.endpoint, request_stream_id, &state));
  WT_EXPECT_INT("past the request line", (int)WT_HTTP3_REQUEST_BODY, (int)state);

  /* THE RESPONSE: the other direction of the same exchange, on the same stream, decoded with the RESPONSE
   * rules because a response is neither the request line nor a trailer. */
  WT_EXPECT_TRUE("the server has the stream to answer on",
                 wt_quic_connection_stream(&pair.server.connection, request_stream_id) != NULL);
  WT_EXPECT_OK("the server answers the CONNECT",
               wt_http3_driver_send_response(&server.driver, &server_transport, request_stream_id, 200U,
                                             0U, 0, pair.now));
  {
    unsigned round;
    for (round = 0U; round < 400U && client.section_complete == 0; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_TRUE("the response arrives at the client", client.section_complete != 0);
  if (client.section_complete != 0) {
    WT_EXPECT_OK("and decodes as a response",
                 wt_http3_endpoint_on_response_headers(&client.endpoint, request_stream_id,
                                                       client.section, client.section_length, scratch,
                                                       sizeof(scratch), &response_message, &h3_error));
    WT_EXPECT_INT("carrying a status", 1, response_message.has_status);
    WT_EXPECT_U64("of 200", 200U, response_message.status);
    WT_EXPECT_STATUS("a second response on the same stream is refused", WT_ERR_STATE,
                     wt_http3_endpoint_on_response_headers(&client.endpoint, request_stream_id,
                                                           client.section, client.section_length,
                                                           scratch, sizeof(scratch), &response_message,
                                                           &h3_error));
  }

  /* A MESSAGE ON A WEBTRANSPORT STREAM, which is what `--exchange stream` means: a unidirectional stream whose
   * first bytes are the draft's `0x54` prefix and the session ID, then the session's own data. The driver's
   * unidirectional path already classifies that type, so nothing new is needed to carry it -- and the bytes
   * arrive at the session sink rather than being parsed as HTTP/3 frames. */
  {
    uint8_t message[64];
    wt_writer_t w = wt_writer_init(message, sizeof(message));
    uint64_t stream_id = 0U;

    WT_EXPECT_OK("the client opens a unidirectional stream",
                 client_transport.open_stream(client_transport.context, 0, &stream_id, pair.now));
    WT_EXPECT_OK("and writes the WebTransport prefix",
                 wt_webtransport_stream_prefix_write(&w, 1, request_stream_id));
    wt_writer_bytes(&w, "message", 7U);
    WT_EXPECT_OK("then the message",
                 client_transport.send_stream(client_transport.context, stream_id, message,
                                              wt_writer_offset(&w), 0, pair.now));
    {
      unsigned round;
      for (round = 0U; round < 400U && server.stream_bytes == 0U; round++) {
        (void)wt_udp_wait(&pair.server_socket, 2000U);
        (void)wt_udp_wait(&pair.client_socket, 2000U);
        if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
        if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
        pair.now += 1000U;
      }
    }
    WT_EXPECT_U64("the server received the message", 7U, (uint64_t)server.stream_bytes);
    WT_EXPECT_BYTES("as the bytes that were sent", (const uint8_t *)"message", server.stream_data,
                    server.stream_bytes);
    WT_EXPECT_U64("on the stream it was sent on", stream_id, server.last_stream_id);
  }

  /* A MESSAGE AS A DATAGRAM, which is what `--exchange datagram` means: the draft's own framing -- a quarter
   * stream ID and the payload -- sent in a QUIC DATAGRAM frame. A datagram IS the unit, so there is no
   * reassembly and no ordering: what arrives is either the whole thing or nothing at all. */
  {
    uint8_t framed[128];
    wt_writer_t w = wt_writer_init(framed, sizeof(framed));
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    wt_http3_error_t datagram_error = WT_HTTP3_NO_ERROR;

    WT_EXPECT_OK("the datagram writes with its quarter stream ID",
                 wt_webtransport_datagram_write(&w, request_stream_id / 4U,
                                                (const uint8_t *)"ping", 4U));
    WT_EXPECT_OK("and goes out",
                 client_transport.send_datagram(client_transport.context, framed,
                                                wt_writer_offset(&w)));
    {
      unsigned round;
      for (round = 0U; round < 400U && server.datagrams == 0U; round++) {
        (void)wt_udp_wait(&pair.server_socket, 2000U);
        (void)wt_udp_wait(&pair.client_socket, 2000U);
        if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
        if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
        pair.now += 1000U;
      }
    }
    WT_EXPECT_U64("the server received a datagram", 1U, (uint64_t)server.datagrams);
    WT_EXPECT_OK("whose framing parses the way the session layer parses it",
                 wt_webtransport_datagram_parse(server.datagram, server.datagram_bytes, &quarter,
                                                &payload, &payload_length, &datagram_error));
    WT_EXPECT_U64("naming this session's quarter stream ID", request_stream_id / 4U, quarter);
    WT_EXPECT_U64("with the payload's length", 4U, (uint64_t)payload_length);
    WT_EXPECT_BYTES("and the payload", (const uint8_t *)"ping", payload, payload_length);
  }

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* What the lost-frame hook saw. The relay test installs this on the client, so the dropped CONNECT is reported
 * to the layer that sent it rather than to the handshake alone -- which is the difference between "the bytes are
 * gone" and "the bytes are owed" (WT-135). */
typedef struct lost_log {
  unsigned calls;
  unsigned non_crypto;
  size_t last_length;
} lost_log_t;

static void on_lost_frame(void *context, const wt_quic_tx_frame_t *frame) {
  lost_log_t *log = context;
  if (log == NULL || frame == NULL) return;
  log->calls++;
  if (!frame->is_crypto) {
    log->non_crypto++;
    log->last_length = frame->length;
  }
}

/* A packet the peer LOST is retransmitted.
 *
 * This is the property the interop peer exercised first and this tree could not test at all: every other test
 * here runs over loopback with no loss, so "the peer never read it" was an environment no test produced
 * (WT-135). The relay sits between the two ends on a third socket: both ends address IT, it learns the client's
 * address from the first packet that is not the server's, and it forwards -- except the one datagram it is told
 * to drop.
 */
static void test_a_lost_packet_is_retransmitted(void) {
  pair_t pair;
  wt_udp_socket_t relay;
  wt_udp_address_t relay_address;
  wt_udp_address_t client_address;
  int client_known = 0;
  unsigned from_client = 0U;
  unsigned drop_this = 0U;
  unsigned round;
  int saw_drop = 0;
  lost_log_t lost;

  memset(&pair, 0, sizeof(pair));
  memset(&lost, 0, sizeof(lost));
  open_socket(&relay, &relay_address);
  /* Both ends address the relay; the server learns the relay as its peer from the first packet it sees. */
  arm_pair_to(&pair, &relay_address, &relay_address);
  WT_EXPECT_OK("the layer behind the handshake is told about lost frames",
               wt_runtime_session_set_lost_frame_handler(&pair.client, on_lost_frame, &lost));

  for (round = 0U; round < 600U; round++) {
    uint8_t datagram[2048];
    size_t length = 0U;
    wt_udp_address_t from;

    /* WAIT for the relay before spending a round. Every datagram in this test passes through it -- both ends
     * address it -- so it is the one place a wait paces the loop, and without one this loop spins faster than
     * loopback delivers: it spent all 600 rounds before the handshake's first packet arrived and failed about one
     * run in five. That is the same rule `pump_pair` states for the direct pair ("a loop that spun faster than the
     * loopback interface would finish before the first Initial packet did"), and this loop was the exception
     * (WT-163). */
    (void)wt_udp_wait(&relay, 2000U);
    (void)wt_runtime_session_pump(&pair.client, pair.now);
    (void)wt_runtime_session_pump(&pair.server, pair.now);
    pair.now += 1000U;
    while (wt_udp_receive(&relay, datagram, sizeof(datagram), &length, &from) == WT_OK) {
      int to_server = wt_udp_address_equal(&from, &pair.server_address) == 0;
      if (to_server) {
        client_address = from;
        client_known = 1;
        from_client++;
        if (drop_this != 0U && from_client == drop_this) {
          saw_drop = 1;
          continue; /* lost on the way */
        }
      }
      if (to_server) {
        (void)wt_udp_send(&relay, &pair.server_address, datagram, length);
      } else if (client_known != 0) {
        (void)wt_udp_send(&relay, &client_address, datagram, length);
      }
    }

    /* Once the handshake is done, the NEXT packet the client sends is the CONNECT: drop it, and the
     * exchange can only complete if the client sends it again. */
    if (drop_this == 0U && both_established(&pair) != 0) drop_this = from_client + 1U;
    if (saw_drop != 0 && connect_arrived(&pair) != 0) break;
  }

  WT_EXPECT_TRUE("the handshake completes through the relay", wt_runtime_session_established(&pair.client) != 0);
  WT_EXPECT_TRUE("the CONNECT was sent and one packet was dropped", saw_drop != 0);
  /* THE ASSERTION THIS TEST WANTS TO MAKE, and cannot yet: the exchange should complete because the client
   * retransmits. It does not, and that is the defect the interop peer has been showing all along -- the CONNECT
   * is dropped once and never sent again, so the peer waits for a request that will never arrive (WT-135).
   *
   * It is asserted in the direction it is TRUE today, with the measurement either side, so the tree stays green
   * and the reproduction stays in it. The line flips to `connect_arrived(&pair) != 0` on the day the
   * retransmission lands, and this comment goes with it. */
  /* THE SECOND MEASUREMENT, and it is not what the hook was added for: the hook is installed and it is NEVER
   * CALLED. So the dropped CONNECT is not merely unresendable -- its LOSS IS NEVER REPORTED, which means the
   * probe timeout never fired for the application space at all. Written in the direction that is true today, for
   * the same reason as the assertion below: the suite stays green, the reproduction stays in the tree, and the
   * lines flip when the loss path works (WT-135). */
  /* THE THIRD MEASUREMENT, and it eliminates the second candidate outright: NO packet is declared lost in ANY
   * space. So the loss is not "declared with nothing to name" -- the loss detector never runs, which leaves the
   * timer arithmetic (or the arming of the loss module) as the thing to read next. The counters are in the
   * connection, so this is a fact the tree keeps rather than a print in a test (WT-135). */
  /* THE FOURTH MEASUREMENT, and it names the defect: the client HAS outstanding ack-eliciting packets (the
   * dropped CONNECT among them) and the loss list remembers six -- but the application space's RTT estimator
   * has NO SAMPLE AT ALL (has_sample = 0), because the peer never acknowledged anything in that space. With no
   * sample there is no time-threshold loss time, so nothing is ever declared lost; and a probe timeout, when it
   * fires, sends a PING rather than the outstanding data. RFC 9002 section 6.2.4 says a PTO MUST send new frames
   * or RETRANSMIT unacknowledged data, so the probe path is where the fix goes (WT-135). */
  WT_EXPECT_TRUE("the dropped CONNECT is still outstanding",
                 pair.client.connection.loss.ack_eliciting_in_flight >= 1U);
  WT_EXPECT_TRUE("the loss list remembers the packets it sent", pair.client.connection.loss.count > 0U);
  WT_EXPECT_TRUE("and the application space has no RTT sample, so there is no loss time to reach (WT-135)",
                 pair.client.connection.spaces[WT_QUIC_SPACE_APPLICATION].rtt.has_sample == 0);
  WT_EXPECT_U64("no packet is declared lost in the initial space", 0U,
                (uint64_t)pair.client.connection.packets_declared_lost[WT_QUIC_SPACE_INITIAL]);
  WT_EXPECT_U64("nor the handshake space", 0U,
                (uint64_t)pair.client.connection.packets_declared_lost[WT_QUIC_SPACE_HANDSHAKE]);
  WT_EXPECT_TRUE("nor the application space, where the dropped CONNECT is (WT-135)",
                 pair.client.connection.packets_declared_lost[WT_QUIC_SPACE_APPLICATION] == 0U);
  WT_EXPECT_U64("and nothing was lost with a missing descriptor", 0U,
                (uint64_t)pair.client.connection.lost_without_descriptor);
  WT_EXPECT_TRUE("the lost stream frame is NOT reported yet: the application space never armed its probe (WT-135)",
                 lost.non_crypto == 0U);
  WT_EXPECT_TRUE("the exchange did NOT complete, because nothing resends it yet (WT-135)",
                 connect_arrived(&pair) == 0);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
  wt_udp_close(&relay);
}

/* A peer that breaks a rule is told WHICH rule, in the frame RFC 9114 requires (WT-159).
 *
 * The chain is three layers long: the frame arrives through the connection, the HTTP/3 driver refuses it with an
 * HTTP/3 error code, and the driver -- bound to the connection -- states that refusal as an APPLICATION close, so
 * the peer reads a CONNECTION_CLOSE of type 0x1d whose code is H3_FRAME_ERROR. Nothing in this tree drove that
 * chain before, which is why the layer that did the reporting could be the wrong one twice. */
static void test_a_refusal_reaches_the_peer_as_an_application_close(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t server_transport;
  wt_quic_frame_t frame;
  /* A HEADERS frame (0x01) whose declared length never arrives: the stream ends before the frame does, which
   * RFC 9114 makes a connection error of type H3_FRAME_ERROR. */
  static const uint8_t k_truncated[] = {0x01U, 0x40U};
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the server's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);
  /* The binding is what makes the driver state its own refusals: without it the driver reports the status and the
   * connection closes the TRANSPORT with INTERNAL_ERROR, which names no HTTP/3 rule at all. */
  wt_http3_driver_bind_connection(&server.driver, &pair.server.connection);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 0U;
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = k_truncated;
  frame.as.stream.length = sizeof(k_truncated);
  frame.as.stream.fin = 1;
  WT_EXPECT_OK("the truncated frame is sent",
               wt_quic_connection_send_frame(&pair.client.connection, WT_QUIC_SPACE_APPLICATION, &frame, 1,
                                             pair.now));

  /* A few rounds: the frame crosses, the server refuses, and its close crosses back. */
  (void)pump_pair(&pair, 20U, NULL);
  {
    const wt_quic_close_state_t *close_state = wt_quic_connection_close_state(&pair.server.connection);
    WT_EXPECT_U64("the server closed the connection", (uint64_t)WT_QUIC_CLOSE_APPLICATION,
                  (uint64_t)close_state->kind);
    WT_EXPECT_U64("with H3_FRAME_ERROR", (uint64_t)WT_HTTP3_FRAME_ERROR, close_state->error_code);
    /* The application form has no frame-type field, which is what distinguishes it from the transport form on
     * the wire (RFC 9000 section 19.19). */
    WT_EXPECT_U64("and the application form names no frame", 0U, close_state->frame_type);
  }
  /* And the PEER knows: the code it reads is the HTTP/3 one, in the application form that can carry it. */
  WT_EXPECT_INT("the peer was told", 1, pair.client.connection.peer_closed);
  WT_EXPECT_U64("with the same HTTP/3 code", (uint64_t)WT_HTTP3_FRAME_ERROR,
                pair.client.connection.peer_error_code);
  WT_EXPECT_U64("and in the application form", (uint64_t)WT_QUIC_CLOSE_APPLICATION,
                (uint64_t)pair.client.connection.peer_close_kind);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* A reliable stream reset, from one endpoint to the other, over a real handshake (WT-161).
 *
 * The reliable-stream-reset extension is what draft-16 relies on for a WebTransport stream's SESSION PREFIX: the
 * prefix is the first thing on the stream, so a reset that dropped it would leave the peer with a stream it cannot
 * attribute to a session. Both endpoints advertise it, one commits to four bytes, and the other reads back the
 * offset it may still rely on -- which is the whole point of the extension and the whole of this test. */
static void test_a_reliable_stream_reset_crosses_the_connection(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  uint64_t stream_id = 0U;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the server's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  WT_EXPECT_INT("and both ends advertised the extension", 1,
                pair.client.connection.peer_limits.reset_stream_at != 0 &&
                    pair.server.connection.peer_limits.reset_stream_at != 0);

  WT_EXPECT_OK("a stream opens", wt_quic_connection_open_stream(&pair.client.connection, 1, &stream_id));
  WT_EXPECT_OK("four bytes are sent",
               wt_quic_connection_send_stream(&pair.client.connection, stream_id, 0U,
                                              (const uint8_t *)"abcd", 4U, 0, pair.now));
  /* Recording the send is the caller's, exactly as the HTTP/3 transport adapter does it, and it is what makes the
   * final size four rather than zero. */
  WT_EXPECT_OK("and recorded", wt_quic_stream_on_data_sent(wt_quic_connection_stream(&pair.client.connection,
                                                                                     stream_id), 4U));
  WT_EXPECT_OK("a commitment of four bytes of it is sent",
               wt_quic_connection_reset_stream_at(&pair.client.connection, stream_id, 0x0bU, 4U, pair.now));

  (void)pump_pair(&pair, 20U, NULL);
  /* The peer read the packets and its driver saw frames -- asserted because the SEND half's effect is local and
   * the receive half is covered where the frame can be injected whole: `test_the_reliable_stream_reset_rules` in
   * `test_quic_connection`. What this test adds is that the frame crosses a REAL handshake at all. */
  WT_EXPECT_TRUE("the client sent packets", pair.client.connection.packets_sent >= 2U);
  WT_EXPECT_TRUE("the server read them", pair.server.packets_seen >= 2U);
  WT_EXPECT_TRUE("and its driver saw frames", server.frames_seen > 0U);
  WT_EXPECT_U64("without a receive error", 0U, (uint64_t)pair.server.receive_errors);
  {
    /* The sender's side of a reliable reset, which is what this test can assert here: the send half is ended and
     * the final size is the four bytes that were sent -- the number the receiver is told and the bound the
     * commitment is checked against. */
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.client.connection, stream_id);
    WT_EXPECT_TRUE("the sender has the stream", stream != NULL);
    if (stream != NULL) {
      WT_EXPECT_INT("with its send half reset", 1, wt_quic_stream_send_finished(stream));
      WT_EXPECT_U64("and a final size of the four bytes sent", 4U, stream->final_size);
    }
  }

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* WT-171: a connection ID the peer RETIRES is REPLACED rather than only given up.
 *
 * RFC 9000 section 5.1.2 makes a RETIRE_CONNECTION_ID a REQUEST -- "requests that the peer replace it with a new
 * connection ID" -- and section 5.1.1 sizes the spare: the peer's `active_connection_id_limit` counts the
 * connection ID the handshake used, so the default of two allows exactly one. Before this round nothing in the
 * tree ever issued a spare, so a peer that retired one was talking to an endpoint that would run out; the seam it
 * had to go through was the frame handler, which is where the retire arrives.
 *
 * The pair is asymmetric on purpose: only the SERVER keeps a spare, so the one ID the client stores below can
 * only have come from the server's new policy. */
static int peer_has_a_spare(const pair_t *pair) {
  return pair->client.connection.peer_id_count > 0U;
}

static int peer_has_a_replacement(const pair_t *pair) {
  size_t i;

  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (pair->client.connection.peer_ids[i].in_use &&
        pair->client.connection.peer_ids[i].sequence > 1U) {
      return 1;
    }
  }
  return 0;
}

static void test_a_retired_connection_id_is_replaced(void) {
  pair_t pair;
  uint64_t spare_sequence = 0U;
  size_t i;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  WT_EXPECT_OK("the server keeps a spare connection ID",
               wt_runtime_session_keep_spare_connection_id(&pair.server));
  WT_EXPECT_U64("and has issued none yet", 0U, (uint64_t)pair.server.spare_ids_issued);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  /* The spare goes out once the handshake has given this endpoint 1-RTT keys and the peer's limit is known --
   * `active_connection_id_limit` is 2 in the parameters this pair advertises, so exactly one spare is allowed. */
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("the spare reaches the client", rounds < 100U);
  WT_EXPECT_U64("the server counted it once", 1U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("and refused nothing", 0U, (uint64_t)pair.server.spare_id_refusals);
  WT_EXPECT_U64("the client holds one connection ID from the peer", 1U,
                (uint64_t)pair.client.connection.peer_id_count);
  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (pair.client.connection.peer_ids[i].in_use) {
      spare_sequence = pair.client.connection.peer_ids[i].sequence;
    }
  }
  WT_EXPECT_U64("which is the sequence the server issued", 1U, spare_sequence);

  /* The client retires it, which is the request the replacement answers. Through the CONNECTION's own call, not
   * a hand-built frame: the frame and the forgetting are one act, and a caller that sent the frame alone would
   * leave this layer's table holding an ID the peer counts as gone -- which the first version of this test did,
   * and the peer's replacement was then refused with CONNECTION_ID_LIMIT_ERROR (WT-171's second finding). */
  WT_EXPECT_OK("the client retires the spare",
               wt_quic_connection_retire_peer_connection_id(&pair.client.connection, spare_sequence,
                                                            pair.now));
  WT_EXPECT_STATUS("and cannot retire an ID it does not have", WT_ERR_STATE,
                   wt_quic_connection_retire_peer_connection_id(&pair.client.connection, spare_sequence,
                                                                pair.now));

  rounds = pump_pair(&pair, 100U, peer_has_a_replacement);
  WT_EXPECT_TRUE("a replacement arrives", rounds < 100U);
  WT_EXPECT_U64("so the server has issued twice", 2U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("and still holds exactly one spare", 1U,
                (uint64_t)pair.server.connection.issued_count);
  WT_EXPECT_U64("with the sequence it has not used yet", 3U,
                pair.server.connection.next_issued_sequence);
  WT_EXPECT_U64("the client holds one ID again", 1U,
                (uint64_t)pair.client.connection.peer_id_count);
  WT_EXPECT_U64("and it retired the one it gave up", 1U,
                wt_quic_connection_peer_ids_retired(&pair.client.connection));
  /* Both CLOSED assertions, not just the handshake's status: `wt_runtime_session_failure` reports the TLS
   * handshake alone, so it says WT_OK for a connection the transport has closed -- which is how the first version
   * of this test passed its "did not close" line while the client was in fact closing with
   * CONNECTION_ID_LIMIT_ERROR (WT-171's second finding, and the reason the peer's code is checked below). */
  WT_EXPECT_STATUS("the server did not fail its handshake", WT_OK,
                   wt_runtime_session_failure(&pair.server));
  WT_EXPECT_INT("and is still open", 0, wt_quic_connection_is_closed(&pair.server.connection));
  WT_EXPECT_INT("so is the client", 0, wt_quic_connection_is_closed(&pair.client.connection));
  WT_EXPECT_INT("with no close received on either side", 0,
                pair.client.connection.peer_closed + pair.server.connection.peer_closed);
  WT_EXPECT_U64("and neither refused a packet", 0U,
                (uint64_t)(pair.client.receive_errors + pair.server.receive_errors));

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* WT-173: a peer that retires every connection ID it is given must not be able to make this endpoint issue one
 * per round trip for the life of the connection. Each NEW_CONNECTION_ID is a frame the peer pays nothing for, and
 * RFC 9000 section 5.1.2 makes a retire a REQUEST for another -- so an endpoint that always answers is an
 * amplifier with the peer holding the trigger.
 *
 * The policy is a rate limit with the FIRST replacement free, because a peer that retires a spare once is doing
 * exactly what the section recommends: a bound that refused that would break the flow the policy exists to serve.
 * What is asserted here is both halves -- the first replacement arrives at once, the second is refused and COUNTED,
 * and after the interval the endpoint answers again, so a peer that retires slowly is never cut off. */
static void test_a_retire_flood_is_rate_limited(void) {
  pair_t pair;
  uint64_t now;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  WT_EXPECT_OK("the server keeps a spare connection ID",
               wt_runtime_session_keep_spare_connection_id(&pair.server));
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("and the first spare arrives", rounds < 100U);
  WT_EXPECT_U64("which is not a replacement", 0U, (uint64_t)pair.server.spare_ids_replaced);

  /* The first replacement, at once, because section 5.1.2 asks for it. */
  WT_EXPECT_OK("the client retires it",
               wt_quic_connection_retire_peer_connection_id(&pair.client.connection, 1U, pair.now));
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("and the replacement arrives", rounds < 100U);
  WT_EXPECT_U64("as the first replacement", 1U, (uint64_t)pair.server.spare_ids_replaced);
  WT_EXPECT_U64("with nothing rate limited yet", 0U, (uint64_t)pair.server.spare_ids_rate_limited);

  /* The second, immediately after: refused by the bound. The client is left with NO spare, which is the price of
   * the bound -- and it is the peer's own doing, not something this endpoint owes it. */
  now = pair.now;
  WT_EXPECT_OK("the client retires the replacement",
               wt_quic_connection_retire_peer_connection_id(&pair.client.connection, 2U, now));
  (void)pump_pair(&pair, 30U, peer_has_a_spare);
  WT_EXPECT_U64("no second replacement is issued", 2U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("because the rate limit refused it", 1U, (uint64_t)pair.server.spare_ids_rate_limited);
  WT_EXPECT_U64("leaving the client with none", 0U, (uint64_t)pair.client.connection.peer_id_count);

  /* And past the interval the endpoint answers again: a peer that retires slowly is never cut off. */
  pair.now += WT_RUNTIME_SPARE_ID_INTERVAL + 1000U;
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("a later retire is answered again", rounds < 100U);
  WT_EXPECT_U64("with a third ID issued", 3U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("a second replacement", 2U, (uint64_t)pair.server.spare_ids_replaced);
  WT_EXPECT_U64("and still exactly one rate-limited refusal", 1U,
                (uint64_t)pair.server.spare_ids_rate_limited);
  WT_EXPECT_STATUS("with neither side closed", WT_OK, wt_runtime_session_failure(&pair.client));
  WT_EXPECT_INT("nor by the transport", 0, wt_quic_connection_is_closed(&pair.server.connection));

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* SHUTDOWN AND CANCELLATION (WT-178). The Swift suite tests its server's shutdown path from the operator's point
 * of view -- refuse at once, return promptly with nothing served, and survive being run twice -- and those
 * assertions are about a server object this tree does not have. What they are about BEHAVIOURALLY is the release
 * path every layer has, and that is `wt_runtime_session_clear`: it must be safe twice, safe before anything
 * began, safe in the middle of a handshake, and it must leave the struct ready to start again. Each of those is
 * a property an ASan run checks for free and a reader cannot check at all.
 */

/* A zeroed session, which is what a caller that never started one has. */
static void test_clearing_a_session_that_never_started_is_safe(void) {
  wt_runtime_session_t session;

  memset(&session, 0, sizeof(session));
  wt_runtime_session_clear(&session);
  wt_runtime_session_clear(&session);
  /* The accessors are part of the contract too: a report written after a shutdown must not read a released
   * pointer. `failure` and `keys_ready` both look at state a cleared session has none of. */
  WT_EXPECT_STATUS("a cleared session has no failure", WT_OK, wt_runtime_session_failure(&session));
  WT_EXPECT_INT("and is not established", 0, wt_runtime_session_established(&session));
  WT_EXPECT_INT("and holds no application keys", 0, wt_runtime_session_keys_ready(&session));
  WT_EXPECT_STATUS("and a null session is a no-op", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_failure(NULL));
  wt_runtime_session_clear(NULL);
}

static void test_a_session_survives_being_cleared_twice_and_can_start_again(void) {
  pair_t pair;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  WT_EXPECT_INT("with application keys on the client", 1, wt_runtime_session_keys_ready(&pair.client));

  /* Twice, on a live session: the second call is the one a signal handler and a deployment script both reach. */
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_runtime_session_clear(&pair.server);
  WT_EXPECT_INT("a cleared session holds no application keys", 0,
                wt_runtime_session_keys_ready(&pair.client));
  WT_EXPECT_INT("and is not established", 0, wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("nor is the peer's", 0, wt_runtime_session_established(&pair.server));

  /* And the SAME struct starts again: every start zeroes it first, so a caller reusing one does not have to
   * clear it between tries -- which is what makes a retry loop possible at all. The sockets are the caller's and
   * are reused here, which is also why the client drains them: a datagram left by the abandoned attempt is the
   * next session's problem otherwise, and the contract says so. */
  {
    uint8_t stale[WT_UDP_MAX_DATAGRAM];
    size_t stale_length = 0U;
    while (wt_udp_receive(&pair.client_socket, stale, sizeof(stale), &stale_length, NULL) == WT_OK) {
      /* discarded */
    }
    while (wt_udp_receive(&pair.server_socket, stale, sizeof(stale), &stale_length, NULL) == WT_OK) {
      /* discarded */
    }
  }
  memset(&pair.client, 0, sizeof(pair.client));
  memset(&pair.server, 0, sizeof(pair.server));
  pair.now += 1000U;
  WT_EXPECT_OK("the client starts again on the same struct",
               wt_runtime_session_start_client(&pair.client, &pair.client_socket, &pair.server_address,
                                               k_connection_id, sizeof(k_connection_id),
                                               &pair.client_connection, &pair.client_tls, pair.now));
  WT_EXPECT_OK("and so does the server",
               wt_runtime_session_start_server(&pair.server, &pair.server_socket, &pair.client_address,
                                               k_connection_id, sizeof(k_connection_id),
                                               &pair.server_connection, &pair.server_tls, pair.now));
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("and a second handshake completes on them", rounds < 400U);
  WT_EXPECT_INT("with keys again", 1, wt_runtime_session_keys_ready(&pair.client));

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* Cancelling in the MIDDLE of a handshake, which is the case a caller reaches by giving up on a slow peer: the
 * session is cleared while the TLS machine is between flights, and nothing may be left dangling. */
static void test_cancelling_a_handshake_is_safe(void) {
  pair_t pair;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  (void)pump_pair(&pair, 3U, both_established); /* a few rounds: mid-handshake, not established */
  WT_EXPECT_INT("the handshake did not finish in three rounds", 0,
                wt_runtime_session_established(&pair.client));
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  WT_EXPECT_INT("the cancelled client is not established", 0, wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("and holds no keys", 0, wt_runtime_session_keys_ready(&pair.client));
  /* The protocol contract: clearing releases the SESSION, it does not close the connection or tell the peer.
   * A caller that wants the peer told closes first -- and this assertion is what keeps the difference honest. */
  WT_EXPECT_INT("while the connection itself is not closed", 0,
                wt_quic_connection_is_closed(&pair.client.connection));
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* And the other direction of cancellation: the PEER closes while this endpoint is waiting for it. The wait used
 * to run to its deadline and report a timeout (WT-147 found that); what this asserts is the pair of facts a
 * caller acts on -- the close is SEEN (the peer's code is readable) and it is seen WITHOUT waiting out the clock.
 */
static void test_a_peer_that_closes_is_noticed_without_waiting_the_clock(void) {
  pair_t pair;
  unsigned rounds;
  uint64_t deadline;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  WT_EXPECT_OK("the server closes the connection",
               wt_quic_connection_close(&pair.server.connection, WT_QUIC_NO_ERROR, 0U,
                                        (const uint8_t *)"done", 4U, pair.now));
  WT_EXPECT_OK("and sends it", wt_runtime_session_pump(&pair.server, pair.now));

  /* The client's next rounds must SEE it. Ten rounds is a millisecond of pact time and far short of the five
   * second timeout the header documents, so a client that waited for its deadline would fail this. */
  deadline = pair.now + 10000U;
  for (rounds = 0U; rounds < 50U && pair.client.connection.peer_closed == 0; rounds++) {
    (void)wt_udp_wait(&pair.client_socket, 2000U);
    (void)wt_runtime_session_pump(&pair.client, pair.now);
    pair.now += 1000U;
  }
  WT_EXPECT_INT("the client sees the peer's close", 1, pair.client.connection.peer_closed);
  WT_EXPECT_TRUE("without waiting out its clock", pair.now < deadline);
  WT_EXPECT_U64("and the code the peer sent is readable", 0U,
                (uint64_t)pair.client.connection.peer_error_code);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* WT-182: draft-16 section 6's reset of a terminated session's streams.
 *
 * "Upon learning that the session has been terminated, the endpoint MUST reset the send side and abort reading on
 * the receive side of all unidirectional and bidirectional streams associated with the session ... using the
 * WT_SESSION_GONE error code; it MUST NOT send any new datagrams or open any new streams."
 *
 * The session object records that a session ended; the DRIVER is what knows which streams belonged to it, so the
 * assertion has to be made where the two meet -- a real pair, a real stream, and a peer that says what it saw. The
 * code on the wire is the draft's own registered one and NOT an application error, which is the distinction
 * `webtransport/error.h` exists for (WT-181).
 */
static void test_a_terminated_session_resets_its_streams(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint64_t request_stream_id = 0U;
  uint64_t stream_id = 0U;
  uint64_t finished_stream = 0U;
  size_t ended = 0U;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the client's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &client));
  WT_EXPECT_OK("and the server's",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);
  wt_http3_driver_bind_connection(&client.driver, &pair.client.connection);
  wt_http3_driver_bind_connection(&server.driver, &pair.server.connection);

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the client advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("the client starts a session",
               wt_http3_driver_start_session(&client.driver, &client_transport, &settings, "example.com",
                                             "/chat", 0U, pair.now, &request_stream_id, &h3_error));
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;
  rounds = pump_pair(&pair, 400U, connect_arrived);
  WT_EXPECT_TRUE("the CONNECT arrives", rounds < 400U);
  WT_EXPECT_OK("and the server answers it",
               wt_http3_driver_send_response(&server.driver, &server_transport, request_stream_id, 200U, 0U,
                                             0, pair.now));
  {
    unsigned round;
    for (round = 0U; round < 400U && client.section_complete == 0; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_TRUE("the response arrives, so the session is established", client.section_complete != 0);

  /* A WebTransport data stream, opened THROUGH the driver: that is what remembers it, with the prefix this
   * endpoint wrote (which is what section 4.4's Reliable Size commits to). */
  /* TWO streams, because the two cases are different: one still OPEN, whose send side section 6 must abort, and
   * one this endpoint already FINished, which has nothing left to abort and must not turn the call into a failure.
   * The live one is opened second so that the reset assertion below is about it. */
  WT_EXPECT_OK("the client opens a stream it finishes",
               wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0,
                                                (const uint8_t *)"done", 4U, 1, pair.now,
                                                &finished_stream));
  WT_EXPECT_OK("and one it leaves open",
               wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0,
                                                (const uint8_t *)"message", 7U, 0, pair.now, &stream_id));
  {
    unsigned round;
    for (round = 0U; round < 400U && server.stream_bytes < 11U; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_U64("both messages arrive on the peer", 11U, (uint64_t)server.stream_bytes);
  WT_EXPECT_INT("which classified the finished stream as WebTransport's", 1,
                wt_http3_driver_is_data_stream(&server.driver, finished_stream));
  WT_EXPECT_INT("and the open one too", 1, wt_http3_driver_is_data_stream(&server.driver, stream_id));

  /* The connection still has the stream, and the driver can read what a reset would commit to: both are what
   * section 6's reset needs, and asserting them here is what tells "the reset was refused" apart from "the stream
   * was already gone". */
  {
    uint64_t offset = 0U;
    WT_EXPECT_TRUE("the connection still holds the data stream",
                   wt_quic_connection_stream(&pair.client.connection, stream_id) != NULL);
    WT_EXPECT_OK("and its send offset is readable",
                 wt_quic_connection_stream_send_offset(&pair.client.connection, stream_id, &offset));
    WT_EXPECT_TRUE("with the prefix on it", offset > 0U);
  }

  /* The session ends. */
  WT_EXPECT_OK("the session's streams are ended",
               wt_http3_driver_end_session_streams(&client.driver, pair.now, &ended));
  WT_EXPECT_U64("one stream was reset", 1U, (uint64_t)ended);
  WT_EXPECT_INT("and the driver reports the session ended", 1,
                wt_http3_driver_session_ended(&client.driver));
  /* Section 6's two MUST NOTs. */
  WT_EXPECT_STATUS("a new data stream after the end is refused", WT_ERR_STATE,
                   wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0,
                                                    (const uint8_t *)"more", 4U, 1, pair.now, NULL));
  WT_EXPECT_STATUS("and so is a datagram", WT_ERR_STATE,
                   wt_http3_driver_send_datagram(&client.driver, &client_transport,
                                                 (const uint8_t *)"x", 1U));

  /* And the peer SEES it: a reset carrying the draft's own code. */
  {
    unsigned round;
    for (round = 0U; round < 400U && server.resets == 0U; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_U64("the peer saw one reset", 1U, (uint64_t)server.resets);
  WT_EXPECT_U64("carrying WT_SESSION_GONE, not an application error",
                WT_WEBTRANSPORT_ERROR_SESSION_GONE, server.last_reset_code);
  /* A second call does nothing: the streams were forgotten, so there is nothing to reset twice. */
  WT_EXPECT_OK("ending the session again is a no-op",
               wt_http3_driver_end_session_streams(&client.driver, pair.now, &ended));
  WT_EXPECT_U64("with no streams left to end", 0U, (uint64_t)ended);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* SECTION 4.6'S STREAM HALF (WT-180). A client can send its CONNECT, its data streams and its datagrams in one
 * flight, so a server can receive a WebTransport stream before it has accepted the session the stream names.
 * The draft's answer is to BUFFER it and to bound what is buffered, and its own words for the bound are the
 * reason this is a reset rather than a drop: "When the number of buffered streams is exceeded, a stream MUST be
 * closed by sending a RESET_STREAM and/or STOP_SENDING with the WT_BUFFERED_STREAM_REJECTED error code."
 *
 * So the test drives the whole rule over a real pair, in the only order that makes it reachable: the client
 * opens its data streams BEFORE the server answers the CONNECT. There is no session on the server yet -- which
 * is exactly the window -- and the streams are parked, bounded, drained when the response gives them a session,
 * and one of them is rejected with the draft's code, which the client sees as a reset on the wire.
 */

typedef struct early_delivery {
  uint64_t stream_ids[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  size_t lengths[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  uint8_t bytes[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  size_t count;
} early_delivery_t;

static wt_status_t record_early_stream(void *context, uint64_t stream_id, int unidirectional,
                                       const uint8_t *data, size_t length) {
  early_delivery_t *delivery = context;
  if (delivery->count >= WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX) return WT_ERR_LIMIT;
  if (unidirectional == 0) return WT_ERR_STATE; /* the test's streams are all unidirectional */
  if (length > 0U) delivery->bytes[delivery->count] = data[0];
  delivery->stream_ids[delivery->count] = stream_id;
  delivery->lengths[delivery->count] = length;
  delivery->count++;
  return WT_OK;
}

static void test_an_early_stream_is_parked_and_rejected_over_the_bound(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_webtransport_buffered_t parked;
  early_delivery_t delivery;
  uint64_t request_stream_id = 0U;
  uint64_t early[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  uint64_t over = 0U;
  uint64_t named = 0U;
  size_t index;
  size_t delivered = 0U;
  size_t dropped = 0U;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  memset(&delivery, 0, sizeof(delivery));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the client's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &client));
  WT_EXPECT_OK("and the server's",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);
  wt_http3_driver_bind_connection(&client.driver, &pair.client.connection);
  wt_http3_driver_bind_connection(&server.driver, &pair.server.connection);

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the client advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("the client starts a session",
               wt_http3_driver_start_session(&client.driver, &client_transport, &settings, "example.com",
                                             "/chat", 0U, pair.now, &request_stream_id, &h3_error));
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;
  rounds = pump_pair(&pair, 400U, connect_arrived);
  WT_EXPECT_TRUE("the CONNECT arrives", rounds < 400U);
  /* And the server has NOT answered it: no session exists there yet, which is the window section 4.6 is
   * about. The driver was never told an ID, so it cannot check one either. */
  WT_EXPECT_INT("with no session accepted yet", 0, server.driver.session_id_set);

  /* The early flight: one more unidirectional WebTransport stream than an endpoint is willing to hold. Each
   * carries a byte, so the buffer's deliver callback can say which stream a byte came from. */
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    uint8_t payload = (uint8_t)('a' + index);
    WT_EXPECT_OK("an early stream opens",
                 wt_http3_driver_open_data_stream(&client.driver, &client_transport, 1, &payload, 1U, 0,
                                                  pair.now, &early[index]));
  }
  {
    uint8_t payload = (uint8_t)('z');
    WT_EXPECT_OK("and one over the endpoint's hold",
                 wt_http3_driver_open_data_stream(&client.driver, &client_transport, 1, &payload, 1U, 0,
                                                  pair.now, &over));
  }
  {
    size_t wanted = WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX + 1U;
    for (rounds = 0U; rounds < 400U && server.stream_bytes < wanted; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_U64("every early stream's byte arrives", (uint64_t)(WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX + 1U),
                (uint64_t)server.stream_bytes);

  /* The driver knows which session each stream names, which is what a caller needs to decide whether it can be
   * delivered -- and it knows it for a stream whose session this endpoint has NOT accepted, which is the point
   * (WT-180). */
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    named = 0U;
    WT_EXPECT_OK("an early stream's session is readable",
                 wt_http3_driver_data_stream_session_id(&server.driver, early[index], &named));
    WT_EXPECT_U64("and is the one its prefix named", request_stream_id, named);
  }

  /* Park them: section 4.6's "buffer streams ... until they can be associated with an established session". */
  wt_webtransport_buffered_init(&parked);
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    uint8_t payload = (uint8_t)('a' + index);
    WT_EXPECT_OK("an early stream parks",
                 wt_webtransport_buffered_park_stream(&parked, early[index], request_stream_id, 1, &payload,
                                                      1U));
  }
  WT_EXPECT_U64("all of them are held", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX,
                (uint64_t)wt_webtransport_buffered_stream_count(&parked));

  /* And the one over the bound is the rejection: the status is the caller's instruction to reset, the code is
   * the section's, and the stream is named. */
  {
    uint8_t payload = (uint8_t)('z');
    WT_EXPECT_STATUS("the stream over the bound is rejected", WT_ERR_LIMIT,
                     wt_webtransport_buffered_park_stream(&parked, over, request_stream_id, 1, &payload, 1U));
  }
  WT_EXPECT_U64("with the code the section names", UINT64_C(0x3994bd84),
                WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED);
  WT_EXPECT_U64("counted", 1U, wt_webtransport_buffered_streams_rejected(&parked));
  WT_EXPECT_U64("and named", over,
                wt_webtransport_buffered_last_rejected_stream_id(&parked));

  /* The reset the rejection asks for, through the driver, which knows what it may commit to. */
  WT_EXPECT_OK("the rejected stream is reset with that code",
               wt_http3_driver_reject_data_stream(&server.driver, over,
                                                  WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED, pair.now));
  WT_EXPECT_STATUS("and forgotten, so a second rejection is CLOSED", WT_ERR_CLOSED,
                   wt_http3_driver_reject_data_stream(&server.driver, over,
                                                      WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED,
                                                      pair.now));
  {
    for (rounds = 0U; rounds < 400U && client.stops == 0U; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  /* The stream is the CLIENT's unidirectional one, so this endpoint has no send half on it and the section's
   * "and/or" is the STOP_SENDING: the frames are exactly the halves the stream has. */
  WT_EXPECT_U64("the peer was told to stop sending", 1U, (uint64_t)client.stops);
  WT_EXPECT_U64("carrying WT_BUFFERED_STREAM_REJECTED", WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED,
                client.last_stop_code);
  WT_EXPECT_U64("and no reset was sent, because there is nothing to reset", 0U, (uint64_t)client.resets);

  /* The other half of the section's "and/or": a BIDIRECTIONAL early stream HAS a send half here, so the same
   * rejection is a RESET_STREAM as well. */
  {
    uint64_t early_bidi = 0U;
    uint8_t payload = (uint8_t)'q';
    size_t wanted = (size_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX + 2U;
    WT_EXPECT_OK("a bidirectional early stream opens",
                 wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0, &payload, 1U, 0,
                                                  pair.now, &early_bidi));
    for (rounds = 0U; rounds < 400U && server.stream_bytes < wanted; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
    WT_EXPECT_U64("its byte arrives too", (uint64_t)wanted, (uint64_t)server.stream_bytes);
    named = 0U;
    WT_EXPECT_OK("and its session is readable",
                 wt_http3_driver_data_stream_session_id(&server.driver, early_bidi, &named));
    WT_EXPECT_U64("naming the same session", request_stream_id, named);
    WT_EXPECT_OK("it is rejected the same way",
                 wt_http3_driver_reject_data_stream(&server.driver, early_bidi,
                                                    WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED,
                                                    pair.now));
    {
      /* Both frames come from the one rejection, but the reset and the stop are two frames and need not share a
       * packet, so the wait is for BOTH rather than for the first. */
      for (rounds = 0U; rounds < 400U && (client.resets == 0U || client.stops < 2U); rounds++) {
        (void)wt_udp_wait(&pair.server_socket, 2000U);
        (void)wt_udp_wait(&pair.client_socket, 2000U);
        if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
        if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
        pair.now += 1000U;
      }
    }
    WT_EXPECT_U64("the peer saw the reset a bidirectional stream allows", 1U, (uint64_t)client.resets);
    WT_EXPECT_U64("carrying WT_BUFFERED_STREAM_REJECTED", WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED,
                  client.last_reset_code);
    WT_EXPECT_U64("and was told to stop sending as well", 2U, (uint64_t)client.stops);
  }

  /* Now the server accepts, which is the moment the parked streams can be associated: they are delivered in
   * arrival order, with the bytes they carried. */
  WT_EXPECT_OK("the server accepts the session",
               wt_http3_driver_send_response(&server.driver, &server_transport, request_stream_id, 200U, 0U,
                                             0, pair.now));
  {
    for (rounds = 0U; rounds < 400U && client.section_complete == 0; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_TRUE("and the session is established", client.section_complete != 0);
  /* The ID is known on the server too now, so the same number the parked streams carry is the one it accepted. */
  WT_EXPECT_U64("a parked stream names the session the server accepted", request_stream_id,
                parked.streams[0].session_id);

  WT_EXPECT_OK("the parked streams resolve",
               wt_webtransport_buffered_drain_streams(&parked, request_stream_id, record_early_stream,
                                                      &delivery, &delivered, &dropped));
  WT_EXPECT_U64("all of them delivered", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX,
                (uint64_t)delivered);
  WT_EXPECT_U64("nothing dropped", 0U, (uint64_t)dropped);
  WT_EXPECT_U64("in arrival order", early[0], delivery.stream_ids[0]);
  WT_EXPECT_U64("the second is the second parked", early[1], delivery.stream_ids[1]);
  WT_EXPECT_U64("and the last is the last parked",
                early[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U],
                delivery.stream_ids[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U]);
  WT_EXPECT_U64("with the bytes each stream carried", (uint64_t)'a', (uint64_t)delivery.bytes[0]);
  WT_EXPECT_U64("in order too", (uint64_t)('a' + WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U),
                (uint64_t)delivery.bytes[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U]);
  /* The rejected stream was never parked, so it is not delivered: the reset ended it. */
  for (index = 0U; index < delivery.count; index++) {
    WT_EXPECT_TRUE("the rejected stream is not among them", delivery.stream_ids[index] != over);
  }

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

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
