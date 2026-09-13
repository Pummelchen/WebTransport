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
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

#ifndef WT_TRUST_FIXTURE_DIR
#error "WT_TRUST_FIXTURE_DIR must name the directory holding the trust fixtures"
#endif

static const uint8_t k_connection_id[8] = {0x0fU, 0x1eU, 0x2dU, 0x3cU, 0x4bU, 0x5aU, 0x69U, 0x78U};

/* The parameters BOTH ends advertise, built with the codec rather than written by hand. The unidirectional
 * counts matter because HTTP/3 opens three unidirectional streams before it sends anything, and the limits
 * matter because the LOCAL grants must match them (see `grant_receive_room`). */
static uint8_t g_parameters[256];
static size_t g_parameters_len;

static void build_parameters(void) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(g_parameters, sizeof(g_parameters));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("initial_max_data", wt_quic_transport_parameters_add_integer(
                                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_OK("initial_max_stream_data_bidi_local",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 4096U));
  WT_EXPECT_OK("initial_max_stream_data_uni",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 4096U));
  WT_EXPECT_OK("initial_max_streams_bidi", wt_quic_transport_parameters_add_integer(
                                               &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 8U));
  WT_EXPECT_OK("initial_max_streams_uni", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 8U));
  WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&w, &params));
  g_parameters_len = wt_writer_offset(&w);
  WT_EXPECT_TRUE("with bytes in them", g_parameters_len > 0U);
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
  http3_side_t *server_side;
  uint64_t now;
} pair_t;

static wt_status_t side_on_frame_payload(void *context_side, uint64_t stream_id, uint64_t type,
                                        const uint8_t *payload, size_t length, int last);
static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);

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
static void arm_pair(pair_t *pair) {
  wt_quic_connection_config_t client_connection;
  wt_quic_connection_config_t server_connection;
  wt_tls_client_config_t client_tls;
  wt_tls_server_config_t server_tls;
  static const char *const alpn_h3[] = {"h3"};

  WT_EXPECT_TRUE("the trust fixtures load", load_fixtures(&pair->fixtures));
  WT_EXPECT_TRUE("the parameters are built", (build_parameters(), g_parameters_len > 0U));
  memset(&client_tls, 0, sizeof(client_tls));
  memset(&server_tls, 0, sizeof(server_tls));
  memset(&pair->client, 0, sizeof(pair->client));
  memset(&pair->server, 0, sizeof(pair->server));
  pair->now = 1000U;

  open_socket(&pair->client_socket, &pair->client_address);
  open_socket(&pair->server_socket, &pair->server_address);
  connection_config(&client_connection, WT_QUIC_ROLE_CLIENT);
  connection_config(&server_connection, WT_QUIC_ROLE_SERVER);

  client_tls.host_name = "example.com";
  client_tls.alpn = alpn_h3;
  client_tls.alpn_count = 1U;
  client_tls.require_transport_parameters = 1;
  client_tls.transport_parameters = g_parameters;
  client_tls.transport_parameters_len = g_parameters_len;
  client_tls.trust.mode = WT_TLS_TRUST_STORE;
  client_tls.trust.ca_bundle = pair->fixtures.ca_bundle;
  client_tls.trust.ca_bundle_len = pair->fixtures.ca_bundle_len;
  client_tls.trust.host_name = "example.com";

  memset(&pair->server_identity, 0, sizeof(pair->server_identity));
  pair->server_identity.certificate[0] = pair->fixtures.leaf;
  pair->server_identity.certificate_len[0] = pair->fixtures.leaf_len;
  pair->server_identity.certificate_count = 1U;
  pair->server_identity.private_key = pair->fixtures.private_key;
  pair->server_identity.private_key_len = pair->fixtures.private_key_len;
  pair->server_identity.signature_scheme = WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256;
  server_tls.identity = &pair->server_identity;
  server_tls.alpn = "h3";
  server_tls.require_transport_parameters = 1;
  server_tls.transport_parameters = g_parameters;
  server_tls.transport_parameters_len = g_parameters_len;

  WT_EXPECT_OK("the server arms",
               wt_runtime_session_start_server(&pair->server, &pair->server_socket,
                                               &pair->client_address, k_connection_id,
                                               sizeof(k_connection_id), &server_connection,
                                               &server_tls, pair->now));
  WT_EXPECT_OK("the client arms",
               wt_runtime_session_start_client(&pair->client, &pair->client_socket,
                                               &pair->server_address, k_connection_id,
                                               sizeof(k_connection_id), &client_connection,
                                               &client_tls, pair->now));
}

/* The receive-side grants, which must MATCH what each endpoint advertises: the advertised number is a promise
 * and the local grant is the enforcement. Without them the flow account starts at zero and the FIRST stream
 * frame is refused as FLOW_CONTROL_ERROR -- which presents as a peer that says nothing. */
static void grant_receive_room(pair_t *pair) {
  wt_quic_connection_t *ends[2];
  size_t i;

  ends[0] = &pair->client.connection;
  ends[1] = &pair->server.connection;
  for (i = 0U; i < 2U; i++) {
    ends[i]->config.local_max_stream_data = 4096U;
    WT_EXPECT_OK("session-level receive credit",
                 wt_quic_connection_set_max_data(ends[i], 100000U));
    WT_EXPECT_OK("bidirectional stream room",
                 wt_quic_connection_set_max_streams(ends[i], WT_QUIC_STREAM_BIDIRECTIONAL, 8U));
    WT_EXPECT_OK("and unidirectional room",
                 wt_quic_connection_set_max_streams(ends[i], WT_QUIC_STREAM_UNIDIRECTIONAL, 8U));
  }
  WT_EXPECT_U64("the server's unidirectional grant is readable", 8U,
                wt_quic_connection_max_streams(&pair->server.connection, WT_QUIC_STREAM_UNIDIRECTIONAL));
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
  return wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 8192U);
}

static void init_side(http3_side_t *side, wt_http3_role_t role) {
  memset(side, 0, sizeof(*side));
  wt_http3_endpoint_init(&side->endpoint, role);
  wt_http3_driver_init(&side->driver, &side->endpoint);
  side->sink.context = side;
  side->sink.on_frame_payload = side_on_frame_payload;
}

/* ---- the tests ------------------------------------------------------------------------------- */

static void test_a_handshake_completes_over_loopback(void) {
  pair_t pair;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  grant_receive_room(&pair);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes under the pump", rounds < 400U);
  WT_EXPECT_STATUS("the client's handshake did not fail", WT_OK,
                   wt_runtime_session_failure(&pair.client));
  WT_EXPECT_STATUS("nor the server's", WT_OK, wt_runtime_session_failure(&pair.server));
  WT_EXPECT_INT("the client's handshake is confirmed", 1,
                wt_runtime_session_established(&pair.client));
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
  grant_receive_room(&pair);

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

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

int main(void) {
  test_a_handshake_completes_over_loopback();
  test_a_connect_and_its_response_cross_the_connection();
  WT_TEST_MAIN_END("wt_runtime_session_pair");
}
