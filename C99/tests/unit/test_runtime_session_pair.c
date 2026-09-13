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
#include "webtransport/webtransport/framing.h"
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
                                               server_peer, k_connection_id,
                                               sizeof(k_connection_id), &server_connection,
                                               &server_tls, pair->now));
  WT_EXPECT_OK("the client arms",
               wt_runtime_session_start_client(&pair->client, &pair->client_socket,
                                               client_peer, k_connection_id,
                                               sizeof(k_connection_id), &client_connection,
                                               &client_tls, pair->now));
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

int main(void) {
  test_a_handshake_completes_over_loopback();
  test_a_refusal_reaches_the_peer_as_an_application_close();
  test_a_reliable_stream_reset_crosses_the_connection();
  test_a_lost_packet_is_retransmitted();
  test_a_connect_and_its_response_cross_the_connection();
  WT_TEST_MAIN_END("wt_runtime_session_pair");
}
