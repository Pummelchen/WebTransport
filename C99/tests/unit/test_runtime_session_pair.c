/* Two packet sessions over loopback, handshaking through the driver (Phase 9).
 *
 * This is the plan's "run local IPv4 and IPv6 packet sessions" at the layer where it can be tested
 * without a tool: two sockets on the loopback interface, two runtime sessions, and a client and a
 * server completing a TLS 1.3 handshake inside QUIC Initial and Handshake packets. Everything below
 * the driver already had its own suite; what this test proves is that the driver ARMS them in an order
 * that works and that a caller who pumps both sides gets a confirmed handshake out of it.
 *
 * The two rules the driver exists to get right are both exercised invisibly here: the Initial keys are
 * derived from the same connection ID at both ends with the send and receive directions opposite (get
 * that wrong and not a single packet decrypts, which looks like a silent peer), and the frame handlers
 * are chained so the handshake sees CRYPTO frames while everything else is left alone. */

#include <stdio.h>
#include <string.h>

#include "wt_test.h"

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/runtime/session.h"
#include "webtransport/writer.h"

#ifndef WT_TRUST_FIXTURE_DIR
#error "WT_TRUST_FIXTURE_DIR must name the directory holding the trust fixtures"
#endif

static const uint8_t k_connection_id[8] = {0x0fU, 0x1eU, 0x2dU, 0x3cU, 0x4bU, 0x5aU, 0x69U, 0x78U};

static uint8_t g_parameters[256];
static size_t g_parameters_len;

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

/* The transport parameters both ends send, built with the codec rather than written by hand: they are
 * what the connection parses its peer limits out of, so a wrong one here would look like a flow-control
 * bug later. */
static void build_parameters(void) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(g_parameters, sizeof(g_parameters));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("initial_max_data", wt_quic_transport_parameters_add_integer(
                                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_OK("initial_max_stream_data_bidi_local",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1000U));
  WT_EXPECT_OK("initial_max_streams_bidi", wt_quic_transport_parameters_add_integer(
                                               &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 4U));
  /* HTTP/3 opens three UNIDIRECTIONAL streams before it sends anything (the control stream and the two
   * QPACK streams), so a peer that grants no unidirectional streams refuses them -- and the refusal
   * arrives as a state error from the open call, which is what the first run of this test reported. */
  WT_EXPECT_OK("initial_max_streams_uni", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 4U));
  WT_EXPECT_OK("initial_max_stream_data_uni",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 1000U));
  WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&w, &params));
  g_parameters_len = wt_writer_offset(&w);
  WT_EXPECT_TRUE("with bytes in them", g_parameters_len > 0U);
}

static void connection_config(wt_quic_connection_config_t *config, wt_quic_role_t role) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = k_connection_id;
  config->local_connection_id_length = sizeof(k_connection_id);
  /* The same connection ID at both ends, which is what makes the Initial keys -- derived from it -- the
   * same on both sides. A real deployment replaces the peer's ID with the one the server chose; that is
   * connection ID management this runtime still needs, and it is recorded on the tracker. */
  config->peer_connection_id = k_connection_id;
  config->peer_connection_id_length = sizeof(k_connection_id);
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = 1200U;
}

/* A loopback socket, and the address a peer sends to. */
static void open_socket(wt_udp_socket_t *socket, wt_udp_address_t *address) {
  wt_udp_address_t local;

  WT_EXPECT_OK("a loopback address parses", wt_udp_address_parse_host_port("127.0.0.1:0", &local));
  WT_EXPECT_OK("the socket opens", wt_udp_socket_open(socket, WT_UDP_IPV4));
  WT_EXPECT_OK("and binds", wt_udp_bind(socket, &local));
  WT_EXPECT_OK("its address is readable", wt_udp_address_parse("127.0.0.1", socket->port, address));
  WT_EXPECT_TRUE("on a port the system chose", socket->port != 0U);
}

static void test_two_sessions_handshake_over_loopback(void) {
  fixtures_t fixtures;
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  wt_quic_connection_config_t client_connection;
  wt_quic_connection_config_t server_connection;
  wt_tls_client_config_t client_tls;
  wt_tls_server_config_t server_tls;
  wt_tls_server_identity_t identity;
  wt_runtime_session_t client;
  wt_runtime_session_t server;
  static const char *const alpn_h3[] = {"h3"};
  uint64_t now = 1000U;
  unsigned round;

  WT_EXPECT_TRUE("the trust fixtures load", load_fixtures(&fixtures));
  memset(&client_tls, 0, sizeof(client_tls));
  memset(&server_tls, 0, sizeof(server_tls));
  build_parameters();

  open_socket(&client_socket, &client_address);
  open_socket(&server_socket, &server_address);

  connection_config(&client_connection, WT_QUIC_ROLE_CLIENT);
  connection_config(&server_connection, WT_QUIC_ROLE_SERVER);

  /* The client trusts the fixture CA for example.com: the handshake is authenticated at both ends, which
   * is the point of doing it with the real fixtures rather than with a bypass. */
  client_tls.host_name = "example.com";
  client_tls.alpn = alpn_h3;
  client_tls.alpn_count = 1U;
  client_tls.require_transport_parameters = 1;
  client_tls.transport_parameters = g_parameters;
  client_tls.transport_parameters_len = g_parameters_len;
  client_tls.trust.mode = WT_TLS_TRUST_STORE;
  client_tls.trust.ca_bundle = fixtures.ca_bundle;
  client_tls.trust.ca_bundle_len = fixtures.ca_bundle_len;
  client_tls.trust.host_name = "example.com";

  memset(&identity, 0, sizeof(identity));
  identity.certificate[0] = fixtures.leaf;
  identity.certificate_len[0] = fixtures.leaf_len;
  identity.certificate_count = 1U;
  identity.private_key = fixtures.private_key;
  identity.private_key_len = fixtures.private_key_len;
  identity.signature_scheme = WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256;
  server_tls.identity = &identity;
  server_tls.alpn = "h3";
  server_tls.require_transport_parameters = 1;
  server_tls.transport_parameters = g_parameters;
  server_tls.transport_parameters_len = g_parameters_len;

  memset(&client, 0, sizeof(client));
  memset(&server, 0, sizeof(server));
  WT_EXPECT_OK("the server arms",
               wt_runtime_session_start_server(&server, &server_socket, &client_address,
                                               k_connection_id, sizeof(k_connection_id),
                                               &server_connection, &server_tls, now));
  WT_EXPECT_OK("the client arms",
               wt_runtime_session_start_client(&client, &client_socket, &server_address,
                                               k_connection_id, sizeof(k_connection_id),
                                               &client_connection, &client_tls, now));

  /* Both sides pump until the handshake is confirmed. The socket is WAITED on before each pump,
   * because a non-blocking receive finds nothing until the packet has actually arrived, and a loop that
   * spun faster than the loopback interface would finish before the first Initial packet did. The round
   * count and the wait are both bounded, so a driver that never completes fails the test rather than
   * hanging it. */
  {
    wt_status_t client_pump = WT_OK;
    wt_status_t server_pump = WT_OK;

    for (round = 0U; round < 400U; round++) {
      if (wt_runtime_session_established(&client) != 0 &&
          wt_runtime_session_established(&server) != 0) {
        break;
      }
      /* A timeout here is the ordinary case and not an error: it means this side had nothing to read. */
      (void)wt_udp_wait(&client_socket, 2000U);
      (void)wt_udp_wait(&server_socket, 2000U);
      client_pump = wt_runtime_session_pump(&client, now);
      server_pump = wt_runtime_session_pump(&server, now);
      if (client_pump != WT_OK || server_pump != WT_OK) break;
      now += 1000U;
    }
    WT_EXPECT_STATUS("the client's pumps were clean", WT_OK, client_pump);
    WT_EXPECT_STATUS("and the server's", WT_OK, server_pump);
  }

  WT_EXPECT_STATUS("the client's handshake did not fail", WT_OK,
                   wt_runtime_session_failure(&client));
  WT_EXPECT_STATUS("nor the server's", WT_OK, wt_runtime_session_failure(&server));
  WT_EXPECT_INT("the client's handshake is confirmed", 1,
                wt_runtime_session_established(&client));
  WT_EXPECT_INT("and the server's too", 1, wt_runtime_session_established(&server));
  WT_EXPECT_INT("with application keys on the client", 1, wt_runtime_session_keys_ready(&client));
  WT_EXPECT_INT("and on the server", 1, wt_runtime_session_keys_ready(&server));
  WT_EXPECT_TRUE("the client read packets", client.packets_seen > 0U);
  WT_EXPECT_TRUE("and the server did too", server.packets_seen > 0U);

  wt_runtime_session_clear(&client);
  wt_runtime_session_clear(&server);
  wt_udp_close(&client_socket);
  wt_udp_close(&server_socket);
}

/* ---- The HTTP/3 layer over a real connection ------------------------------------------------
 *
 * The handshake is only the doorway: what a WebTransport endpoint IS is an HTTP/3 connection carrying a
 * CONNECT. This test walks the whole path -- two sessions handshaking, then the client opening HTTP/3's
 * own streams, sending an extended CONNECT as a QPACK field section, and the SERVER decoding it off the
 * wire and accepting it as a WebTransport request.
 *
 * The layer division is visible in the code below and is the point: the driver reports a frame's payload
 * in pieces and buffers NOTHING, so the side that owns the memory (here, the test) is the side that
 * assembles it -- which is why there is a bounded buffer in this file and not in the library. */

typedef struct http3_side {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  /* What the driver handed over for the request stream: the test's bounded buffer, assembled from the
   * pieces, because a frame's payload is the caller's to hold. */
  uint8_t section[2048];
  size_t section_length;
  int section_complete;
  unsigned control_frames;
  /* Which stream carries the exchange this side cares about: the client's request stream and the server's
   * view of it are the same number, and the sink needs to know which one to assemble. */
  uint64_t request_stream_id;
  /* Every frame the chained handler was asked about, whatever its kind: a count of zero here means the
   * chain never reached this layer, which is a different bug from a frame that arrived and was refused. */
  unsigned frames_seen;
  uint64_t last_control_type;
} http3_side_t;

static wt_status_t side_on_frame_payload(void *context, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last) {
  http3_side_t *side = context;

  if (stream_id != side->request_stream_id && type != WT_HTTP3_FRAME_HEADERS) {
    /* HTTP/3's own streams: the frames are the layer's, and this test only counts them. */
    side->control_frames++;
    side->last_control_type = type;
    return WT_OK;
  }
  if (type != WT_HTTP3_FRAME_HEADERS) return WT_OK;
  if (side->section_length + length > sizeof(side->section)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(side->section + side->section_length, payload, length);
  side->section_length += length;
  if (last != 0) side->section_complete = 1;
  return WT_OK;
}

static wt_status_t side_on_frame(void *context, wt_quic_space_t space,
                                 const wt_quic_frame_t *frame) {
  http3_side_t *side = context;
  side->frames_seen++;
  return wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 8192U);
}

/* The same pair, armed the same way, factored out so both tests use one setup. */
typedef struct pair {
  fixtures_t fixtures;
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  wt_runtime_session_t client;
  wt_runtime_session_t server;
  /* The server's HTTP/3 side, referenced by the pump's predicate: what "done" means here is the
   * CONNECT having arrived, not merely the handshake. */
  struct http3_side *server_http3;
  /* The server's identity LIVES HERE rather than in the arming function: the handshake keeps the pointer
   * it is given, so an identity on a stack frame that returned would leave the server signing with freed
   * memory -- and it did, which is how this comment came to be written. */
  wt_tls_server_identity_t server_identity;
  uint64_t now;
} pair_t;

static void arm_pair(pair_t *pair) {
  wt_quic_connection_config_t client_connection;
  wt_quic_connection_config_t server_connection;
  wt_tls_client_config_t client_tls;
  wt_tls_server_config_t server_tls;
  static const char *const alpn_h3[] = {"h3"};

  WT_EXPECT_TRUE("the trust fixtures load", load_fixtures(&pair->fixtures));
  memset(&client_tls, 0, sizeof(client_tls));
  memset(&server_tls, 0, sizeof(server_tls));
  memset(&pair->client, 0, sizeof(pair->client));
  memset(&pair->server, 0, sizeof(pair->server));

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

/* Pump both sides until the predicate says so, or the bound runs out. Bounded on purpose: a handshake
 * that never completes has to FAIL this test rather than hang the suite. */
static unsigned pump_pair(pair_t *pair, unsigned rounds,
                          int (*done)(const pair_t *)) {
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

static int both_established(const pair_t *pair) {
  return wt_runtime_session_established(&pair->client) != 0 &&
         wt_runtime_session_established(&pair->server) != 0;
}

static void test_a_connect_crosses_a_real_connection(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t transport;
  wt_http3_driver_transport_t transport_for_server;
  wt_http3_settings_t settings;
  wt_http3_message_t decoded;
  wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint64_t request_stream_id = 0U;
  uint8_t scratch[1024];
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  memset(&client, 0, sizeof(client));
  memset(&server, 0, sizeof(server));
  pair.now = 1000U;
  build_parameters();
  arm_pair(&pair);
  pair.server_http3 = &server;

  /* The handshake first: without it there are no application keys and the HTTP/3 bytes would be sent
   * into a connection that cannot protect them. */
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes under the pump", rounds < 400U);
  WT_EXPECT_INT("with the client confirmed", 1, wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("and the server too", 1, wt_runtime_session_established(&pair.server));

  /* The grants each side makes to the other. A connection accepts stream data only within what its OWN
   * configuration granted, and it opens streams only within what the PEER's parameters granted: both
   * halves are needed, and a missing one shows up as a stream that never arrives rather than as an
   * error. */
  {
    wt_quic_connection_t *ends[2];
    size_t side;
    ends[0] = &pair.client.connection;
    ends[1] = &pair.server.connection;
    for (side = 0U; side < 2U; side++) {
      ends[side]->config.local_max_stream_data = 4096U;
      /* The connection-level receive credit, which must MATCH the `initial_max_data` this endpoint
       * advertises in its parameters: the advertised number is a promise and the local grant is the
       * enforcement, and nothing pairs them yet. Without it the flow account starts at zero and the FIRST
       * stream frame is refused as FLOW_CONTROL_ERROR -- which the server raised here, frame type 8. */
      WT_EXPECT_OK("the endpoint grants session-level receive credit",
                   wt_quic_connection_set_max_data(ends[side], 100000U));
      WT_EXPECT_OK("the endpoint grants bidirectional streams",
                   wt_quic_connection_set_max_streams(ends[side], WT_QUIC_STREAM_BIDIRECTIONAL, 8U));
      WT_EXPECT_OK("and unidirectional ones",
                   wt_quic_connection_set_max_streams(ends[side], WT_QUIC_STREAM_UNIDIRECTIONAL, 8U));
    }
  }

  /* The grant the admission check will read, asserted on the very connections that closed with
   * STREAM_LIMIT_ERROR: if the setter and the check disagree about which slot a direction uses, or the
   * handshake overwrites the slot, this is where that shows. */
  WT_EXPECT_U64("the server's unidirectional grant is what it asked for", 8U,
                wt_quic_connection_max_streams(&pair.server.connection, WT_QUIC_STREAM_UNIDIRECTIONAL));
  WT_EXPECT_U64("and its bidirectional grant too", 8U,
                wt_quic_connection_max_streams(&pair.server.connection, WT_QUIC_STREAM_BIDIRECTIONAL));
  WT_EXPECT_U64("the client's unidirectional grant as well", 8U,
                wt_quic_connection_max_streams(&pair.client.connection, WT_QUIC_STREAM_UNIDIRECTIONAL));
  WT_EXPECT_U64("and the client's bidirectional one", 8U,
                wt_quic_connection_max_streams(&pair.client.connection, WT_QUIC_STREAM_BIDIRECTIONAL));

  /* Each side of the HTTP/3 conversation: an endpoint, a driver, and the sink the driver reports to. */
  wt_http3_endpoint_init(&client.endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_endpoint_init(&server.endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&client.driver, &client.endpoint);
  wt_http3_driver_init(&server.driver, &server.endpoint);
  client.sink.context = &client;
  client.sink.on_frame_payload = side_on_frame_payload;
  server.sink.context = &server;
  server.sink.on_frame_payload = side_on_frame_payload;

  /* The driver joins the session BEHIND the handshake's handler, which is what the chaining is for. */
  WT_EXPECT_OK("the client's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &client));
  WT_EXPECT_OK("and the server's",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));

  /* The transport the driver sends through is the connection itself, through the adapter. */
  wt_http3_driver_quic_transport(&pair.client.connection, &transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &transport_for_server);

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the client advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));

  /* The whole client opening sequence in ONE call -- control stream, both QPACK streams, a request stream and
   * the extended CONNECT -- which is the same sequence the tools will run. It exists because doing it by hand
   * is where three separate bugs were found in this phase: a grant that did not match the advertised value, a
   * stream opened on one machine and not the other, and a send whose offset was never recorded. */
  WT_EXPECT_OK("the client starts a session",
               wt_http3_driver_start_session(&client.driver, &transport, &settings, "example.com",
                                             "/chat", 0U, pair.now, &request_stream_id, &h3_error));
  WT_EXPECT_U64("on its first bidirectional stream", 0U, request_stream_id);

  /* THE RESPONSE IS NOT YET SENT, and the measurement says exactly why -- recorded rather than papered over
   * (WT-115). The client's CONNECT DOES arrive and DOES decode (the assertions above), so the receive path is
   * whole; what the server lacks is a QUIC STREAM to answer on:
   *
   *     wt_quic_connection_stream(&server.connection, request_stream_id) == NULL
   *
   * while the frame walk demonstrably delivered that stream's STREAM frame to this layer. A frame that was
   * walked for a stream the connection does not have is the next thing to explain, and it is the last thing
   * between this phase and a session a caller can use: a response needs a stream to go back on. The client's
   * sink is told which stream carries the exchange so the moment the server can answer, this test can assert
   * the whole exchange without being rewritten. */
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;
  /* A CONTRADICTION, recorded as the next thing to explain (WT-115). After the milestone assertions pass --
   * the CONNECT assembled and decoded on this very side -- the server's connection reports:
   *
   *     is_closed = 0, close code = 0, stream_frames_seen = 0, and NO streams in its table at all.
   *
   * A connection that walked zero STREAM frames cannot have delivered a STREAM frame to the HTTP/3 driver,
   * and a table with no streams cannot answer on any of them. One of the two objects the test talks to is
   * therefore not the one the frames arrive on, and the next probe is to print the CONNECTION pointer inside
   * the chained handler beside the side pointer -- `side_on_frame` is bound to `&server` and the session to
   * `&pair.server`, and if those are the same object in this test then the library is the place to look.
   *
   * The client's sink is told which stream carries the exchange now, so the moment a stream exists to answer
   * on, the whole exchange can be asserted without rewriting this test. */
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;

  /* The CONNECT is on the wire. What happens to it on the FAR side is the next part and is NOT
   * asserted here, because it does not happen yet: the client sends, the server reads packets, and the
   * HTTP/3 layer behind the handshake is never asked about a frame (`frames_seen` stays zero) -- which
   * means the connection consumes STREAM frames into its own stream state and the inbound path has to
   * come from there rather than from the frame handler. That is recorded as WT-110 on the tracker with
   * this evidence, and the test asserts only what is true today: the bytes went out. */
  /* MEASURED, and this round CORRECTED the previous reading of the same number. `packets_sent` was 9
   * BEFORE the measurement window and 9 after it, which the last round read as "the packet never leaves".
   * It had already been incremented by the send itself: the CONNECT packet WAS sent. The measurements that
   * hold are: the server reads packets, refuses none (a receive that is neither success nor "nothing there"
   * is counted and is zero), the flush reports OK on both sides, and application keys are installed in both
   * directions -- and still no stream is created and no frame reaches the handler.
   *
   * So the next counter belongs inside the connection's FRAME WALK (ensure_peer_stream and
   * deliver_to_handler), not in the session. WT-110 carries the corrected sequence. */
  rounds = pump_pair(&pair, 60U, NULL);
  /* The pump's own instrumentation, asserted rather than printed: both sides read packets, neither side
   * refused one (a receive that is neither success nor "nothing there" is counted), and the flush reported
   * OK -- so "the packet was refused somewhere on the way in" is now ruled out by measurement rather than
   * by reading. What is left is the server's frame WALK, which is where the next counter belongs. */
  /* MEASURED, and this round found the reason nothing arrived: BOTH connections are CLOSED, with transport
   * error code **3 -- STREAM_LIMIT_ERROR** -- long before the CONNECT matters. The server's frame walk did see
   * the client's STREAM frames (`stream_frames_seen` is 4), and then `ensure_peer_stream` decided the client
   * had opened more streams than this endpoint granted and closed the connection; everything after that is
   * ignored, which is exactly why no stream was created for the request and no frame reached the handler.
   *
   * The admission check reads `local_max_streams[bidirectional ? 0 : 1]`, and this test sets BOTH to 8 before
   * any stream is opened -- so the accounting, not the test, is what believes one unidirectional stream was
   * granted. That is the next thing to reproduce in isolation (set 8, open peer streams, read the grant), and
   * WT-110 carries it. The assertions below are the ones that are TRUE today and that would have saved three
   * rounds: frames DO arrive, and the walk DOES see them. */
  /* THE CONNECT ARRIVED. The server's HTTP/3 layer was asked about four frames (the control stream's
   * SETTINGS among them), the request stream's field section was assembled from the pieces the driver
   * reported, and the section below is decoded off the wire. */
  WT_EXPECT_TRUE("the server's HTTP/3 layer was asked about frames", server.frames_seen > 0U);
  WT_EXPECT_U64("the control stream's SETTINGS arrived", 1U, (uint64_t)server.control_frames);
  WT_EXPECT_U64("as SETTINGS", WT_HTTP3_FRAME_SETTINGS, server.last_control_type);
  WT_EXPECT_TRUE("and the CONNECT's section assembled", server.section_complete != 0);
  WT_EXPECT_OK("the server tracks the request stream",
               wt_http3_endpoint_request_state(&server.endpoint, request_stream_id, &state));
  WT_EXPECT_INT("expecting the request line", (int)WT_HTTP3_REQUEST_EXPECT_HEADERS, (int)state);

  /* The section decodes, and the DRAFT-16 layer decides -- the separation every part of this phase kept:
   * HTTP/3 does not know what a WebTransport request is. This is the milestone: an extended CONNECT that
   * crossed a real QUIC connection, was assembled from the frames a driver reported, and was accepted. */
  WT_EXPECT_OK("the section decodes off the wire",
               wt_http3_endpoint_on_request_headers(&server.endpoint, request_stream_id,
                                                    server.section, server.section_length, scratch,
                                                    sizeof(scratch), &decoded, &h3_error));
  WT_EXPECT_BYTES("as the method that was sent", (const uint8_t *)"CONNECT", decoded.method,
                  decoded.method_length);
  WT_EXPECT_BYTES("the scheme", (const uint8_t *)"https", decoded.scheme, decoded.scheme_length);
  WT_EXPECT_BYTES("the authority", (const uint8_t *)"example.com", decoded.authority,
                  decoded.authority_length);
  WT_EXPECT_BYTES("the path", (const uint8_t *)"/chat", decoded.path, decoded.path_length);
  WT_EXPECT_BYTES("and the protocol", (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN,
                  decoded.protocol, decoded.protocol_length);

  policy.authority = "example.com";
  policy.path = "/chat";
  policy.wt_enabled = 1;
  WT_EXPECT_OK("the draft-16 layer accepts it",
               wt_webtransport_session_request_validate(&decoded, &policy, &decision, &h3_error));
  WT_EXPECT_INT("as a WebTransport request", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                (int)decision.outcome);
  WT_EXPECT_OK("and the server's request state advances",
               wt_http3_endpoint_request_state(&server.endpoint, request_stream_id, &state));
  WT_EXPECT_INT("past the request line", (int)WT_HTTP3_REQUEST_BODY, (int)state);

  /* The pump's own instrumentation, asserted rather than printed: both sides read packets, neither side
   * refused one, and both flushes reported OK. */
  WT_EXPECT_U64("the server refused no packet", 0U, (uint64_t)pair.server.receive_errors);
  WT_EXPECT_U64("and neither did the client", 0U, (uint64_t)pair.client.receive_errors);
  WT_EXPECT_STATUS("the client's flush succeeded", WT_OK, pair.client.last_flush);
  WT_EXPECT_STATUS("the server's flush succeeded", WT_OK, pair.server.last_flush);

  WT_EXPECT_INT("with the request stream tracked by the client", 1,
                wt_http3_endpoint_request_state(&client.endpoint, request_stream_id, &state) == WT_OK);
  (void)decoded;
  (void)policy;
  (void)decision;
  (void)scratch;
  (void)server;
  (void)rounds;

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

int main(void) {
  test_two_sessions_handshake_over_loopback();
  test_a_connect_crosses_a_real_connection();
  WT_TEST_MAIN_END("wt_runtime_session_pair");
}
