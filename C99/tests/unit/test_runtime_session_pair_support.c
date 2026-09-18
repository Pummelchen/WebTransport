/* Fixtures shared by the test_runtime_session_pair topic files: the connection ID and transport
 * parameters both ends use, the trust fixtures a pair is armed with, and the sinks the HTTP/3
 * layers report through. */

#include "test_runtime_session_pair_internal.h"

#ifndef WT_TRUST_FIXTURE_DIR
#error "WT_TRUST_FIXTURE_DIR must name the directory holding the trust fixtures"
#endif

const uint8_t k_connection_id[8] = {0x0fU, 0x1eU, 0x2dU, 0x3cU, 0x4bU, 0x5aU, 0x69U, 0x78U};

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
  WT_EXPECT_OK("max_datagram_frame_size", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 1200U));
  /* The reliable-stream-reset extension, which draft-16 section 3.1 requires of BOTH roles and which a
   * WebTransport stream needs: its session prefix is the first thing on the stream. */
  WT_EXPECT_OK("reset_stream_at", wt_quic_transport_parameters_add_bytes(
                                      &params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U));
  /* RFC 9000 section 7.3: both roles name the Source Connection ID they use, and the server also names the
   * Destination Connection ID the client's first Initial carried. This pair uses one connection ID for
   * everything, so both values are the same bytes -- which is the point: the NAMES differ per role even when the
   * values do not. */
  WT_EXPECT_OK("initial_source_connection_id", wt_quic_transport_parameters_add_bytes(
                                                   &params, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
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

/* Reads the trust fixtures named by WT_TRUST_FIXTURE_DIR into a pair. */
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
  fixtures->ca_bundle_len =
      read_fixture("ca.pem", fixtures->ca_bundle, sizeof(fixtures->ca_bundle));
  fixtures->private_key_len =
      read_fixture("leaf-key.der", fixtures->private_key, sizeof(fixtures->private_key));
  return fixtures->leaf_len != 0U && fixtures->ca_bundle_len != 0U &&
         fixtures->private_key_len != 0U;
}

static wt_status_t side_on_frame_payload(void *context_side, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last);
static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin);
static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length);

void open_socket(wt_udp_socket_t *socket, wt_udp_address_t *address) {
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
void arm_pair_to(pair_t *pair, const wt_udp_address_t *client_peer,
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

  WT_EXPECT_OK("the server arms", wt_runtime_session_start_server(
                                      &pair->server, &pair->server_socket, server_peer,
                                      k_connection_id, sizeof(k_connection_id),
                                      &pair->server_connection, &pair->server_tls, pair->now));
  WT_EXPECT_OK("the client arms", wt_runtime_session_start_client(
                                      &pair->client, &pair->client_socket, client_peer,
                                      k_connection_id, sizeof(k_connection_id),
                                      &pair->client_connection, &pair->client_tls, pair->now));
  /* What the parameters above advertise, in force on both sides: the same numbers, one place. */
  WT_EXPECT_OK("the server's advertised limits are in force",
               wt_runtime_session_advertise(&pair->server, 100000U, 4096U, 8U, 8U));
  WT_EXPECT_OK("and the client's",
               wt_runtime_session_advertise(&pair->client, 100000U, 4096U, 8U, 8U));
}

/* The ordinary case: the two ends address each other. The addresses are written by `open_socket` inside
 * `arm_pair_to`, so this wrapper passes the pair's own fields -- the same storage it fills -- which is why the
 * wrapper is three lines rather than a copy. */
void arm_pair(pair_t *pair) {
  arm_pair_to(pair, &pair->server_address, &pair->client_address);
}

int both_established(const pair_t *pair) {
  return wt_runtime_session_established(&pair->client) != 0 &&
         wt_runtime_session_established(&pair->server) != 0;
}

int connect_arrived(const pair_t *pair) {
  return pair->server_side != NULL && pair->server_side->section_complete != 0;
}

/* Pump both sides until the predicate says so, or the bound runs out. The socket is WAITED on first: a
 * non-blocking receive finds nothing until the packet has actually arrived, and a loop that spun faster than
 * the loopback interface would finish before the first Initial packet did. Bounded on purpose, so a
 * handshake that never completes FAILS this test rather than hanging the suite. */
unsigned pump_pair(pair_t *pair, unsigned rounds, int (*done)(const pair_t *)) {
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

wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  http3_side_t *side = context;
  side->frames_seen++;
  if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM ||
      frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM_AT) {
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

void init_side(http3_side_t *side, wt_http3_role_t role) {
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
