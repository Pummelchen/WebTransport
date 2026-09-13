/* Two endpoints in one process, over loopback: the harness the scenarios share (WT-160). */

#include "scenario_pair.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/http3/settings.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/tls/self_signed.h"
#include "webtransport/writer.h"

void scenario_detail_set(char *detail, size_t size, const char *text) {
  if (detail == NULL || size == 0U) return;
  (void)snprintf(detail, size, "%s", text);
}

/* The client's own connection ID, which it also chooses as the destination of its first Initial. */
static const uint8_t k_client_connection_id[8] = {0x21U, 0x32U, 0x43U, 0x54U,
                                                  0x65U, 0x76U, 0x87U, 0x98U};
/* And the server's OWN Source Connection ID, deliberately different (RFC 9000 section 7.2): the rule that a client
 * adopts it is only exercised when the two differ, and one shared constant is exactly how a client that never
 * adopted it -- and a server that answered only to its own ID -- passed every test in this tree (WT-151). */
static const uint8_t k_server_connection_id[8] = {0x12U, 0x34U, 0x56U, 0x78U,
                                                  0x9aU, 0xbcU, 0xdeU, 0xf0U};

static wt_status_t side_on_frame_payload(void *context, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last) {
  scenario_side_t *side = context;
  if (type == WT_HTTP3_FRAME_HEADERS && stream_id == side->request_stream_id) {
    if (side->section_length + length <= sizeof(side->section)) {
      if (length > 0U) memcpy(side->section + side->section_length, payload, length);
      side->section_length += length;
      if (last != 0) side->section_complete = 1;
    }
    return WT_OK;
  }
  side->control_frames++;
  return WT_OK;
}

static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin) {
  scenario_side_t *side = context;

  /* The CONNECT stream is the session's: its bytes after the one HEADERS frame are capsules, which the driver
   * routes here rather than framing (WT-164). A scenario that sends one asserts what this applied. */
  if (stream_id == side->request_stream_id) {
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_status_t status = wt_capsule_stream_on_bytes(&side->capsules, data, length, fin,
                                                    wt_capsule_stream_apply_flow, &side->capsules, &error);
    if (status != WT_OK) {
      /* A refused capsule is stated to the peer in its own error space: an HTTP/3 code to the connection, a
       * session code into a close capsule, which is what the scenario below asserts (WT-165). */
      side->capsule_error = (uint64_t)error;
      if (wt_capsule_stream_refuse(&side->capsules, side->transport, side->request_stream_id, side->connection,
                                   side->now, error) == WT_CAPSULE_REFUSAL_SESSION) {
        /* The session is closed and the peer has been told in the capsule itself: the connection stays up, so this
         * failure must NOT reach the transport (section 5.1, WT-165). */
        return WT_OK;
      }
    }
    return status;
  }
  if (side->stream_bytes + length <= sizeof(side->stream_data)) {
    if (length > 0U) memcpy(side->stream_data + side->stream_bytes, data, length);
    side->stream_bytes += length;
  }
  return WT_OK;
}

static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length) {
  scenario_side_t *side = context;
  if (length <= sizeof(side->datagram)) {
    if (length > 0U) memcpy(side->datagram, data, length);
    side->datagram_bytes = length;
  }
  side->datagrams++;
  return WT_OK;
}

static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  scenario_side_t *side = context;
  side->frames_seen++;
  return wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 16384U);
}

static void init_side(scenario_side_t *side, wt_http3_role_t role) {
  memset(side, 0, sizeof(*side));
  wt_http3_endpoint_init(&side->endpoint, role);
  wt_http3_driver_init(&side->driver, &side->endpoint);
  wt_capsule_stream_init(&side->capsules);
  side->sink.context = side;
  side->sink.on_frame_payload = side_on_frame_payload;
  side->sink.on_stream_data = side_on_stream_data;
  side->sink.on_datagram = side_on_datagram;
}

/* The endpoint's transport parameters, built by the LIBRARY: the mandatory connection-ID parameters live in
 * `wt_quic_transport_parameters_build` so that this file cannot forget one. It did forget one -- the parameter
 * that says which Source Connection ID these packets carry -- and only a third-party peer ever said so (WT-141).
 * The same lesson arrived again from the other side: a test that rolled its own list kept a defect the library had
 * already lost (WT-145, WT-162), which is why this helper exists and is not duplicated. */
static uint64_t build_parameters(uint8_t *out, size_t capacity, int is_server, const uint8_t *source,
                                 size_t source_length, const uint8_t *original_destination,
                                 size_t original_length, int retried,
                                 const uint8_t *retry_source, size_t retry_source_length) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);
  if (wt_quic_transport_parameters_build(&params, is_server, source, source_length, original_destination,
                                         original_length, retried, retry_source,
                                         retry_source_length) != WT_OK) {
    return 0U;
  }
  if (wt_quic_transport_parameters_encode(&w, &params) != WT_OK) return 0U;
  return (uint64_t)wt_writer_offset(&w);
}

static void connection_config(wt_quic_connection_config_t *config, wt_quic_role_t role,
                              const uint8_t *connection_id, size_t connection_id_length) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = connection_id;
  config->local_connection_id_length = connection_id_length;
  config->peer_connection_id = connection_id;
  config->peer_connection_id_length = connection_id_length;
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = 1200U;
}

void scenario_pump_once(scenario_pair_t *pair) {
  (void)wt_udp_wait(&pair->client_socket, WT_SCENARIO_WAIT_MICROS);
  (void)wt_udp_wait(&pair->server_socket, WT_SCENARIO_WAIT_MICROS);
  (void)wt_runtime_session_pump(&pair->client, pair->now);
  (void)wt_runtime_session_pump(&pair->server, pair->now);
  /* Each side's own clock, because a refusal sends a frame and a frame has a time (WT-165). */
  pair->client_side.now = pair->now;
  pair->server_side.now = pair->now;
  pair->now += 1000U;
}

void scenario_pair_close(scenario_pair_t *pair) {
  if (pair == NULL) return;
  wt_runtime_session_clear(&pair->client);
  wt_runtime_session_clear(&pair->server);
  wt_udp_close(&pair->client_socket);
  wt_udp_close(&pair->server_socket);
}

wt_cli_result_t scenario_pair_open(scenario_pair_t *pair, int ipv6, char *detail, size_t detail_size) {
  uint8_t parameters[256];
  uint8_t server_parameters[256];
  uint64_t parameters_len;
  uint64_t server_parameters_len;
  wt_quic_connection_config_t client_config;
  wt_quic_connection_config_t server_config;
  wt_tls_client_config_t client_tls;
  wt_tls_server_config_t server_tls;
  wt_tls_server_identity_t identity;
  static const char *const alpn_h3[] = {"h3"};
  wt_udp_address_t local;
  unsigned round;

  if (pair == NULL) return WT_CLI_RESULT_FAILED;
  memset(pair, 0, sizeof(*pair));
  pair->now = 1000U;

  /* Two lists, because the two sides do not send the same parameters: a client sends its own Source Connection ID,
   * a server sends that PLUS the Destination Connection ID the client's first Initial carried (RFC 9000 section
   * 7.3). One buffer for both was the shape that made the omission invisible. */
  parameters_len = build_parameters(parameters, sizeof(parameters), 0, k_client_connection_id,
                                    sizeof(k_client_connection_id), NULL, 0U, 0, NULL, 0U);
  server_parameters_len = build_parameters(server_parameters, sizeof(server_parameters), 1,
                                           k_server_connection_id, sizeof(k_server_connection_id),
                                           k_client_connection_id, sizeof(k_client_connection_id), 0, NULL, 0U);
  if (parameters_len == 0U) {
    scenario_detail_set(detail, detail_size, "the transport parameters did not encode");
    return WT_CLI_RESULT_FAILED;
  }

  /* The sockets: the family comes from the ADDRESS, because the runtime sets IPV6_V6ONLY explicitly and an IPv4
   * address on an IPv6 socket is not reachable. */
  if (ipv6 != 0) {
    if (wt_udp_address_parse_host_port("[::1]:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair->client_socket, WT_UDP_IPV6) != WT_OK ||
        wt_udp_bind(&pair->client_socket, &local) != WT_OK) {
      scenario_detail_set(detail, detail_size, "this machine has no IPv6 loopback to bind");
      return WT_CLI_RESULT_UNSUPPORTED;
    }
    if (wt_udp_address_parse_host_port("[::1]:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair->server_socket, WT_UDP_IPV6) != WT_OK ||
        wt_udp_bind(&pair->server_socket, &local) != WT_OK) {
      wt_udp_close(&pair->client_socket);
      scenario_detail_set(detail, detail_size, "this machine has no IPv6 loopback to bind");
      return WT_CLI_RESULT_UNSUPPORTED;
    }
    (void)snprintf(pair->authority, sizeof(pair->authority), "[::1]");
  } else {
    if (wt_udp_address_parse_host_port("127.0.0.1:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair->client_socket, WT_UDP_IPV4) != WT_OK ||
        wt_udp_bind(&pair->client_socket, &local) != WT_OK) {
      scenario_detail_set(detail, detail_size, "the IPv4 loopback socket did not open");
      return WT_CLI_RESULT_FAILED;
    }
    if (wt_udp_address_parse_host_port("127.0.0.1:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair->server_socket, WT_UDP_IPV4) != WT_OK ||
        wt_udp_bind(&pair->server_socket, &local) != WT_OK) {
      wt_udp_close(&pair->client_socket);
      scenario_detail_set(detail, detail_size, "the IPv4 loopback socket did not open");
      return WT_CLI_RESULT_FAILED;
    }
    (void)snprintf(pair->authority, sizeof(pair->authority), "127.0.0.1");
  }
  if (wt_udp_address_parse(ipv6 != 0 ? "::1" : "127.0.0.1", pair->server_socket.port,
                           &pair->server_address) != WT_OK ||
      wt_udp_address_parse(ipv6 != 0 ? "::1" : "127.0.0.1", pair->client_socket.port,
                           &pair->client_address) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the bound addresses did not read back");
    scenario_pair_close(pair);
    return WT_CLI_RESULT_FAILED;
  }

  /* An identity generated in memory and PINNED by the client: a self-signed certificate is trusted by nothing, so
   * the pin is what makes the handshake authenticated rather than a bypass. */
  if (wt_tls_self_signed_generate(&pair->identity, "localhost") != WT_OK) {
    scenario_detail_set(detail, detail_size, "a self-signed identity could not be generated");
    scenario_pair_close(pair);
    return WT_CLI_RESULT_FAILED;
  }
  wt_tls_self_signed_identity(&pair->identity, &identity);

  connection_config(&client_config, WT_QUIC_ROLE_CLIENT, k_client_connection_id,
                    sizeof(k_client_connection_id));
  connection_config(&server_config, WT_QUIC_ROLE_SERVER, k_server_connection_id,
                    sizeof(k_server_connection_id));
  /* The server answers the client, so the client's own ID is what it sends TO. */
  server_config.peer_connection_id = k_client_connection_id;
  server_config.peer_connection_id_length = sizeof(k_client_connection_id);
  memset(&client_tls, 0, sizeof(client_tls));
  memset(&server_tls, 0, sizeof(server_tls));
  client_tls.host_name = "localhost";
  client_tls.alpn = alpn_h3;
  client_tls.alpn_count = 1U;
  client_tls.require_transport_parameters = 1;
  client_tls.transport_parameters = parameters;
  client_tls.transport_parameters_len = (size_t)parameters_len;
  client_tls.trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
  client_tls.trust.host_name = "localhost";
  memcpy(client_tls.trust.fingerprints[0], pair->identity.fingerprint, WT_SHA256_LEN);
  client_tls.trust.fingerprint_count = 1U;
  server_tls.identity = &identity;
  server_tls.alpn = "h3";
  server_tls.require_transport_parameters = 1;
  server_tls.transport_parameters = server_parameters;
  server_tls.transport_parameters_len = (size_t)server_parameters_len;

  if (wt_runtime_session_start_server(&pair->server, &pair->server_socket, &pair->client_address,
                                      k_client_connection_id, sizeof(k_client_connection_id),
                                      &server_config, &server_tls, pair->now) != WT_OK ||
      wt_runtime_session_start_client(&pair->client, &pair->client_socket, &pair->server_address,
                                      k_client_connection_id, sizeof(k_client_connection_id),
                                      &client_config, &client_tls, pair->now) != WT_OK) {
    scenario_detail_set(detail, detail_size, "a session did not arm");
    scenario_pair_close(pair);
    return WT_CLI_RESULT_FAILED;
  }
  /* The advertised limits, in force: the promise and the enforcement in one place. */
  if (wt_runtime_session_advertise(&pair->server, 100000U, 4096U, 8U, 8U) != WT_OK ||
      wt_runtime_session_advertise(&pair->client, 100000U, 4096U, 8U, 8U) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the advertised limits could not be put in force");
    scenario_pair_close(pair);
    return WT_CLI_RESULT_FAILED;
  }

  /* The handshake. */
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (wt_runtime_session_established(&pair->client) != 0 &&
        wt_runtime_session_established(&pair->server) != 0) {
      break;
    }
    scenario_pump_once(pair);
  }
  if (wt_runtime_session_established(&pair->client) == 0 ||
      wt_runtime_session_established(&pair->server) == 0) {
    scenario_detail_set(detail, detail_size, "the handshake did not complete within the bound");
    scenario_pair_close(pair);
    return WT_CLI_RESULT_FAILED;
  }

  /* The HTTP/3 layer joins behind the handshake's handler on both sides. */
  init_side(&pair->client_side, WT_HTTP3_ROLE_CLIENT);
  init_side(&pair->server_side, WT_HTTP3_ROLE_SERVER);
  (void)wt_runtime_session_set_frame_handler(&pair->client, side_on_frame, &pair->client_side);
  (void)wt_runtime_session_set_frame_handler(&pair->server, side_on_frame, &pair->server_side);
  wt_http3_driver_quic_transport(&pair->client.connection, &pair->client_transport);
  wt_http3_driver_quic_transport(&pair->server.connection, &pair->server_transport);
  /* Bound so that a refusal with an HTTP/3 error reaches the peer as an APPLICATION close carrying the HTTP/3 code
   * (RFC 9114 section 8) rather than as the transport's INTERNAL_ERROR (WT-159). */
  wt_http3_driver_bind_connection(&pair->client_side.driver, &pair->client.connection);
  wt_http3_driver_bind_connection(&pair->server_side.driver, &pair->server.connection);
  /* And where a REFUSED capsule is stated to this side's peer: the transport that carries a close capsule, the
   * connection an HTTP/3 code is refused to, and the clock both need (WT-165). */
  pair->client_side.transport = &pair->client_transport;
  pair->client_side.connection = &pair->client.connection;
  pair->client_side.now = pair->now;
  pair->server_side.transport = &pair->server_transport;
  pair->server_side.connection = &pair->server.connection;
  pair->server_side.now = pair->now;
  return WT_CLI_RESULT_PASSED;
}
