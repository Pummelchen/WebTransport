/* The session scenarios: two endpoints in one process, over loopback (Phase 9). */

#include "scenario_session.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/session.h"
#include "webtransport/tls/self_signed.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

#define WT_SCENARIO_TIMEOUT_ROUNDS 400U
#define WT_SCENARIO_WAIT_MICROS 2000U

/* What each side records: the field section it assembles, the frames it was asked about, and the session bytes
 * and datagrams it receives. The driver reports streams in pieces and buffers nothing, so the side that owns
 * the memory assembles them -- here, this file. */
typedef struct scenario_side {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  uint8_t section[2048];
  size_t section_length;
  int section_complete;
  uint64_t request_stream_id;
  unsigned frames_seen;
  uint64_t control_frames;
  uint8_t stream_data[128];
  size_t stream_bytes;
  uint8_t datagram[256];
  size_t datagram_bytes;
  unsigned datagrams;
} scenario_side_t;

typedef struct scenario_pair {
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  wt_runtime_session_t client;
  wt_runtime_session_t server;
  wt_tls_self_signed_t identity;
  scenario_side_t client_side;
  scenario_side_t server_side;
  uint64_t now;
} scenario_pair_t;

static wt_status_t side_on_frame_payload(void *context, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last);
static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin);
static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length);
static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);

static void detail_set(char *detail, size_t size, const char *text) {
  if (detail == NULL || size == 0U) return;
  (void)snprintf(detail, size, "%s", text);
}

static void init_side(scenario_side_t *side, wt_http3_role_t role) {
  memset(side, 0, sizeof(*side));
  wt_http3_endpoint_init(&side->endpoint, role);
  wt_http3_driver_init(&side->driver, &side->endpoint);
  side->sink.context = side;
  side->sink.on_frame_payload = side_on_frame_payload;
  side->sink.on_stream_data = side_on_stream_data;
  side->sink.on_datagram = side_on_datagram;
}

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
  (void)stream_id;
  (void)fin;
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

/* The endpoint's transport parameters, built by the LIBRARY: the mandatory connection-ID parameters live in
 * `wt_quic_transport_parameters_build` so that this file cannot forget one. It did forget one -- the parameter
 * that says which Source Connection ID these packets carry -- and only a third-party peer ever said so (WT-141). */
static uint64_t build_parameters(uint8_t *out, size_t capacity, int is_server, const uint8_t *source,
                                 size_t source_length, const uint8_t *original_destination,
                                 size_t original_length) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);
  if (wt_quic_transport_parameters_build(&params, is_server, source, source_length, original_destination,
                                         original_length) != WT_OK) {
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

/* Pump both sides once. The socket is waited on first: a non-blocking receive finds nothing until the packet
 * has arrived, and a loop that spun faster than loopback would finish before the first Initial packet did. */
static void pump_once(scenario_pair_t *pair) {
  (void)wt_udp_wait(&pair->client_socket, WT_SCENARIO_WAIT_MICROS);
  (void)wt_udp_wait(&pair->server_socket, WT_SCENARIO_WAIT_MICROS);
  (void)wt_runtime_session_pump(&pair->client, pair->now);
  (void)wt_runtime_session_pump(&pair->server, pair->now);
  pair->now += 1000U;
}

wt_cli_result_t wt_scenario_session_run(int ipv6, char *detail, size_t detail_size) {
  /* The CLIENT's own ID, which it also chooses as the destination of its first Initial. */
  static const uint8_t k_connection_id[8] = {0x21U, 0x32U, 0x43U, 0x54U,
                                             0x65U, 0x76U, 0x87U, 0x98U};
  /* And the server's OWN Source Connection ID, deliberately different: the rule that a client adopts it (RFC 9000
   * section 7.2) is only exercised when the two differ, and one shared constant is exactly how a client that never
   * adopted it -- and a server that answered only to its own ID -- passed every test in this tree (WT-151). */
  static const uint8_t k_server_connection_id[8] = {0x12U, 0x34U, 0x56U, 0x78U,
                                                    0x9aU, 0xbcU, 0xdeU, 0xf0U};
  scenario_pair_t pair;
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
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_message_t decoded;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_udp_address_t local;
  uint8_t scratch[1024];
  uint64_t request_stream_id = 0U;
  unsigned round;
  char authority[64];

  memset(&pair, 0, sizeof(pair));
  pair.now = 1000U;
  /* Two lists, because the two sides do not send the same parameters: a client sends its own Source Connection
   * ID, a server sends that PLUS the Destination Connection ID the client's first Initial carried (RFC 9000
   * section 7.3). One buffer for both was the shape that made the omission invisible. */
  parameters_len = build_parameters(parameters, sizeof(parameters), 0, k_connection_id,
                                    sizeof(k_connection_id), NULL, 0U);
  server_parameters_len = build_parameters(server_parameters, sizeof(server_parameters), 1,
                                           k_server_connection_id, sizeof(k_server_connection_id),
                                           k_connection_id, sizeof(k_connection_id));
  if (parameters_len == 0U) {
    detail_set(detail, detail_size, "the transport parameters did not encode");
    return WT_CLI_RESULT_FAILED;
  }

  /* The sockets: the family comes from the ADDRESS, because the runtime sets IPV6_V6ONLY explicitly and an
   * IPv4 address on an IPv6 socket is not reachable. */
  if (ipv6 != 0) {
    if (wt_udp_address_parse_host_port("[::1]:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair.client_socket, WT_UDP_IPV6) != WT_OK ||
        wt_udp_bind(&pair.client_socket, &local) != WT_OK) {
      detail_set(detail, detail_size, "this machine has no IPv6 loopback to bind");
      return WT_CLI_RESULT_UNSUPPORTED;
    }
    if (wt_udp_address_parse_host_port("[::1]:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair.server_socket, WT_UDP_IPV6) != WT_OK ||
        wt_udp_bind(&pair.server_socket, &local) != WT_OK) {
      wt_udp_close(&pair.client_socket);
      detail_set(detail, detail_size, "this machine has no IPv6 loopback to bind");
      return WT_CLI_RESULT_UNSUPPORTED;
    }
    (void)snprintf(authority, sizeof(authority), "[::1]");
  } else {
    if (wt_udp_address_parse_host_port("127.0.0.1:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair.client_socket, WT_UDP_IPV4) != WT_OK ||
        wt_udp_bind(&pair.client_socket, &local) != WT_OK) {
      detail_set(detail, detail_size, "the IPv4 loopback socket did not open");
      return WT_CLI_RESULT_FAILED;
    }
    if (wt_udp_address_parse_host_port("127.0.0.1:0", &local) != WT_OK ||
        wt_udp_socket_open(&pair.server_socket, WT_UDP_IPV4) != WT_OK ||
        wt_udp_bind(&pair.server_socket, &local) != WT_OK) {
      wt_udp_close(&pair.client_socket);
      detail_set(detail, detail_size, "the IPv4 loopback socket did not open");
      return WT_CLI_RESULT_FAILED;
    }
    (void)snprintf(authority, sizeof(authority), "127.0.0.1");
  }
  if (wt_udp_address_parse(ipv6 != 0 ? "::1" : "127.0.0.1", pair.server_socket.port,
                           &pair.server_address) != WT_OK ||
      wt_udp_address_parse(ipv6 != 0 ? "::1" : "127.0.0.1", pair.client_socket.port,
                           &pair.client_address) != WT_OK) {
    detail_set(detail, detail_size, "the bound addresses did not read back");
    wt_udp_close(&pair.client_socket);
    wt_udp_close(&pair.server_socket);
    return WT_CLI_RESULT_FAILED;
  }

  /* An identity generated in memory and PINNED by the client: a self-signed certificate is trusted by nothing,
   * so the pin is what makes the handshake authenticated rather than a bypass. */
  if (wt_tls_self_signed_generate(&pair.identity, "localhost") != WT_OK) {
    detail_set(detail, detail_size, "a self-signed identity could not be generated");
    wt_udp_close(&pair.client_socket);
    wt_udp_close(&pair.server_socket);
    return WT_CLI_RESULT_FAILED;
  }
  wt_tls_self_signed_identity(&pair.identity, &identity);

  connection_config(&client_config, WT_QUIC_ROLE_CLIENT, k_connection_id, sizeof(k_connection_id));
  connection_config(&server_config, WT_QUIC_ROLE_SERVER, k_server_connection_id,
                    sizeof(k_server_connection_id));
  /* The server answers the client, so the client's own ID is what it sends TO. */
  server_config.peer_connection_id = k_connection_id;
  server_config.peer_connection_id_length = sizeof(k_connection_id);
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
  memcpy(client_tls.trust.fingerprints[0], pair.identity.fingerprint, WT_SHA256_LEN);
  client_tls.trust.fingerprint_count = 1U;
  server_tls.identity = &identity;
  server_tls.alpn = "h3";
  server_tls.require_transport_parameters = 1;
  server_tls.transport_parameters = server_parameters;
  server_tls.transport_parameters_len = (size_t)server_parameters_len;

  if (wt_runtime_session_start_server(&pair.server, &pair.server_socket, &pair.client_address,
                                      k_connection_id, sizeof(k_connection_id), &server_config,
                                      &server_tls, pair.now) != WT_OK ||
      wt_runtime_session_start_client(&pair.client, &pair.client_socket, &pair.server_address,
                                      k_connection_id, sizeof(k_connection_id), &client_config,
                                      &client_tls, pair.now) != WT_OK) {
    detail_set(detail, detail_size, "a session did not arm");
    wt_runtime_session_clear(&pair.client);
    wt_runtime_session_clear(&pair.server);
    wt_udp_close(&pair.client_socket);
    wt_udp_close(&pair.server_socket);
    return WT_CLI_RESULT_FAILED;
  }
  {
    /* The advertised limits, in force: the promise and the enforcement in one place. */
    wt_status_t granted = wt_runtime_session_advertise(&pair.server, 100000U, 4096U, 8U, 8U);
    if (granted == WT_OK) granted = wt_runtime_session_advertise(&pair.client, 100000U, 4096U, 8U, 8U);
    if (granted != WT_OK) {
      detail_set(detail, detail_size, "the advertised limits could not be put in force");
      goto done_failed;
    }
  }

  /* The handshake. */
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (wt_runtime_session_established(&pair.client) != 0 &&
        wt_runtime_session_established(&pair.server) != 0) {
      break;
    }
    pump_once(&pair);
  }
  if (wt_runtime_session_established(&pair.client) == 0 ||
      wt_runtime_session_established(&pair.server) == 0) {
    detail_set(detail, detail_size, "the handshake did not complete within the bound");
    wt_runtime_session_clear(&pair.client);
    wt_runtime_session_clear(&pair.server);
    wt_udp_close(&pair.client_socket);
    wt_udp_close(&pair.server_socket);
    return WT_CLI_RESULT_FAILED;
  }

  /* The HTTP/3 layer joins behind the handshake's handler on both sides. */
  init_side(&pair.client_side, WT_HTTP3_ROLE_CLIENT);
  init_side(&pair.server_side, WT_HTTP3_ROLE_SERVER);
  (void)wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &pair.client_side);
  (void)wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &pair.server_side);
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  if (wt_http3_driver_start_session(&pair.client_side.driver, &client_transport, &settings, authority,
                                    "/conformance", 0U, pair.now, &request_stream_id,
                                    &h3_error) != WT_OK) {
    detail_set(detail, detail_size, "the CONNECT could not be started");
    goto done_failed;
  }
  pair.client_side.request_stream_id = request_stream_id;
  pair.server_side.request_stream_id = request_stream_id;

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.section_complete != 0) break;
    pump_once(&pair);
  }
  if (pair.server_side.section_complete == 0) {
    detail_set(detail, detail_size, "the CONNECT did not arrive");
    goto done_failed;
  }
  if (wt_http3_endpoint_on_request_headers(&pair.server_side.endpoint, request_stream_id,
                                           pair.server_side.section, pair.server_side.section_length,
                                           scratch, sizeof(scratch), &decoded, &h3_error) != WT_OK) {
    detail_set(detail, detail_size, "the CONNECT did not decode");
    goto done_failed;
  }
  policy.authority = authority;
  policy.path = "/conformance";
  policy.wt_enabled = 1;
  if (wt_webtransport_session_request_validate(&decoded, &policy, &decision, &h3_error) != WT_OK ||
      decision.outcome != WT_WEBTRANSPORT_REQUEST_ACCEPT) {
    detail_set(detail, detail_size, "the draft-16 layer did not accept the CONNECT");
    goto done_failed;
  }

  /* The response, a message on a WebTransport stream, and a message as a datagram. */
  if (wt_http3_driver_send_response(&pair.server_side.driver, &server_transport, request_stream_id, 200U,
                                    0U, 0, pair.now) != WT_OK) {
    detail_set(detail, detail_size, "the response could not be sent");
    goto done_failed;
  }
  {
    uint8_t message[128];
    wt_writer_t w = wt_writer_init(message, sizeof(message));
    uint64_t stream_id = 0U;

    if (client_transport.open_stream(client_transport.context, 0, &stream_id, pair.now) != WT_OK ||
        wt_webtransport_stream_prefix_write(&w, 1, request_stream_id) != WT_OK) {
      detail_set(detail, detail_size, "a WebTransport stream could not be opened");
      goto done_failed;
    }
    wt_writer_bytes(&w, "conformance", 11U);
    if (client_transport.send_stream(client_transport.context, stream_id, message,
                                     wt_writer_offset(&w), 0, pair.now) != WT_OK) {
      detail_set(detail, detail_size, "the stream message could not be sent");
      goto done_failed;
    }
    w = wt_writer_init(message, sizeof(message));
    if (wt_webtransport_datagram_write(&w, request_stream_id / 4U, (const uint8_t *)"probe", 5U) != WT_OK ||
        client_transport.send_datagram(client_transport.context, message, wt_writer_offset(&w)) != WT_OK) {
      detail_set(detail, detail_size, "the datagram could not be sent");
      goto done_failed;
    }
  }

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.stream_bytes >= 11U && pair.server_side.datagrams > 0U &&
        pair.client_side.section_complete != 0) {
      break;
    }
    pump_once(&pair);
  }
  if (pair.server_side.stream_bytes != 11U || memcmp(pair.server_side.stream_data, "conformance", 11U) != 0) {
    detail_set(detail, detail_size, "the stream message did not arrive as sent");
    goto done_failed;
  }
  if (pair.server_side.datagrams == 0U || pair.server_side.datagram_bytes == 0U) {
    detail_set(detail, detail_size, "the datagram did not arrive");
    goto done_failed;
  }
  {
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    wt_http3_error_t datagram_error = WT_HTTP3_NO_ERROR;
    if (wt_webtransport_datagram_parse(pair.server_side.datagram, pair.server_side.datagram_bytes, &quarter,
                                       &payload, &payload_length, &datagram_error) != WT_OK ||
        quarter != request_stream_id / 4U || payload_length != 5U ||
        memcmp(payload, "probe", 5U) != 0) {
      detail_set(detail, detail_size, "the datagram's framing did not match");
      goto done_failed;
    }
  }
  (void)snprintf(detail, detail_size,
                 "%s: handshake, CONNECT accepted, response, 11-byte stream message and a datagram",
                 ipv6 != 0 ? "ipv6" : "ipv4");
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
  return WT_CLI_RESULT_PASSED;

done_failed:
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
  return WT_CLI_RESULT_FAILED;
}
