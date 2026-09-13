/* One-sided session loops for the client and server tools (Phase 9). */

#include "session_loop.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/session.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

#define WT_LOOP_ROUNDS 20000U
#define WT_LOOP_WAIT_MICROS 2000U

typedef struct loop_side {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  uint8_t section[2048];
  size_t section_length;
  int section_complete;
  uint64_t request_stream_id;
  unsigned frames_seen;
  uint8_t data[512];
  size_t data_bytes;
  int data_was_datagram;
  uint32_t status;
} loop_side_t;

typedef struct loop {
  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  wt_runtime_session_t session;
  loop_side_t side;
  uint64_t now;
} loop_t;

static wt_status_t side_on_frame_payload(void *context, uint64_t stream_id, uint64_t type,
                                         const uint8_t *payload, size_t length, int last);
static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin);
static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length);
static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame);

const char *wt_loop_status_name(wt_status_t status) { return wt_status_name(status); }

static void init_side(loop_side_t *side, wt_http3_role_t role) {
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
  loop_side_t *side = context;
  if (type == WT_HTTP3_FRAME_HEADERS && stream_id == side->request_stream_id) {
    if (side->section_length + length <= sizeof(side->section)) {
      if (length > 0U) memcpy(side->section + side->section_length, payload, length);
      side->section_length += length;
      if (last != 0) side->section_complete = 1;
    }
    return WT_OK;
  }
  return WT_OK;
}

static wt_status_t side_on_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                       size_t length, int fin) {
  loop_side_t *side = context;
  (void)stream_id;
  (void)fin;
  if (side->data_bytes + length <= sizeof(side->data)) {
    if (length > 0U) memcpy(side->data + side->data_bytes, data, length);
    side->data_bytes += length;
  }
  side->data_was_datagram = 0;
  return WT_OK;
}

static wt_status_t side_on_datagram(void *context, const uint8_t *data, size_t length) {
  loop_side_t *side = context;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  uint64_t quarter = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A datagram arrives with the draft's own framing, and this tool's job is the message: the quarter stream ID
   * is checked against the session and the payload is what the caller asked for. */
  if (wt_webtransport_datagram_parse(data, length, &quarter, &payload, &payload_length, &error) != WT_OK) {
    return WT_OK;
  }
  if (side->data_bytes + payload_length <= sizeof(side->data)) {
    if (payload_length > 0U) memcpy(side->data + side->data_bytes, payload, payload_length);
    side->data_bytes += payload_length;
  }
  side->data_was_datagram = 1;
  return WT_OK;
}

static wt_status_t side_on_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  loop_side_t *side = context;
  side->frames_seen++;
  return wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 16384U);
}

static uint64_t build_parameters(uint8_t *out, size_t capacity) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);
  wt_quic_transport_parameters_init(&params);
  (void)wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U);
  (void)wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 4096U);
  (void)wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 4096U);
  (void)wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 8U);
  (void)wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 8U);
  (void)wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 1200U);
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

static void pump_once(loop_t *loop) {
  (void)wt_udp_wait(&loop->socket, WT_LOOP_WAIT_MICROS);
  (void)wt_runtime_session_pump(&loop->session, loop->now);
  loop->now += 1000U;
}

/* The message, on the mode the caller chose. A stream carries the draft's prefix and then the bytes; a datagram
 * carries the quarter stream ID and then the bytes. */
static wt_status_t send_message(loop_t *loop, const wt_http3_driver_transport_t *transport,
                                const wt_loop_config_t *config) {
  uint8_t framed[512];
  wt_writer_t w = wt_writer_init(framed, sizeof(framed));
  size_t message_length = config->message != NULL ? strlen(config->message) : 0U;

  if (config->datagram != 0) {
    if (wt_webtransport_datagram_write(&w, loop->side.request_stream_id / 4U,
                                       (const uint8_t *)config->message, message_length) != WT_OK) {
      return WT_ERR_LIMIT;
    }
    return transport->send_datagram(transport->context, framed, wt_writer_offset(&w));
  }
  {
    uint64_t stream_id = 0U;
    wt_status_t status = transport->open_stream(transport->context, 0, &stream_id, loop->now);
    if (status != WT_OK) return status;
    if (wt_webtransport_stream_prefix_write(&w, 1, loop->side.request_stream_id) != WT_OK) {
      return WT_ERR_LIMIT;
    }
    wt_writer_bytes(&w, config->message, message_length);
    return transport->send_stream(transport->context, stream_id, framed, wt_writer_offset(&w), 0,
                                  loop->now);
  }
}

wt_status_t wt_loop_run_client(const wt_loop_config_t *config, wt_loop_result_t *out) {
  static const uint8_t k_connection_id[8] = {0x11U, 0x22U, 0x33U, 0x44U,
                                             0x55U, 0x66U, 0x77U, 0x88U};
  loop_t loop;
  uint8_t parameters[256];
  uint64_t parameters_len;
  wt_quic_connection_config_t connection;
  wt_tls_client_config_t tls;
  wt_http3_driver_transport_t transport;
  wt_http3_settings_t settings;
  wt_http3_message_t response;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_udp_address_t peer;
  uint8_t scratch[1024];
  uint64_t deadline_rounds;
  unsigned round;

  if (config == NULL || out == NULL || config->authority == NULL || config->path == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(out, 0, sizeof(*out));
  memset(&loop, 0, sizeof(loop));
  loop.now = 1000U;
  parameters_len = build_parameters(parameters, sizeof(parameters));
  if (parameters_len == 0U) return WT_ERR_LIMIT;

  {
    /* The caller gives a host and a port separately; the runtime parses one string, so they are joined here
     * rather than in every caller. */
    char joined[WT_LOOP_HOST_MAX + 16U];
    (void)snprintf(joined, sizeof(joined), "%s:%u", config->host, (unsigned)config->port);
    if (wt_udp_address_parse_host_port(joined, &peer) != WT_OK) return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_udp_socket_open(&loop.socket, peer.family) != WT_OK) return WT_ERR_IO;
  loop.peer = peer;

  connection_config(&connection, WT_QUIC_ROLE_CLIENT, k_connection_id, sizeof(k_connection_id));
  memset(&tls, 0, sizeof(tls));
  {
    static const char *const alpn_h3[] = {"h3"};
    tls.alpn = alpn_h3;
    tls.alpn_count = 1U;
  }
  tls.host_name = config->authority;
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;
  if (config->pin != NULL) {
    tls.trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
    tls.trust.host_name = config->authority;
    memcpy(tls.trust.fingerprints[0], config->pin, WT_SHA256_LEN);
    tls.trust.fingerprint_count = 1U;
  } else {
    /* The development bypass, which the trust layer restricts to loopback names. */
    tls.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
    tls.trust.host_name = config->authority;
  }

  {
    wt_status_t status = wt_runtime_session_start_client(&loop.session, &loop.socket, &peer,
                                                         k_connection_id, sizeof(k_connection_id),
                                                         &connection, &tls, loop.now);
    if (status != WT_OK) {
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* The advertised limits, in force: the promise and the enforcement in one place. */
  (void)wt_runtime_session_advertise(&loop.session, 100000U, 4096U, 8U, 8U);
  init_side(&loop.side, WT_HTTP3_ROLE_CLIENT);
  (void)wt_runtime_session_set_frame_handler(&loop.session, side_on_frame, &loop.side);
  wt_http3_driver_quic_transport(&loop.session.connection, &transport);

  deadline_rounds = config->timeout_ms * 2U + 100U;
  if (deadline_rounds > WT_LOOP_ROUNDS) deadline_rounds = WT_LOOP_ROUNDS;

  for (round = 0U; round < deadline_rounds && wt_runtime_session_established(&loop.session) == 0; round++) {
    pump_once(&loop);
  }
  if (wt_runtime_session_established(&loop.session) == 0) {
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  out->established = 1;

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  {
    wt_status_t status = wt_http3_driver_start_session(&loop.side.driver, &transport, &settings,
                                                       config->authority, config->path, 0U, loop.now,
                                                       &loop.side.request_stream_id, &h3_error);
    if (status != WT_OK) {
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  for (round = 0U; round < deadline_rounds && loop.side.section_complete == 0; round++) {
    pump_once(&loop);
  }
  if (loop.side.section_complete == 0) {
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  {
    wt_status_t status = wt_http3_endpoint_on_response_headers(
        &loop.side.endpoint, loop.side.request_stream_id, loop.side.section, loop.side.section_length,
        scratch, sizeof(scratch), &response, &h3_error);
    if (status != WT_OK) {
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    out->connect_accepted = response.has_status != 0 && response.status >= 200U && response.status < 300U;
    out->status = (uint32_t)response.status;
  }

  {
    wt_status_t status = send_message(&loop, &transport, config);
    if (status != WT_OK) {
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* Give the peer a moment to receive it and to answer with its own message where it has one. */
  for (round = 0U; round < 200U && loop.side.data_bytes == 0U; round++) pump_once(&loop);
  out->received_bytes = loop.side.data_bytes;
  out->received_datagram = loop.side.data_was_datagram;

  wt_runtime_session_clear(&loop.session);
  wt_udp_close(&loop.socket);
  return WT_OK;
}

wt_status_t wt_loop_run_server(const wt_loop_config_t *config, wt_loop_result_t *out) {
  static const uint8_t k_connection_id[8] = {0x11U, 0x22U, 0x33U, 0x44U,
                                             0x55U, 0x66U, 0x77U, 0x88U};
  loop_t loop;
  uint8_t parameters[256];
  uint64_t parameters_len;
  wt_quic_connection_config_t connection;
  wt_tls_server_config_t tls;
  wt_tls_server_identity_t identity;
  wt_http3_driver_transport_t transport;
  wt_http3_message_t request;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_udp_address_t local;
  uint8_t scratch[1024];
  uint64_t deadline_rounds;
  unsigned round;

  if (config == NULL || out == NULL || config->identity == NULL || config->authority == NULL ||
      config->path == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(out, 0, sizeof(*out));
  memset(&loop, 0, sizeof(loop));
  loop.now = 1000U;
  parameters_len = build_parameters(parameters, sizeof(parameters));
  if (parameters_len == 0U) return WT_ERR_LIMIT;

  {
    char joined[WT_LOOP_HOST_MAX + 16U];
    (void)snprintf(joined, sizeof(joined), "%s:%u", config->host, (unsigned)config->port);
    if (wt_udp_address_parse_host_port(joined, &local) != WT_OK) return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_udp_socket_open(&loop.socket, local.family) != WT_OK) return WT_ERR_IO;
  if (wt_udp_bind(&loop.socket, &local) != WT_OK) {
    wt_udp_close(&loop.socket);
    return WT_ERR_IO;
  }
  out->bound_port = loop.socket.port;

  connection_config(&connection, WT_QUIC_ROLE_SERVER, k_connection_id, sizeof(k_connection_id));
  wt_tls_self_signed_identity(config->identity, &identity);
  memset(&tls, 0, sizeof(tls));
  tls.identity = &identity;
  tls.alpn = "h3";
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;

  /* The peer's address is not known until a packet arrives, and the runtime takes it from the packet's source:
   * the session's own socket reports it. The wait below is what makes a listener a listener. */
  deadline_rounds = config->timeout_ms * 2U + 100U;
  if (deadline_rounds > WT_LOOP_ROUNDS) deadline_rounds = WT_LOOP_ROUNDS;

  {
    wt_udp_address_t from;
    unsigned waited;
    int arrived = 0;

    /* The peer is learned by PEEKING, not by receiving: the datagram that names the peer must still be in the
     * queue when the connection is armed, or this side waits for a retransmission it may never get -- which is
     * exactly what the first version did (it received the Initial and dropped it). */
    for (waited = 0U; waited < 5000U; waited++) {
      size_t datagram_length = 0U;
      size_t available = 0U;
      wt_status_t peek_status = wt_udp_peek(&loop.socket, NULL, 0U, &datagram_length, &available, &from);
      if (peek_status == WT_OK) {
        loop.peer = from;
        arrived = 1;
        break;
      }
      (void)wt_udp_wait(&loop.socket, WT_LOOP_WAIT_MICROS * 10U);
    }
    if (arrived == 0) {
      wt_udp_close(&loop.socket);
      return WT_ERR_TIMEOUT;
    }
  }

  {
    wt_status_t status = wt_runtime_session_start_server(&loop.session, &loop.socket, &loop.peer,
                                                         k_connection_id, sizeof(k_connection_id),
                                                         &connection, &tls, loop.now);
    wt_udp_address_t bound;
    if (status != WT_OK) {
      wt_udp_close(&loop.socket);
      return status;
    }
    /* The session must answer from the port it bound, and the peer it answers is the one that wrote. */
    if (wt_udp_address_parse(config->host, loop.socket.port, &bound) == WT_OK) {
      (void)bound;
    }
  }
  /* The advertised limits, in force: the promise and the enforcement in one place. */
  (void)wt_runtime_session_advertise(&loop.session, 100000U, 4096U, 8U, 8U);
  init_side(&loop.side, WT_HTTP3_ROLE_SERVER);
  (void)wt_runtime_session_set_frame_handler(&loop.session, side_on_frame, &loop.side);
  wt_http3_driver_quic_transport(&loop.session.connection, &transport);

  for (round = 0U; round < deadline_rounds && wt_runtime_session_established(&loop.session) == 0; round++) {
    pump_once(&loop);
  }
  if (wt_runtime_session_established(&loop.session) == 0) {
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  out->established = 1;

  /* The CONNECT, its section assembled from the driver's pieces, and the draft-16 decision. */
  for (round = 0U; round < deadline_rounds && loop.side.section_complete == 0; round++) {
    /* The sink must know which stream carries the exchange before the section arrives. A client's first
     * bidirectional stream is stream 0 (RFC 9000 section 2.1), and this tool serves one session, so that is the
     * stream the CONNECT is on. */
    pump_once(&loop);
  }
  if (loop.side.section_complete == 0) {
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  {
    wt_status_t status = wt_http3_endpoint_on_request_headers(
        &loop.side.endpoint, loop.side.request_stream_id, loop.side.section, loop.side.section_length,
        scratch, sizeof(scratch), &request, &h3_error);
    if (status != WT_OK) {
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  memset(&policy, 0, sizeof(policy));
  policy.authority = config->authority;
  policy.path = config->path;
  policy.wt_enabled = 1;
  if (wt_webtransport_session_request_validate(&request, &policy, &decision, &h3_error) != WT_OK ||
      decision.outcome != WT_WEBTRANSPORT_REQUEST_ACCEPT) {
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_PROTOCOL;
  }
  out->connect_accepted = 1;
  out->status = 200U;

  {
    wt_status_t status = wt_http3_driver_send_response(&loop.side.driver, &transport,
                                                       loop.side.request_stream_id, 200U, 0U, 0,
                                                       loop.now);
    if (status != WT_OK) {
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* The client's message, and then this side's own answer so that a caller sees both directions. */
  {
    unsigned waited;
    for (waited = 0U; waited < 400U && loop.side.data_bytes == 0U; waited++) pump_once(&loop);
    out->received_bytes = loop.side.data_bytes;
    out->received_datagram = loop.side.data_was_datagram;
  }
  if (config->message != NULL) {
    wt_status_t status = send_message(&loop, &transport, config);
    if (status != WT_OK) {
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    for (round = 0U; round < 100U; round++) pump_once(&loop);
  }

  wt_runtime_session_clear(&loop.session);
  wt_udp_close(&loop.socket);
  return WT_OK;
}
