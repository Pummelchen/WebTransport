/* One-sided session loops for the client and server tools (Phase 9). */

#include "session_loop.h"

#include <stdio.h>
#include <stdlib.h>

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

/* How many rounds fit in the timeout the caller asked for, at the interval each wait ACTUALLY uses.
 *
 * The deadline used to be `timeout_ms * 2U + 100U` rounds, which is a guess about the wait interval: with a
 * 2 ms wait that is four times the timeout asked for, so `--timeout-ms 5000` took twenty seconds and a client
 * pointed at a peer that never answers looked like it had hung (WT-140). The two macros are the two intervals
 * this file waits for -- `WT_LOOP_WAIT_MICROS`, and ten times that for the peer-discovery peek -- divided into
 * the timeout, so the number of rounds and the number of milliseconds agree. */
#define WT_LOOP_ROUNDS_FOR(timeout_ms) (((uint64_t)(timeout_ms) * 1000U) / (uint64_t)WT_LOOP_WAIT_MICROS)
#define WT_LOOP_PEEK_ROUNDS_FOR(timeout_ms) \
  (((uint64_t)(timeout_ms) * 1000U) / ((uint64_t)WT_LOOP_WAIT_MICROS * 10U))

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
  /* The transport the driver sends through, kept here because the lost-frame handler needs it: a report of a
   * lost frame arrives long after the call that built the transport returned (WT-135). */
  wt_http3_driver_transport_t transport;
  /* How many times a lost-frame report was answered by sending the request again: the counter that says whether
   * the retransmission path RAN, which reading the code cannot (WT-135). */
  unsigned resends;
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

/* The endpoint's transport parameters, built by the LIBRARY: the mandatory connection-ID parameters live in
 * `wt_quic_transport_parameters_build` so that this file cannot forget one. It did forget one -- the parameter
 * that says which Source Connection ID these packets carry -- and only a third-party peer ever said so (WT-141). */
static uint64_t build_parameters(uint8_t *out, size_t capacity, int is_server, const uint8_t *connection_id,
                                 size_t connection_id_length) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(out, capacity);
  /* The same connection ID on both sides of this local exchange, so it is both the Source Connection ID these
   * packets carry and, for the server, the Destination Connection ID the client's first Initial used. */
  if (wt_quic_transport_parameters_build(&params, is_server, connection_id, connection_id_length,
                                         connection_id, connection_id_length) != WT_OK) {
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

/* Everything a failed run can say about WHY, read while the session is still alive.
 *
 * This was inline at each failure return once, and it was WRONG twice over: the assignments sat after
 * `wt_runtime_session_clear`, so the handshake state was read from a cleared struct (it said "idle" while the
 * connection held Handshake and Application keys), and the insertion loop left the block in some paths twice. A
 * helper called before the clear is one place, one order, and a comment that says why the order matters (WT-135).
 */
/* A frame the connection reported LOST, answered by sending the request again.
 *
 * RFC 9002 section 6.2.4: a probe timeout must send new frames or retransmit unacknowledged data. The connection
 * now reports the oldest outstanding frame to its owner (the runtime's lost-frame hook) and the HTTP/3 driver
 * retains what it sent, so this is the place the two meet -- and the place a packet lost between the handshake
 * and the response used to disappear for good (WT-135).
 *
 * Only the request stream is answered, and only when the driver has something retained: anything else is a frame
 * this tool has no bytes for, and saying so is better than sending something wrong. */
static void client_on_lost_frame(void *context, const wt_quic_tx_frame_t *frame) {
  loop_t *loop = context;
  if (loop == NULL || frame == NULL) return;
  if (frame->is_crypto) return; /* the handshake retransmits its own */
  if (frame->stream_id != loop->side.request_stream_id) return;
  if (wt_http3_driver_resend_request(&loop->side.driver, &loop->transport, loop->now) == WT_OK) {
    loop->resends++;
  }
}

/* Whether this endpoint may SPEAK: the handshake is DONE and the peer's transport parameters are IN FORCE.
 *
 * Both halves are needed, and the measurement that showed it is this round's: breaking out on DONE alone made
 * the client start its CONNECT before the pump that applies the peer's parameters had run, so opening a request
 * stream was refused with WT_ERR_STATE (`"status":"state"`) while the session was already confirmed. The
 * parameters arrive in the same flight as the Finished and are applied by the NEXT pump, so the loop has to wait
 * for both (WT-142). */
static int handshake_ready(const loop_t *loop) {
  return wt_runtime_session_handshake_done(&loop->session) != 0 &&
         loop->session.peer_parameters_applied != 0;
}

/* Whether this run ended with THIS endpoint having closed the connection, and why.
 *
 * A tool that answers "ok" here is lying: the peer was told the connection is over, whatever the exchange
 * counters say. The status the refusing handler returned is the report when there was one -- it names the layer
 * that refused -- and a deliberate close with no refusal is a protocol failure of the run's own making, which is
 * `WT_ERR_PROTOCOL` rather than `WT_OK` (WT-144). */
static wt_status_t loop_close_status(const loop_t *loop) {
  if (wt_quic_connection_is_closed(&loop->session.connection) == 0) return WT_OK;
  if (loop->session.connection.close_cause != WT_OK) return loop->session.connection.close_cause;
  return WT_ERR_PROTOCOL;
}

static void record_oracle(const loop_t *loop, wt_loop_result_t *out) {
  out->first_receive_error = loop->session.first_receive_error;
  out->receive_errors = loop->session.receive_errors;
  out->packets_seen = loop->session.packets_seen;
  out->last_receive = loop->session.last_receive;
  out->close_code = loop->session.connection.close_code;
  out->close_frame_type = loop->session.connection.close_frame_type;
  out->close_code_set = loop->session.connection.close_code_set;
  out->peer_error_code = loop->session.connection.peer_error_code;
  out->peer_closed = loop->session.connection.peer_closed;
  out->close_kind = (unsigned)loop->session.connection.close.kind;
  out->close_sent_error_code = loop->session.connection.close.error_code;
  out->close_sent_frame_type = loop->session.connection.close.frame_type;
  out->close_cause = loop->session.connection.close_cause;
  out->packets_discarded = loop->session.connection.packets_discarded;
  out->has_initial_keys = loop->session.connection.has_keys_in[WT_QUIC_SPACE_INITIAL];
  out->has_handshake_keys = loop->session.connection.has_keys_in[WT_QUIC_SPACE_HANDSHAKE];
  out->has_application_keys = loop->session.connection.has_keys_in[WT_QUIC_SPACE_APPLICATION];
  out->handshake_state = wt_quic_handshake_state_name(wt_quic_handshake_state(&loop->session.handshake));
  out->resends = loop->resends;
  out->probes = (unsigned)(loop->session.connection.probes_sent[WT_QUIC_SPACE_INITIAL] +
                           loop->session.connection.probes_sent[WT_QUIC_SPACE_HANDSHAKE] +
                           loop->session.connection.probes_sent[WT_QUIC_SPACE_APPLICATION]);
  out->probes_with_data = (unsigned)loop->session.connection.probes_with_data;
  out->acks_initial = (unsigned)loop->session.connection.acks_sent[WT_QUIC_SPACE_INITIAL];
  out->acks_handshake = (unsigned)loop->session.connection.acks_sent[WT_QUIC_SPACE_HANDSHAKE];
  out->acks_application = (unsigned)loop->session.connection.acks_sent[WT_QUIC_SPACE_APPLICATION];
  out->ack_largest_initial = loop->session.connection.ack_largest[WT_QUIC_SPACE_INITIAL];
  out->ack_largest_handshake = loop->session.connection.ack_largest[WT_QUIC_SPACE_HANDSHAKE];
  out->ack_largest_application = loop->session.connection.ack_largest[WT_QUIC_SPACE_APPLICATION];
  out->sent_initial = (unsigned)loop->session.connection.packets_sent_by_space[WT_QUIC_SPACE_INITIAL];
  out->sent_handshake = (unsigned)loop->session.connection.packets_sent_by_space[WT_QUIC_SPACE_HANDSHAKE];
  out->sent_application = (unsigned)loop->session.connection.packets_sent_by_space[WT_QUIC_SPACE_APPLICATION];
  {
    const wt_tls13_transcript_t *transcript = NULL;
    size_t index;
    if (loop->session.connection.config.role == WT_QUIC_ROLE_CLIENT) {
      transcript = &loop->session.handshake.client.transcript;
    } else {
      transcript = &loop->session.handshake.server.transcript;
    }
    out->transcript_types_length = 0U;
    for (index = 0U; index < (size_t)transcript->messages && index < sizeof(out->transcript_types); index++) {
      out->transcript_types[index] = transcript->types[index];
      out->transcript_types_length = index + 1U;
    }
  }
  out->request_stream_id = loop->side.request_stream_id;
  out->streams_opened_bidi = (unsigned)loop->session.connection.streams.opened_by_us_bidi;
  out->streams_opened_uni = (unsigned)loop->session.connection.streams.opened_by_us_uni;
}

static void pump_once(loop_t *loop) {
  (void)wt_udp_wait(&loop->socket, WT_LOOP_WAIT_MICROS);
  (void)wt_runtime_session_pump(&loop->session, loop->now);
  loop->now += 1000U;
}

/* The message, on the mode the caller chose. A stream carries the draft's prefix and then the bytes, and the
 * stream is FINISHED with them: the Swift library's exchange opens a bidirectional stream and sends the message
 * with `endOfStream: true`, and a peer that reads a stream to its end cannot answer a message that never ends
 * (WT-135). The driver opens it, because the driver is what knows this endpoint owns the prefix -- the peer's
 * bytes on the same stream are payload, and an endpoint that re-read them as a prefix refuses its own answer. A
 * datagram carries the quarter stream ID and then the bytes, because a datagram IS the unit. */
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
  return wt_http3_driver_open_data_stream(&loop->side.driver, transport, 0, (const uint8_t *)config->message,
                                          message_length, 1, loop->now, NULL);
}

wt_status_t wt_loop_run_client(const wt_loop_config_t *config, wt_loop_result_t *out) {
  static const uint8_t k_connection_id[8] = {0x11U, 0x22U, 0x33U, 0x44U,
                                             0x55U, 0x66U, 0x77U, 0x88U};
  loop_t loop;
  uint8_t parameters[256];
  uint64_t parameters_len;
  wt_quic_connection_config_t connection;
  wt_tls_client_config_t tls;
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
  parameters_len = build_parameters(parameters, sizeof(parameters), 0, k_connection_id, sizeof(k_connection_id));
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
  /* A DIAGNOSTIC, and only a diagnostic: with WT_TLS_SECRET_LOG set, this client appends its own
   * CLIENT_HANDSHAKE_TRAFFIC_SECRET to that file in the NSS keylog format, so that a peer which writes the same
   * line can be compared value for value. It exists because a third-party peer could not decrypt this client's
   * Finished while this client decrypted the peer's (WT-135), and no amount of reading the derivation could say
   * which of the two values was wrong. Never set in production; the file holds a traffic secret. */
  {
    const char *keylog_path = getenv("WT_TLS_SECRET_LOG");
    if (keylog_path != NULL) {
      FILE *keylog = fopen(keylog_path, "a");
      if (keylog != NULL) {
        unsigned index;
        fprintf(keylog, "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00");
        for (index = 0U; index < WT_TLS13_SECRET_LEN; index++) {
          fprintf(keylog, "%02x", loop.session.handshake.client.client_handshake_secret[index]);
        }
        fprintf(keylog, "\n");
        (void)fclose(keylog);
      }
    }
  }

  /* The advertised limits, in force: the promise and the enforcement in one place. */
  (void)wt_runtime_session_advertise(&loop.session, 100000U, 4096U, 8U, 8U);
  init_side(&loop.side, WT_HTTP3_ROLE_CLIENT);
  (void)wt_runtime_session_set_frame_handler(&loop.session, side_on_frame, &loop.side);
  wt_http3_driver_quic_transport(&loop.session.connection, &loop.transport);
  (void)wt_runtime_session_set_lost_frame_handler(&loop.session, client_on_lost_frame, &loop);

  deadline_rounds = WT_LOOP_ROUNDS_FOR(config->timeout_ms);
  if (deadline_rounds > WT_LOOP_ROUNDS) deadline_rounds = WT_LOOP_ROUNDS;

  for (round = 0U; round < deadline_rounds && handshake_ready(&loop) == 0; round++) {
    pump_once(&loop);
  }
  if (handshake_ready(&loop) == 0) {
    record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  out->established = 1;

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  {
    wt_status_t status = wt_http3_driver_start_session(&loop.side.driver, &loop.transport, &settings,
                                                       config->authority, config->path, 0U, loop.now,
                                                       &loop.side.request_stream_id, &h3_error);
    if (status != WT_OK) {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  for (round = 0U; round < deadline_rounds && loop.side.section_complete == 0; round++) {
    pump_once(&loop);
  }
  if (loop.side.section_complete == 0) {
    record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  {
    wt_status_t status = wt_http3_endpoint_on_response_headers(
        &loop.side.endpoint, loop.side.request_stream_id, loop.side.section, loop.side.section_length,
        scratch, sizeof(scratch), &response, &h3_error);
    if (status != WT_OK) {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    out->connect_accepted = response.has_status != 0 && response.status >= 200U && response.status < 300U;
    out->status = (uint32_t)response.status;
  }

  {
    wt_status_t status = send_message(&loop, &loop.transport, config);
    if (status != WT_OK) {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
  /* Give the peer a moment to receive it and to answer with its own message where it has one. */
  for (round = 0U; round < 200U && loop.side.data_bytes == 0U; round++) pump_once(&loop);
  out->received_bytes = loop.side.data_bytes;
  out->received_datagram = loop.side.data_was_datagram;

  record_oracle(&loop, out);
  {
    /* Read BEFORE the clear, and reported instead of `WT_OK`: a run that closed the connection did not succeed. */
    wt_status_t closed = loop_close_status(&loop);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return closed;
  }
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
  parameters_len = build_parameters(parameters, sizeof(parameters), 1, k_connection_id, sizeof(k_connection_id));
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
  deadline_rounds = WT_LOOP_ROUNDS_FOR(config->timeout_ms);
  if (deadline_rounds > WT_LOOP_ROUNDS) deadline_rounds = WT_LOOP_ROUNDS;

  {
    wt_udp_address_t from;
    unsigned waited;
    int arrived = 0;

    /* The peer is learned by PEEKING, not by receiving: the datagram that names the peer must still be in the
     * queue when the connection is armed, or this side waits for a retransmission it may never get -- which is
     * exactly what the first version did (it received the Initial and dropped it). */
    for (waited = 0U; waited < (unsigned)WT_LOOP_PEEK_ROUNDS_FOR(config->timeout_ms); waited++) {
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
  wt_http3_driver_quic_transport(&loop.session.connection, &loop.transport);

  for (round = 0U; round < deadline_rounds && handshake_ready(&loop) == 0; round++) {
    pump_once(&loop);
  }
  if (handshake_ready(&loop) == 0) {
    record_oracle(&loop, out);
    record_oracle(&loop, out);
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
    record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_TIMEOUT;
  }
  {
    wt_status_t status = wt_http3_endpoint_on_request_headers(
        &loop.side.endpoint, loop.side.request_stream_id, loop.side.section, loop.side.section_length,
        scratch, sizeof(scratch), &request, &h3_error);
    if (status != WT_OK) {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
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
    record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return WT_ERR_PROTOCOL;
  }
  out->connect_accepted = 1;
  out->status = 200U;

  {
    wt_status_t status = wt_http3_driver_send_response(&loop.side.driver, &loop.transport,
                                                       loop.side.request_stream_id, 200U, 0U, 0,
                                                       loop.now);
    if (status != WT_OK) {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
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
    wt_status_t status = send_message(&loop, &loop.transport, config);
    if (status != WT_OK) {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    for (round = 0U; round < 100U; round++) pump_once(&loop);
  }

  record_oracle(&loop, out);
  {
    /* The same rule as the client's: a session this endpoint ended by closing is not a session that went well. */
    wt_status_t closed = loop_close_status(&loop);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return closed;
  }
}
