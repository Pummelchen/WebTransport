/* One-sided session loops for the client and server tools (Phase 9). */

#include "session_loop.h"

#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/packet.h"
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
  /* The connection this side refuses TO. An HTTP/3 refusal has to reach the peer as an application close carrying
   * the HTTP/3 code, so the boundary between the two layers is where the code is translated (WT-158). */
  wt_quic_connection_t *connection;
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
  /* A DIAGNOSTIC, gated by the same file the request's field section goes to: what this stream carries AFTER the
   * response. Draft-16 puts the session's capsules on the CONNECT stream, and a third-party peer's flow-control
   * capsule read as an HTTP/3 frame is a frame whose length runs past the end of the stream (WT-156). */
  {
    const char *log_path = getenv("WT_HTTP3_SECTION_LOG");
    if (log_path != NULL) {
      FILE *log = fopen(log_path, "a");
      if (log != NULL) {
        size_t index;
        fprintf(log, "frame stream=%llu type=%llu length=%llu last=%d bytes=",
                (unsigned long long)stream_id, (unsigned long long)type, (unsigned long long)length, last);
        for (index = 0U; index < length && index < 64U; index++) {
          fprintf(log, "%02x", payload[index]);
        }
        fprintf(log, "\n");
        (void)fclose(log);
      }
    }
  }
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
  wt_status_t status;

  side->frames_seen++;
  status = wt_http3_driver_on_quic_frame(&side->driver, space, frame, &side->sink, 16384U);
  if (status != WT_OK && side->connection != NULL) {
    /* RFC 9114 section 8: an HTTP/3 error is carried by a CONNECTION_CLOSE of type 0x1d whose code is the HTTP/3
     * error code. A refusal WITHOUT one -- a caller's own bound, WT_ERR_LIMIT -- is not an HTTP/3 error, and the
     * connection's own default stays in force for it. */
    wt_http3_error_t h3_error = wt_http3_driver_last_error(&side->driver);
    if (h3_error != WT_HTTP3_NO_ERROR) {
      wt_quic_connection_refuse_application(side->connection, (uint64_t)h3_error, 0U);
    }
  }
  return status;
}

/* The endpoint's transport parameters, built by the LIBRARY: the mandatory connection-ID parameters live in
 * `wt_quic_transport_parameters_build` so that this file cannot forget one. It did forget one -- the parameter
 * that says which Source Connection ID these packets carry -- and only a third-party peer ever said so (WT-141).
 *
 * `source` is the ID these packets carry; `original_destination` is the one the CLIENT put in its first Initial,
 * which only a server sends (RFC 9000 section 7.3) and which the client validates. They were the same constant
 * here, and that is why this tree could not see the connection-ID rule at all: with one ID on both ends the ID
 * never has to change, so a client that kept sending to its own ID looked exactly like one that had adopted the
 * server's (WT-151). */
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
 * counters say. It asks whether the close was SENT, not merely decided on -- the idle timeout closes silently
 * (RFC 9000 section 10.1), and a run whose only close is that one has told the peer nothing, so `WT_OK` is the
 * honest answer and `WT_ERR_PROTOCOL` would be an invented failure (WT-144, WT-145). The status the refusing
 * handler returned is the report when there was one, because it names the layer that refused. */
static wt_status_t loop_close_status(const loop_t *loop) {
  if (wt_quic_connection_close_was_sent(&loop->session.connection) == 0) return WT_OK;
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
  out->close_cause_frame = loop->session.connection.close_cause_frame;
  out->close_was_sent = wt_quic_connection_close_was_sent(&loop->session.connection);
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
  out->acked_initial = (unsigned)loop->session.connection.packets_acked[WT_QUIC_SPACE_INITIAL];
  out->acked_handshake = (unsigned)loop->session.connection.packets_acked[WT_QUIC_SPACE_HANDSHAKE];
  out->acked_application = (unsigned)loop->session.connection.packets_acked[WT_QUIC_SPACE_APPLICATION];
  out->in_flight = (unsigned)wt_quic_loss_count(&loop->session.connection.loss);
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
  parameters_len = build_parameters(parameters, sizeof(parameters), 0, k_connection_id,
                                   sizeof(k_connection_id), NULL, 0U);
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
  loop.side.connection = &loop.session.connection;
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

  /* The client's SETTINGS, from the one place that owns them: section 3.1 requires SETTINGS_H3_DATAGRAM and the
   * draft-specific codepoint, and the set also carries the enabling codepoints of the earlier drafts, which is
   * how section 7.1 negotiates with a peer that predates the rename (WT-145). */
  wt_http3_settings_init(&settings);
  {
    wt_status_t status = wt_webtransport_settings_apply(&settings, 0);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }
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
  /* A server chooses its OWN Source Connection ID, and it is deliberately not the client's: the rule that a
   * client adopts it (RFC 9000 section 7.2) is only exercised when the two differ, and a local exchange that
   * shared one ID is exactly how a client that never adopted it passed every test in this tree (WT-151). */
  static const uint8_t k_connection_id[8] = {0x21U, 0x32U, 0x43U, 0x54U,
                                             0x65U, 0x76U, 0x87U, 0x98U};
  uint8_t initial_header[64];
  const uint8_t *client_destination_id = NULL;
  size_t client_destination_id_length = 0U;
  const uint8_t *client_source_id = NULL;
  size_t client_source_id_length = 0U;
  loop_t loop;
  uint8_t parameters[256];
  uint64_t parameters_len;
  wt_quic_connection_config_t connection;
  wt_tls_server_config_t tls;
  wt_tls_server_identity_t identity;
  wt_http3_message_t request;
  wt_http3_settings_t settings;
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

  /* The peer's address is not known until a packet arrives, and the runtime takes it from the packet's source:
   * the session's own socket reports it. The wait below is what makes a listener a listener. */
  deadline_rounds = WT_LOOP_ROUNDS_FOR(config->timeout_ms);
  if (deadline_rounds > WT_LOOP_ROUNDS) deadline_rounds = WT_LOOP_ROUNDS;

  {
    unsigned waited;
    int arrived = 0;

    /* The peer is learned by PEEKING, not by receiving: the datagram that names the peer must still be in the
     * queue when the connection is armed, or this side waits for a retransmission it may never get -- which is
     * exactly what the first version did (it received the Initial and dropped it). The peek reads the HEADER as
     * well, because the client's first Initial names both connection IDs this server needs and nothing else on
     * the wire will: its own Source Connection ID is what the server must address its answer to, and the
     * destination it chose is the `original_destination_connection_id` the client validates (RFC 9000 sections
     * 7.2 and 7.3).
     *
     * The peek buffer is deliberately smaller than an Initial, so `available` is NOT required to equal the
     * datagram's length: the connection IDs are at the FRONT of a packet and 64 bytes covers the longest header
     * possible (version and two 20-byte connection IDs), while an Initial is 1200. `wt_quic_long_header_connection_ids`
     * reads exactly those and refuses a header that is not all there -- the full decoder needs the Length field
     * and a view of the payload, so it cannot be asked for this at all, and requiring the whole datagram in the
     * buffer meant no packet was ever accepted and the server timed out having read nothing. */
    for (waited = 0U; waited < (unsigned)WT_LOOP_PEEK_ROUNDS_FOR(config->timeout_ms); waited++) {
      size_t datagram_length = 0U;
      size_t available = 0U;
      wt_udp_address_t candidate;
      wt_status_t peek_status = wt_udp_peek(&loop.socket, initial_header, sizeof(initial_header),
                                            &datagram_length, &available, &candidate);
      if (peek_status == WT_OK) {
        const uint8_t *destination = NULL;
        size_t destination_length = 0U;
        const uint8_t *source = NULL;
        size_t source_length = 0U;
        if (wt_quic_long_header_connection_ids(initial_header, available, &destination, &destination_length,
                                               &source, &source_length) == WT_OK &&
            destination_length > 0U && source_length > 0U) {
          loop.peer = candidate;
          client_destination_id = destination;
          client_destination_id_length = destination_length;
          client_source_id = source;
          client_source_id_length = source_length;
          arrived = 1;
          break;
        }
      }
      (void)wt_udp_wait(&loop.socket, WT_LOOP_WAIT_MICROS * 10U);
    }
    if (arrived == 0) {
      wt_udp_close(&loop.socket);
      return WT_ERR_TIMEOUT;
    }
  }

  parameters_len = build_parameters(parameters, sizeof(parameters), 1, k_connection_id,
                                   sizeof(k_connection_id), client_destination_id,
                                   client_destination_id_length);
  if (parameters_len == 0U) {
    wt_udp_close(&loop.socket);
    return WT_ERR_LIMIT;
  }

  connection_config(&connection, WT_QUIC_ROLE_SERVER, k_connection_id, sizeof(k_connection_id));
  /* Its own Source Connection ID is the one it chose; the client's is the one it answers. */
  connection.peer_connection_id = client_source_id;
  connection.peer_connection_id_length = client_source_id_length;
  wt_tls_self_signed_identity(config->identity, &identity);
  memset(&tls, 0, sizeof(tls));
  tls.identity = &identity;
  tls.alpn = "h3";
  tls.require_transport_parameters = 1;
  tls.transport_parameters = parameters;
  tls.transport_parameters_len = (size_t)parameters_len;

  {
    /* The Initial secret is derived from the Destination Connection ID of the client's FIRST Initial (RFC 9001
     * section 5.2), which is the one the peek above read -- not this server's own ID, which is what it was. */
    wt_status_t status = wt_runtime_session_start_server(&loop.session, &loop.socket, &loop.peer,
                                                         client_destination_id,
                                                         client_destination_id_length,
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
  loop.side.connection = &loop.session.connection;
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

  /* A WebTransport endpoint's SETTINGS, in the one place that owns them, and the server's own streams: this
   * server sent NEITHER before, so it had no control stream and no SETTINGS frame at all. RFC 9114 section 6.2.1
   * makes both mandatory for any HTTP/3 endpoint, and draft-16 section 3.1 makes the settings the thing a client
   * waits for -- so this tool was not a server a third-party client could have talked to, and its own client
   * never checked. Sent as soon as the handshake can carry 1-RTT data, which is before the response (WT-145). */
  wt_http3_settings_init(&settings);
  {
    wt_status_t status = wt_webtransport_settings_apply(&settings, 1);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
    status = wt_http3_driver_start_own_streams(&loop.side.driver, &loop.transport, &settings, loop.now);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }

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
  /* A DIAGNOSTIC, gated by WT_HTTP3_SECTION_LOG: the request's field section exactly as it arrived, so that a
   * decoder disagreement with a third-party encoder can be settled by decoding the same bytes twice instead of by
   * reading either decoder (WT-153). */
  {
    const char *section_log_path = getenv("WT_HTTP3_SECTION_LOG");
    if (section_log_path != NULL) {
      FILE *section_log = fopen(section_log_path, "a");
      if (section_log != NULL) {
        size_t index;
        for (index = 0U; index < loop.side.section_length; index++) {
          fprintf(section_log, "%02x", loop.side.section[index]);
        }
        fprintf(section_log, "\n");
        (void)fclose(section_log);
      }
    }
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
  {
    wt_status_t validated = wt_webtransport_session_request_validate(&request, &policy, &decision, &h3_error);
    /* The four pseudo-headers a WebTransport CONNECT is made of, in one line, for the report. */
    {
      size_t used = 0U;
      struct {
        const uint8_t *bytes;
        size_t length;
      } parts[4];
      size_t part;
      parts[0].bytes = request.method;
      parts[0].length = request.method_length;
      parts[1].bytes = request.protocol;
      parts[1].length = request.protocol_length;
      parts[2].bytes = request.authority;
      parts[2].length = request.authority_length;
      parts[3].bytes = request.path;
      parts[3].length = request.path_length;
      out->request_line[0] = '\0';
      for (part = 0U; part < 4U; part++) {
        size_t index;
        if (part != 0U && used + 1U < sizeof(out->request_line)) out->request_line[used++] = ' ';
        for (index = 0U; index < parts[part].length && used + 1U < sizeof(out->request_line); index++) {
          uint8_t byte = parts[part].bytes[index];
          out->request_line[used++] = (byte >= 0x20U && byte < 0x7fU) ? (char)byte : '?';
        }
      }
      out->request_line[used] = '\0';
    }
    out->request_outcome = (unsigned)decision.outcome;
    out->request_status = (uint64_t)decision.status;
    out->h3_error = (uint64_t)h3_error;
    if (validated == WT_OK && decision.outcome == WT_WEBTRANSPORT_REQUEST_ACCEPT) {
      /* The decision is kept and the exchange continues below. */
    } else {
      record_oracle(&loop, out);
    record_oracle(&loop, out);
  wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return WT_ERR_PROTOCOL;
    }
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
