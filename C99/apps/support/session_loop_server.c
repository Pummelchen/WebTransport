/* The SERVER half of the one-sided session loops (Phase 9): `wt_loop_run_server`.
 *
 * Wait for one session, accept its CONNECT, answer it, and exchange one message. The sink, the pump
 * and every helper it uses are in `session_loop.c`, declared by "session_loop_internal.h". */

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
#include "webtransport/runtime/server_retry.h"
#include "webtransport/runtime/session.h"
#include "webtransport/webtransport/buffered.h"
#include "webtransport/webtransport/error.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

#include "capsule_stream.h"

#include "session_loop_internal.h"

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
  /* How much of the first Initial the peek actually read, which is what the Retry module may look at: the buffer
   * is larger than the header, and handing it a length it does not have would be reading a datagram that is not
   * there. */
  size_t initial_available = 0U;
  /* The connection ID this server uses, and the two identities a Retry adds: the ID the Retry chose (which
   * becomes this server's own) and the original destination connection ID the token carried back. The buffers are
   * here rather than inside the retry block because the values outlive it, and they are copies rather than views
   * because the Retry object holds the ID it drew. */
  const uint8_t *local_connection_id = k_connection_id;
  size_t local_connection_id_length = sizeof(k_connection_id);
  uint8_t original_destination_buffer[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  const uint8_t *original_destination_id = NULL;
  size_t original_destination_id_length = 0U;
  uint8_t retry_source_buffer[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  const uint8_t *retry_source_id = NULL;
  size_t retry_source_id_length = 0U;
  int retried = 0;
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
          initial_available = available;
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

  /* WT-168: validate the client's address with a Retry before this server has done any work for it. What follows
   * is one round trip and NOTHING kept about the client: the token carries what the connection will need, and the
   * Source Connection ID the Retry chose is the ID every later packet is addressed to (RFC 9000 section 17.2.5),
   * so it is the ID this connection is configured with -- one value in four places, which is why it is copied into
   * a local buffer rather than referred to through the Retry object. */
  if (config->retry != 0) {
    uint8_t retry_datagram[WT_RUNTIME_SERVER_RETRY_MAX];
    wt_runtime_server_retry_t retry;
    size_t retry_length = 0U;
    size_t issued_length = 0U;
    const uint8_t *issued;
    int sent = 0;
    unsigned waited;

    if (wt_runtime_server_retry_arm(&retry, sizeof(k_connection_id), 10000000U) != WT_OK) {
      wt_udp_close(&loop.socket);
      return WT_ERR_UNSUPPORTED;
    }
    if (wt_runtime_server_retry_build(&retry, initial_header, initial_available, &loop.peer, loop.now,
                                      retry_datagram, sizeof(retry_datagram), &retry_length,
                                      &sent) != WT_OK ||
        sent == 0) {
      /* `sent == 0` means the first datagram was not an Initial without a token, which cannot be true here: the
       * peek above only accepted one that named both connection IDs. Reporting a state error rather than
       * pretending to retry is the honest answer for a listener that somehow got here. */
      wt_udp_close(&loop.socket);
      return WT_ERR_STATE;
    }
    if (wt_udp_send(&loop.socket, &loop.peer, retry_datagram, retry_length) != WT_OK) {
      wt_udp_close(&loop.socket);
      return WT_ERR_IO;
    }
    issued = wt_runtime_server_retry_source_id(&retry, &issued_length);
    if (issued == NULL || issued_length > sizeof(retry_source_buffer)) {
      wt_udp_close(&loop.socket);
      return WT_ERR_STATE;
    }
    memcpy(retry_source_buffer, issued, issued_length);
    retry_source_id = retry_source_buffer;
    retry_source_id_length = issued_length;
    local_connection_id = retry_source_buffer;
    local_connection_id_length = issued_length;
    retried = 1;

    /* And the client's second Initial, which carries the token and is addressed to the Retry's Source Connection
     * ID. The buffer is large enough for a whole header INCLUDING the token, which is the one thing the first
     * peek's 64 bytes could not have held. */
    sent = 0;
    for (waited = 0U; waited < (unsigned)WT_LOOP_PEEK_ROUNDS_FOR(config->timeout_ms); waited++) {
      static uint8_t answered[512];
      size_t datagram_length = 0U;
      size_t available = 0U;
      wt_udp_address_t candidate;
      if (wt_udp_peek(&loop.socket, answered, sizeof(answered), &datagram_length, &available, &candidate) ==
          WT_OK) {
        int accepted = 0;
        (void)candidate;
        if (wt_runtime_server_retry_accept(&retry, answered, available, &loop.peer, loop.now,
                                           original_destination_buffer, sizeof(original_destination_buffer),
                                           &original_destination_id_length, &accepted) == WT_OK &&
            accepted != 0) {
          original_destination_id = original_destination_buffer;
          sent = 1;
          /* The answering Initial is LEFT IN THE QUEUE: the connection is armed next and must read it as its first
           * packet, which is why this loop peeks rather than receives. */
          break;
        }
        /* A peek does not consume, and the Initial the listener peeked BEFORE the Retry -- and any retransmission
         * of it -- is still in the queue: without this the loop reads the same stale datagram until it times out,
         * which is exactly what the first version of this flow did while the client's answer waited behind it. */
        (void)wt_udp_receive(&loop.socket, answered, sizeof(answered), &datagram_length, &candidate);
      }
      (void)wt_udp_wait(&loop.socket, WT_LOOP_WAIT_MICROS * 10U);
    }
    if (sent == 0) {
      /* No answer to the Retry: the client had its chance and the address stays unvalidated. Silence is the
       * right answer for a listener that will not spend state on an address nobody has proved. */
      wt_udp_close(&loop.socket);
      return WT_ERR_TIMEOUT;
    }
  }

  parameters_len = build_parameters(parameters, sizeof(parameters), 1, local_connection_id,
                                   local_connection_id_length,
                                   retried != 0 ? original_destination_id : client_destination_id,
                                   retried != 0 ? original_destination_id_length : client_destination_id_length,
                                   retried, retry_source_id, retry_source_id_length);
  if (parameters_len == 0U) {
    wt_udp_close(&loop.socket);
    return WT_ERR_LIMIT;
  }

  connection_config(&connection, WT_QUIC_ROLE_SERVER, local_connection_id, local_connection_id_length);
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
    /* The Initial secret is derived from the Destination Connection ID of the client's LAST Initial (RFC 9001
     * section 5.2), which is the one the peek above read -- not this server's own ID, which is what it was. A
     * server that retried has TWO IDs in play and starts through the form that takes both, because the one the
     * client's FIRST Initial carried is what the transport parameters must name (WT-168). */
    wt_status_t status =
        retried != 0
            ? wt_runtime_session_start_server_retried(&loop.session, &loop.socket, &loop.peer,
                                                      local_connection_id, local_connection_id_length,
                                                      original_destination_id,
                                                      original_destination_id_length, &connection, &tls,
                                                      loop.now)
            : wt_runtime_session_start_server(&loop.session, &loop.socket, &loop.peer,
                                              client_destination_id, client_destination_id_length,
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
  /* And one spare connection ID kept out there (WT-171), so a peer that retires one is answered with a
   * replacement instead of talking to an endpoint that runs out. */
  (void)wt_runtime_session_keep_spare_connection_id(&loop.session);
  init_side(&loop.side, WT_HTTP3_ROLE_SERVER);
  (void)wt_runtime_session_set_frame_handler(&loop.session, side_on_frame, &loop.side);
  wt_http3_driver_quic_transport(&loop.session.connection, &loop.transport);
  /* What a refused capsule is stated to (WT-165), and the clock it is stated at. */
  loop.side.transport = &loop.transport;
  loop.side.connection = &loop.session.connection;
  loop.side.now_for_close = loop.now;
  /* Bound so that a refusal with an HTTP/3 error reaches the peer as an application close (WT-159). */
  wt_http3_driver_bind_connection(&loop.side.driver, &loop.session.connection);

  for (round = 0U; round < deadline_rounds && handshake_ready(&loop) == 0 && loop_is_closed(&loop) == 0;
       round++) {
    pump_once(&loop);
  }
  if (handshake_ready(&loop) == 0) {
    record_oracle(&loop, out);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    return loop_is_closed(&loop) != 0 ? loop_wait_status(&loop) : WT_ERR_TIMEOUT;
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
    /* Section 5.1's LOCAL half: the set above advertises flow control, and the capsule gate keeps that fact
     * so each grant is decided against both ends (WT-252). */
    wt_capsule_stream_set_flow_advertised(&loop.side.capsules, &settings);
    status = wt_http3_driver_start_own_streams(&loop.side.driver, &loop.transport, &settings, loop.now);
    if (status != WT_OK) {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return status;
    }
  }

  /* The CONNECT, its section assembled from the driver's pieces, and the draft-16 decision. */
  for (round = 0U; round < deadline_rounds && loop.side.section_complete == 0 && loop_is_closed(&loop) == 0;
       round++) {
    /* The sink must know which stream carries the exchange before the section arrives. A client's first
     * bidirectional stream is stream 0 (RFC 9000 section 2.1), and this tool serves one session, so that is the
     * stream the CONNECT is on. */
    pump_once(&loop);
  }
  if (loop.side.section_complete == 0) {
    record_oracle(&loop, out);
    wt_runtime_session_clear(&loop.session);
    wt_udp_close(&loop.socket);
    if (loop.side.section_overflow != 0) {
      /* The same bound as the client's, reported the same way: a request whose section did not fit is not a
       * request that never arrived. */
      out->request_outcome = (unsigned)WT_WEBTRANSPORT_REQUEST_REJECT;
      return WT_ERR_LIMIT;
    }
    return loop_is_closed(&loop) != 0 ? loop_wait_status(&loop) : WT_ERR_TIMEOUT;
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
    /* `status` is documented as "the answer to send when the outcome is a rejection" (session_request.h), and
     * the validator leaves its default rejection in the field for an ACCEPTED request -- which is how this
     * report came to say 404, with no error beside it, for a session the same report calls accepted and
     * established. Zero for an acceptance: there was no answer to send, and a script that switches on this
     * number must not read a refusal out of an accepted session (WT-190). */
    out->request_status = decision.outcome == WT_WEBTRANSPORT_REQUEST_ACCEPT ? 0U : (uint64_t)decision.status;
    out->h3_error = (uint64_t)h3_error;
    if (validated == WT_OK && decision.outcome == WT_WEBTRANSPORT_REQUEST_ACCEPT) {
      /* The decision is kept and the exchange continues below. The request stream becomes a CAPSULE stream here,
       * which is the earliest moment this endpoint can know it is one: the request's HEADERS frame has just been
       * read, so the peer's capsules begin after it (WT-164). */
      if (wt_http3_driver_mark_capsule_stream(&loop.side.driver, loop.side.request_stream_id, 0) != WT_OK) {
        record_oracle(&loop, out);
        wt_runtime_session_clear(&loop.session);
        wt_udp_close(&loop.socket);
        return WT_ERR_LIMIT;
      }
    } else {
      record_oracle(&loop, out);
      wt_runtime_session_clear(&loop.session);
      wt_udp_close(&loop.socket);
      return WT_ERR_PROTOCOL;
    }
  }
  out->connect_accepted = 1;
  /* The CONNECT was accepted: the session has an ID now, so what arrived before it can be associated (draft-16
   * section 4.6). */
  side_session_known(&loop.side);
  out->status = 200U;

  {
    wt_status_t status = wt_http3_driver_send_response(&loop.side.driver, &loop.transport,
                                                       loop.side.request_stream_id, 200U, 0U, 0,
                                                       loop.now);
    if (status != WT_OK) {
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
