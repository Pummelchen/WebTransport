/* A listening peer that MISBEHAVES after a handshake, so the CLI tools can be tested against one (WT-147).
 *
 * Every other peer this repository can stand up — the tools against each other, and the container peers — is
 * well behaved, which means the tools' REFUSAL path has only ever been exercised in one process, by the
 * conformance scenarios that drive both endpoints directly. A caller who runs `wt-client-c99` against a peer that
 * breaks a rule has no such luxury: what is being tested is the TOOL's report and exit status, and that needs a
 * peer on the other side of a real socket.
 *
 * The acts are a small closed set, refused by name in the options parser if unknown (`--hostile <act>`):
 *
 *   - `max-streams-decrease`: send a MAX_STREAMS whose limit is BELOW what this peer granted in its transport
 *     parameters. RFC 9000 section 4.6 makes a limit that decreases a PROTOCOL_VIOLATION, because the peer has
 *     already been told it may open that many streams, and section 19.11 names the frame. The expected answer is
 *     a transport close with code 0x0a naming frame type 0x12, which is what the test asserts -- on the CLIENT's
 *     report AND on this peer's, because "the code we sent" and "the code the peer received" are two claims.
 *
 * This lives in the conformance tool rather than in a shipped server for a reason the plan states as a rule: a
 * production server that could be told to break a transport rule would be a server nobody could trust, so the
 * misbehaviour is a capability of the TEST peer and not a flag on `wt-server-c99`.
 */

#include "hostile_peer.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/quic/packet.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/session.h"
#include "webtransport/tls/self_signed.h"
#include "webtransport/writer.h"

/* How many rounds a phase gets before the act is reported as not attempted. A peer that never handshakes is a
 * fact about the run, not a failure of the act, so the two are reported differently. */
#define WT_HOSTILE_ROUNDS 400U
#define WT_HOSTILE_WAIT_MICROS 2000U

/* This peer's own Source Connection ID, a constant because nothing here reuses an ID or migrates: the act is what
 * is under test, and a random ID would only make a failure harder to read. */
static const uint8_t k_server_connection_id[8] = {0x5aU, 0x6bU, 0x7cU, 0x8dU,
                                                 0x9eU, 0xafU, 0xb0U, 0xc1U};

static wt_cli_result_t fail_peer(char *detail, size_t detail_size, const char *text) {
  snprintf(detail, detail_size, "%s", text);
  return WT_CLI_RESULT_FAILED;
}

/* Learn the peer by PEEKING, not by receiving: the datagram that names the client must still be in the queue when
 * the connection is armed, or this side waits for a retransmission it may never get. The same rule the tool's
 * other listener follows, and the reason `wt_quic_long_header_connection_ids` exists. */
static wt_status_t wait_for_initial(wt_udp_socket_t *socket, wt_udp_address_t *peer, uint8_t *header,
                                    size_t capacity, size_t *out_available, const uint8_t **out_destination,
                                    size_t *out_destination_length, const uint8_t **out_source,
                                    size_t *out_source_length) {
  unsigned waited;

  for (waited = 0U; waited < WT_HOSTILE_ROUNDS; waited++) {
    size_t datagram_length = 0U;
    size_t available = 0U;
    wt_udp_address_t candidate;

    if (wt_udp_peek(socket, header, capacity, &datagram_length, &available, &candidate) == WT_OK &&
        wt_quic_long_header_connection_ids(header, available, out_destination, out_destination_length,
                                           out_source, out_source_length) == WT_OK &&
        *out_destination_length > 0U && *out_source_length > 0U) {
      *peer = candidate;
      *out_available = available;
      return WT_OK;
    }
    (void)wt_udp_wait(socket, WT_HOSTILE_WAIT_MICROS * 10U);
  }
  return WT_ERR_TIMEOUT;
}

static void peer_pump(wt_runtime_session_t *session, wt_udp_socket_t *socket, uint64_t *now) {
  (void)wt_udp_wait(socket, WT_HOSTILE_WAIT_MICROS);
  (void)wt_runtime_session_pump(session, *now);
  *now += 1000U;
}

/* The one act, and what it is: a MAX_STREAMS below the limit this peer's own transport parameters granted.
 * `granted` is what the parameters advertised, so the frame is a DECREASE by construction rather than by a number
 * a reader has to check against another file. */
static wt_status_t send_hostile_frame(wt_runtime_session_t *session, uint64_t now, int *out_sent) {
  wt_quic_frame_t frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_STREAMS);
  wt_status_t status;

  *out_sent = 0;
  frame.as.max_streams.direction = WT_QUIC_STREAM_BIDIRECTIONAL;
  frame.as.max_streams.maximum = 4U; /* the parameters advertise 8 (WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI) */
  status = wt_quic_connection_send_frame(&session->connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, now);
  if (status != WT_OK) return status;
  status = wt_quic_connection_flush(&session->connection, now);
  if (status != WT_OK) return status;
  *out_sent = 1;
  return WT_OK;
}

wt_cli_result_t wt_scenario_hostile_peer_run(const char *address, const char *act, char *detail,
                                             size_t detail_size) {
  wt_udp_socket_t socket;
  wt_udp_address_t local;
  wt_udp_address_t peer;
  wt_runtime_session_t session;
  wt_tls_self_signed_t identity;
  wt_tls_server_identity_t server_identity;
  wt_tls_server_config_t tls;
  wt_quic_connection_config_t connection;
  wt_quic_transport_parameters_t params;
  uint8_t initial_header[512];
  uint8_t encoded[256];
  wt_writer_t writer = wt_writer_init(encoded, sizeof(encoded));
  const uint8_t *client_destination = NULL;
  const uint8_t *client_source = NULL;
  size_t client_destination_length = 0U;
  size_t client_source_length = 0U;
  size_t available = 0U;
  uint64_t now = 1000U;
  unsigned round;
  int sent = 0;
  wt_status_t status;
  wt_cli_result_t result = WT_CLI_RESULT_FAILED;

  if (address == NULL || act == NULL) return fail_peer(detail, detail_size, "no address or act");
  if (strcmp(act, "max-streams-decrease") != 0) {
    return fail_peer(detail, detail_size, "the act is not one this peer implements");
  }
  if (wt_udp_address_parse_host_port(address, &local) != WT_OK) {
    return fail_peer(detail, detail_size, "the address is not host:port");
  }
  if (wt_udp_socket_open(&socket, local.family) != WT_OK) {
    return fail_peer(detail, detail_size, "the socket did not open");
  }
  if (wt_udp_bind(&socket, &local) != WT_OK) {
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "the socket did not bind");
  }
  /* The port it actually got, on its own line, so a caller that asked for 0 can reach it -- and the same line the
   * tool prints for a scenario run, because this is the same tool. */
  printf("{\"role\":\"hostile-peer\",\"boundPort\":%u,\"act\":\"%s\"}\n", (unsigned)socket.port, act);

  memset(&session, 0, sizeof(session));
  memset(&identity, 0, sizeof(identity));
  memset(&tls, 0, sizeof(tls));
  memset(&connection, 0, sizeof(connection));

  status = wait_for_initial(&socket, &peer, initial_header, sizeof(initial_header), &available,
                            &client_destination, &client_destination_length, &client_source,
                            &client_source_length);
  if (status != WT_OK) {
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "no Initial arrived from the client");
  }

  /* The parameters, through the library's own builder so that a mandatory one cannot be forgotten here (WT-141),
   * and with the SAME limits the session is told to advertise -- the promise and the enforcement are one pair, and
   * a peer that advertised 8 and enforced 0 would refuse the client's first stream for its own mistake (WT-110). */
  if (wt_quic_transport_parameters_build(&params, 1, k_server_connection_id, sizeof(k_server_connection_id),
                                         client_destination, client_destination_length, 0, NULL,
                                         0U) != WT_OK ||
      wt_quic_transport_parameters_encode(&writer, &params) != WT_OK) {
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "the transport parameters did not encode");
  }
  if (wt_tls_self_signed_generate(&identity, "localhost") != WT_OK) {
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "no identity could be generated");
  }
  wt_tls_self_signed_identity(&identity, &server_identity);
  tls.identity = &server_identity;
  tls.alpn = "h3";
  tls.require_transport_parameters = 1;
  tls.transport_parameters = encoded;
  tls.transport_parameters_len = wt_writer_offset(&writer);

  connection.role = WT_QUIC_ROLE_SERVER;
  connection.version = WT_QUIC_VERSION_1;
  connection.local_connection_id = k_server_connection_id;
  connection.local_connection_id_length = sizeof(k_server_connection_id);
  connection.peer_connection_id = client_source;
  connection.peer_connection_id_length = client_source_length;
  connection.aead = WT_AEAD_AES_128_GCM;
  connection.max_ack_delay = 25000U;
  connection.local_max_ack_delay = 25000U;
  connection.idle_timeout = 30000000U;
  connection.max_datagram_size = 1200U;

  if (wt_runtime_session_start_server(&session, &socket, &peer, client_destination,
                                      client_destination_length, &connection, &tls, now) != WT_OK) {
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "the session did not arm");
  }
  if (wt_runtime_session_advertise(&session, 100000U, 4096U, 8U, 8U) != WT_OK) {
    wt_runtime_session_clear(&session);
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "the advertised limits could not be put in force");
  }

  /* The handshake, then the act: a MAX_STREAMS can only travel in the Application space, so a peer that sent one
   * before 1-RTT keys would be the one breaking a rule. */
  for (round = 0U; round < WT_HOSTILE_ROUNDS; round++) {
    if (wt_runtime_session_established(&session) != 0) break;
    peer_pump(&session, &socket, &now);
  }
  if (wt_runtime_session_established(&session) == 0) {
    wt_runtime_session_clear(&session);
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "the handshake did not complete, so the act was not performed");
  }

  status = send_hostile_frame(&session, now, &sent);
  if (status != WT_OK || sent == 0) {
    wt_runtime_session_clear(&session);
    wt_udp_close(&socket);
    return fail_peer(detail, detail_size, "the hostile frame could not be sent");
  }

  /* And the answer: the client must close the connection with the code section 4.6 names, and this peer reads it.
   * A few rounds are enough on loopback, and the bound is what keeps a client that ignores the frame from
   * hanging the suite. */
  for (round = 0U; round < WT_HOSTILE_ROUNDS; round++) {
    if (wt_quic_connection_is_closed(&session.connection) != 0) break;
    peer_pump(&session, &socket, &now);
  }

  printf("{\"role\":\"hostile-peer\",\"act\":\"%s\",\"established\":true,\"sentHostileFrame\":%s,"
         "\"peerClosed\":%s,\"peerErrorCode\":%llu,\"peerCloseFrameType\":%llu,\"peerCloseKind\":%u}\n",
         act, sent != 0 ? "true" : "false",
         session.connection.peer_closed != 0 ? "true" : "false",
         (unsigned long long)session.connection.peer_error_code,
         (unsigned long long)session.connection.peer_frame_type,
         (unsigned)session.connection.peer_close_kind);

  if (session.connection.peer_closed != 0 &&
      session.connection.peer_error_code == (uint64_t)WT_QUIC_PROTOCOL_VIOLATION &&
      session.connection.peer_frame_type == WT_QUIC_FRAME_MAX_STREAMS_BIDI) {
    snprintf(detail, detail_size,
             "the peer sent a MAX_STREAMS below its own grant and the client closed with 0x%llx naming frame "
             "0x%llx",
             (unsigned long long)session.connection.peer_error_code,
             (unsigned long long)session.connection.peer_frame_type);
    result = WT_CLI_RESULT_PASSED;
  } else {
    snprintf(detail, detail_size,
             "the client did not refuse the decreasing MAX_STREAMS: peerClosed=%d code=0x%llx frame=0x%llx",
             session.connection.peer_closed, (unsigned long long)session.connection.peer_error_code,
             (unsigned long long)session.connection.peer_frame_type);
  }

  wt_runtime_session_clear(&session);
  wt_udp_close(&socket);
  return result;
}
