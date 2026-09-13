/* A packet session: a socket, a QUIC connection and a TLS handshake, driven together (Phase 9). */

#include "webtransport/runtime/session.h"

#include <string.h>

#include "webtransport/quic/protection.h"

/* The session's own frame handler: the handshake first, then whatever the caller installed. The order
 * matters and is the reason the handshake returns WT_OK for frames that are not its business -- a
 * handler that refused them would stop the walk before the layer behind it saw anything. */
static wt_status_t session_on_frame(void *context, wt_quic_space_t space,
                                    const wt_quic_frame_t *frame) {
  wt_runtime_session_t *session = context;
  wt_status_t status;

  status = wt_quic_handshake_on_frame(&session->handshake, space, frame);
  if (status != WT_OK) return status;
  if (session->next_handler != NULL) {
    return session->next_handler(session->next_context, space, frame);
  }
  return WT_OK;
}

static void session_on_lost(void *context, const wt_quic_tx_frame_t *frame) {
  wt_runtime_session_t *session = context;
  wt_quic_handshake_on_lost(&session->handshake, frame);
}

static wt_status_t install_initial_keys(wt_runtime_session_t *session, const uint8_t *connection_id,
                                        size_t connection_id_length, int is_server) {
  uint8_t initial_secret[WT_SHA256_LEN];
  wt_quic_packet_keys_t keys;
  wt_status_t status;

  status = wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1),
                                  connection_id, connection_id_length, initial_secret);
  if (status != WT_OK) return status;

  /* This endpoint's SEND keys are the peer's opposite: a server sends with the server keys and receives
   * with the client keys, and the flag says which of the two is being derived. */
  status = wt_quic_initial_packet_keys(initial_secret, is_server, WT_AEAD_AES_128_GCM, &keys);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_keys(&session->connection, WT_QUIC_SPACE_INITIAL, 0, &keys);
  if (status != WT_OK) {
    wt_quic_packet_keys_clear(&keys);
    return status;
  }
  status = wt_quic_initial_packet_keys(initial_secret, !is_server, WT_AEAD_AES_128_GCM, &keys);
  if (status != WT_OK) {
    wt_quic_packet_keys_clear(&keys);
    return status;
  }
  status = wt_quic_connection_set_keys(&session->connection, WT_QUIC_SPACE_INITIAL, 1, &keys);
  wt_quic_packet_keys_clear(&keys);
  return status;
}

wt_status_t wt_runtime_session_start_client(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_client_config_t *tls_config, uint64_t now) {
  wt_status_t status;

  (void)now;
  if (session == NULL || socket == NULL || peer == NULL || initial_connection_id == NULL ||
      connection_config == NULL || tls_config == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(session, 0, sizeof(*session));
  session->socket = socket;
  session->peer = *peer;
  session->is_client = 1;

  status = wt_quic_connection_init(&session->connection, connection_config);
  if (status != WT_OK) return status;
  status = wt_quic_connection_attach(&session->connection, socket, peer);
  if (status != WT_OK) return status;
  status = install_initial_keys(session, initial_connection_id, initial_connection_id_length, 0);
  if (status != WT_OK) return status;

  /* The handlers before the handshake starts, so a ClientHello-sized Initial packet that arrives during
   * the same round is already routed. */
  wt_quic_connection_set_handlers(&session->connection, session_on_frame, session, session_on_lost,
                                  session);
  status = wt_quic_handshake_start_client(&session->handshake, &session->connection, tls_config);
  if (status != WT_OK) {
    wt_runtime_session_clear(session);
    return status;
  }
  session->started = 1;
  return WT_OK;
}

wt_status_t wt_runtime_session_start_server(wt_runtime_session_t *session,
                                            const wt_udp_socket_t *socket,
                                            const wt_udp_address_t *peer,
                                            const uint8_t *initial_connection_id,
                                            size_t initial_connection_id_length,
                                            const wt_quic_connection_config_t *connection_config,
                                            const wt_tls_server_config_t *tls_config, uint64_t now) {
  wt_status_t status;

  (void)now;
  if (session == NULL || socket == NULL || peer == NULL || initial_connection_id == NULL ||
      connection_config == NULL || tls_config == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  memset(session, 0, sizeof(*session));
  session->socket = socket;
  session->peer = *peer;
  session->is_client = 0;

  status = wt_quic_connection_init(&session->connection, connection_config);
  if (status != WT_OK) return status;
  status = wt_quic_connection_attach(&session->connection, socket, peer);
  if (status != WT_OK) return status;
  status = install_initial_keys(session, initial_connection_id, initial_connection_id_length, 1);
  if (status != WT_OK) return status;
  wt_quic_connection_set_handlers(&session->connection, session_on_frame, session, session_on_lost,
                                  session);
  status = wt_quic_handshake_start_server(&session->handshake, &session->connection, tls_config);
  if (status != WT_OK) {
    wt_runtime_session_clear(session);
    return status;
  }
  session->started = 1;
  return WT_OK;
}

wt_status_t wt_runtime_session_advertise(wt_runtime_session_t *session, uint64_t initial_max_data,
                                         uint64_t initial_max_stream_data,
                                         uint64_t initial_max_streams_bidi,
                                         uint64_t initial_max_streams_uni) {
  wt_status_t status;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* The per-stream limit is a field of the connection's configuration rather than a frame: it is read when a
   * stream is created, so it must be in place before the first peer stream arrives. The three counts and the
   * data limit are state the connection updates and can also announce. */
  session->connection.config.local_max_stream_data = initial_max_stream_data;
  status = wt_quic_connection_set_max_data(&session->connection, initial_max_data);
  if (status != WT_OK) return status;
  status = wt_quic_connection_set_max_streams(&session->connection, WT_QUIC_STREAM_BIDIRECTIONAL,
                                              initial_max_streams_bidi);
  if (status != WT_OK) return status;
  return wt_quic_connection_set_max_streams(&session->connection, WT_QUIC_STREAM_UNIDIRECTIONAL,
                                            initial_max_streams_uni);
}

wt_status_t wt_runtime_session_set_frame_handler(wt_runtime_session_t *session,
                                                 wt_runtime_frame_handler_fn handler,
                                                 void *context) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  session->next_handler = handler;
  session->next_context = context;
  return WT_OK;
}

wt_status_t wt_runtime_session_pump(wt_runtime_session_t *session, uint64_t now) {
  wt_status_t received;
  wt_status_t status;

  if (session == NULL || session->started == 0) return WT_ERR_INVALID_ARGUMENT;

  /* One packet per call, and the caller loops: a pump that drained the socket would starve the other
   * endpoint in a two-session test, which is exactly the shape a test has. */
  /* The peer's transport parameters, applied once, the moment the handshake has them: they ARE this
   * connection's limits, and a connection without them refuses the unidirectional streams HTTP/3 opens
   * before it sends anything. */
  if (session->peer_parameters_applied == 0 && session->handshake.peer_parameters_len > 0U) {
    status = wt_quic_connection_set_peer_parameters(&session->connection,
                                                    session->handshake.peer_parameters,
                                                    session->handshake.peer_parameters_len);
    if (status != WT_OK) return status;
    session->peer_parameters_applied = 1;
  }

  received = wt_quic_connection_receive(&session->connection, now);
  session->last_receive = received;
  if (received == WT_OK) {
    session->packets_seen++;
  } else if (received != WT_ERR_AGAIN) {
    if (session->receive_errors == 0U) session->first_receive_error = received;
    session->receive_errors++;
  }

  status = wt_quic_handshake_flush(&session->handshake, now);
  if (status != WT_OK && status != WT_ERR_AGAIN) return status;
  if (status == WT_OK) session->flushes++;

  status = wt_quic_connection_flush(&session->connection, now);
  session->last_flush = status;
  if (status != WT_OK && status != WT_ERR_AGAIN) return status;

  status = wt_quic_connection_on_timeout(&session->connection, now);
  if (status != WT_OK && status != WT_ERR_AGAIN) return status;

  /* Nothing to read and nothing owed is the ordinary case in a pump loop, not an error: the caller
   * decides when to give up, which is what its --timeout-ms is for. */
  return WT_OK;
}

int wt_runtime_session_handshake_done(const wt_runtime_session_t *session) {
  if (session == NULL) return 0;
  /* The handshake's own CONNECTED state: both Finished messages are in, and 1-RTT keys are installed. A client
   * may send 1-RTT data from here; CONFIRMED (below) is the server's HANDSHAKE_DONE and matters for discarding
   * the Handshake keys (RFC 9000 section 7). */
  return wt_quic_handshake_is_connected(&session->handshake);
}

int wt_runtime_session_established(const wt_runtime_session_t *session) {
  if (session == NULL || session->started == 0) return 0;
  return session->handshake.confirmed;
}

wt_status_t wt_runtime_session_failure(const wt_runtime_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  return session->handshake.failure;
}

int wt_runtime_session_keys_ready(const wt_runtime_session_t *session) {
  if (session == NULL || session->started == 0) return 0;
  return session->handshake.application_keys_installed;
}

void wt_runtime_session_clear(wt_runtime_session_t *session) {
  if (session == NULL) return;
  wt_quic_handshake_clear(&session->handshake);
  wt_quic_connection_clear(&session->connection);
  session->started = 0;
  session->socket = NULL;
  session->next_handler = NULL;
  session->next_context = NULL;
}
