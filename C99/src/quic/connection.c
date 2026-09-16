/* One connection: its packet number spaces, its timer and its socket. See webtransport/quic/connection.h.
 *
 * The shape of the receive path is the part worth reading first. A datagram is a sequence of coalesced
 * packets (RFC 9000 section 12.2); each is unprotected, authenticated and decrypted by packet_io, and
 * its frames are walked by the frame decoder with a visitor that acts on the ones this layer owns and
 * hands the rest to the caller's handler. Only after the walk does this file decide whether the packet
 * was ack-eliciting, because that is a property of the frames it carried and not of its header: a
 * packet of PADDING alone is not, and neither is an acknowledgement (RFC 9000 section 13.2.1).
 *
 * The send path is the mirror image, and the order the two protections impose is packet_io's business,
 * not this file's. What this file adds is the three refusals that must happen BEFORE a packet reaches
 * the wire: the congestion window has to have room, the sent-packet list has to have room to remember
 * it (a packet that is not remembered is one that is never retransmitted, so sending it is worse than
 * not sending it), and a retransmission descriptor has to exist for anything worth sending again.
 */

#include "connection_internal.h"

const char *wt_quic_space_name(wt_quic_space_t space) {
  switch (space) {
    case WT_QUIC_SPACE_INITIAL:
      return "initial";
    case WT_QUIC_SPACE_HANDSHAKE:
      return "handshake";
    case WT_QUIC_SPACE_APPLICATION:
      return "application";
    case WT_QUIC_SPACE_COUNT:
      break;
  }
  return "unknown";
}
static uint64_t microseconds_of_milliseconds(uint64_t milliseconds) {
  if (milliseconds > UINT64_MAX / 1000U) return UINT64_MAX;
  return milliseconds * 1000U;
}
uint64_t idle_timeout_of(const wt_quic_connection_t *connection) {
  uint64_t local = connection->config.idle_timeout;
  uint64_t peer = connection->peer_limits.max_idle_timeout;

  if (local == 0U) return peer;
  if (peer == 0U) return local;
  return local < peer ? local : peer;
}
static uint64_t parameter_or(const wt_quic_transport_parameters_t *params, uint64_t id,
                             uint64_t fallback) {
  uint64_t value = 0U;
  if (wt_quic_transport_parameters_integer(params, id, &value) != WT_OK) return fallback;
  return value;
}
void adopt_peer_connection_id(wt_quic_connection_t *connection, const uint8_t *id, size_t length) {
  if (connection == NULL || id == NULL) return;
  if (length > (size_t)WT_QUIC_MAX_CONNECTION_ID_LENGTH) return;
  if (length == connection->peer_connection_id_length &&
      (length == 0U || memcmp(connection->peer_connection_id, id, length) == 0)) {
    return;
  }
  if (length > 0U) memcpy(connection->peer_connection_id, id, length);
  connection->peer_connection_id_length = length;
  connection->config.peer_connection_id = connection->peer_connection_id;
  connection->config.peer_connection_id_length = length;
}
wt_status_t wt_quic_connection_set_peer_parameters(wt_quic_connection_t *connection,
                                                   const uint8_t *data, size_t length) {
  wt_quic_transport_parameters_t params;
  wt_quic_error_t error = WT_QUIC_NO_ERROR;
  uint64_t offender = 0U;
  wt_quic_peer_limits_t limits;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  wt_quic_transport_parameters_init(&params);
  status = wt_quic_transport_parameters_decode(data, length, &params, &error);
  if (status != WT_OK) return status;
  /* RFC 9000 section 18.2's own rules -- a max_udp_payload_size below 1200, an ack delay exponent
   * above 20, a stream limit above 2^60 -- are an error rather than something to clamp. `peer_is_client`
   * is this endpoint's own role inverted: the parameters being checked are the peer's, and the
   * stateless_reset_token rule depends on which end sent them. */
  status = wt_quic_transport_parameters_check(
      &params, connection->config.role == WT_QUIC_ROLE_SERVER ? 1 : 0, &error, &offender);
  if (status != WT_OK) return status;

  memset(&limits, 0, sizeof(limits));
  limits.max_idle_timeout =
      microseconds_of_milliseconds(parameter_or(&params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 0U));
  limits.max_udp_payload_size = parameter_or(&params, WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
                                            WT_QUIC_DEFAULT_MAX_UDP_PAYLOAD_SIZE);
  limits.initial_max_data = parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_DATA, 0U);
  limits.initial_max_stream_data_bidi_local =
      parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0U);
  limits.initial_max_stream_data_bidi_remote =
      parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0U);
  limits.initial_max_stream_data_uni =
      parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 0U);
  limits.initial_max_streams_bidi = parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 0U);
  limits.initial_max_streams_uni = parameter_or(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 0U);
  /* RFC 9000 section 18.2's default is 2, not zero: a peer that says nothing still allows the two
   * connection IDs the handshake itself needs. */
  limits.active_connection_id_limit =
      parameter_or(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2U);
  limits.max_datagram_frame_size = parameter_or(&params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 0U);
  /* Presence is the whole parameter: an empty value advertises the extension. `check` has already refused a
   * non-empty one, so this is a flag rather than a length. */
  {
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    limits.reset_stream_at =
        wt_quic_transport_parameters_get(&params, WT_QUIC_TP_RESET_STREAM_AT, &value, &value_length) == WT_OK
            ? 1
            : 0;
  }
  limits.set = 1;
  connection->peer_limits = limits;
  connection->flow.peer_max_data = limits.initial_max_data;

/* RFC 9000 section 7.2: after the ServerHello, a client addresses every packet to the SOURCE CONNECTION ID the
   * server chose, and a server addresses a client the same way.
   *
   * NOTHING DID THAT HERE, and it cost this tree a third-party interop: the destination connection ID was written
   * once from the configuration, so a peer that chose its own ID dropped every packet this endpoint sent after the
   * handshake as belonging to another connection -- before consulting any key. The peer said "Decryption key is not
   * available", retransmitted its handshake CRYPTO forever and never left SERVER_EXPECT_FINISHED, while everything
   * about those packets was correct: typed, numbered, protected, and carrying a Finished that opens with the
   * peer's OWN key. It was invisible to the C99 pair because this tree's server does not enforce CID routing, so
   * both ends accepted the configured ID (WT-135).
   *
   * A Retry's retry_source_connection_id is the same idea one message later. */
  {
    const uint8_t *peer_source = NULL;
    size_t peer_source_length = 0U;
    if (wt_quic_transport_parameters_get(&params, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &peer_source,
                                         &peer_source_length) == WT_OK) {
      /* RFC 9000 section 7.3: "Endpoints MUST validate that received transport parameters match received
       * connection ID values", and a mismatch is a connection error of type TRANSPORT_PARAMETER_ERROR or
       * PROTOCOL_VIOLATION. The reference value is the Source Connection ID of the Initial packets the peer
       * sent, which the receive path recorded; the parameter is compared with it BEFORE it is adopted,
       * because adopting it is what aims everything this endpoint sends at the ID it names. A connection that
       * was never handed a real packet has nothing to compare -- the same rule the original_destination
       * check below uses -- so a synthetic object or a caller that supplies parameters out of band is not
       * made to satisfy a requirement it has no data for. */
      if (connection->peer_source_connection_id_set != 0 &&
          (peer_source_length != connection->peer_source_connection_id_length ||
           (peer_source_length != 0U &&
            memcmp(peer_source, connection->peer_source_connection_id, peer_source_length) != 0))) {
        return WT_ERR_PROTOCOL;
      }
      if (peer_source != NULL && peer_source_length > 0U &&
          peer_source_length <= (size_t)WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
        adopt_peer_connection_id(connection, peer_source, peer_source_length);
      }
    }
  }

  /* RFC 9000 section 7.3's client half, which is the other side of the Retry exchange. The server names the
   * destination connection ID this client's first Initial carried and, if it retried, the Source Connection ID that
   * Retry sent; both must match, and the section is explicit that ABSENCE counts -- a missing
   * original_destination_connection_id is an error, and a retry_source_connection_id present when no Retry was
   * received is one too. Without this a client would accept a connection whose connection IDs an attacker who
   * injected packets could have influenced, which is the attack the parameters exist to close. */
  if (connection->config.role == WT_QUIC_ROLE_CLIENT) {
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    int present = wt_quic_transport_parameters_get(&params,
                                                   WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &value,
                                                   &value_length) == WT_OK;

    /* The check needs something to check AGAINST: an endpoint only has an original destination connection ID
     * when it chose one, and the runtime session records it for every client it starts. A bare connection object
     * that was never told (which only a caller bypassing the runtime can build) has nothing to compare, and
     * inventing a requirement it cannot satisfy would make conformant parameters impossible. */
    if (connection->original_destination_id_length != 0U &&
        (present == 0 || value_length != connection->original_destination_id_length ||
         memcmp(value, connection->original_destination_id, value_length) != 0)) {
      return WT_ERR_PROTOCOL;
    }
    value = NULL;
    value_length = 0U;
    present = wt_quic_transport_parameters_get(&params, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID, &value,
                                               &value_length) == WT_OK;
    if (connection->retry_accepted != 0) {
      if (present == 0 || value_length != connection->retry_source_connection_id_length ||
          (value_length != 0U &&
           memcmp(value, connection->retry_source_connection_id, value_length) != 0)) {
        return WT_ERR_PROTOCOL;
      }
    } else if (present != 0) {
      return WT_ERR_PROTOCOL;
    }
  }
  return WT_OK;
}
const wt_quic_peer_limits_t *wt_quic_connection_peer_limits(const wt_quic_connection_t *connection) {
  return connection == NULL ? NULL : &connection->peer_limits;
}
wt_status_t wt_quic_connection_discard_keys(wt_quic_connection_t *connection, wt_quic_space_t space) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  /* Zeroed rather than marked unused: the key material must not be left in memory a caller can read,
   * and `has_keys` is what makes the layer treat the space as gone. A packet for a discarded space is
   * then discarded by the receive path, which is what RFC 9001 section 4.9.3 asks for. Idempotent, so
   * the two places that discard the Initial keys -- a Handshake packet in either direction -- cannot
   * disagree. */
  wt_quic_packet_keys_clear(&connection->keys_in[space]);
  wt_quic_packet_keys_clear(&connection->keys_out[space]);
  connection->has_keys_in[space] = 0;
  connection->has_keys_out[space] = 0;
  return WT_OK;
}
wt_status_t close_with(wt_quic_connection_t *connection, uint64_t error_code,
                              uint64_t frame_type, uint64_t now) {
  return wt_quic_connection_close(connection, error_code, frame_type, NULL, 0U, now);
}
void wt_quic_connection_refuse_application(wt_quic_connection_t *connection, uint64_t error_code,
                                           uint64_t frame_type) {
  if (connection == NULL) return;
  connection->close_code = error_code;
  connection->close_frame_type = frame_type;
  connection->close_code_set = 1;
  connection->close_code_application = 1;
}
wt_status_t wt_quic_connection_init(wt_quic_connection_t *connection,
                                    const wt_quic_connection_config_t *config) {
  size_t i;

  if (connection == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (config->local_connection_id_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH ||
      config->peer_connection_id_length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->max_datagram_size < WT_QUIC_MAX_PACKET) return WT_ERR_INVALID_ARGUMENT;

  memset(connection, 0, sizeof(*connection));
  connection->config = *config;
  /* The IDs are copied, and the configuration kept in the connection is then pointed at the copies:
   * a caller may let its own buffers go, and every later read of `config` -- the send path reads the
   * peer's ID from it -- describes this connection rather than the caller's memory. */
  memcpy(connection->local_connection_id, config->local_connection_id,
         config->local_connection_id_length);
  memcpy(connection->peer_connection_id, config->peer_connection_id,
         config->peer_connection_id_length);
  connection->local_connection_id_length = config->local_connection_id_length;
  connection->peer_connection_id_length = config->peer_connection_id_length;
  connection->config.local_connection_id = connection->local_connection_id;
  connection->config.peer_connection_id = connection->peer_connection_id;

  connection->socket.fd = WT_UDP_INVALID_FD;
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_pn_space_init(&connection->spaces[i]);
  }
  wt_quic_loss_init(&connection->loss);
  wt_quic_datagram_queue_init(&connection->datagrams);
  wt_quic_stream_table_init(&connection->streams);
  /* Both limits are zero until a caller that knows what it can buffer grants them: an endpoint that
   * advertises nothing cannot receive (RFC 9000 section 4.1), which is the honest default. */
  wt_quic_flow_init(&connection->flow, 0U, 0U);
  wt_quic_congestion_init(&connection->congestion, (uint64_t)config->max_datagram_size);
  wt_quic_close_state_init(&connection->close);
  /* Sequence 0 belongs to the connection ID the handshake used (RFC 9000 section 5.1.1), so the first ID
   * this endpoint announces to the peer is sequence 1. */
  connection->next_issued_sequence = 1U;
  /* RFC 9001 section 6.6: the usage limits belong to the suite, and the connection is the only place that
   * knows which one it was configured with. */
  aead_limits_for(connection->config.aead, &connection->aead_confidentiality_limit,
                  &connection->aead_integrity_limit);
  return WT_OK;
}
wt_status_t wt_quic_connection_attach(wt_quic_connection_t *connection,
                                      const wt_udp_socket_t *socket,
                                      const wt_udp_address_t *peer) {
  if (connection == NULL || socket == NULL) return WT_ERR_INVALID_ARGUMENT;
  connection->socket = *socket;
  if (peer != NULL) {
    connection->peer = *peer;
    connection->has_peer = 1;
  }
  return WT_OK;
}
wt_status_t wt_quic_connection_set_keys(wt_quic_connection_t *connection, wt_quic_space_t space,
                                        int inbound, const wt_quic_packet_keys_t *keys) {
  if (connection == NULL || keys == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (inbound) {
    connection->keys_in[space] = *keys;
    connection->has_keys_in[space] = 1;
  } else {
    connection->keys_out[space] = *keys;
    connection->has_keys_out[space] = 1;
  }
  return WT_OK;
}
void wt_quic_connection_set_handlers(wt_quic_connection_t *connection,
                                     wt_quic_frame_handler_fn handler, void *handler_context,
                                     wt_quic_frame_lost_fn lost_handler, void *lost_context) {
  if (connection == NULL) return;
  connection->handler = handler;
  connection->handler_context = handler_context;
  connection->lost_handler = lost_handler;
  connection->lost_context = lost_context;
}
wt_status_t wt_quic_connection_send_crypto(wt_quic_connection_t *connection, wt_quic_space_t space,
                                           uint64_t offset, const uint8_t *data, size_t length,
                                           uint64_t now) {
  wt_quic_frame_t frame;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (space >= WT_QUIC_SPACE_COUNT) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U) return WT_ERR_INVALID_ARGUMENT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CRYPTO);
  frame.as.crypto.offset = offset;
  frame.as.crypto.data = data;
  frame.as.crypto.length = length;

  status = send_one_frame(connection, space, &frame, 1, 1, 1, 0U, offset, length, &sent, now);
  if (status != WT_OK) return status;
  return sent ? WT_OK : WT_ERR_STATE;
}
wt_status_t wt_quic_connection_close(wt_quic_connection_t *connection, uint64_t error_code,
                                     uint64_t frame_type, const uint8_t *reason, size_t reason_length,
                                     uint64_t now) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (reason == NULL && reason_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_connection_is_closed(connection)) return WT_OK;

  return wt_quic_close_transport(&connection->close, error_code, frame_type, reason, reason_length,
                                 now, pto_of(connection));
}
int wt_quic_connection_is_closed(const wt_quic_connection_t *connection) {
  if (connection == NULL) return 0;
  return connection->peer_closed != 0 || wt_quic_close_is_closed(&connection->close) != 0;
}
const wt_quic_close_state_t *wt_quic_connection_close_state(const wt_quic_connection_t *connection) {
  if (connection == NULL) return NULL;
  return &connection->close;
}
wt_status_t wt_quic_connection_close_cause(const wt_quic_connection_t *connection) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  return connection->close_cause;
}
wt_status_t wt_quic_connection_set_original_destination_id(wt_quic_connection_t *connection,
                                                           const uint8_t *id, size_t length) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (id == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) return WT_ERR_INVALID_ARGUMENT;
  if (length > 0U) memcpy(connection->original_destination_id, id, length);
  connection->original_destination_id_length = length;
  return WT_OK;
}
int wt_quic_connection_close_was_sent(const wt_quic_connection_t *connection) {
  if (connection == NULL) return 0;
  return connection->close_frame_sent;
}
int wt_quic_connection_is_drained(const wt_quic_connection_t *connection, uint64_t now) {
  if (connection == NULL) return 0;
  if (!wt_quic_connection_is_closed(connection)) return 0;
  return wt_quic_close_draining_expired(&connection->close, now);
}
void wt_quic_connection_clear(wt_quic_connection_t *connection) {
  size_t i;
  if (connection == NULL) return;
  for (i = 0U; i < WT_QUIC_SPACE_COUNT; i++) {
    wt_quic_packet_keys_clear(&connection->keys_in[i]);
    wt_quic_packet_keys_clear(&connection->keys_out[i]);
  }
  /* The key-update sets are live 1-RTT KEY MATERIAL after an update, and clearing only `keys_in`/`keys_out` left
   * them in a struct a caller may reuse or hand on: an audit read all three back after `clear`. Every set this
   * struct holds is cleared here, which is what "clear" has to mean. */
  wt_quic_packet_keys_clear(&connection->previous_keys_in);
  wt_quic_packet_keys_clear(&connection->next_keys_in);
  wt_quic_packet_keys_clear(&connection->next_keys_out);
  connection->has_peer = 0;
  connection->socket.fd = WT_UDP_INVALID_FD;
}
int wt_quic_connection_retry_pending_keys(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->retry_pending_keys : 0;
}
void wt_quic_connection_retry_keys_installed(wt_quic_connection_t *connection) {
  if (connection == NULL) return;
  connection->retry_pending_keys = 0;
}
int wt_quic_connection_key_phase(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->key_phase : 0;
}
uint64_t wt_quic_connection_key_updates_initiated(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->key_updates_initiated : 0U;
}
uint64_t wt_quic_connection_key_updates_responded(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->key_updates_responded : 0U;
}
uint64_t wt_quic_connection_key_update_errors(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->key_update_errors : 0U;
}
uint64_t wt_quic_connection_aead_encrypted(const wt_quic_connection_t *connection, wt_quic_space_t space) {
  if (connection == NULL || space >= WT_QUIC_SPACE_COUNT) return 0U;
  return connection->aead_encrypted[space];
}
uint64_t wt_quic_connection_aead_failed(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->aead_failed : 0U;
}
uint64_t wt_quic_connection_aead_confidentiality_limit(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->aead_confidentiality_limit : 0U;
}
uint64_t wt_quic_connection_aead_integrity_limit(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->aead_integrity_limit : 0U;
}
