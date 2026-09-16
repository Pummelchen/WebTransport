/* Packet keys and the 1-RTT key update (RFC 9001 section 6). */

#include "connection_internal.h"

void aead_limits_for(wt_aead_t aead, uint64_t *out_confidentiality, uint64_t *out_integrity) {
  switch (aead) {
    case WT_AEAD_AES_128_GCM:
      *out_confidentiality = UINT64_C(1) << 23;
      *out_integrity = UINT64_C(1) << 52;
      return;
    case WT_AEAD_CHACHA20_POLY1305:
      *out_confidentiality = UINT64_MAX;
      *out_integrity = UINT64_C(1) << 36;
      return;
  }
  /* No other suite exists in this tree, and a connection cannot be configured with one -- but a value is
   * better than whatever the caller's stack held. */
  *out_confidentiality = UINT64_C(1) << 23;
  *out_integrity = UINT64_C(1) << 52;
}
static wt_status_t derive_next_keys(const wt_quic_packet_keys_t *current, wt_quic_packet_keys_t *out) {
  /* One call: the "header protection key is not updated" rule (RFC 9001 section 6.1) lives INSIDE
   * `wt_quic_packet_keys_update` now, because a caller of that public function has to get it right too. This
   * wrapper used to copy the old hp back over the freshly derived one, which is what made the tree work while the
   * public function was wrong. */
  return wt_quic_packet_keys_update(current, out);
}
wt_status_t ensure_next_keys_in(wt_quic_connection_t *connection) {
  if (connection->next_keys_in_ready != 0) return WT_OK;
  if (connection->has_keys_in[WT_QUIC_SPACE_APPLICATION] == 0) return WT_ERR_STATE;
  {
    wt_status_t status = derive_next_keys(&connection->keys_in[WT_QUIC_SPACE_APPLICATION],
                                          &connection->next_keys_in);
    if (status != WT_OK) return status;
  }
  connection->next_keys_in_ready = 1;
  return WT_OK;
}
static wt_status_t ensure_next_keys_out(wt_quic_connection_t *connection) {
  if (connection->next_keys_out_ready != 0) return WT_OK;
  if (connection->has_keys_out[WT_QUIC_SPACE_APPLICATION] == 0) return WT_ERR_STATE;
  {
    wt_status_t status = derive_next_keys(&connection->keys_out[WT_QUIC_SPACE_APPLICATION],
                                          &connection->next_keys_out);
    if (status != WT_OK) return status;
  }
  connection->next_keys_out_ready = 1;
  return WT_OK;
}
int wt_quic_connection_key_update_allowed(const wt_quic_connection_t *connection) {
  if (connection == NULL) return 0;
  if (connection->handshake_confirmed == 0) return 0;
  if (connection->has_keys_out[WT_QUIC_SPACE_APPLICATION] == 0) return 0;
  if (connection->key_update_awaiting_confirmation != 0) return 0;
  /* A phase whose first packet has NOT been sent has nothing to confirm: section 6.1's condition is about an
   * ACKNOWLEDGED packet of the current phase, and before the first send there is none. */
  if (connection->key_phase_first_pn_set != 0) return 1;
  return (connection->key_updates_initiated == 0U && connection->key_updates_responded == 0U) ? 1 : 0;
}
wt_status_t wt_quic_connection_initiate_key_update(wt_quic_connection_t *connection, uint64_t now) {
  wt_quic_packet_keys_t updated;
  wt_status_t status;

  (void)now;
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9001 section 6.1: "An endpoint MUST NOT initiate a key update prior to having confirmed the
   * handshake." The caller is told rather than the peer: nothing about the connection is wrong. */
  if (connection->handshake_confirmed == 0) return WT_ERR_STATE;
  if (connection->has_keys_out[WT_QUIC_SPACE_APPLICATION] == 0) return WT_ERR_STATE;
  /* And the other MUST NOT: "unless it has received an acknowledgment for a packet that was sent protected
   * with keys from the current key phase." A second update before that is this endpoint's own mistake, so it
   * is a state error and not a connection close. */
  if (connection->key_update_awaiting_confirmation != 0) return WT_ERR_STATE;

  /* The new SEND keys, and the phase being left behind becomes the retained RECEIVE keys: section 6.1 makes the
   * initiator update both directions, because the peer answers in the new phase. */
  status = derive_next_keys(&connection->keys_out[WT_QUIC_SPACE_APPLICATION], &updated);
  if (status != WT_OK) return status;
  connection->keys_out[WT_QUIC_SPACE_APPLICATION] = updated;

  connection->previous_keys_in = connection->keys_in[WT_QUIC_SPACE_APPLICATION];
  connection->previous_keys_in_ready = 1;
  status = derive_next_keys(&connection->previous_keys_in, &updated);
  if (status != WT_OK) return status;
  connection->keys_in[WT_QUIC_SPACE_APPLICATION] = updated;

  connection->key_phase ^= 1;
  connection->key_phase_in ^= 1;
  /* The keys for the phase AFTER this one are derived from the new ones, so the next update -- either
   * direction's -- has them ready. */
  connection->next_keys_out_ready = 0;
  connection->next_keys_in_ready = 0;
  (void)ensure_next_keys_out(connection);
  (void)ensure_next_keys_in(connection);

  connection->key_phase_first_pn = 0U;
  connection->key_phase_first_pn_set = 0;
  connection->key_phase_in_first_pn_set = 0;
  connection->key_update_awaiting_confirmation = 1;
  connection->key_updates_initiated++;
  /* A new key set: section 6.6 counts packets per key, so the Application space's count starts again. */
  connection->aead_encrypted[WT_QUIC_SPACE_APPLICATION] = 0U;
  return WT_OK;
}
wt_status_t key_update_respond(wt_quic_connection_t *connection, uint64_t now) {
  wt_quic_packet_keys_t updated;
  wt_status_t status;

  /* "If an endpoint detects a second update before it has sent any packets with updated keys containing an
   * acknowledgment for the packet that initiated the key update, it indicates that its peer has updated keys
   * twice without awaiting confirmation." A MAY, and this endpoint takes it: the alternative is a peer whose
   * keys move under every packet. */
  if (connection->key_update_response_pending != 0 && connection->key_phase_first_pn_set == 0) {
    connection->key_update_errors++;
    return close_with(connection, WT_QUIC_KEY_UPDATE_ERROR, 0U, now);
  }

  /* The phase that was current becomes the retained one, the derived next phase becomes current, and the send
   * keys move with them -- section 6.2's "Sending keys MUST be updated before sending an acknowledgment for the
   * packet that was received with updated keys". */
  connection->previous_keys_in = connection->keys_in[WT_QUIC_SPACE_APPLICATION];
  connection->previous_keys_in_ready = 1;
  connection->keys_in[WT_QUIC_SPACE_APPLICATION] = connection->next_keys_in;
  connection->next_keys_in_ready = 0;

  status = derive_next_keys(&connection->keys_out[WT_QUIC_SPACE_APPLICATION], &updated);
  if (status != WT_OK) return status;
  connection->keys_out[WT_QUIC_SPACE_APPLICATION] = updated;

  connection->key_phase ^= 1;
  connection->key_phase_in ^= 1;
  connection->key_phase_first_pn_set = 0;
  connection->key_phase_in_first_pn_set = 0;
  connection->key_update_response_pending = 1;
  connection->key_update_awaiting_confirmation = 1;
  connection->next_keys_out_ready = 0;
  connection->key_updates_responded++;
  /* The send keys moved, so the count of packets protected with them starts again (section 6.6). */
  connection->aead_encrypted[WT_QUIC_SPACE_APPLICATION] = 0U;
  return WT_OK;
}
