/* Retry and version handling, and the connection IDs either endpoint manages. */

#include "connection_internal.h"

static wt_status_t send_retire_connection_id(wt_quic_connection_t *connection, uint64_t sequence,
                                             uint64_t now) {
  wt_quic_frame_t frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);

  frame.as.retire_connection_id.sequence = sequence;
  return wt_quic_connection_send_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, now);
}
static wt_status_t forget_peer_connection_id(wt_quic_connection_t *connection, uint64_t sequence,
                                             uint64_t now, int *out_forgotten) {
  size_t i;
  wt_status_t status;

  if (out_forgotten != NULL) *out_forgotten = 0;
  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (!connection->peer_ids[i].in_use || connection->peer_ids[i].sequence != sequence) continue;
    status = send_retire_connection_id(connection, sequence, now);
    if (status != WT_OK) return status;
    connection->peer_ids[i].in_use = 0;
    connection->peer_id_count--;
    connection->peer_ids_retired++;
    if (connection->current_peer_sequence_set != 0 &&
        connection->current_peer_sequence == sequence) {
      /* The ID being abandoned was the one in use: this endpoint is now addressing the peer by an ID it has
       * retired, which section 5.1.2 forbids, so the caller has to adopt another (or the handshake's) before
       * anything else goes out. */
      connection->current_peer_sequence_set = 0;
    }
    if (out_forgotten != NULL) *out_forgotten = 1;
    return WT_OK;
  }
  return WT_OK;
}
static void adopt_stored_peer_id(wt_quic_connection_t *connection, size_t slot) {
  adopt_peer_connection_id(connection, connection->peer_ids[slot].id, connection->peer_ids[slot].length);
  connection->current_peer_sequence = connection->peer_ids[slot].sequence;
  connection->current_peer_sequence_set = 1;
}
static size_t first_other_peer_id(const wt_quic_connection_t *connection) {
  size_t i;
  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (!connection->peer_ids[i].in_use) continue;
    if (connection->current_peer_sequence_set != 0 &&
        connection->peer_ids[i].sequence == connection->current_peer_sequence) {
      continue;
    }
    return i;
  }
  return WT_QUIC_PEER_CONNECTION_IDS_MAX;
}
wt_status_t wt_quic_connection_use_new_connection_id(wt_quic_connection_t *connection, uint64_t now) {
  size_t slot;
  uint64_t abandoned;
  int had_current;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  slot = first_other_peer_id(connection);
  if (slot == WT_QUIC_PEER_CONNECTION_IDS_MAX) return WT_ERR_STATE;

  /* Adopt FIRST, then retire. RFC 9000 section 19.16: "The sequence number specified in a RETIRE_CONNECTION_ID
   * frame MUST NOT refer to the Destination Connection ID field of the packet in which the frame is contained" --
   * so the retirement has to ride an ID that is not the one being retired, and the replacement is right here. A
   * first version retired first and addressed the frame to the ID it was abandoning, which the peer rightly
   * refused as a PROTOCOL_VIOLATION. */
  abandoned = connection->current_peer_sequence;
  had_current = connection->current_peer_sequence_set;
  adopt_stored_peer_id(connection, slot);
  if (had_current != 0) {
    int forgotten = 0;
    return forget_peer_connection_id(connection, abandoned, now, &forgotten);
  }
  return WT_OK;
}
wt_status_t wt_quic_connection_retire_peer_connection_id(wt_quic_connection_t *connection,
                                                         uint64_t sequence, uint64_t now) {
  int forgotten = 0;
  wt_status_t status;

  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (wt_quic_connection_is_closed(connection) != 0) return WT_ERR_STATE;
  /* RFC 9000 section 19.16 forbids a RETIRE_CONNECTION_ID from naming the Destination Connection ID of the
   * packet that carries it, and the packet this frame rides is addressed by the ID in use -- so the ID in use is
   * given up by ADOPTING another (`wt_quic_connection_use_new_connection_id`), which retires it on the way. */
  if (connection->current_peer_sequence_set != 0 && connection->current_peer_sequence == sequence) {
    return WT_ERR_STATE;
  }
  status = forget_peer_connection_id(connection, sequence, now, &forgotten);
  if (status != WT_OK) return status;
  /* Nothing was stored under that sequence, so there is nothing to retire and nothing to tell the peer. */
  return forgotten != 0 ? WT_OK : WT_ERR_STATE;
}
uint64_t wt_quic_connection_retires_received(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->retires_received : 0U;
}
uint64_t wt_quic_connection_peer_ids_retired(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->peer_ids_retired : 0U;
}
size_t wt_quic_connection_peer_id_count(const wt_quic_connection_t *connection) {
  return connection != NULL ? connection->peer_id_count : 0U;
}
wt_status_t handle_new_connection_id(wt_quic_connection_t *connection,
                                            const wt_quic_frame_t *frame, uint64_t now) {
  const uint8_t *id = frame->as.new_connection_id.connection_id;
  size_t length = frame->as.new_connection_id.connection_id_length;
  uint64_t sequence = frame->as.new_connection_id.sequence;
  size_t slot = WT_QUIC_PEER_CONNECTION_IDS_MAX;
  size_t i;
  uint64_t allowed;

  /* A length outside 1..20 is a FRAME_ENCODING_ERROR, and a retire_prior_to above the sequence it
   * arrives with is one too (section 19.15). */
  if (length == 0U || length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) {
    return close_with(connection, WT_QUIC_FRAME_ENCODING_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }
  if (frame->as.new_connection_id.retire_prior_to > sequence) {
    return close_with(connection, WT_QUIC_FRAME_ENCODING_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }

  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    const wt_quic_peer_connection_id_t *known = &connection->peer_ids[i];
    if (!known->in_use) {
      if (slot == WT_QUIC_PEER_CONNECTION_IDS_MAX) slot = i;
      continue;
    }
    if (known->sequence == sequence) {
      /* The same sequence twice: the section makes a DIFFERENT connection ID or token for it a
       * PROTOCOL_VIOLATION, and the same one again merely a duplicate. */
      if (known->length != length || memcmp(known->id, id, length) != 0 ||
          memcmp(known->reset_token, frame->as.new_connection_id.stateless_reset_token, 16U) != 0) {
        return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION,
                          WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
      }
      return WT_OK;
    }
  }

  /* A retire_prior_to retires everything below it. WHICH ORDER the two halves of that take depends on whether
   * the ID this endpoint is USING is one of them:
   *
   *   - if it is not, the RETIRE frames go out first and the new ID is stored after, which is section 5.1.2's
   *     own ordering ("retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection
   *     ID to the set of active connection IDs");
   *   - if it IS, the replacement has to be adopted first, because section 19.16 forbids a RETIRE_CONNECTION_ID
   *     from naming the destination of the packet that carries it -- the retires then ride the ID this frame
   *     provides, which is exactly why the peer put a new one in it.
   *
   * Either way an endpoint that cannot SEND a retire does not forget the ID (section 5.1.2's MUST NOT). */
  {
    int dropped_current = 0;
    for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
      if (!connection->peer_ids[i].in_use) continue;
      if (connection->peer_ids[i].sequence >= frame->as.new_connection_id.retire_prior_to) continue;
      if (connection->current_peer_sequence_set != 0 &&
          connection->peer_ids[i].sequence == connection->current_peer_sequence) {
        dropped_current = 1;
      }
    }
    connection->retire_current_after_store = dropped_current;
  }
  if (slot == WT_QUIC_PEER_CONNECTION_IDS_MAX) {
    /* Every slot is taken by an ID that is still active, which is more than this endpoint said it would
     * store: section 5.1.1 makes that a CONNECTION_ID_LIMIT_ERROR. */
    return close_with(connection, WT_QUIC_CONNECTION_ID_LIMIT_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }
  allowed = connection->config.local_active_connection_id_limit;
  /* Zero means a caller that did not say, and the RFC's own default is two -- counting the handshake's
   * ID, which leaves room for one spare. A limit of zero would otherwise refuse every NEW_CONNECTION_ID,
   * which is a policy no caller asked for. */
  if (allowed == 0U) allowed = 2U;
  allowed -= 1U;
  if ((uint64_t)connection->peer_id_count >= allowed) {
    return close_with(connection, WT_QUIC_CONNECTION_ID_LIMIT_ERROR,
                      WT_QUIC_FRAME_NEW_CONNECTION_ID, now);
  }

  connection->peer_ids[slot].in_use = 1;
  connection->peer_ids[slot].sequence = sequence;
  memcpy(connection->peer_ids[slot].id, id, length);
  connection->peer_ids[slot].length = length;
  memcpy(connection->peer_ids[slot].reset_token,
         frame->as.new_connection_id.stateless_reset_token, 16U);
  connection->peer_id_count++;
  if (connection->retire_current_after_store != 0) {
    connection->retire_current_after_store = 0;
    adopt_stored_peer_id(connection, slot);
  }
  /* And now the retires, in whichever order the branch above left them: addressed to an ID that is not being
   * retired, because the one in use has just been replaced if it was covered. */
  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    int forgotten = 0;
    wt_status_t status;
    if (!connection->peer_ids[i].in_use) continue;
    if (connection->peer_ids[i].sequence >= frame->as.new_connection_id.retire_prior_to) continue;
    status = forget_peer_connection_id(connection, connection->peer_ids[i].sequence, now, &forgotten);
    if (status != WT_OK) return status;
    i = (size_t)-1; /* the table compacted under this index; start again */
  }
  return WT_OK;
}
wt_status_t handle_retire_connection_id(wt_quic_connection_t *connection,
                                               const wt_quic_frame_t *frame,
                                               wt_quic_visit_t *visit) {
  uint64_t sequence = frame->as.retire_connection_id.sequence;
  size_t i;

  connection->retires_received++;
  if (sequence == visit->destination_sequence || sequence >= connection->next_issued_sequence) {
    return close_with(connection, WT_QUIC_PROTOCOL_VIOLATION, WT_QUIC_FRAME_RETIRE_CONNECTION_ID,
                      visit->now);
  }
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use && connection->issued_ids[i].sequence == sequence) {
      connection->issued_ids[i].in_use = 0;
      /* `issued_count` was incremented only for an entry that is in use, so it cannot underflow here. */
      connection->issued_count--;
      break;
    }
  }
  return deliver_to_handler(connection, visit, frame);
}
int local_connection_id_sequence(const wt_quic_connection_t *connection, const uint8_t *id,
                                        size_t length, uint64_t *out_sequence) {
  size_t i;

  if (length == connection->local_connection_id_length &&
      (length == 0U || memcmp(id, connection->local_connection_id, length) == 0)) {
    *out_sequence = 0U;
    return 1;
  }
  /* The ID the CLIENT chose, which a server reads from the first Initial and must answer to until the client
   * has the server's own Source Connection ID (RFC 9000 section 7.2). Without this a server accepts only a
   * client that happens to pick the server's ID -- which is what this tree's two tools did, one constant shared
   * by both roles, so no local test could tell the difference (WT-151). Sequence 0 is what it is reported as:
   * it was never issued, so a RETIRE_CONNECTION_ID naming sequence 0 while this ID is in use is exactly the
   * protocol violation section 19.16 describes. */
  if (connection->handshake_confirmed == 0 && connection->original_destination_id_length != 0U &&
      length == connection->original_destination_id_length &&
      memcmp(id, connection->original_destination_id, length) == 0) {
    *out_sequence = 0U;
    return 1;
  }
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use && connection->issued_ids[i].length == length &&
        (length == 0U || memcmp(id, connection->issued_ids[i].id, length) == 0)) {
      *out_sequence = connection->issued_ids[i].sequence;
      return 1;
    }
  }
  return 0;
}
wt_status_t wt_quic_connection_issue_connection_id(wt_quic_connection_t *connection,
                                                   const uint8_t *id, size_t length,
                                                   const uint8_t reset_token[16], uint64_t now) {
  wt_quic_frame_t frame;
  size_t slot = WT_QUIC_CONNECTION_IDS_MAX;
  size_t i;
  uint64_t allowed;
  int sent = 0;
  wt_status_t status;

  if (connection == NULL || id == NULL || reset_token == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (length == 0U || length > WT_QUIC_MAX_CONNECTION_ID_LENGTH) return WT_ERR_INVALID_ARGUMENT;
  /* A short header does not carry the length of its Destination Connection ID (RFC 9000 section 17.2),
   * so this endpoint can only recognise the IDs it issued if they are the length it already uses: the
   * receive path parses with one length for the whole connection. Issuing one of another length would
   * hand the peer an ID whose packets would be discarded as somebody else's, which is worse than
   * refusing it here. */
  if (length != connection->local_connection_id_length) return WT_ERR_INVALID_ARGUMENT;
  if (!connection->peer_limits.set) return WT_ERR_STATE;

  /* A caller that hands the same ID twice has made a mistake whether or not there is room, so the
   * duplicate is reported before the limit: the two are different answers and the first is the one that
   * describes what the caller did. */
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use) {
      if (connection->issued_ids[i].length == length &&
          memcmp(connection->issued_ids[i].id, id, length) == 0) {
        /* The same ID twice is a new sequence number for an ID the peer already has, which is not what a
         * caller means and would waste the peer's storage. */
        return WT_ERR_STATE;
      }
      continue;
    }
    if (slot == WT_QUIC_CONNECTION_IDS_MAX) slot = i;
  }
  if (slot == WT_QUIC_CONNECTION_IDS_MAX) return WT_ERR_LIMIT;

  /* RFC 9000 section 5.1.1: the peer's limit counts the connection ID the handshake used, so this
   * endpoint may have one fewer than the limit outstanding. A peer that granted the minimum (two, the
   * default) therefore allows exactly one spare. */
  allowed = connection->peer_limits.active_connection_id_limit;
  if (allowed > 0U) allowed -= 1U;
  if ((uint64_t)connection->issued_count >= allowed) return WT_ERR_LIMIT;

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
  frame.as.new_connection_id.sequence = connection->next_issued_sequence;
  frame.as.new_connection_id.retire_prior_to = 0U;
  frame.as.new_connection_id.connection_id = id;
  frame.as.new_connection_id.connection_id_length = length;
  frame.as.new_connection_id.stateless_reset_token = reset_token;
  status = send_control_frame(connection, WT_QUIC_SPACE_APPLICATION, &frame, 1, &sent, now);
  if (status != WT_OK) return status;
  if (!sent) return WT_ERR_STATE;

  connection->issued_ids[slot].in_use = 1;
  connection->issued_ids[slot].sequence = frame.as.new_connection_id.sequence;
  memcpy(connection->issued_ids[slot].id, id, length);
  connection->issued_ids[slot].length = length;
  memcpy(connection->issued_ids[slot].reset_token, reset_token, 16U);
  connection->issued_count++;
  /* The sequence is spent whether or not this ID is ever retired: RFC 9000 section 5.1.1 keys every
   * reference to an ID by its sequence, so a number is never reused. */
  connection->next_issued_sequence++;
  return WT_OK;
}
const wt_quic_issued_connection_id_t *wt_quic_connection_issued_id(
    const wt_quic_connection_t *connection, uint64_t sequence) {
  size_t i;
  if (connection == NULL) return NULL;
  for (i = 0U; i < WT_QUIC_CONNECTION_IDS_MAX; i++) {
    if (connection->issued_ids[i].in_use && connection->issued_ids[i].sequence == sequence) {
      return &connection->issued_ids[i];
    }
  }
  return NULL;
}
static void discard_retry(wt_quic_connection_t *connection) {
  connection->retries_discarded++;
  connection->packets_discarded++;
}
wt_status_t on_retry_packet(wt_quic_connection_t *connection, const uint8_t *packet, size_t length,
                                   uint64_t now) {
  wt_quic_retry_packet_t retry;
  wt_quic_error_t error = WT_QUIC_NO_ERROR;

  (void)now;
  /* "A server MUST discard a Retry packet", and a client accepts at most ONE per connection attempt: after it has
   * processed an Initial or a Retry from the server, later Retries are discarded too. */
  if (connection->config.role != WT_QUIC_ROLE_CLIENT || connection->retry_accepted != 0 ||
      connection->server_packet_received != 0) {
    discard_retry(connection);
    return WT_OK;
  }
  if (wt_quic_retry_packet_decode(packet, length, &retry, &error) != WT_OK) {
    discard_retry(connection);
    return WT_OK;
  }
  /* A Retry for another version says nothing about this connection, and section 6.3 makes a packet of the wrong
   * version ordinary. */
  if (retry.version != connection->config.version) {
    discard_retry(connection);
    return WT_OK;
  }
  /* "A client MUST discard a Retry packet with a zero-length Retry Token field." */
  if (retry.token_len == 0U) {
    discard_retry(connection);
    return WT_OK;
  }
  /* "The value MUST NOT be equal to the Destination Connection ID field of the packet sent by the client": that is
   * this endpoint's original destination connection ID, and it is also what the tag is computed over. */
  if (retry.source_connection_id_len == 0U ||
      (retry.source_connection_id_len == connection->original_destination_id_length &&
       connection->original_destination_id_length != 0U &&
       memcmp(retry.source_connection_id, connection->original_destination_id,
              connection->original_destination_id_length) == 0)) {
    discard_retry(connection);
    return WT_OK;
  }
  /* "Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated" (RFC 9001
   * section 5.8): the tag covers this endpoint's ORIGINAL destination connection ID, which only an endpoint that
   * saw the first Initial can compute. */
  if (wt_quic_retry_integrity_verify(connection->original_destination_id,
                                     connection->original_destination_id_length, packet,
                                     length) != WT_OK) {
    discard_retry(connection);
    return WT_OK;
  }
  /* A token beyond this endpoint's bound is discarded rather than truncated: echoing a prefix of a peer's token is
   * echoing a different token, and this bound is a hundred times what an integrity-protected token needs. */
  if (retry.token_len > sizeof(connection->retry_token)) {
    discard_retry(connection);
    return WT_OK;
  }

  /* Accepted. The token goes in every later Initial (section 17.2.5.3) and the Retry's Source Connection ID is the
   * destination of every later packet (section 17.2.5.1). The packet NUMBERS are deliberately untouched: "A client
   * MUST NOT reset the packet number for any packet number space after processing a Retry packet." */
  memcpy(connection->retry_token, retry.token, retry.token_len);
  connection->retry_token_length = retry.token_len;
  memcpy(connection->retry_source_connection_id, retry.source_connection_id,
         retry.source_connection_id_len);
  connection->retry_source_connection_id_length = retry.source_connection_id_len;
  adopt_peer_connection_id(connection, retry.source_connection_id, retry.source_connection_id_len);
  connection->retry_accepted = 1;
  connection->retry_accepted_count++;
  /* The Initial keys are derived from the destination connection ID, so they are now the WRONG keys and only the
   * runtime session can derive the right ones. Until it does, nothing at Initial level may go out. */
  connection->retry_pending_keys = 1;

  /* Everything already sent in the Initial space is unreachable: the server threw those keys away when it sent the
   * Retry, so those packets can never be acknowledged and holding them in flight would hold the congestion window
   * against bytes that will never arrive. The descriptors come back through `on_lost`, which is what makes the
   * handshake re-offer the SAME cryptographic handshake message -- section 17.2.5.3 requires exactly that
   * message, and the retransmit path is the one that re-sends bytes it still holds. */
  (void)wt_quic_loss_discard_space(&connection->loss, (uint8_t)WT_QUIC_SPACE_INITIAL, on_lost, connection);
  return WT_OK;
}
wt_status_t wt_quic_connection_retry(const wt_quic_connection_t *connection, const uint8_t **out_token,
                                     size_t *out_token_length, const uint8_t **out_source_connection_id,
                                     size_t *out_source_connection_id_length) {
  if (connection == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (connection->retry_accepted == 0) return WT_ERR_STATE;
  if (out_token != NULL) *out_token = connection->retry_token;
  if (out_token_length != NULL) *out_token_length = connection->retry_token_length;
  if (out_source_connection_id != NULL) *out_source_connection_id = connection->retry_source_connection_id;
  if (out_source_connection_id_length != NULL) {
    *out_source_connection_id_length = connection->retry_source_connection_id_length;
  }
  return WT_OK;
}
