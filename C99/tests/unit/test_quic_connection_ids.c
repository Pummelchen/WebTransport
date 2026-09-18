/* The ids tests for the connection runtime. */

#include "test_quic_connection_internal.h"

/* RFC 9000 sections 5.1.1 and 19.15: an endpoint issues connection IDs bounded by what the peer said it
 * will store, and the peer's limit counts the ID the handshake used. */
void test_issue_connection_id(void) {
  connection_pair_t pair;
  uint8_t payload[64];
  wt_quic_transport_parameters_t params;
  /* Eight bytes, like the connection ID the handshake used: an issued ID of another length could not be
   * received, because a short header carries no length, so the connection refuses one. */
  static const uint8_t first_id[8] = {0x11U, 0x22U, 0x33U, 0x44U, 0x11U, 0x22U, 0x33U, 0x44U};
  static const uint8_t second_id[8] = {0x55U, 0x66U, 0x77U, 0x88U, 0x55U, 0x66U, 0x77U, 0x88U};
  uint8_t token[16];
  uint64_t now = 103000000U;

  memset(token, 0x5a, sizeof(token));
  open_pair(WT_UDP_IPV4, &pair);
  {
    wt_quic_packet_keys_t keys;
    uint8_t secret[WT_SHA256_LEN];
    size_t i;
    for (i = 0U; i < sizeof(secret); i++)
      secret[i] = (uint8_t)(0xe0U + i);
    WT_EXPECT_OK("application keys",
                 wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
    WT_EXPECT_OK("client writes",
                 wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  }
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK(
      "a limit of two connection IDs",
      wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2U));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and is parsed", wt_quic_connection_set_peer_parameters(&pair.client, payload,
                                                                         wt_writer_offset(&pw)));
  }

  WT_EXPECT_STATUS("an empty connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_issue_connection_id(&pair.client, first_id, 0U, token, now));
  /* A short header carries no connection ID length, so an ID of another length could never be received:
   * this endpoint parses every packet with the one length it uses. */
  WT_EXPECT_STATUS("and so is one of a length this endpoint does not use", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_issue_connection_id(&pair.client, first_id, 4U, token, now));
  WT_EXPECT_STATUS(
      "and a null token is", WT_ERR_INVALID_ARGUMENT,
      wt_quic_connection_issue_connection_id(&pair.client, first_id, sizeof(first_id), NULL, now));
  WT_EXPECT_OK("one is issued", wt_quic_connection_issue_connection_id(
                                    &pair.client, first_id, sizeof(first_id), token, now));
  {
    /* RFC 9000 section 5.1.1: sequence 0 is the connection ID the handshake used, so the first ID this
     * endpoint announces is sequence 1. Numbering the spares from zero would collide with it. */
    const wt_quic_issued_connection_id_t *issued = wt_quic_connection_issued_id(&pair.client, 1U);
    WT_EXPECT_TRUE("and remembered by sequence", issued != NULL);
    if (issued != NULL) {
      WT_EXPECT_U64("with its length", (uint64_t)sizeof(first_id), (uint64_t)issued->length);
      WT_EXPECT_BYTES("and its bytes", first_id, issued->id, sizeof(first_id));
    }
    WT_EXPECT_U64("while the next sequence to hand out is the one after it", 2U,
                  pair.client.next_issued_sequence);
  }
  WT_EXPECT_TRUE("and the handshake's own sequence is not in the table",
                 wt_quic_connection_issued_id(&pair.client, 0U) == NULL);
  WT_EXPECT_STATUS(
      "the same ID again is a caller error", WT_ERR_STATE,
      wt_quic_connection_issue_connection_id(&pair.client, first_id, sizeof(first_id), token, now));
  /* The limit counts the handshake's ID, so a grant of two leaves room for ONE spare. */
  WT_EXPECT_STATUS("a second is beyond what the peer will store", WT_ERR_LIMIT,
                   wt_quic_connection_issue_connection_id(&pair.client, second_id,
                                                          sizeof(second_id), token, now));
  WT_EXPECT_TRUE("and a sequence that was never issued is not found",
                 wt_quic_connection_issued_id(&pair.client, 7U) == NULL);
  close_pair(&pair);
}

void test_peer_connection_ids(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  static const uint8_t id_a[6] = {1U, 2U, 3U, 4U, 5U, 6U};
  uint8_t token_a[16];
  uint8_t token_b[16];
  uint64_t now = 104000000U;
  size_t i;

  memset(token_a, 0x11, sizeof(token_a));
  memset(token_b, 0x22, sizeof(token_b));
  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x30U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client writes",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
  frame.as.new_connection_id.sequence = 1U;
  frame.as.new_connection_id.retire_prior_to = 0U;
  frame.as.new_connection_id.connection_id = id_a;
  frame.as.new_connection_id.connection_id_length = sizeof(id_a);
  frame.as.new_connection_id.stateless_reset_token = token_a;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server is not closed by it", 0, wt_quic_connection_is_closed(&pair.server));
  {
    size_t found = 0U;
    for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
      if (pair.server.peer_ids[i].in_use && pair.server.peer_ids[i].sequence == 1U) {
        found = 1U;
        WT_EXPECT_U64("and it is stored with its length", (uint64_t)sizeof(id_a),
                      (uint64_t)pair.server.peer_ids[i].length);
        WT_EXPECT_BYTES("and its bytes", id_a, pair.server.peer_ids[i].id, sizeof(id_a));
      }
    }
    WT_EXPECT_U64("which the table holds", 1U, (uint64_t)found);
  }

  /* The same sequence with a different token is the PROTOCOL_VIOLATION the section names. */
  frame.as.new_connection_id.stateless_reset_token = token_b;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a changed token for a known sequence closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  close_pair(&pair);

  /* The `retire_prior_to` rule is not exercised here: the frame ENCODER refuses to produce a
   * retire_prior_to above the sequence -- this library refuses to encode what it would refuse to decode --
   * so testing the decoder's refusal needs a hand-built packet, which is recorded as a task. */
}

/* RFC 9000 section 19.16: a RETIRE_CONNECTION_ID gives up an ID this endpoint issued. The two sequences
 * the section makes a PROTOCOL_VIOLATION are tested separately: one that was never issued, and the one
 * the carrying packet was addressed to. A repeat of a retirement already made is not an error, because
 * the frame is retransmitted when it is lost. */
void test_retire_connection_id(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  wt_quic_transport_parameters_t params;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  static const uint8_t first_id[8] = {0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U};
  static const uint8_t replacement_id[8] = {0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U};
  uint8_t token[16];
  uint64_t now = 105000000U;
  size_t i;

  memset(token, 0x77, sizeof(token));
  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x40U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  /* The server issues the ID and reads the peer's frames, so both directions of the application keys are
   * needed on the server: one to announce the ID, one to decrypt the packet that retires it. */
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  /* Three IDs allowed, so there is room for the issued ID, the retirement, and its replacement. */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK(
      "a limit of three connection IDs",
      wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 3U));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and are parsed", wt_quic_connection_set_peer_parameters(&pair.server, payload,
                                                                          wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK("the server issues one", wt_quic_connection_issue_connection_id(
                                            &pair.server, first_id, sizeof(first_id), token, now));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 1U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("retiring an issued ID does not close the connection", 0,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("the slot is given up", 0U, (uint64_t)pair.server.issued_count);
  WT_EXPECT_TRUE("and the ID is no longer known",
                 wt_quic_connection_issued_id(&pair.server, 1U) == NULL);

  /* The room the retirement freed is usable again, under a sequence that has never been handed out. */
  WT_EXPECT_OK("a replacement is issued",
               wt_quic_connection_issue_connection_id(&pair.server, replacement_id,
                                                      sizeof(replacement_id), token, now));
  WT_EXPECT_TRUE("under the next sequence", wt_quic_connection_issued_id(&pair.server, 2U) != NULL);
  WT_EXPECT_TRUE("while the retired sequence stays retired",
                 wt_quic_connection_issued_id(&pair.server, 1U) == NULL);

  /* The same retirement again is a retransmission of a frame whose effect is already in place. */
  frame.as.retire_connection_id.sequence = 1U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a repeated retirement is tolerated", 0,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and does not touch the replacement", 1U, (uint64_t)pair.server.issued_count);

  /* `next_issued_sequence` is 3, so sequence 3 has never been sent to the peer. */
  frame.as.retire_connection_id.sequence = 3U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 2U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a sequence that was never issued closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the frame that caused it", (uint64_t)WT_QUIC_FRAME_RETIRE_CONNECTION_ID,
                pair.server.close.frame_type);
  close_pair(&pair);
}

/* RFC 9000 section 19.16: an endpoint cannot retire the connection ID that the packet carrying the frame
 * was addressed to. Here that is the handshake's ID, which section 5.1.1 numbers 0; the same rule with an
 * issued ID as the destination is covered by `test_packets_to_issued_connection_ids`. */
void test_retire_handshake_connection_id(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 106000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x50U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 0U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("retiring the handshake's own connection ID closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the frame that caused it", (uint64_t)WT_QUIC_FRAME_RETIRE_CONNECTION_ID,
                pair.server.close.frame_type);
  close_pair(&pair);
}

/* RFC 9000 section 19.15: a NEW_CONNECTION_ID whose `retire_prior_to` is above its own sequence is a
 * FRAME_ENCODING_ERROR, because it would retire the connection ID the frame itself introduces. The
 * decoder checks it, and this is the test the frame ENCODER cannot produce: this library refuses to
 * encode what it would refuse to decode, so the bytes are written by hand (WT-83). */
void test_new_connection_id_retire_prior_to_is_refused(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  uint8_t payload[32];
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 111000000U;
  size_t len = 0U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x60U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  payload[len++] = 0x18U; /* NEW_CONNECTION_ID */
  payload[len++] = 0x00U; /* sequence */
  payload[len++] = 0x01U; /* retire_prior_to: above the sequence, which is the error */
  payload[len++] = 0x04U; /* connection ID length */
  payload[len++] = 0x01U;
  payload[len++] = 0x02U;
  payload[len++] = 0x03U;
  payload[len++] = 0x04U;
  for (i = 0U; i < 16U; i++)
    payload[len++] = 0xaaU; /* stateless reset token */

  send_raw_payload_to(&pair, payload, len, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server closes the connection", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a frame encoding error", (uint64_t)WT_QUIC_FRAME_ENCODING_ERROR,
                pair.server.close.error_code);
  close_pair(&pair);
}
