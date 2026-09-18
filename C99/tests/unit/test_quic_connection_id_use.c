/* The ids tests for the connection runtime. */

#include "test_quic_connection_internal.h"

/* RFC 9000 sections 5.1 and 7.2: an endpoint accepts packets addressed to any connection ID it issued and
 * has not retired -- that is what issuing them is for, and it is how a peer that moves to a new path keeps
 * its packets addressed to this connection -- and discards packets addressed to an ID it has retired.
 *
 * The third phase is RFC 9000 section 19.16's other PROTOCOL_VIOLATION, and it only exists once the first
 * two do: a peer cannot retire the connection ID it addressed the packet to, which is not always the
 * handshake's ID any more. */
void test_packets_to_issued_connection_ids(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_transport_parameters_t params;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  static const uint8_t issued[8] = {0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U, 0x58U};
  static const uint8_t ping_and_padding[4] = {0x01U, 0x00U, 0x00U, 0x00U};
  uint8_t token[16];
  uint64_t now = 112000000U;
  size_t i;

  memset(token, 0x33, sizeof(token));

  /* Phase one: a packet addressed to an issued ID is processed. */
  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x70U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
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
                                            &pair.server, issued, sizeof(issued), token, now));

  send_raw_payload_with_dcid(&pair, ping_and_padding, sizeof(ping_and_padding), issued,
                             sizeof(issued), &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("a packet addressed to an issued ID is processed", 1U,
                (uint64_t)pair.server.spaces[WT_QUIC_SPACE_APPLICATION].received.has_largest);
  WT_EXPECT_U64("and is not discarded", 0U, pair.server.packets_discarded);
  WT_EXPECT_U64("for sequence zero, the handshake's", 0U,
                pair.server.spaces[WT_QUIC_SPACE_APPLICATION].received.largest_received);

  /* Phase two: retiring that ID and then addressing a packet to it. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 1U;
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("the retirement is applied", 0U, (uint64_t)pair.server.issued_count);
  send_raw_payload_with_dcid(&pair, ping_and_padding, sizeof(ping_and_padding), issued,
                             sizeof(issued), &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 2U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("a packet addressed to a retired ID is discarded", 1U,
                pair.server.packets_discarded);
  /* The packets that were accepted were 0 and 1; the discarded one was 2, so the received set must not
   * have advanced to it. */
  WT_EXPECT_U64("with the discarded packet not recorded", 1U,
                pair.server.spaces[WT_QUIC_SPACE_APPLICATION].received.largest_received);
  close_pair(&pair);

  /* Phase three: retiring the connection ID the packet itself was addressed to. */
  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and are parsed", wt_quic_connection_set_peer_parameters(&pair.server, payload,
                                                                          wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK(
      "the server issues one again",
      wt_quic_connection_issue_connection_id(&pair.server, issued, sizeof(issued), token, now));
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 1U;
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the retire frame encodes", wt_quic_frame_encode(&pw, &frame));
    send_raw_payload_with_dcid(&pair, payload, wt_writer_offset(&pw), issued, sizeof(issued),
                               &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  }
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("retiring the ID the packet was addressed to closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  close_pair(&pair);
}

/* A server answers to the ID the CLIENT chose for its first Initial, which it cannot know from its own
 * configuration: a client picks that value arbitrarily (RFC 9000 section 7.2). This tree's two tools shared one
 * constant across both roles, so a server that accepted only its own ID looked exactly like a server that
 * accepted the client's -- and a third-party client, which picks its own, would have been refused outright
 * (WT-151). The packet is a 1-RTT one because an Initial below 1200 bytes is discarded by section 14.1, which
 * is a different rule and would hide this one. */
void test_a_server_answers_to_the_clients_chosen_id(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  uint64_t now = 96000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x60U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  {
    static const uint8_t k_chosen[8] = {0xdeU, 0xadU, 0xbeU, 0xefU, 0x01U, 0x02U, 0x03U, 0x04U};
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
    WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, &frame));
    WT_EXPECT_OK(
        "the server is told what the client chose",
        wt_quic_connection_set_original_destination_id(&pair.server, k_chosen, sizeof(k_chosen)));
    WT_EXPECT_U64("before the handshake is confirmed", 0U,
                  (uint64_t)pair.server.handshake_confirmed);

    send_raw_payload_with_dcid(&pair, payload, wt_writer_offset(&w), k_chosen, sizeof(k_chosen),
                               &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("so the packet reaches the handler", 1U, (uint64_t)pair.server_witness.count);
    WT_EXPECT_INT("and the connection is not closed", 0,
                  wt_quic_connection_is_closed(&pair.server));
  }

  /* An ID that is neither this endpoint's nor the client's chosen one is another connection's, and RFC 9000
   * section 5.2 makes discarding it the rule. */
  {
    static const uint8_t k_unknown[8] = {0x0fU, 0x0eU, 0x0dU, 0x0cU, 0x0bU, 0x0aU, 0x09U, 0x08U};
    unsigned before = (unsigned)pair.server_witness.count;
    uint64_t discarded_before = pair.server.packets_discarded;
    w = wt_writer_init(payload, sizeof(payload));
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
    WT_EXPECT_OK("another frame encodes", wt_quic_frame_encode(&w, &frame));
    now += 1000U;
    send_raw_payload_with_dcid(&pair, payload, wt_writer_offset(&w), k_unknown, sizeof(k_unknown),
                               &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("a packet for an unknown connection is discarded, not delivered",
                  (uint64_t)before, (uint64_t)pair.server_witness.count);
    WT_EXPECT_U64("and counted as discarded", discarded_before + 1U, pair.server.packets_discarded);
  }

  close_pair(&pair);
}

/* RFC 9000 section 5.1.2's first sentence: "An endpoint can change the connection ID it uses for a peer to
 * another available one at any time during the connection", and the section's MUST NOT: "An endpoint MUST NOT
 * forget a connection ID without retiring it."
 *
 * The frames are the ISSUER's own: `wt_quic_connection_issue_connection_id` sends the NEW_CONNECTION_ID, so the
 * client reads a real one. A test that hand-built them instead would be sending a second frame for a sequence the
 * client already has -- which section 19.15 rightly treats as a duplicate to ignore, and which is how a first
 * version of this test quietly proved nothing.
 */
void test_using_an_issued_connection_id(void) {
  connection_pair_t pair;
  uint8_t token_a[16];
  uint8_t token_b[16];
  static const uint8_t id_a[8] = {0xa1U, 0xa2U, 0xa3U, 0xa4U, 0xa5U, 0xa6U, 0xa7U, 0xa8U};
  static const uint8_t id_b[8] = {0xb1U, 0xb2U, 0xb3U, 0xb4U, 0xb5U, 0xb6U, 0xb7U, 0xb8U};
  uint64_t now = 106000000U;

  memset(token_a, 0x33, sizeof(token_a));
  memset(token_b, 0x44, sizeof(token_b));
  open_pair(WT_UDP_IPV4, &pair);
  arm_for_connection_ids(&pair, 0x50U);

  /* A connection whose peer has issued nothing has only the handshake's ID, and this API does not move away
   * from that one. */
  WT_EXPECT_STATUS("with no issued ID there is nothing to switch to", WT_ERR_STATE,
                   wt_quic_connection_use_new_connection_id(&pair.client, now));

  WT_EXPECT_OK(
      "the server issues the first ID",
      wt_quic_connection_issue_connection_id(&pair.server, id_a, sizeof(id_a), token_a, now));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_U64("the client stored it", 1U,
                (uint64_t)wt_quic_connection_peer_id_count(&pair.client));

  WT_EXPECT_OK("and the second", wt_quic_connection_issue_connection_id(
                                     &pair.server, id_b, sizeof(id_b), token_b, now + 1U));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_U64("which it stored too", 2U,
                (uint64_t)wt_quic_connection_peer_id_count(&pair.client));

  /* Use one: the destination becomes an ID the peer issued. Nothing is retired yet, because the handshake's ID
   * is not in the peer's table and has no sequence to name. */
  WT_EXPECT_OK("the client switches to an issued ID",
               wt_quic_connection_use_new_connection_id(&pair.client, now + 1U));
  WT_EXPECT_TRUE("and addresses the peer by it",
                 pair.client.config.peer_connection_id_length == sizeof(id_a) &&
                     memcmp(pair.client.config.peer_connection_id, id_a, sizeof(id_a)) == 0);
  WT_EXPECT_U64("with nothing retired", 0U, wt_quic_connection_peer_ids_retired(&pair.client));

  /* And again, which abandons the first: this is where a RETIRE_CONNECTION_ID is owed, and it goes out
   * addressed to the ID still in use, which the server issued and therefore accepts. */
  WT_EXPECT_OK("switching again abandons the first",
               wt_quic_connection_use_new_connection_id(&pair.client, now + 2U));
  WT_EXPECT_TRUE("so the destination is the second ID",
                 pair.client.config.peer_connection_id_length == sizeof(id_b) &&
                     memcmp(pair.client.config.peer_connection_id, id_b, sizeof(id_b)) == 0);
  WT_EXPECT_U64("with one ID retired", 1U, wt_quic_connection_peer_ids_retired(&pair.client));
  WT_EXPECT_U64("and one still available", 1U,
                (uint64_t)wt_quic_connection_peer_id_count(&pair.client));
  WT_EXPECT_INT("and nothing closed", 0, wt_quic_connection_is_closed(&pair.client));

  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64(
      "the peer was TOLD, with a RETIRE_CONNECTION_ID frame", 1U,
      (uint64_t)witness_frames_of(&pair.server_witness, WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID));
  WT_EXPECT_INT("and did not close over it", 0, wt_quic_connection_is_closed(&pair.server));

  close_pair(&pair);
}

/* RFC 9000 section 5.1.2's ordering rule: "Upon receipt of an increased Retire Prior To field, the peer MUST stop
 * using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly
 * provided connection ID to the set of active connection IDs... This ordering allows an endpoint to replace all
 * active connection IDs without the possibility of a peer having no available connection IDs."
 *
 * The library's own issuer writes retire_prior_to zero, so this is the one frame a test has to build: a fresh
 * sequence (the peer's next, read from its counter) carrying a retire_prior_to that covers the ID in use.
 */
void test_a_retire_prior_to_replaces_the_id_in_use(void) {
  connection_pair_t pair;
  wt_quic_frame_t frame;
  uint8_t token_a[16];
  uint8_t token_b[16];
  uint8_t token_c[16];
  static const uint8_t id_a[8] = {0xc1U, 0xc2U, 0xc3U, 0xc4U, 0xc5U, 0xc6U, 0xc7U, 0xc8U};
  static const uint8_t id_b[8] = {0xd1U, 0xd2U, 0xd3U, 0xd4U, 0xd5U, 0xd6U, 0xd7U, 0xd8U};
  static const uint8_t id_c[8] = {0xe1U, 0xe2U, 0xe3U, 0xe4U, 0xe5U, 0xe6U, 0xe7U, 0xe8U};
  uint64_t next_sequence;
  uint64_t now = 107000000U;

  memset(token_a, 0x55, sizeof(token_a));
  memset(token_b, 0x66, sizeof(token_b));
  memset(token_c, 0x77, sizeof(token_c));
  open_pair(WT_UDP_IPV4, &pair);
  arm_for_connection_ids(&pair, 0x60U);

  /* Two IDs issued and told, so the client has something to be using when the third arrives. */
  WT_EXPECT_OK("the server issues the first", wt_quic_connection_issue_connection_id(
                                                  &pair.server, id_a, sizeof(id_a), token_a, now));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_OK("and the second", wt_quic_connection_issue_connection_id(
                                     &pair.server, id_b, sizeof(id_b), token_b, now + 1U));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_OK("the client uses the first",
               wt_quic_connection_use_new_connection_id(&pair.client, now + 1U));
  WT_EXPECT_TRUE("which is the ID it now sends to",
                 pair.client.config.peer_connection_id_length == sizeof(id_a) &&
                     memcmp(pair.client.config.peer_connection_id, id_a, sizeof(id_a)) == 0);
  WT_EXPECT_U64("and nothing is retired yet", 0U,
                wt_quic_connection_peer_ids_retired(&pair.client));

  /* The peer issues the third ID -- so its own receive path will accept the retires that follow, which ride the
   * ID being adopted -- and its automatic NEW_CONNECTION_ID frame is TAKEN OFF THE WIRE unread. That is the only
   * way to see a `retire_prior_to` at all: the library's issuer writes zero, and a second frame for a sequence
   * the client already has is the duplicate section 19.15 says to ignore. */
  WT_EXPECT_OK(
      "the server issues the third ID",
      wt_quic_connection_issue_connection_id(&pair.server, id_c, sizeof(id_c), token_c, now + 2U));
  now += 1000U;
  discard_one_datagram(&pair.client_socket);

  /* And now the frame that tells the client about it, with a retire_prior_to covering everything below it.
   * Read the counter first, so this is the FIRST frame the client sees for that sequence. */
  next_sequence = pair.server.next_issued_sequence - 1U;
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
  frame.as.new_connection_id.sequence = next_sequence;
  frame.as.new_connection_id.retire_prior_to = next_sequence;
  frame.as.new_connection_id.connection_id = id_c;
  frame.as.new_connection_id.connection_id_length = sizeof(id_c);
  frame.as.new_connection_id.stateless_reset_token = token_c;
  send_frame_from_side(&pair, 1, &frame, &pair.server.keys_out[WT_QUIC_SPACE_APPLICATION], 0U,
                       k_dcid, sizeof(k_dcid));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);

  /* Everything below the field is retired, not only the ID in use: two were stored, so two go. */
  WT_EXPECT_U64("both IDs below the field were retired", 2U,
                wt_quic_connection_peer_ids_retired(&pair.client));
  WT_EXPECT_U64("only the new one is left", 1U,
                (uint64_t)wt_quic_connection_peer_id_count(&pair.client));
  WT_EXPECT_TRUE("and the client already ADDRESSES the peer by it, rather than by an ID it retired",
                 pair.client.config.peer_connection_id_length == sizeof(id_c) &&
                     memcmp(pair.client.config.peer_connection_id, id_c, sizeof(id_c)) == 0);
  WT_EXPECT_INT("with nothing closed", 0, wt_quic_connection_is_closed(&pair.client));

  /* Both retires went out, each in its own packet, addressed to the ID the client just adopted -- which the
   * peer issued and therefore accepts. Two datagrams, so two reads. */
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64(
      "and the peer was told about both", 2U,
      (uint64_t)witness_frames_of(&pair.server_witness, WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID));

  close_pair(&pair);
}

/* RFC 9000 section 7.3's client half, whose stake the code states: "Without this a client would accept a
 * connection whose connection IDs an attacker who injected packets could have influenced, which is the attack
 * the parameters exist to close." Three refusals had no test (AUD-0033). Every case differs from an ACCEPTED
 * one only in the value under test, so a parameter that is merely absent from a message cannot pass for the
 * wrong reason. */
void test_the_client_half_of_section_7_3(void) {
  connection_pair_t pair;
  wt_quic_transport_parameters_t params;
  uint8_t payload[128];
  static const uint8_t odcid[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
  static const uint8_t other_odcid[8] = {8U, 7U, 6U, 5U, 4U, 3U, 2U, 1U};
  static const uint8_t retry_scid[4] = {9U, 10U, 11U, 12U};
  static const uint8_t other_retry_scid[4] = {12U, 11U, 10U, 9U};
  wt_writer_t w;

  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("the client is told the id it first addressed",
               wt_quic_connection_set_original_destination_id(&pair.client, odcid, sizeof(odcid)));

  /* The matching parameter is accepted, which is what makes the refusals below about the VALUE. */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("the id it sent is echoed back",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, odcid, sizeof(odcid)));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_OK("and are accepted",
               wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  /* ABSENCE counts: the section makes a missing original_destination_connection_id an error. */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("parameters without it", wt_quic_transport_parameters_add_integer(
                                            &params, WT_QUIC_TP_MAX_IDLE_TIMEOUT, 1000U));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_STATUS(
      "a missing original destination id is refused", WT_ERR_PROTOCOL,
      wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a different id", wt_quic_transport_parameters_add_bytes(
                                     &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                                     other_odcid, sizeof(other_odcid)));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_STATUS(
      "a mismatched original destination id is refused", WT_ERR_PROTOCOL,
      wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  /* A retry_source_connection_id when no Retry was received is the peer naming a Retry this client never
   * answered. */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("the echoed id",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, odcid, sizeof(odcid)));
  WT_EXPECT_OK("and a retry source id",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID, retry_scid, sizeof(retry_scid)));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_STATUS(
      "a retry source id without a Retry is refused", WT_ERR_PROTOCOL,
      wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  /* Now the state accepting a Retry leaves behind: required, and it must match. */
  pair.client.retry_accepted = 1;
  memcpy(pair.client.retry_source_connection_id, retry_scid, sizeof(retry_scid));
  pair.client.retry_source_connection_id_length = sizeof(retry_scid);

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("only the echoed id",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, odcid, sizeof(odcid)));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_STATUS(
      "a Retry the parameters do not name is refused", WT_ERR_PROTOCOL,
      wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("the echoed id",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, odcid, sizeof(odcid)));
  WT_EXPECT_OK("and the Retry's own source id",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID, retry_scid, sizeof(retry_scid)));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_OK("the matching pair is accepted",
               wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("the echoed id",
               wt_quic_transport_parameters_add_bytes(
                   &params, WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, odcid, sizeof(odcid)));
  WT_EXPECT_OK("and a DIFFERENT source id", wt_quic_transport_parameters_add_bytes(
                                                &params, WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID,
                                                other_retry_scid, sizeof(other_retry_scid)));
  w = wt_writer_init(payload, sizeof(payload));
  WT_EXPECT_OK("encode", wt_quic_transport_parameters_encode(&w, &params));
  WT_EXPECT_STATUS(
      "a mismatched retry source id is refused", WT_ERR_PROTOCOL,
      wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&w)));

  close_pair(&pair);
}
