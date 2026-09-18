/* The retry tests for the connection runtime. */

#include "test_quic_connection_internal.h"

void test_a_retry_is_accepted_and_answered(void) {
  connection_pair_t pair;
  uint8_t retry[128];
  uint8_t initial[64];
  size_t retry_length;

  open_pair(WT_UDP_IPV4, &pair);
  retry_client(&pair);
  retry_length = build_retry(retry, sizeof(retry), k_retry_scid, sizeof(k_retry_scid),
                             k_retry_token, sizeof(k_retry_token));
  WT_EXPECT_TRUE("the Retry is large enough to be one", retry_length > 1U + 4U + 16U);
  WT_EXPECT_OK(
      "and its tag verifies against the client's destination",
      wt_quic_retry_integrity_verify(k_retry_odcid, sizeof(k_retry_odcid), retry, retry_length));

  /* Something to re-send: the ClientHello's stand-in, recorded with a retransmission descriptor so that the
   * discard below has something to hand back. */
  WT_EXPECT_OK("the client sends a CRYPTO frame",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U,
                                              (const uint8_t *)"client-hello", 12U, 1000U));
  WT_EXPECT_U64("which is remembered", 1U, (uint64_t)wt_quic_loss_count(&pair.client.loss));

  deliver_to(&pair, 0, retry, retry_length, 2000U);

  WT_EXPECT_U64("the Retry was ACCEPTED", 1U, pair.client.retry_accepted_count);
  WT_EXPECT_U64("and none was discarded", 0U, pair.client.retries_discarded);
  WT_EXPECT_INT("the connection knows a Retry happened", 1, pair.client.retry_accepted);
  WT_EXPECT_INT("and that the Initial keys no longer match", 1, pair.client.retry_pending_keys);
  WT_EXPECT_U64("the destination is now the Retry's Source Connection ID",
                (uint64_t)sizeof(k_retry_scid), (uint64_t)pair.client.peer_connection_id_length);
  WT_EXPECT_INT("which is the bytes it named", 0,
                memcmp(pair.client.peer_connection_id, k_retry_scid, sizeof(k_retry_scid)));
  WT_EXPECT_INT("and the send path sees it too", 0,
                memcmp(pair.client.config.peer_connection_id, k_retry_scid, sizeof(k_retry_scid)));
  {
    const uint8_t *token = NULL;
    const uint8_t *source = NULL;
    size_t token_length = 0U;
    size_t source_length = 0U;
    WT_EXPECT_OK(
        "the token is remembered",
        wt_quic_connection_retry(&pair.client, &token, &token_length, &source, &source_length));
    /* Compound rather than a memcmp after a length assertion: a failure here must report, not dereference a view
     * the accessor did not set. */
    WT_EXPECT_TRUE("whole, and as the peer sent it",
                   token != NULL && token_length == sizeof(k_retry_token) &&
                       memcmp(token, k_retry_token, sizeof(k_retry_token)) == 0);
    WT_EXPECT_TRUE("along with the Source Connection ID",
                   source != NULL && source_length == sizeof(k_retry_scid) &&
                       memcmp(source, k_retry_scid, sizeof(k_retry_scid)) == 0);
  }

  /* Everything sent in the Initial space was protected with keys the server threw away, so it is gone from the
   * loss list -- and its DESCRIPTOR came back through the lost-frame handler, which is what makes the handshake
   * re-offer the same ClientHello. */
  WT_EXPECT_U64("the Initial space is emptied of packets that can never be acknowledged", 0U,
                (uint64_t)wt_quic_loss_count(&pair.client.loss));
  WT_EXPECT_TRUE("and the frame that was on it was handed back to be sent again",
                 pair.client_witness.lost_count > 0U);
  WT_EXPECT_U64("with the offset the handshake keeps its bytes at", 0U,
                (uint64_t)pair.client_witness.lost_offsets[0]);

  /* Nothing at Initial level may go out until the keys are derived again: a packet protected with the old ones is
   * byte-for-byte what a client that ignored the Retry would send. */
  WT_EXPECT_STATUS(
      "an Initial is refused until the keys are re-derived", WT_ERR_AGAIN,
      wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U, initial, 4U, 2500U));

  /* What the runtime session does next (RFC 9001 section 5.2): derive them from the Retry's connection ID. */
  {
    wt_quic_packet_keys_t keys;
    uint8_t secret[WT_SHA256_LEN];

    WT_EXPECT_OK("the new Initial secret derives",
                 wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1),
                                        k_retry_scid, sizeof(k_retry_scid), secret));
    WT_EXPECT_OK("with new send keys",
                 wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM, &keys));
    WT_EXPECT_OK("installed",
                 wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_INITIAL, 0, &keys));
    WT_EXPECT_OK("and new receive keys",
                 wt_quic_initial_packet_keys(secret, 1, WT_AEAD_AES_128_GCM, &keys));
    WT_EXPECT_OK("installed too",
                 wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_INITIAL, 1, &keys));
  }
  wt_quic_connection_retry_keys_installed(&pair.client);
  WT_EXPECT_INT("the connection stops refusing once they are", 0,
                wt_quic_connection_retry_pending_keys(&pair.client));
  /* Empty the socket first: it still holds the Initial sent BEFORE the Retry, and the assertion below is about
   * the packet the token is on. A non-blocking receive on an empty queue is WT_ERR_AGAIN, which ends the drain. */
  {
    uint8_t stale[WT_QUIC_MAX_PACKET];
    size_t stale_length = 0U;
    while (wt_udp_receive(&pair.server_socket, stale, sizeof(stale), &stale_length, NULL) ==
           WT_OK) {
      /* discarded */
    }
  }
  WT_EXPECT_OK(
      "and an Initial goes out",
      wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U, initial, 4U, 3000U));

  /* Read it off the wire: the token and the destination are the two fields RFC 9000 section 17.2.5.3 says every
   * later Initial carries, and the header protection comes off with the NEW keys -- which is itself the assertion
   * that the sender used them. */
  {
    uint8_t packet[WT_QUIC_MAX_PACKET];
    size_t packet_length = 0U;
    size_t pn_offset = 0U;
    size_t total = 0U;
    size_t pn_length = 0U;
    int short_header = 0;
    wt_quic_long_header_t header;
    wt_cursor_t cursor;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;

    WT_EXPECT_OK("the server socket is waited on", wt_udp_wait(&pair.server_socket, 2000U));
    WT_EXPECT_OK("and reads the Initial",
                 wt_udp_receive(&pair.server_socket, packet, sizeof(packet), &packet_length, NULL));
    WT_EXPECT_OK(
        "its protected header is located",
        wt_quic_protected_pn_offset(packet, packet_length, 0U, &pn_offset, &total, &short_header));
    WT_EXPECT_INT("as a long header", 0, short_header);
    WT_EXPECT_OK("and unprotected with the new keys",
                 wt_quic_unprotect_header(pair.client.keys_out[WT_QUIC_SPACE_INITIAL].aead,
                                          pair.client.keys_out[WT_QUIC_SPACE_INITIAL].hp,
                                          pair.client.keys_out[WT_QUIC_SPACE_INITIAL].hp_len,
                                          packet, packet_length, pn_offset, &pn_length));
    cursor = wt_cursor_init(packet, packet_length);
    memset(&header, 0, sizeof(header));
    WT_EXPECT_OK("the header parses", wt_quic_long_header_decode(&cursor, &header, &error));
    WT_EXPECT_TRUE(
        "the destination is the Retry's Source Connection ID, byte for byte",
        header.destination_connection_id != NULL &&
            header.destination_connection_id_len == sizeof(k_retry_scid) &&
            memcmp(header.destination_connection_id, k_retry_scid, sizeof(k_retry_scid)) == 0);
    WT_EXPECT_TRUE("and the TOKEN is on the wire as the peer sent it",
                   header.token != NULL && header.token_len == sizeof(k_retry_token) &&
                       memcmp(header.token, k_retry_token, sizeof(k_retry_token)) == 0);
  }
}

/* Every way a Retry is discarded, each of which the section states as a MUST. */
void test_a_retry_that_breaks_a_rule_is_discarded(void) {
  static const uint8_t k_another_scid[6] = {0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U};

  /* A bad integrity tag: what an attacker who did not see the first Initial can produce, and the reason the tag
   * exists. Built by flipping one byte of a tag that verified. */
  {
    connection_pair_t pair;
    uint8_t retry[128];
    size_t retry_length;

    open_pair(WT_UDP_IPV4, &pair);
    retry_client(&pair);
    retry_length = build_retry(retry, sizeof(retry), k_retry_scid, sizeof(k_retry_scid),
                               k_retry_token, sizeof(k_retry_token));
    retry[retry_length - 1U] ^= 0x01U;
    deliver_to(&pair, 0, retry, retry_length, 2000U);
    WT_EXPECT_U64("a Retry with a bad tag is discarded", 1U, pair.client.retries_discarded);
    WT_EXPECT_U64("and not accepted", 0U, pair.client.retry_accepted_count);
    WT_EXPECT_INT("leaving the destination alone", 0,
                  memcmp(pair.client.peer_connection_id, k_retry_odcid, sizeof(k_retry_odcid)));
  }

  /* No token at all, which the section names explicitly. */
  {
    connection_pair_t pair;
    uint8_t retry[128];
    size_t retry_length;

    open_pair(WT_UDP_IPV4, &pair);
    retry_client(&pair);
    retry_length = build_retry(retry, sizeof(retry), k_retry_scid, sizeof(k_retry_scid), NULL, 0U);
    deliver_to(&pair, 0, retry, retry_length, 2000U);
    WT_EXPECT_U64("a Retry with no token is discarded", 1U, pair.client.retries_discarded);
    WT_EXPECT_U64("and not accepted", 0U, pair.client.retry_accepted_count);
  }

  /* A Source Connection ID equal to the destination of the client's Initial, which the section makes an explicit
   * discard: it is a packet that tells the client to keep addressing itself. */
  {
    connection_pair_t pair;
    uint8_t retry[128];
    size_t retry_length;

    open_pair(WT_UDP_IPV4, &pair);
    retry_client(&pair);
    retry_length = build_retry(retry, sizeof(retry), k_retry_odcid, sizeof(k_retry_odcid),
                               k_retry_token, sizeof(k_retry_token));
    deliver_to(&pair, 0, retry, retry_length, 2000U);
    WT_EXPECT_U64("a Retry naming the client's own destination is discarded", 1U,
                  pair.client.retries_discarded);
    WT_EXPECT_U64("and not accepted", 0U, pair.client.retry_accepted_count);
  }

  /* A SECOND Retry, after one was accepted: "A client MUST accept and process at most one Retry packet for each
   * connection attempt." */
  {
    connection_pair_t pair;
    uint8_t retry[128];
    uint8_t another[128];
    size_t retry_length;
    size_t another_length;

    open_pair(WT_UDP_IPV4, &pair);
    retry_client(&pair);
    retry_length = build_retry(retry, sizeof(retry), k_retry_scid, sizeof(k_retry_scid),
                               k_retry_token, sizeof(k_retry_token));
    deliver_to(&pair, 0, retry, retry_length, 2000U);
    WT_EXPECT_U64("the first is accepted", 1U, pair.client.retry_accepted_count);
    another_length = build_retry(another, sizeof(another), k_another_scid, sizeof(k_another_scid),
                                 k_retry_token, sizeof(k_retry_token));
    deliver_to(&pair, 0, another, another_length, 3000U);
    WT_EXPECT_U64("a second is discarded", 1U, pair.client.retries_discarded);
    WT_EXPECT_U64("and the first one still stands", 1U, pair.client.retry_accepted_count);
    WT_EXPECT_INT("with its Source Connection ID still the destination", 0,
                  memcmp(pair.client.peer_connection_id, k_retry_scid, sizeof(k_retry_scid)));
  }

  /* A server MUST discard a Retry: it is a client's packet, and a server that obeyed one would be answering
   * itself. */
  {
    connection_pair_t pair;
    uint8_t retry[128];
    size_t retry_length;

    open_pair(WT_UDP_IPV4, &pair);
    retry_length = build_retry(retry, sizeof(retry), k_retry_scid, sizeof(k_retry_scid),
                               k_retry_token, sizeof(k_retry_token));
    deliver_to(&pair, 1, retry, retry_length, 2000U);
    WT_EXPECT_U64("a server discards a Retry", 1U, pair.server.retries_discarded);
    WT_EXPECT_U64("and never accepts one", 0U, pair.server.retry_accepted_count);
  }
}

/* A datagram that cannot be shown to come from the peer is DISCARDED, not reported as a violation (WT-167).
 *
 * This is the measured defect: a packet protected with a key set this endpoint no longer holds -- quiche's
 * answer to an Initial the Retry had already invalidated -- failed the header decode and came back as
 * WT_ERR_PROTOCOL, so a successful interop reported `"firstReceiveError":"protocol"`. RFC 9001 section 5.3 makes
 * a packet that cannot be authenticated one to DISCARD, and the fixed bit is in the AEAD's associated data, so a
 * header this endpoint cannot parse is evidence of a packet that is not the peer's rather than of a peer
 * breaking a rule. The packet below is well-formed enough to reach the read (a Length, a packet number, a
 * payload) with the fixed bit CLEAR, which RFC 9000 section 17.2 says must be discarded.
 */
void test_an_unauthenticable_packet_is_discarded(void) {
  connection_pair_t pair;
  uint8_t packet[32];
  uint64_t now = 60000000U;
  size_t at = 0U;

  open_pair(WT_UDP_IPV4, &pair);
  memset(packet, 0, sizeof(packet));
  packet[at++] = 0x80U; /* a long header, an Initial by its type bits, and the fixed bit CLEAR */
  packet[at++] = 0x00U;
  packet[at++] = 0x00U;
  packet[at++] = 0x00U;
  packet[at++] = 0x01U; /* version 1 */
  packet[at++] = 8U;    /* an eight-byte Destination Connection ID */
  at += 8U;             /* which may be anything: the header is refused before it is used */
  packet[at++] = 0U;    /* a zero-length Source Connection ID */
  packet[at++] = 0U;    /* no token */
  packet[at++] = 8U;    /* Length: one packet number byte and seven of payload */
  packet[at++] = 0U;    /* the packet number */
  at += 7U;             /* and the payload, which is never reached */

  WT_EXPECT_OK("the datagram is sent",
               wt_udp_send(&pair.server_socket, &pair.client_address, packet, at));
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_U64("the client DISCARDED it", 1U, pair.client.packets_discarded);
  WT_EXPECT_INT("leaving the connection open", 0, wt_quic_connection_is_closed(&pair.client));
  WT_EXPECT_INT("and with no refusal to report", 0, pair.client.close_code_set);
  close_pair(&pair);
}
