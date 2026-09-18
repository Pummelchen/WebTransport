/* The keys tests for the connection runtime. */

#include "test_quic_connection_internal.h"

/* A key update, end to end and in both directions (WT-69).
 *
 * RFC 9001 section 6's shape: one endpoint moves its secret forward and toggles the Key Phase bit, the peer reads
 * the packet with the NEXT keys -- which it had to have derived before it could know the phase, because the bit
 * arrives inside header protection -- and answers with its own keys moved to the same phase, "before sending an
 * acknowledgment for the packet that was received with updated keys". The assertion that matters most is not that
 * the packets decrypt but that the two ends DERIVE THE SAME SECRETS: `quic ku` is only correct if both sides
 * agree, and a test that let each side keep its own keys would pass with a wrong derivation.
 */
void test_a_key_update_moves_both_directions(void) {
  connection_pair_t pair;
  uint8_t datagram[128];
  size_t datagram_len;
  uint64_t now = 80000000U;
  wt_quic_packet_keys_t phase_one;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0x40U);

  /* Nothing is updated before the handshake is confirmed, which section 6.1 makes a MUST NOT. */
  pair.client.handshake_confirmed = 0;
  WT_EXPECT_STATUS("a client that has not confirmed the handshake cannot update", WT_ERR_STATE,
                   wt_quic_connection_initiate_key_update(&pair.client, now));
  WT_EXPECT_INT("and is told so rather than closed", 0, wt_quic_connection_is_closed(&pair.client));
  pair.client.handshake_confirmed = 1;
  WT_EXPECT_INT("with the handshake confirmed it may", 1,
                wt_quic_connection_key_update_allowed(&pair.client));

  /* One packet in phase zero, so the phase has a first packet number for section 6.1's later comparison. */
  datagram_len = build_application_packet(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], 0U, 0,
                                          datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 1, datagram, datagram_len, now + 1000U);
  WT_EXPECT_U64("the server read a packet in phase zero", 0U,
                (uint64_t)wt_quic_connection_key_phase(&pair.server));

  /* The update. The client's phase bit moves, and so do both directions' keys. */
  {
    wt_quic_packet_keys_t before = pair.client.keys_out[WT_QUIC_SPACE_APPLICATION];
    WT_EXPECT_OK("the client initiates an update",
                 wt_quic_connection_initiate_key_update(&pair.client, now + 2000U));
    WT_EXPECT_U64("its phase bit moved", 1U, (uint64_t)wt_quic_connection_key_phase(&pair.client));
    WT_EXPECT_U64("and the update is counted", 1U,
                  wt_quic_connection_key_updates_initiated(&pair.client));
    WT_EXPECT_TRUE("the write secret changed",
                   memcmp(before.secret, pair.client.keys_out[WT_QUIC_SPACE_APPLICATION].secret,
                          WT_SHA256_LEN) != 0);
    /* Section 6.1: the header protection key is NOT updated, which is what lets the peer unprotect a header of
     * any phase with the keys it holds. */
    WT_EXPECT_TRUE(
        "while header protection did not",
        memcmp(before.hp, pair.client.keys_out[WT_QUIC_SPACE_APPLICATION].hp, before.hp_len) == 0);
    /* Section 6.1 also moves the initiator's RECEIVE keys, because the peer answers in the new phase. */
    WT_EXPECT_TRUE("and the receive secret changed with it",
                   memcmp(before.secret, pair.client.keys_in[WT_QUIC_SPACE_APPLICATION].secret,
                          WT_SHA256_LEN) != 0);
  }
  /* A second update before the first is acknowledged is the other MUST NOT, and it is this endpoint's own
   * mistake: a state error, not a connection close. */
  WT_EXPECT_STATUS("a second update without an acknowledgement is refused", WT_ERR_STATE,
                   wt_quic_connection_initiate_key_update(&pair.client, now + 3000U));
  WT_EXPECT_INT("without closing anything", 0, wt_quic_connection_is_closed(&pair.client));

  /* A packet in the NEW phase, built with the updated keys. The server has never seen phase one. */
  datagram_len = build_application_packet(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], 1U, 1,
                                          datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 1, datagram, datagram_len, now + 4000U);
  WT_EXPECT_INT("the server read it", 0, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and RESPONDED by moving its own keys", 1U,
                wt_quic_connection_key_updates_responded(&pair.server));
  WT_EXPECT_U64("its phase bit moved too", 1U,
                (uint64_t)wt_quic_connection_key_phase(&pair.server));

  /* The assertion the whole feature rests on: both ends derived the same secret in both directions. */
  phase_one = pair.client.keys_out[WT_QUIC_SPACE_APPLICATION];
  WT_EXPECT_TRUE("the server's receive keys are the client's send keys",
                 memcmp(phase_one.secret, pair.server.keys_in[WT_QUIC_SPACE_APPLICATION].secret,
                        WT_SHA256_LEN) == 0);
  WT_EXPECT_TRUE("and its send keys are the client's receive keys",
                 memcmp(pair.server.keys_out[WT_QUIC_SPACE_APPLICATION].secret,
                        pair.client.keys_in[WT_QUIC_SPACE_APPLICATION].secret, WT_SHA256_LEN) == 0);

  /* The server's answer, in the new phase, reaches the client -- which is reading with the keys it moved when it
   * initiated the update (section 6.1). */
  datagram_len = build_application_packet(&pair.server.keys_out[WT_QUIC_SPACE_APPLICATION], 0U, 1,
                                          datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 0, datagram, datagram_len, now + 5000U);
  WT_EXPECT_U64("the client read the answer in the new phase", 1U,
                (uint64_t)wt_quic_connection_key_phase(&pair.client));
  WT_EXPECT_INT("still open", 0, wt_quic_connection_is_closed(&pair.client));

  close_pair(&pair);
}

/* Section 6.2: acknowledging a packet of the new phase is what COMPLETES an update, and section 6.1 makes that
 * completion the condition for another one.
 *
 * Every packet here goes through the connection's own send path, unlike the test above: an acknowledgement is
 * only meaningful for a packet the receiver actually recorded, and `handle_ack` refuses one that names a packet
 * the send side never sent. Mixing hand-built packets with the send path is exactly how this failed the first
 * time -- the server acknowledged bytes the client's loss list had never heard of.
 */
void test_an_acknowledgement_confirms_the_update(void) {
  connection_pair_t pair;
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  uint64_t now = 85000000U;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0x50U);

  /* One packet in phase zero, so the server has something to acknowledge and the phase has a start. */
  WT_EXPECT_OK(
      "the client sends in phase zero",
      wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1, now));
  WT_EXPECT_OK("and flushes it", wt_quic_connection_flush(&pair.client, now));
  receive_on(&pair.server, &pair.server_socket, now + 1000U);

  WT_EXPECT_OK("the client updates",
               wt_quic_connection_initiate_key_update(&pair.client, now + 2000U));
  WT_EXPECT_U64("awaiting confirmation", 1U,
                (uint64_t)pair.client.key_update_awaiting_confirmation);
  WT_EXPECT_OK("a packet in the new phase goes out",
               wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1,
                                             now + 3000U));
  WT_EXPECT_INT("recording the phase's first packet number", 1, pair.client.key_phase_first_pn_set);
  WT_EXPECT_OK("and is flushed", wt_quic_connection_flush(&pair.client, now + 3000U));
  receive_on(&pair.server, &pair.server_socket, now + 4000U);
  WT_EXPECT_U64("the server responded to the update", 1U,
                wt_quic_connection_key_updates_responded(&pair.server));

  /* The server's acknowledgement goes out in the phase it moved to (section 6.2: sending keys are updated BEFORE
   * that acknowledgement), and it covers the packet that started the update. */
  WT_EXPECT_OK("the server flushes its acknowledgement",
               wt_quic_connection_flush(&pair.server, now + 5000U));
  receive_on(&pair.client, &pair.client_socket, now + 6000U);
  WT_EXPECT_INT("the client is still open", 0, wt_quic_connection_is_closed(&pair.client));
  WT_EXPECT_U64("and the update is CONFIRMED by that acknowledgement", 0U,
                (uint64_t)pair.client.key_update_awaiting_confirmation);
  WT_EXPECT_INT("which makes another update allowed", 1,
                wt_quic_connection_key_update_allowed(&pair.client));
  WT_EXPECT_U64("with the retained phase dropped", 0, (uint64_t)pair.client.previous_keys_in_ready);

  /* And the next update goes through, now that the previous one is confirmed. */
  WT_EXPECT_OK("a second update is allowed once the first is confirmed",
               wt_quic_connection_initiate_key_update(&pair.client, now + 7000U));
  WT_EXPECT_U64("with the phase back where it started, one bit later", 0U,
                (uint64_t)wt_quic_connection_key_phase(&pair.client));
  WT_EXPECT_U64("and counted", 2U, wt_quic_connection_key_updates_initiated(&pair.client));

  close_pair(&pair);
}

/* RFC 9001 section 6.5: the phase being retired and the phase arriving carry the SAME Key Phase bit, so a packet
 * from before an update can only be told from one that starts the next update by its packet number. This is that
 * delayed packet, read with the keys the update retained. */
void test_a_reordered_packet_is_read_with_the_retained_keys(void) {
  connection_pair_t pair;
  uint8_t delayed[128];
  uint8_t datagram[128];
  size_t delayed_len;
  size_t datagram_len;
  uint64_t now = 90000000U;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0x60U);

  /* A packet the network holds back, protected with the phase-zero keys and numbered BELOW the ones that
   * follow it. */
  delayed_len = build_application_packet(&pair.server.keys_out[WT_QUIC_SPACE_APPLICATION], 0U, 0,
                                         delayed, sizeof(delayed), 4U);

  /* The client initiates an update: it retains the phase-zero KEYS it was reading with (section 6.1). */
  WT_EXPECT_OK("the client updates", wt_quic_connection_initiate_key_update(&pair.client, now));

  /* The client sends a packet in the phase it moved to, so the SERVER responds and its send keys move too --
   * without that the server is still protecting with phase zero and there is no reordered packet to read. */
  datagram_len = build_application_packet(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], 2U, 1,
                                          datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 1, datagram, datagram_len, now + 1000U);
  WT_EXPECT_U64("the server responded by moving its keys", 1U,
                wt_quic_connection_key_updates_responded(&pair.server));
  WT_EXPECT_TRUE("so both ends hold the same secret in this direction",
                 memcmp(pair.server.keys_out[WT_QUIC_SPACE_APPLICATION].secret,
                        pair.client.keys_in[WT_QUIC_SPACE_APPLICATION].secret, WT_SHA256_LEN) == 0);

  /* A packet the server sends NOW, in the new phase, numbered well above the delayed one. */
  datagram_len = build_application_packet(&pair.server.keys_out[WT_QUIC_SPACE_APPLICATION], 9U, 1,
                                          datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 0, datagram, datagram_len, now + 2000U);
  WT_EXPECT_INT("the client read the new phase", 0, wt_quic_connection_is_closed(&pair.client));
  WT_EXPECT_U64("with the first packet number of that phase recorded", 9U,
                pair.client.key_phase_in_first_pn);

  /* And NOW the delayed one arrives: phase ZERO, packet number 0, while the current incoming phase began at 9.
   * The phase bits are the same value -- which is the whole point of section 6.5 -- so only the packet number
   * can say that this belongs to the retained keys.
   *
   * The evidence that it was READ rather than discarded is that the client now OWES an acknowledgement: a
   * discarded packet leaves no acknowledgement behind, and `packets_received` counts datagrams ARRIVED rather
   * than packets processed -- which is why it is not the assertion here (it was, and it proved nothing). */
  {
    uint64_t acks_before;

    /* Drain anything already owed, so the count below is this packet's doing. */
    WT_EXPECT_OK("the client flushes first", wt_quic_connection_flush(&pair.client, now + 2500U));
    acks_before = pair.client.acks_sent[WT_QUIC_SPACE_APPLICATION];
    deliver_to_peer(&pair, 0, delayed, delayed_len, now + 3000U);
    WT_EXPECT_INT("the delayed packet did not close the connection", 0,
                  wt_quic_connection_is_closed(&pair.client));
    WT_EXPECT_OK("and the client answers it", wt_quic_connection_flush(&pair.client, now + 3500U));
    WT_EXPECT_TRUE("with an acknowledgement, which only a packet it READ can owe",
                   pair.client.acks_sent[WT_QUIC_SPACE_APPLICATION] > acks_before);
  }

  close_pair(&pair);
}

/* The same shape as the test above on the OTHER end, and harder: a delayed packet that arrives before ANY packet
 * of the receiving endpoint's new phase, so section 6.5's packet-number comparison has nothing to compare against.
 * The retained keys are what answers it, and the evidence is that an acknowledgement is owed afterwards.
 *
 * A pair of its own, because a queued datagram from an earlier scenario is read FIRST by `receive_on` and would
 * make this a test of something else -- which is exactly how this failed before it was split out.
 */
void test_a_reordered_packet_with_no_reference_is_read(void) {
  connection_pair_t pair;
  uint8_t delayed[128];
  uint8_t datagram[128];
  size_t delayed_len;
  size_t datagram_len;
  wt_quic_packet_keys_t client_phase_one;
  uint64_t now = 92000000U;
  uint64_t acks_before;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0x70U);

  /* The packet the network holds back: phase ZERO, packet number 0, protected with the keys the client is still
   * sending with -- it has not updated anything. */
  delayed_len = build_application_packet(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], 0U, 0,
                                         delayed, sizeof(delayed), 4U);

  /* The update: the client's OWN next phase, derived the way `initiate_key_update` derives it. The header's bit
   * and the keys have to agree, which is what a first version of this test got wrong -- it set the bit and kept
   * the old keys, so the server was right to discard it. */
  update_keys_keeping_hp(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], &client_phase_one);
  datagram_len = build_application_packet(&client_phase_one, 1U, 1, datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 1, datagram, datagram_len, now + 1000U);
  WT_EXPECT_U64("the server responded to the update", 1U,
                wt_quic_connection_key_updates_responded(&pair.server));
  WT_EXPECT_INT("and has read nothing in its new phase", 0, pair.server.key_phase_in_first_pn_set);
  WT_EXPECT_OK("with nothing owed to send", wt_quic_connection_flush(&pair.server, now + 2000U));
  acks_before = pair.server.acks_sent[WT_QUIC_SPACE_APPLICATION];

  /* The delayed packet, whose bit is the same as the phase the server is now reading and whose keys are the ones
   * it has retained. */
  deliver_to_peer(&pair, 1, delayed, delayed_len, now + 3000U);
  WT_EXPECT_INT("the delayed packet did not close the server", 0,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and no key update error was raised", 0U,
                wt_quic_connection_key_update_errors(&pair.server));
  WT_EXPECT_OK("the server answers it", wt_quic_connection_flush(&pair.server, now + 4000U));
  WT_EXPECT_TRUE("with an acknowledgement, so it was read with the retained keys",
                 pair.server.acks_sent[WT_QUIC_SPACE_APPLICATION] > acks_before);

  close_pair(&pair);
}

/* RFC 9001 section 6.2's consecutive-update refusal: "if an endpoint detects a second update before it has sent
 * any packets with updated keys containing an acknowledgment for the packet that initiated the key update... an
 * endpoint MAY treat such consecutive key updates as a connection error of type KEY_UPDATE_ERROR". */
void test_a_second_update_without_an_answer_is_refused(void) {
  connection_pair_t pair;
  uint8_t datagram[128];
  size_t datagram_len;
  uint64_t now = 95000000U;
  wt_quic_packet_keys_t phase_three;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0x80U);
  WT_EXPECT_OK("the client updates once",
               wt_quic_connection_initiate_key_update(&pair.client, now));

  /* Phase one reaches the server, which responds and now OWES an acknowledgement in the new phase. */
  datagram_len = build_application_packet(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], 0U, 1,
                                          datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 1, datagram, datagram_len, now + 1000U);
  WT_EXPECT_U64("the server responded", 1U, wt_quic_connection_key_updates_responded(&pair.server));
  WT_EXPECT_INT("and has sent nothing in the new phase yet", 0, pair.server.key_phase_first_pn_set);

  /* Now a SECOND update from the peer, which is two generations ahead: its keys are the ones after the ones the
   * server just moved to, and its phase bit is the same as the phase it is reading. */
  update_keys_keeping_hp(&pair.client.keys_out[WT_QUIC_SPACE_APPLICATION], &phase_three);
  datagram_len = build_application_packet(&phase_three, 1U, 0, datagram, sizeof(datagram), 4U);
  deliver_to_peer(&pair, 1, datagram, datagram_len, now + 2000U);
  WT_EXPECT_INT("the server closes the connection", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with KEY_UPDATE_ERROR", (uint64_t)WT_QUIC_KEY_UPDATE_ERROR,
                pair.server.close.error_code);
  WT_EXPECT_U64("and counts it", 1U, wt_quic_connection_key_update_errors(&pair.server));

  close_pair(&pair);
}

/* RFC 9001 section 6.6's usage limits (WT-169).
 *
 * The limits exist so that a key is never used for more packets than the AEAD's security proof allows, and they
 * are unreachable in a test that sends hundreds of packets: AES-GCM's confidentiality limit is 2^23 ENCRYPTIONS
 * and its integrity limit is 2^52 INVALID packets. They are fields on the connection rather than constants --
 * appendix B allows higher ones for endpoints that bound their packet sizes -- which is also what lets these
 * tests drive them down far enough to see the policy, rather than trusting it by reading it.
 */
void test_the_confidentiality_limit_rotates_the_keys(void) {
  connection_pair_t pair;
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  uint64_t now = 100000000U;
  unsigned i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0xa0U);

  /* The suite's own limits, before a test touches them: AES-128-GCM is 2^23 encrypted and 2^52 invalid. */
  WT_EXPECT_U64("AES-GCM's confidentiality limit is the section's 2^23",
                (uint64_t)UINT64_C(1) << 23,
                wt_quic_connection_aead_confidentiality_limit(&pair.client));
  WT_EXPECT_U64("and its integrity limit is 2^52", (uint64_t)UINT64_C(1) << 52,
                wt_quic_connection_aead_integrity_limit(&pair.client));

  /* Down to two encrypted packets, which is the smallest number that can show both the count and the rotation. */
  pair.client.aead_confidentiality_limit = 2U;
  WT_EXPECT_U64("nothing encrypted yet", 0U,
                wt_quic_connection_aead_encrypted(&pair.client, WT_QUIC_SPACE_APPLICATION));

  for (i = 0U; i < 2U; i++) {
    WT_EXPECT_OK("a packet is protected",
                 wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1,
                                               now + i * 1000U));
    WT_EXPECT_U64("and counted against the key", i + 1U,
                  wt_quic_connection_aead_encrypted(&pair.client, WT_QUIC_SPACE_APPLICATION));
    WT_EXPECT_U64("with the phase unchanged", 0U,
                  (uint64_t)wt_quic_connection_key_phase(&pair.client));
    WT_EXPECT_OK("and flushed", wt_quic_connection_flush(&pair.client, now + i * 1000U));
  }

  /* The third packet is where the limit bites: section 6.6 requires an update BEFORE exceeding it, so the keys
   * rotate rather than the packet being refused. */
  WT_EXPECT_OK("the packet at the limit is sent by ROTATING the keys",
               wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1,
                                             now + 3000U));
  WT_EXPECT_U64("which the connection counts", 1U,
                wt_quic_connection_key_updates_initiated(&pair.client));
  WT_EXPECT_U64("with the phase bit moved", 1U,
                (uint64_t)wt_quic_connection_key_phase(&pair.client));
  WT_EXPECT_U64("and the new key set's count started", 1U,
                wt_quic_connection_aead_encrypted(&pair.client, WT_QUIC_SPACE_APPLICATION));
  WT_EXPECT_INT("and nothing closed", 0, wt_quic_connection_is_closed(&pair.client));

  close_pair(&pair);
}

/* The other half of section 6.6: "If a key update is not possible or integrity limits are reached, the endpoint
 * MUST stop using the connection"; and it RECOMMENDS the close that this does. */
void test_a_limit_with_no_update_possible_closes(void) {
  connection_pair_t pair;
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  uint64_t now = 101000000U;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0xb0U);

  /* An update that has been sent and not yet acknowledged is one that cannot be initiated again (section 6.1),
   * so a connection in that state that reaches its limit has nowhere to go. */
  WT_EXPECT_OK("one packet goes out", wt_quic_connection_send_frame(
                                          &pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1, now));
  WT_EXPECT_OK("and is flushed", wt_quic_connection_flush(&pair.client, now));
  WT_EXPECT_OK("the client updates",
               wt_quic_connection_initiate_key_update(&pair.client, now + 1000U));
  pair.client.aead_confidentiality_limit = 0U;
  WT_EXPECT_INT("and no FURTHER update is possible while that one is unconfirmed", 0,
                wt_quic_connection_key_update_allowed(&pair.client));
  WT_EXPECT_STATUS("so the next packet closes the connection instead of exceeding the limit", WT_OK,
                   wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1,
                                                 now + 1000U));
  WT_EXPECT_INT("the connection is closed", 1, wt_quic_connection_is_closed(&pair.client));
  WT_EXPECT_U64("with AEAD_LIMIT_REACHED", (uint64_t)WT_QUIC_AEAD_LIMIT_REACHED,
                pair.client.close.error_code);

  close_pair(&pair);
}

/* And the integrity limit, which counts something different: received packets that FAIL authentication, over the
 * lifetime of the connection and across every key it has used. */
void test_the_integrity_limit_closes_the_connection(void) {
  connection_pair_t pair;
  uint8_t packet[64];
  uint8_t saved[64];
  size_t packet_len;
  uint64_t now = 102000000U;
  unsigned i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0xc0U);
  pair.server.aead_integrity_limit = 2U;

  /* A well-formed packet whose tag is wrong, which is what a forgery attempt looks like to a receiver. Built
   * once and corrupted per attempt, because the first two failures wipe it (that is the point of the wipe). */
  packet_len = build_application_packet(&pair.server.keys_out[WT_QUIC_SPACE_APPLICATION], 0U, 0,
                                        saved, sizeof(saved), 4U);
  for (i = 0U; i < 3U; i++) {
    memcpy(packet, saved, packet_len);
    packet[packet_len - 1U] ^= (uint8_t)(0x01U + i);
    deliver_to_peer(&pair, 1, packet, packet_len, now + i * 1000U);
    WT_EXPECT_U64("the forgery attempt is counted", i + 1U,
                  wt_quic_connection_aead_failed(&pair.server));
  }
  WT_EXPECT_INT("and the third closes the connection", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with AEAD_LIMIT_REACHED", (uint64_t)WT_QUIC_AEAD_LIMIT_REACHED,
                pair.server.close.error_code);

  close_pair(&pair);
}

/* ChaCha20-Poly1305's confidentiality limit is "greater than the number of possible packets (2^62) and so can be
 * disregarded", while its integrity limit is 2^36 -- the two suites are not interchangeable numbers. */
void test_the_limits_follow_the_suite(void) {
  wt_quic_connection_config_t config;
  wt_quic_connection_t connection;
  static const uint8_t k_id[4] = {1U, 2U, 3U, 4U};

  memset(&config, 0, sizeof(config));
  config.role = WT_QUIC_ROLE_CLIENT;
  config.version = WT_QUIC_VERSION_1;
  config.local_connection_id = k_id;
  config.local_connection_id_length = sizeof(k_id);
  config.peer_connection_id = k_id;
  config.peer_connection_id_length = sizeof(k_id);
  config.aead = WT_AEAD_CHACHA20_POLY1305;
  config.max_ack_delay = 25000U;
  config.local_max_ack_delay = 25000U;
  config.idle_timeout = 30000000U;
  config.max_datagram_size = WT_QUIC_MAX_PACKET;
  WT_EXPECT_OK("a ChaCha20-Poly1305 connection initialises",
               wt_quic_connection_init(&connection, &config));
  WT_EXPECT_U64("whose confidentiality limit is above the packet number space", UINT64_MAX,
                wt_quic_connection_aead_confidentiality_limit(&connection));
  WT_EXPECT_U64("and whose integrity limit is the section's 2^36", (uint64_t)UINT64_C(1) << 36,
                wt_quic_connection_aead_integrity_limit(&connection));
}
