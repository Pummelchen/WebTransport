/* The loss tests for the connection runtime. */

#include "test_quic_connection_internal.h"

/* RFC 9000 section 13.3 and the machinery that implements it: one retransmission descriptor per sent packet,
 * handed back when the packet is ACKNOWLEDGED or declared lost. The second half was missing -- `on_lost` released
 * the slot and an acknowledgement did not -- so the table filled at sixteen retransmittable packets NET OF
 * LOSSES and every later send that needs a descriptor was refused with WT_ERR_LIMIT. A session that exchanges
 * more than sixteen messages would have failed with a limit error that names nothing.
 */
void test_a_retransmission_descriptor_is_released_on_acknowledgement(void) {
  connection_pair_t pair;
  uint8_t payload[32];
  uint64_t now = 108000000U;
  unsigned i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(payload); i++)
    payload[i] = (uint8_t)i;

  /* One CRYPTO frame at a time -- each takes a descriptor -- carried, acknowledged, and acknowledged AGAIN
   * until the loop has sent more than the descriptor table holds. */
  for (i = 0U; i < WT_QUIC_CONNECTION_FRAMES_MAX + 4U; i++) {
    WT_EXPECT_OK("a frame with a descriptor is sent",
                 wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, (uint64_t)i,
                                                payload, sizeof(payload), now));
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_OK("the peer owes an acknowledgement", wt_quic_connection_flush(&pair.server, now));
    now += 1000U;
    receive_on(&pair.client, &pair.client_socket, now);
    WT_EXPECT_INT("the client is still open", 0, wt_quic_connection_is_closed(&pair.client));
  }
  close_pair(&pair);
}

/* RFC 9000 section 13.3: "Control frames ... are retransmitted until they are acknowledged" -- and the ones the
 * CONNECTION sends for itself are the frames nothing else can re-send. MAX_DATA is the plainest of them: the
 * value is this layer's, and a peer that never receives it stalls against a limit this endpoint believes it has
 * raised. Before this, `wt_quic_connection_send_frame` sent control frames with NO descriptor at all, so a lost
 * one was lost for good.
 *
 * The loss is REAL here -- the datagram is taken off the socket and thrown away -- and so is the acknowledgement
 * that declares it lost: RFC 9002's packet threshold needs an acknowledged packet three numbers higher, and the
 * server's acknowledgement is delayed by `max_ack_delay`, so the clock moves by more than that before it flushes.
 *
 * The observable is the limit the frame moves rather than the frame, because a connection applies MAX_DATA
 * itself and never shows it to a handler.
 */
void test_a_lost_control_frame_is_sent_again(void) {
  connection_pair_t pair;
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  uint64_t now = 109000000U;
  unsigned i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0xd0U);

  WT_EXPECT_OK("a grant is in force", wt_quic_connection_set_max_data(&pair.client, 100000U));
  WT_EXPECT_OK("a MAX_DATA frame goes out",
               wt_quic_connection_send_max_data(&pair.client, 200000U, now));
  now += 1000U;
  /* The network drops it. The peer's limit stays where it was, which is the whole stake of this test. */
  discard_one_datagram(&pair.server_socket);

  /* Three more packets, delivered, so that the dropped one is three below what gets acknowledged. */
  for (i = 0U; i < 3U; i++) {
    WT_EXPECT_OK("a later packet goes out",
                 wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1,
                                               now + i * 1000U));
    WT_EXPECT_OK("and is flushed", wt_quic_connection_flush(&pair.client, now + i * 1000U));
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
  }
  WT_EXPECT_U64("the peer never saw the raised limit", 0U,
                pair.server.peer_limits.initial_max_data);

  /* Past the acknowledgement delay the server's TIMER is what sends the acknowledgement -- `flush` only sends one
   * early for the two cases RFC 9000 section 13.2.1 names -- and that acknowledgement is what makes the client
   * declare the dropped packet lost, by RFC 9002's packet threshold. */
  now += 40000U;
  WT_EXPECT_OK("the peer's timer acknowledges", wt_quic_connection_on_timeout(&pair.server, now));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_TRUE("the dropped packet was declared lost",
                 pair.client.packets_declared_lost[WT_QUIC_SPACE_APPLICATION] > 0U);

  WT_EXPECT_TRUE("the connection sent a second copy of its own frame",
                 pair.client.packets_sent >= 5U);
  /* Bounded pumping rather than one read: the re-sent packet is sent from inside the client's own receive, so
   * whether it is already queued when this line runs is a race the test has no business depending on. */
  {
    unsigned round;
    for (round = 0U; round < 50U && pair.server.peer_limits.initial_max_data != 200000U; round++) {
      now += 1000U;
      if (wt_udp_wait(&pair.server_socket, 20000U) != WT_OK) continue;
      /* The connection reads the datagram itself: reading it raw here first would consume it and leave the
       * connection with nothing to parse, which is what made this pump look like a silent peer. */
      (void)wt_quic_connection_receive(&pair.server, now);
    }
  }
  WT_EXPECT_U64("and the limit finally arrived, carried by a second copy", 200000U,
                pair.server.peer_limits.initial_max_data);
  WT_EXPECT_INT("with nobody closed", 0, wt_quic_connection_is_closed(&pair.client));

  close_pair(&pair);
}

/* And the other half of "until acknowledged": once the peer HAS it, the frame is not sent again. The claim is
 * measured where it is made -- the acknowledged packet is never declared lost, so nothing is re-sent -- and the
 * slot the connection kept for it is released, which is what an acknowledgement is for.
 */
void test_an_acknowledged_control_frame_is_not_sent_again(void) {
  connection_pair_t pair;
  uint64_t now = 110000000U;
  uint64_t received_before;
  size_t i;
  int retained = 0;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0xe0U);

  WT_EXPECT_OK("a grant is in force", wt_quic_connection_set_max_data(&pair.client, 100000U));
  WT_EXPECT_OK("a MAX_DATA frame goes out",
               wt_quic_connection_send_max_data(&pair.client, 300000U, now));
  for (i = 0U; i < WT_QUIC_CONTROL_FRAMES_MAX; i++) {
    if (pair.client.control_frames[i].in_use) retained = 1;
  }
  WT_EXPECT_INT("which the connection KEEPS, in case it is lost", 1, retained);

  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("the peer applied it", 300000U, pair.server.peer_limits.initial_max_data);

  now += 40000U;
  WT_EXPECT_OK("and its timer acknowledges it", wt_quic_connection_on_timeout(&pair.server, now));
  WT_EXPECT_U64("the peer's timer SENT an acknowledgement", 1U,
                (uint64_t)pair.server.acks_sent[WT_QUIC_SPACE_APPLICATION]);
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_U64("which the client counts", 1U,
                (uint64_t)pair.client.packets_acked[WT_QUIC_SPACE_APPLICATION]);
  {
    int still_retained = 0;
    for (i = 0U; i < WT_QUIC_CONTROL_FRAMES_MAX; i++) {
      if (pair.client.control_frames[i].in_use) still_retained = 1;
    }
    WT_EXPECT_INT("and RELEASES the frame, because the obligation is answered", 0, still_retained);
  }

  /* Long enough that an outstanding packet would have been declared lost, and nothing is. */
  received_before = pair.server.packets_received;
  now += 2000000U;
  WT_EXPECT_OK("the loss timer runs", wt_quic_connection_on_timeout(&pair.client, now));
  WT_EXPECT_OK("and nothing is owed", wt_quic_connection_flush(&pair.client, now));
  WT_EXPECT_U64("with the acknowledged packet never declared lost", 0U,
                (uint64_t)pair.client.packets_declared_lost[WT_QUIC_SPACE_APPLICATION]);
  /* Nothing is expected to arrive, so this waits WITHOUT asserting: a timeout is the result the test wants, and
   * a helper that asserts on one would be testing itself. A datagram that DID arrive is handed to the connection
   * rather than read raw, because reading it here would consume it without counting it -- and then the assertion
   * below could not fail, which is the one thing a test of "nothing arrives" must not be. */
  {
    unsigned round;
    for (round = 0U; round < 3U; round++) {
      now += 1000U;
      if (wt_udp_wait(&pair.server_socket, 20000U) != WT_OK) continue;
      (void)wt_quic_connection_receive(&pair.server, now);
    }
  }
  WT_EXPECT_U64("so the peer keeps the one copy it had", received_before,
                pair.server.packets_received);

  close_pair(&pair);
}

/* And the third half of "until acknowledged": a re-send that CANNOT go out. `send_encoded_frame` frees the
 * descriptor when the send fails, and the descriptor is the only handle a later loss names the obligation by --
 * so a discarded failure drops the frame for the life of the connection AND keeps its slot occupied forever.
 * Here the path's datagram limit is too small at the instant the loss is declared (one of the ways `send_packet`
 * fails), and the slot must stay owed so the next flush re-drives it. */
void test_a_failed_control_resend_is_redriven_by_flush(void) {
  connection_pair_t pair;
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  uint64_t now = 111500000U;
  uint64_t packets_before;
  unsigned i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0x90U);

  WT_EXPECT_OK("a grant is in force", wt_quic_connection_set_max_data(&pair.client, 100000U));
  WT_EXPECT_OK("a MAX_DATA frame goes out",
               wt_quic_connection_send_max_data(&pair.client, 200000U, now));
  now += 1000U;
  /* The network drops it. */
  discard_one_datagram(&pair.server_socket);

  /* Three more packets, delivered, so the dropped one is three below what gets acknowledged. */
  for (i = 0U; i < 3U; i++) {
    WT_EXPECT_OK("a later packet goes out",
                 wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1,
                                               now + i * 1000U));
    WT_EXPECT_OK("and is flushed", wt_quic_connection_flush(&pair.client, now + i * 1000U));
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
  }

  now += 40000U;
  WT_EXPECT_OK("the peer's timer acknowledges", wt_quic_connection_on_timeout(&pair.server, now));
  now += 1000U;

  /* The path's limit is too small for ANY packet right now, so the re-send that the acknowledgement's loss
   * detection triggers cannot go out. */
  packets_before = pair.client.packets_sent;
  pair.client.config.max_datagram_size = 8U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_TRUE("the dropped packet was declared lost",
                 pair.client.packets_declared_lost[WT_QUIC_SPACE_APPLICATION] > 0U);
  WT_EXPECT_U64("and the failed re-send put nothing new on the wire", packets_before,
                pair.client.packets_sent);

  /* The path recovers, and the next flush re-drives the retained obligation. */
  pair.client.config.max_datagram_size = WT_QUIC_MAX_PACKET;
  WT_EXPECT_OK("the next flush runs", wt_quic_connection_flush(&pair.client, now + 1000U));
  WT_EXPECT_U64("and re-sends the retained control frame", packets_before + 1U,
                pair.client.packets_sent);

  /* The peer sees the raised limit only now, carried by the re-driven copy. */
  WT_EXPECT_U64("which the dropped packet never delivered", 0U,
                pair.server.peer_limits.initial_max_data);
  {
    unsigned round;
    for (round = 0U; round < 50U && pair.server.peer_limits.initial_max_data != 200000U; round++) {
      now += 1000U;
      if (wt_udp_wait(&pair.server_socket, 20000U) != WT_OK) continue;
      (void)wt_quic_connection_receive(&pair.server, now);
    }
  }
  WT_EXPECT_U64("but the re-driven copy does", 200000U, pair.server.peer_limits.initial_max_data);
  WT_EXPECT_INT("with nobody closed", 0, wt_quic_connection_is_closed(&pair.client));

  close_pair(&pair);
}

/* RFC 9000 section 13.3 is a list of exceptions in BOTH directions. Lost PING and PADDING frames "do not require
 * repair", an old ACK must not be resent (it would inflate the peer's RTT sample) and is replaced rather than
 * repeated, a CONNECTION_CLOSE "is not sent again when packet loss is detected", and a DATAGRAM is never
 * retransmitted at all (RFC 9221 section 5.2). None of those may spend one of this connection's eight
 * retransmission slots -- and the stake is not tidiness: a connection that spent them on probes would have none
 * left for the MAX_DATA that needs one.
 */
void test_only_retransmittable_frames_keep_a_slot(void) {
  connection_pair_t pair;
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
  wt_quic_transport_parameters_t params;
  uint8_t payload[128];
  wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
  uint64_t now = 111000000U;
  size_t i;
  int retained = 0;

  open_pair(WT_UDP_IPV4, &pair);
  arm_application(&pair, 0xf0U);
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK(
      "the peer offers datagrams",
      wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 1200U));
  WT_EXPECT_OK("which encodes", wt_quic_transport_parameters_encode(&pw, &params));
  WT_EXPECT_OK("and is applied", wt_quic_connection_set_peer_parameters(&pair.client, payload,
                                                                        wt_writer_offset(&pw)));

  /* Thirty frames over a table of eight slots. If any one of them took a slot, the table would fill and the
   * frame after it would go out unretained, which the counter below would show. */
  for (i = 0U; i < 10U; i++) {
    WT_EXPECT_OK("a probe goes out", wt_quic_connection_send_frame(
                                         &pair.client, WT_QUIC_SPACE_APPLICATION, &ping, 1, now));
    WT_EXPECT_OK("and a datagram after it",
                 wt_quic_connection_send_datagram(&pair.client, (const uint8_t *)"d", 1U, now));
    WT_EXPECT_OK(
        "then an acknowledgement, which is replaced rather than repeated",
        wt_quic_connection_send_frame(&pair.client, WT_QUIC_SPACE_APPLICATION, &ack, 0, now));
  }
  WT_EXPECT_U64("none of them asked for a retransmission slot", 0U,
                pair.client.control_frames_unretained);

  /* Which is only worth something if a frame that DOES need one still finds room afterwards. */
  WT_EXPECT_OK("a grant is in force", wt_quic_connection_set_max_data(&pair.client, 100000U));
  WT_EXPECT_OK("a MAX_DATA goes out", wt_quic_connection_send_max_data(&pair.client, 250000U, now));
  for (i = 0U; i < WT_QUIC_CONTROL_FRAMES_MAX; i++) {
    if (pair.client.control_frames[i].in_use) retained = 1;
  }
  WT_EXPECT_INT("and is retained, because the table was left empty", 1, retained);
  WT_EXPECT_U64("with nothing at all counted as unretained", 0U,
                pair.client.control_frames_unretained);

  close_pair(&pair);
}

/* AUD-0024. `validate_ack` is RFC 9000 section 19.3.1's chain, and its REFUSALS had no test at all: every ACK in
 * the suite was well formed, so the three checks below could be deleted without CI noticing. Measured, not
 * guessed -- line coverage showed lines 85 to 94 of `connection_loss.c` never executed.
 *
 * Each malformed range is encoded into a real packet and sent over the socket pair, so the refusal is exercised
 * through the public receive path exactly as a peer's frame would be. The expected close reason is
 * FRAME_ENCODING_ERROR, which is what `handle_ack` raises for a failed `validate_ack` -- and NOT the
 * PROTOCOL_VIOLATION an acknowledgement of an unsent packet gets, so a test that reached the wrong check cannot
 * pass by accident.
 */
void test_a_malformed_ack_range_is_refused(void) {
  /* Each case names the check it is aimed at. */
  static const struct {
    const char *label;
    uint64_t largest;
    uint64_t first_range;
    uint8_t ranges[4];
    size_t ranges_len;
  } cases[] = {
      /* Section 19.3.1: the Length of a range is at least one, so a zero-length range is malformed. */
      {"a zero-length range", 10U, 0U, {0x00U, 0x00U}, 2U},
      /* A Gap that would put `smallest` below zero: the chain is `smallest = largest - gap - 2`. */
      {"a gap past the smallest acknowledged", 1U, 0U, {0x00U, 0x00U}, 2U},
      /* A range that reaches past the largest acknowledged packet number. */
      /* 99 is a TWO-byte QUIC varint (0b01 prefix), so it is 0x40,0x63 -- not one byte. */
      {"a range longer than the acknowledgement", 10U, 0U, {0x00U, 0x40U, 0x63U}, 3U},
  };
  size_t i;

  for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
    connection_pair_t pair;
    wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
    uint8_t payload[64];
    uint8_t datagram[128];
    wt_writer_t w = wt_writer_init(payload, sizeof(payload));
    wt_quic_packet_build_t build;
    size_t payload_len;
    size_t datagram_len = 0U;
    uint64_t now = 30000000U + ((uint64_t)i * 1000000U);

    open_pair(WT_UDP_IPV4, &pair);
    ack.as.ack.largest = cases[i].largest;
    ack.as.ack.delay = 0U;
    ack.as.ack.first_range = cases[i].first_range;
    ack.as.ack.range_count = 1U;
    ack.as.ack.ranges = cases[i].ranges;
    ack.as.ack.ranges_len = cases[i].ranges_len;
    WT_EXPECT_OK(cases[i].label, wt_quic_frame_encode(&w, &ack));
    payload_len = wt_writer_offset(&w);

    memset(&build, 0, sizeof(build));
    build.type = WT_QUIC_PACKET_INITIAL;
    build.version = WT_QUIC_VERSION_1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.source_connection_id = k_server_scid;
    build.source_connection_id_len = sizeof(k_server_scid);
    build.packet_number = 0U;
    build.packet_number_length = 1U;
    build.payload = payload;
    build.payload_len = payload_len;
    build.keys = &pair.server.keys_out[WT_QUIC_SPACE_INITIAL];
    WT_EXPECT_OK("  the packet builds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("  the peer sends it",
                 wt_udp_send(&pair.server_socket, &pair.client_address, datagram, datagram_len));

    receive_on(&pair.client, &pair.client_socket, now);
    WT_EXPECT_INT("  and the client closes", 1, wt_quic_connection_is_closed(&pair.client));
    WT_EXPECT_U64("  with a frame encoding error", (uint64_t)WT_QUIC_FRAME_ENCODING_ERROR,
                  pair.client.close.error_code);
    close_pair(&pair);
  }
}
