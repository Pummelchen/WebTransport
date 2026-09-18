/* The basics tests for the connection runtime. */

#include "test_quic_connection_internal.h"

/* One exchange: the client sends a CRYPTO payload, the server receives it and acknowledges, and the
 * client takes the acknowledgement. Everything the runtime is for happens in these four calls. */
void test_round_trip(wt_udp_family_t family) {
  connection_pair_t pair;
  static const uint8_t payload[] = {0x01U, 0x00U, 0x00U, 0x2aU, 0x03U, 0x03U, 0xaaU, 0xbbU};
  uint64_t now = 1000000U;
  uint64_t window_before;

  open_pair(family, &pair);
  window_before = wt_quic_congestion_window(&pair.client.congestion);
  WT_EXPECT_TRUE("a fresh connection has a window", window_before > 0U);

  WT_EXPECT_OK("the client's first packet is sent",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U, payload,
                                              sizeof(payload), now));
  WT_EXPECT_U64("which counts as one packet", 1U, pair.client.packets_sent);
  WT_EXPECT_U64("with one packet in flight", 1U, (uint64_t)wt_quic_loss_count(&pair.client.loss));
  WT_EXPECT_TRUE("and bytes in flight", wt_quic_loss_bytes_in_flight(&pair.client.loss) > 0U);

  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("as one packet", 1U, pair.server.packets_received);
  WT_EXPECT_U64("whose CRYPTO frame reached the handler", 1U, (uint64_t)pair.server_witness.count);
  WT_EXPECT_U64("in the Initial space", (uint64_t)WT_QUIC_SPACE_INITIAL,
                (uint64_t)pair.server_witness.frames[0].space);
  WT_EXPECT_U64("of kind CRYPTO", (uint64_t)WT_QUIC_FRAME_KIND_CRYPTO,
                (uint64_t)pair.server_witness.frames[0].kind);
  WT_EXPECT_U64("at offset zero", 0U, pair.server_witness.frames[0].offset);
  WT_EXPECT_U64("with the payload", (uint64_t)sizeof(payload),
                (uint64_t)pair.server_witness.frames[0].length);
  WT_EXPECT_BYTES("byte for byte", payload, pair.server_witness.frames[0].data, sizeof(payload));

  /* The acknowledgement is owed, and appears on the next flush. A CRYPTO frame is ack-eliciting, so
   * the acknowledgement is prompt (RFC 9000 section 13.2.1). */
  now += 1000U;
  WT_EXPECT_OK("the server flushes", wt_quic_connection_flush(&pair.server, now));
  WT_EXPECT_U64("sending one packet", 1U, pair.server.packets_sent);
  WT_EXPECT_INT("and owing none afterwards", 0,
                wt_quic_ack_should_send(&pair.server.spaces[WT_QUIC_SPACE_INITIAL].received));

  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_U64("with nothing left in flight", 0U, (uint64_t)wt_quic_loss_count(&pair.client.loss));
  WT_EXPECT_U64("and no bytes in flight", 0U, wt_quic_loss_bytes_in_flight(&pair.client.loss));
  /* The round trip sample is the difference between the two `now` values the test chose: 3000us. */
  WT_EXPECT_U64("the round trip is measured", 3000U,
                pair.client.spaces[WT_QUIC_SPACE_INITIAL].rtt.latest);
  WT_EXPECT_U64("the largest acknowledged is remembered", 0U,
                pair.client.spaces[WT_QUIC_SPACE_INITIAL].largest_acked);
  /* RFC 9002 section 7.3.1: in slow start the window grows by the acknowledged bytes. */
  WT_EXPECT_TRUE("and the congestion window grew",
                 wt_quic_congestion_window(&pair.client.congestion) > window_before);

  /* Nothing else is owed, so a second flush sends nothing. */
  now += 1000U;
  WT_EXPECT_OK("a second flush", wt_quic_connection_flush(&pair.client, now));
  WT_EXPECT_U64("sends nothing", 1U, pair.client.packets_sent);

  close_pair(&pair);
}

/* The padding rule WT-72 asks for: a packet whose payload is too short to carry a header protection
 * sample is padded rather than refused, and the padding is not ack-eliciting. This is checked on the
 * wire: a fresh connection's first packet number is zero and its largest acknowledged is unset, so the
 * number is encoded in one byte, and a one-byte PING is below the three bytes the sample needs. */
void test_short_packet_is_padded(wt_udp_family_t family) {
  connection_pair_t pair;
  uint64_t now = 5000000U;

  open_pair(family, &pair);
  /* A fresh connection owes no acknowledgement, so a flush sends nothing. */
  WT_EXPECT_OK("a flush on a fresh connection", wt_quic_connection_flush(&pair.client, now));
  WT_EXPECT_U64("as nothing, because nothing is owed", 0U, pair.client.packets_sent);

  /* The padding is exercised through the probe path: arm a probe by giving the connection something
   * in flight and letting the probe timeout fire. */
  WT_EXPECT_OK("a CRYPTO payload is sent",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U,
                                              (const uint8_t *)"\x01\x02\x03\x04", 4U, now));
  WT_EXPECT_U64("as one packet", 1U, pair.client.packets_sent);

  /* The server never answers, so the probe timeout fires and the client sends a PING -- which is one
   * byte, and with a one-byte packet number it cannot be header-protected without padding. */
  now += 2000000U;
  WT_EXPECT_OK("the timeout fires", wt_quic_connection_on_timeout(&pair.client, now));
  WT_EXPECT_U64("sending a probe", 2U, pair.client.packets_sent);

  /* And it arrives, which is the proof that the padding made it protectable at all: a packet whose
   * sample did not fit would never have been built. */
  /* Two datagrams are waiting: the CRYPTO payload and the probe. */
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("as two packets", 2U, pair.server.packets_received);

  close_pair(&pair);
}

/* The packet threshold: RFC 9002 section 6.1.1 declares a packet lost when a packet at least three
 * numbers higher has been acknowledged. The test acknowledges the fourth packet by hand -- which is
 * what makes it a test of the threshold rather than of the network -- and requires that exactly the
 * first packet is reported lost, that its descriptor names the CRYPTO offset to send again, and that
 * the congestion controller entered recovery once. */
void test_packet_threshold_loss(void) {
  connection_pair_t pair;
  uint64_t now = 9000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < 4U; i++) {
    uint8_t payload[2] = {(uint8_t)i, (uint8_t)(0xf0U + i)};
    WT_EXPECT_OK("a payload is sent",
                 wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, i * 2U,
                                                payload, sizeof(payload), now));
    now += 100U;
  }
  WT_EXPECT_U64("four packets are in flight", 4U, (uint64_t)wt_quic_loss_count(&pair.client.loss));

  /* An acknowledgement of packet number 3 and nothing else, built here and protected with the keys
   * the client can read: what the server would have sent if only the last of the four had arrived. */
  {
    wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
    uint8_t payload[64];
    uint8_t datagram[128];
    size_t payload_len = 0U;
    size_t datagram_len = 0U;
    wt_writer_t w = wt_writer_init(payload, sizeof(payload));
    wt_quic_packet_build_t build;

    ack.as.ack.largest = 3U;
    ack.as.ack.delay = 0U;
    ack.as.ack.first_range = 0U;
    /* ACK Range Count counts the ADDITIONAL ranges, and this one has none: it acknowledges the single
     * packet number in Largest Acknowledged. */
    ack.as.ack.range_count = 0U;
    WT_EXPECT_OK("a hand-built acknowledgement encodes", wt_quic_frame_encode(&w, &ack));
    payload_len = wt_writer_offset(&w);

    memset(&build, 0, sizeof(build));
    build.type = WT_QUIC_PACKET_INITIAL;
    build.version = WT_QUIC_VERSION_1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.source_connection_id = k_server_scid;
    build.source_connection_id_len = sizeof(k_server_scid);
    build.packet_number = 7U;
    build.packet_number_length = 1U;
    build.payload = payload;
    build.payload_len = payload_len;
    /* The server's send keys are the client's receive keys, which is what makes this a packet the
     * client accepts as coming from its peer. */
    build.keys = &pair.server.keys_out[WT_QUIC_SPACE_INITIAL];
    WT_EXPECT_OK("and the packet builds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("which the server's socket sends",
                 wt_udp_send(&pair.server_socket, &pair.client_address, datagram, datagram_len));
  }

  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  /* The packet threshold declares exactly the first packet lost; the time threshold may also declare
   * the second, because the fourth packet's round trip sample makes the first packets old. The
   * property that matters is that the losses start at the first packet -- a sender retransmits in the
   * order packets were sent -- and that the descriptor names the bytes to send again. */
  WT_EXPECT_TRUE("at least the first packet is lost", pair.client_witness.lost_count >= 1U);
  WT_EXPECT_U64("and it is the first, by its CRYPTO offset", 0U,
                pair.client_witness.lost_offsets[0]);
  /* Four were sent, one was acknowledged and `lost_count` were declared lost; what is left is in
   * flight. Counting it this way keeps the test from encoding the threshold arithmetic twice. */
  WT_EXPECT_U64("and the rest are neither acknowledged nor lost",
                (uint64_t)(3U - pair.client_witness.lost_count),
                (uint64_t)wt_quic_loss_count(&pair.client.loss));
  WT_EXPECT_INT("and the congestion controller is in recovery", 1,
                wt_quic_congestion_in_recovery(&pair.client.congestion));

  close_pair(&pair);
}

/* RFC 9000 section 13.1: an acknowledgement of a packet that was never sent is a protocol violation. */
void test_ack_for_unsent_packet(void) {
  connection_pair_t pair;
  uint64_t now = 20000000U;
  wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
  uint8_t payload[64];
  uint8_t datagram[128];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t payload_len;
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;

  open_pair(WT_UDP_IPV4, &pair);
  ack.as.ack.largest = 0U;
  ack.as.ack.delay = 0U;
  ack.as.ack.first_range = 0U;
  ack.as.ack.range_count = 0U;
  WT_EXPECT_OK("an acknowledgement of packet zero encodes", wt_quic_frame_encode(&w, &ack));
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
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("the server sends it",
               wt_udp_send(&pair.server_socket, &pair.client_address, datagram, datagram_len));

  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_INT("and closes", 1, wt_quic_connection_is_closed(&pair.client));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.client.close.error_code);
  WT_EXPECT_U64("naming the acknowledgement", WT_QUIC_FRAME_ACK, pair.client.close.frame_type);

  close_pair(&pair);
}

/* The close paths: a close is a frame, a peer's close ends the connection, and the draining period is
 * three probe timeouts. */
void test_close_paths(void) {
  connection_pair_t pair;
  uint64_t now = 30000000U;

  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("a CRYPTO payload is sent",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U,
                                              (const uint8_t *)"\x09\x09", 2U, now));
  now += 1000U;
  WT_EXPECT_INT("the client is not closed", 0, wt_quic_connection_is_closed(&pair.client));

  WT_EXPECT_OK(
      "it closes with an error",
      wt_quic_connection_close(&pair.client, 0x0aU, WT_QUIC_FRAME_STREAM_BASE, NULL, 0U, now));
  WT_EXPECT_INT("and is closed", 1, wt_quic_connection_is_closed(&pair.client));
  WT_EXPECT_U64("with the transport kind", (uint64_t)WT_QUIC_CLOSE_TRANSPORT,
                (uint64_t)wt_quic_close_kind(&pair.client.close));
  WT_EXPECT_INT("but not drained yet", 0, wt_quic_connection_is_drained(&pair.client, now));

  /* The close frame goes out on the next flush, in the highest space with keys. */
  WT_EXPECT_OK("the close is flushed", wt_quic_connection_flush(&pair.client, now));
  WT_EXPECT_U64("sending a packet", 2U, pair.client.packets_sent);
  WT_EXPECT_INT("and only once", 1, pair.client.close_sent);
  WT_EXPECT_OK("a second flush", wt_quic_connection_flush(&pair.client, now));
  WT_EXPECT_U64("sends nothing more", 2U, pair.client.packets_sent);

  /* The server reads the close and ends too, without sending anything back: the peer closed first. */
  /* Two datagrams are waiting: the CRYPTO packet sent before the close, and the close itself. A
   * caller reads what is there, in the order it arrived. */
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the first datagram is not a close", 0, wt_quic_connection_is_closed(&pair.server));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("and is closed", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_INT("by the peer", 1, pair.server.peer_closed);
  WT_EXPECT_U64("with the peer's code", 0x0aU, pair.server.peer_error_code);
  WT_EXPECT_U64("and the frame that caused it", WT_QUIC_FRAME_STREAM_BASE,
                pair.server.peer_frame_type);
  WT_EXPECT_U64("sending nothing in response", 0U, pair.server.packets_sent);

  /* The draining period is three probe timeouts, and after it the connection is gone. */
  {
    uint64_t drain = 0U;
    WT_EXPECT_OK("the server has a draining deadline",
                 wt_quic_connection_next_timeout(&pair.server, now, &drain));
    WT_EXPECT_TRUE("which is in the future", drain > 0U);
    WT_EXPECT_INT("the connection is not drained before it", 0,
                  wt_quic_connection_is_drained(&pair.server, now + drain - 1U));
    WT_EXPECT_INT("and is after", 1, wt_quic_connection_is_drained(&pair.server, now + drain));
  }

  /* RFC 9000 section 10.2.1: a frame that arrives after the connection closed is not processed. The
   * server is peer-closed by now, and a MAX_DATA frame from the client must not move the limit it
   * grants -- the packet is read, because a closed connection still reads PADDING and closes, and the
   * frame inside it is ignored. */
  {
    wt_quic_frame_t max_data = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
    uint8_t payload[64];
    uint8_t datagram[128];
    wt_writer_t w = wt_writer_init(payload, sizeof(payload));
    size_t payload_len;
    size_t datagram_len = 0U;
    wt_quic_packet_build_t build;
    uint64_t granted;
    /* The server is told what its peer grants it, so that the frame below has something to move. It is
     * the PEER's limit, not this endpoint's: one is what it may send, the other what it allows. */
    {
      wt_quic_transport_parameters_t params;
      wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
      wt_quic_transport_parameters_init(&params);
      WT_EXPECT_OK(
          "a peer limit to be contradicted",
          wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_DATA, 50000U));
      WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
      WT_EXPECT_OK(
          "and is parsed by the server",
          wt_quic_connection_set_peer_parameters(&pair.server, payload, wt_writer_offset(&pw)));
    }
    granted = wt_quic_connection_peer_limits(&pair.server)->initial_max_data;
    WT_EXPECT_U64("the server knows what the peer granted", 50000U, granted);
    max_data.as.max_data.maximum = 90000U;
    WT_EXPECT_OK("a MAX_DATA frame encodes", wt_quic_frame_encode(&w, &max_data));
    payload_len = wt_writer_offset(&w);

    memset(&build, 0, sizeof(build));
    build.type = WT_QUIC_PACKET_INITIAL;
    build.version = WT_QUIC_VERSION_1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.source_connection_id = k_server_scid;
    build.source_connection_id_len = sizeof(k_server_scid);
    build.packet_number = 9U;
    build.packet_number_length = 1U;
    build.payload = payload;
    build.payload_len = payload_len;
    /* The keys the server reads with, so that only the close can be the reason this is ignored. */
    build.keys = &pair.server.keys_in[WT_QUIC_SPACE_INITIAL];
    WT_EXPECT_OK("the packet builds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("and is sent from the client's socket",
                 wt_udp_send(&pair.client_socket, &pair.server_address, datagram, datagram_len));
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("whose frame is ignored rather than applied", granted,
                  wt_quic_connection_peer_limits(&pair.server)->initial_max_data);
  }

  /* The idle timeout is a silent close: nothing is sent and the state says so. */
  {
    uint64_t deadline = 0U;
    WT_EXPECT_OK("a quiet connection has an idle deadline",
                 wt_quic_connection_next_timeout(&pair.client, now, &deadline));
    WT_EXPECT_TRUE("which is armed", deadline > 0U);
  }

  close_pair(&pair);
}

/* A datagram from an address the connection is not talking to is discarded rather than answered: a
 * server that learned its peer from the first packet must not become a way to make this endpoint send
 * to an arbitrary address. A packet whose destination connection ID is not this endpoint's is
 * discarded too, which is what the client's own address is used for here -- so that only the
 * connection ID can be the reason. */
void test_discards(void) {
  connection_pair_t pair;
  wt_udp_socket_t stranger;
  wt_udp_address_t stranger_address;
  uint64_t now = 40000000U;
  uint16_t port = 0U;
  uint8_t datagram[64] = {0};
  size_t length = 0U;
  uint64_t ack_pending_before;
  wt_quic_packet_build_t build;

  open_pair(WT_UDP_IPV4, &pair);

  /* The client's first packet teaches the server its address. */
  WT_EXPECT_OK("the client sends a packet",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U,
                                              (const uint8_t *)"\x01", 1U, now));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("processing one packet", 1U, pair.server.packets_received);
  WT_EXPECT_INT("and knowing its peer", 1, pair.server.has_peer);

  /* A second socket sends a well-formed packet to the server. Its bytes would be accepted; its
   * address is not the one the server is talking to. */
  WT_EXPECT_OK("a stranger opens a socket", wt_udp_socket_open(&stranger, WT_UDP_IPV4));
  WT_EXPECT_OK("and binds loopback", wt_udp_bind_loopback(&stranger, 0U, &port));
  wt_udp_address_loopback(WT_UDP_IPV4, &stranger_address);
  stranger_address.port = port;

  memset(&build, 0, sizeof(build));
  build.type = WT_QUIC_PACKET_INITIAL;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.source_connection_id = k_server_scid;
  build.source_connection_id_len = sizeof(k_server_scid);
  build.packet_number = 0U;
  build.packet_number_length = 1U;
  /* Four bytes, because a one-byte packet number needs three bytes of payload before the header
   * protection sample fits at all (WT-72). */
  build.payload = (const uint8_t *)"\x01\x02\x03\x04";
  build.payload_len = 4U;
  /* The keys the server can read, so that only the address can refuse this one. */
  build.keys = &pair.server.keys_in[WT_QUIC_SPACE_INITIAL];
  WT_EXPECT_OK("a packet for the server builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &length));
  WT_EXPECT_OK("and the stranger sends it",
               wt_udp_send(&stranger, &pair.server_address, datagram, length));

  /* The acknowledgement the first packet is owed is unchanged: a discarded datagram is not
   * recorded, so it cannot make the connection owe anything. */
  ack_pending_before = (uint64_t)pair.server.spaces[WT_QUIC_SPACE_INITIAL].received.ack_pending;
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("and discards it for the address", 1U, pair.server.packets_discarded);
  WT_EXPECT_U64("processing nothing more", 1U, pair.server.packets_received);
  WT_EXPECT_U64("and owing no more acknowledgement than before", ack_pending_before,
                (uint64_t)pair.server.spaces[WT_QUIC_SPACE_INITIAL].received.ack_pending);

  /* Now one from the client's own address, with a destination connection ID that is not the server's:
   * the address is right and the packet is readable, so the connection ID is the only thing left to
   * refuse it. */
  build.destination_connection_id = k_server_scid;
  build.destination_connection_id_len = sizeof(k_server_scid);
  build.packet_number = 1U;
  WT_EXPECT_OK("a packet with another destination builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &length));
  WT_EXPECT_OK("and is sent from the client's own socket",
               wt_udp_send(&pair.client_socket, &pair.server_address, datagram, length));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("and discards it for the connection ID", 2U, pair.server.packets_discarded);
  WT_EXPECT_U64("processing two datagrams in all", 2U, pair.server.packets_received);

  wt_udp_close(&stranger);
  close_pair(&pair);
}

/* A datagram that is not a packet at all, and an empty one, are discarded rather than crashing. */
void test_garbage(wt_udp_family_t family) {
  connection_pair_t pair;
  wt_udp_socket_t stranger;
  wt_udp_address_t stranger_address;
  uint8_t garbage[32];
  uint16_t port = 0U;
  uint64_t now = 50000000U;
  size_t i;
  uint64_t received_before;

  open_pair(family, &pair);
  for (i = 0U; i < sizeof(garbage); i++)
    garbage[i] = (uint8_t)(0x40U + i);

  WT_EXPECT_OK("a stranger opens a socket", wt_udp_socket_open(&stranger, family));
  WT_EXPECT_OK("and binds loopback", wt_udp_bind_loopback(&stranger, 0U, &port));
  wt_udp_address_loopback(family, &stranger_address);
  stranger_address.port = port;

  /* The first datagram teaches the server the address, so what follows is judged on its bytes. The
   * first byte is 0x40, which is a short header with the fixed bit set: a 1-RTT packet, for which
   * this connection has no keys, so it is discarded. */
  WT_EXPECT_OK("garbage is sent",
               wt_udp_send(&stranger, &pair.server_address, garbage, sizeof(garbage)));
  WT_EXPECT_OK("the socket becomes readable", wt_udp_wait(&pair.server_socket, 2000000U));
  WT_EXPECT_OK("and the server reads it", wt_quic_connection_receive(&pair.server, now));
  /* It is discarded for the address, before its bytes are looked at: this connection was attached with
   * a peer, which is what a client has and what a server does not until its first packet arrives. */
  WT_EXPECT_U64("as a datagram from an unknown address", 1U, pair.server.packets_discarded);
  WT_EXPECT_U64("that is not a packet", 0U, pair.server.packets_received);

  /* An empty datagram from the peer itself reaches the length check, and is discarded as a datagram
   * that carries no packet. */
  received_before = pair.server.packets_received;
  WT_EXPECT_OK("an empty datagram is sent",
               wt_udp_send(&pair.client_socket, &pair.server_address, NULL, 0U));
  now += 1000U;
  WT_EXPECT_OK("the socket becomes readable", wt_udp_wait(&pair.server_socket, 2000000U));
  WT_EXPECT_OK("and the datagram is read", wt_quic_connection_receive(&pair.server, now));
  WT_EXPECT_U64("as a discarded datagram", 2U, pair.server.packets_discarded);
  WT_EXPECT_U64("and not a packet", received_before, pair.server.packets_received);

  wt_udp_close(&stranger);
  close_pair(&pair);
}

/* Discarding a space's keys is what RFC 9001 section 4.9 requires and what makes a packet of that
 * level stop being readable: the space is zeroed, a send there is refused, and doing it twice is not an
 * error. */
void test_key_discard(void) {
  connection_pair_t pair;
  static const uint8_t payload[] = {0x01U, 0x02U};

  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("a payload is sent in the Initial space",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U, payload,
                                              sizeof(payload), 1000U));
  WT_EXPECT_OK("the Initial keys are discarded",
               wt_quic_connection_discard_keys(&pair.client, WT_QUIC_SPACE_INITIAL));
  WT_EXPECT_INT("in both directions", 0, pair.client.has_keys_in[WT_QUIC_SPACE_INITIAL]);
  WT_EXPECT_INT("so nothing more can be sent there", 0,
                pair.client.has_keys_out[WT_QUIC_SPACE_INITIAL]);
  WT_EXPECT_STATUS("which a send reports", WT_ERR_STATE,
                   wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 2U, payload,
                                                  sizeof(payload), 2000U));
  WT_EXPECT_OK("discarding again is not an error",
               wt_quic_connection_discard_keys(&pair.client, WT_QUIC_SPACE_INITIAL));
  /* A space that never had keys, and the arguments. */
  WT_EXPECT_OK("a space with no keys is not an error either",
               wt_quic_connection_discard_keys(&pair.client, WT_QUIC_SPACE_HANDSHAKE));
  WT_EXPECT_STATUS("a space that is not one is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_discard_keys(&pair.client, WT_QUIC_SPACE_COUNT));
  WT_EXPECT_STATUS("and a null connection is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_discard_keys(NULL, WT_QUIC_SPACE_INITIAL));
  close_pair(&pair);
}

/* RFC 9000 section 19.20: a client sends HANDSHAKE_DONE only if it believes it is the server, and a
 * server that receives one must close the connection with a PROTOCOL_VIOLATION naming the frame. A client
 * that receives one is doing exactly what the frame is for, so it is not an error there.
 *
 * No handshake is needed: both ends are given application keys derived from one secret, so the packet the
 * test builds is one the receiver can read and the rule is the only thing that can refuse it. The payload
 * is padded to the three bytes header protection needs (WT-72) -- a bare one-byte HANDSHAKE_DONE frame
 * cannot be protected with a one-byte packet number, and a packet that cannot be built is a test that
 * proves nothing. */
void test_handshake_done_role(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 60000000U;
  uint8_t payload[8];
  uint8_t datagram[128];
  wt_writer_t w;
  size_t payload_len;
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x20U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("the server sends with them too",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and the client reads with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  /* A HANDSHAKE_DONE frame, then PADDING to what header protection needs. */
  w = wt_writer_init(payload, sizeof(payload));
  {
    wt_quic_frame_t done = wt_quic_frame_make(WT_QUIC_FRAME_KIND_HANDSHAKE_DONE);
    WT_EXPECT_OK("a HANDSHAKE_DONE encodes", wt_quic_frame_encode(&w, &done));
  }
  while (wt_writer_offset(&w) < 4U)
    wt_writer_u8(&w, 0U);
  payload_len = wt_writer_offset(&w);

  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 0U;
  build.packet_number_length = 1U;
  build.payload = payload;
  build.payload_len = payload_len;
  build.keys = &pair.client.keys_out[WT_QUIC_SPACE_APPLICATION];
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("and the client sends it",
               wt_udp_send(&pair.client_socket, &pair.server_address, datagram, datagram_len));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server is closed by it", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the frame", WT_QUIC_FRAME_HANDSHAKE_DONE, pair.server.close.frame_type);

  /* The other direction: a client that receives one is doing what the frame is for. */
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 1U;
  build.packet_number_length = 1U;
  build.payload = payload;
  build.payload_len = payload_len;
  build.keys = &pair.server.keys_out[WT_QUIC_SPACE_APPLICATION];
  datagram_len = 0U;
  WT_EXPECT_OK("a packet to the client builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("and the server sends it",
               wt_udp_send(&pair.server_socket, &pair.client_address, datagram, datagram_len));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_INT("the client is not closed by it", 0, wt_quic_connection_is_closed(&pair.client));

  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* RFC 9000 section 12.4: a frame that may not appear in the packet type it arrived in is a
 * PROTOCOL_VIOLATION. A STREAM frame in an Initial packet is the case the table rules out most plainly --
 * stream data has no meaning before the handshake is done -- and the connection names the frame it
 * refused. The packet is padded to the three bytes header protection needs (WT-72). */
void test_frame_permission(void) {
  connection_pair_t pair;
  uint64_t now = 70000000U;
  uint8_t payload[WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE];
  uint8_t datagram[WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE + 64U];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t payload_len;
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;

  open_pair(WT_UDP_IPV4, &pair);
  {
    static const uint8_t data[4] = {1U, 2U, 3U, 4U};
    wt_quic_frame_t stream = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
    stream.as.stream.id = 0U;
    stream.as.stream.offset = 0U;
    stream.as.stream.length = sizeof(data);
    stream.as.stream.has_length = 1;
    stream.as.stream.data = data;
    WT_EXPECT_OK("a STREAM frame encodes", wt_quic_frame_encode(&w, &stream));
  }
  while (wt_writer_offset(&w) < 3U)
    wt_writer_u8(&w, 0U);
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
  build.keys = &pair.server.keys_in[WT_QUIC_SPACE_INITIAL];
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  /* RFC 9000 section 14.1: a server discards an Initial datagram below 1200 bytes. This test is about
   * the frame permission rule, so the datagram is expanded to the minimum with PADDING frames -- the
   * discard itself is covered by its own test. */
  while (datagram_len < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE) {
    size_t shortfall = WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE - datagram_len;
    WT_EXPECT_TRUE("there is room for the padding", payload_len + shortfall <= sizeof(payload));
    memset(payload + payload_len, 0, shortfall);
    payload_len += shortfall;
    build.payload_len = payload_len;
    WT_EXPECT_OK("the packet rebuilds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  }
  WT_EXPECT_OK("the client sends it",
               wt_udp_send(&pair.client_socket, &pair.server_address, datagram, datagram_len));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server refuses it", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the STREAM frame", WT_QUIC_FRAME_STREAM_BASE, pair.server.close.frame_type);

  close_pair(&pair);
}

/* RFC 9000 section 14.1: a client expands every UDP datagram carrying an Initial packet to at least
 * 1200 bytes. The four-byte CRYPTO payload below is the case that matters, because a conformant
 * server discards the datagram that is not expanded -- so without this the handshake cannot start. */
void test_client_initial_datagram_is_padded(void) {
  connection_pair_t pair;
  uint64_t now = 109000000U;

  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("a four-byte CRYPTO payload is sent",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U,
                                              (const uint8_t *)"\x01\x02\x03\x04", 4U, now));
  WT_EXPECT_U64("as one datagram, expanded to the minimum", 1200U, pair.client.bytes_sent);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("and the server reads it", 1U, pair.server.packets_received);
  WT_EXPECT_U64("processing it rather than discarding it", 0U, pair.server.packets_discarded);
  WT_EXPECT_TRUE("with its packet number recorded",
                 pair.server.spaces[WT_QUIC_SPACE_INITIAL].received.has_largest != 0);
  close_pair(&pair);
}

/* The other half of section 14.1, which is what makes the send rule observable: a server discards an
 * Initial packet carried in a datagram smaller than 1200 bytes. The packet is hand-built because this
 * library's own client would have padded it. */
void test_short_initial_datagram_is_discarded(void) {
  connection_pair_t pair;
  wt_quic_frame_t frame;
  uint64_t now = 110000000U;

  open_pair(WT_UDP_IPV4, &pair);
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  send_short_initial_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_INITIAL], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("the datagram arrives", 1U, pair.server.packets_received);
  WT_EXPECT_U64("and is discarded", 1U, pair.server.packets_discarded);
  WT_EXPECT_TRUE("without a packet number being recorded",
                 pair.server.spaces[WT_QUIC_SPACE_INITIAL].received.has_largest == 0);
  WT_EXPECT_INT("and without closing the connection", 0,
                wt_quic_connection_is_closed(&pair.server));
  close_pair(&pair);
}

/* What a refusal leaves behind, which is the question a tool asks when a session ends badly (WT-144).
 *
 * The device this replaces was the HINT: a refusing handler may leave `close_code`/`close_code_set` for the
 * connection to name in its CONNECTION_CLOSE, and the connection CLEARS that flag before it closes. So a caller
 * that asked "what did we close with, and why" read zeroes -- indistinguishable from a connection that never
 * closed -- and a CLI went on printing `"status":"ok"` for a session it had ended with INTERNAL_ERROR. The close
 * STATE and the cause are kept instead, and this is the test that says so. */
void test_a_refusal_leaves_a_readable_close(wt_udp_family_t family) {
  connection_pair_t pair;
  static const uint8_t payload[] = {0x01U, 0x02U, 0x03U, 0x04U};
  unsigned refused = 0U;
  const wt_quic_close_state_t *close_state;
  uint64_t now = 1000000U;

  open_pair(family, &pair);
  wt_quic_connection_set_handlers(&pair.server, refuse_frame, &refused, record_lost,
                                  &pair.server_witness);
  WT_EXPECT_INT("a fresh connection has no close to report", 0,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and no cause", (uint64_t)WT_OK,
                (uint64_t)wt_quic_connection_close_cause(&pair.server));
  WT_EXPECT_U64("and no close state", (uint64_t)WT_QUIC_CLOSE_NONE,
                (uint64_t)wt_quic_connection_close_state(&pair.server)->kind);

  WT_EXPECT_OK("the client sends a frame",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U, payload,
                                              sizeof(payload), now));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("which the server's handler refused", 1U, (uint64_t)refused);

  WT_EXPECT_INT("so this endpoint is closed", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with the handler's own status kept as the cause", (uint64_t)WT_ERR_PROTOCOL,
                (uint64_t)wt_quic_connection_close_cause(&pair.server));
  close_state = wt_quic_connection_close_state(&pair.server);
  WT_EXPECT_U64("and a close state of kind transport", (uint64_t)WT_QUIC_CLOSE_TRANSPORT,
                (uint64_t)close_state->kind);
  /* No handler named a code, so the connection says what it sent: INTERNAL_ERROR, blaming no frame. That is
   * exactly the `code 0x1` the interop peer logged while this tree's tool reported success. */
  WT_EXPECT_U64("naming INTERNAL_ERROR", (uint64_t)WT_QUIC_INTERNAL_ERROR, close_state->error_code);
  WT_EXPECT_U64("and no frame type", 0U, close_state->frame_type);
  /* The hint is cleared, which is WHY the state above has to exist. */
  WT_EXPECT_INT("while the hint the handler could have left is cleared", 0,
                pair.server.close_code_set);
  /* The peer's own close is a different question and is still unanswered. */
  WT_EXPECT_INT("and nothing is recorded about the peer closing", 0, pair.server.peer_closed);

  close_pair(&pair);
}

void test_a_handler_can_name_the_code_it_refused_with(wt_udp_family_t family) {
  connection_pair_t pair;
  static const uint8_t payload[] = {0x05U, 0x06U, 0x07U, 0x08U};
  const wt_quic_close_state_t *close_state;
  uint64_t now = 1000000U;

  open_pair(family, &pair);
  wt_quic_connection_set_handlers(&pair.server, refuse_frame_with_code, &pair.server, record_lost,
                                  &pair.server_witness);
  WT_EXPECT_OK("the client sends a frame",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U, payload,
                                              sizeof(payload), now));
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);

  close_state = wt_quic_connection_close_state(&pair.server);
  WT_EXPECT_U64("the close the peer is told about names the handler's code",
                (uint64_t)WT_QUIC_STREAM_STATE_ERROR, close_state->error_code);
  WT_EXPECT_U64("and the frame the handler blamed", (uint64_t)WT_QUIC_FRAME_CRYPTO,
                close_state->frame_type);
  WT_EXPECT_U64("while the cause is still the status", (uint64_t)WT_ERR_PROTOCOL,
                (uint64_t)wt_quic_connection_close_cause(&pair.server));

  close_pair(&pair);
}

/* RFC 9000 section 12.4's Table 3 gives CRYPTO the packet types `IH01`, so a 1-RTT CRYPTO frame is ALLOWED --
 * that is where a server's post-handshake messages live. This endpoint used to answer one with PROTOCOL_VIOLATION
 * and close, and a third-party peer rejected it: quinn sends its NewSessionTicket on a 1-RTT CRYPTO frame, so the
 * session never started (WT-145). What the RFCs forbid is CRYPTO in 0-RTT (RFC 9001 section 4.6.1), and this tree
 * implements no 0-RTT. */
void test_crypto_is_permitted_in_the_application_space(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  static const uint8_t ticket[] = {0x04U, 0x00U, 0x00U, 0x00U};
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 95000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x50U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CRYPTO);
  frame.as.crypto.offset = 0U;
  frame.as.crypto.data = ticket;
  frame.as.crypto.length = sizeof(ticket);
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);

  WT_EXPECT_INT("a 1-RTT CRYPTO frame does not close the connection", 0,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and it reaches the handler", 1U, (uint64_t)pair.server_witness.count);
  WT_EXPECT_U64("as a CRYPTO frame", (uint64_t)WT_QUIC_FRAME_KIND_CRYPTO,
                (uint64_t)pair.server_witness.frames[0].kind);
  WT_EXPECT_U64("in the application space", (uint64_t)WT_QUIC_SPACE_APPLICATION,
                (uint64_t)pair.server_witness.frames[0].space);

  close_pair(&pair);
}

void test_an_http3_refusal_is_an_application_close(wt_udp_family_t family) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  const wt_quic_close_state_t *close_state;
  uint64_t now = 97000000U;
  size_t i;

  open_pair(family, &pair);
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x70U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  wt_quic_connection_set_handlers(&pair.server, refuse_with_h3_error, &pair.server, record_lost,
                                  &pair.server_witness);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);

  close_state = wt_quic_connection_close_state(&pair.server);
  WT_EXPECT_U64("the close is of the APPLICATION kind", (uint64_t)WT_QUIC_CLOSE_APPLICATION,
                (uint64_t)close_state->kind);
  WT_EXPECT_U64("carrying the HTTP/3 code the handler named", 0x107U, close_state->error_code);
  WT_EXPECT_U64("and the cause is still the status", (uint64_t)WT_ERR_PROTOCOL,
                (uint64_t)wt_quic_connection_close_cause(&pair.server));

  /* And the frame the peer is SENT is the application form: the transport form carries a frame-type field, and a
   * peer that read the HTTP/3 code as a transport code would blame a rule that does not exist. Asserted through
   * the encoder rather than by opening the packet, because the encoder is what writes the bytes. */
  {
    wt_quic_frame_t close_frame;
    memset(&close_frame, 0, sizeof(close_frame));
    WT_EXPECT_OK("the close encodes", wt_quic_close_frame(&pair.server.close, &close_frame));
    WT_EXPECT_U64("as a CONNECTION_CLOSE of the application form",
                  (uint64_t)WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION,
                  (uint64_t)close_frame.kind);
    WT_EXPECT_U64("whose code is the HTTP/3 one", 0x107U,
                  close_frame.as.connection_close.error_code);
    WT_EXPECT_INT("and which has no frame-type field", 0,
                  close_frame.as.connection_close.has_frame_type);
  }
  WT_EXPECT_OK("the server flushes its close", wt_quic_connection_flush(&pair.server, now));
  WT_EXPECT_INT("which was sent", 1, wt_quic_connection_close_was_sent(&pair.server));

  close_pair(&pair);
}

/* The space-name diagnostic. `wt_quic_space_name` is public API and, before
 * this test, had no caller anywhere in the tree; its siblings
 * (`wt_quic_frame_kind_name`, `wt_quic_packet_type_name`) are exercised by their
 * own suites, so this gives it the same treatment (F-repo-ops-08). WT_QUIC_SPACE_COUNT
 * is not a space and an out-of-range value must not be named as one. */
void test_quic_space_names(void) {
  WT_EXPECT_STR("the Initial space is named", "initial", wt_quic_space_name(WT_QUIC_SPACE_INITIAL));
  WT_EXPECT_STR("the Handshake space is named", "handshake",
                wt_quic_space_name(WT_QUIC_SPACE_HANDSHAKE));
  WT_EXPECT_STR("the Application space is named", "application",
                wt_quic_space_name(WT_QUIC_SPACE_APPLICATION));
  WT_EXPECT_STR("the count sentinel is not a space", "unknown",
                wt_quic_space_name(WT_QUIC_SPACE_COUNT));
  WT_EXPECT_STR("and neither is an out-of-range value", "unknown",
                wt_quic_space_name((wt_quic_space_t)99));
}
