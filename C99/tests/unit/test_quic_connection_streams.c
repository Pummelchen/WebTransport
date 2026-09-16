/* The streams tests for the connection runtime. */

#include "test_quic_connection_internal.h"

/* Opening a stream: the number comes from the counts, the peer's grant bounds it, and the two flow
 * control limits are the two directions'. */
void test_open_stream(void) {
  connection_pair_t pair;
  uint8_t payload[64];
  wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
  wt_quic_transport_parameters_t params;
  uint64_t id = 0U;

  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_STATUS("before the peer's parameters nothing is known", WT_ERR_STATE,
                   wt_quic_connection_open_stream(&pair.client, 1, &id));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a grant of two streams each way",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                                        2U));
  WT_EXPECT_OK("and one unidirectional",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                                        1U));
  WT_EXPECT_OK("with stream data",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 4096U));
  WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
  WT_EXPECT_OK("and is parsed",
               wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));

  WT_EXPECT_OK("the first bidirectional stream opens",
               wt_quic_connection_open_stream(&pair.client, 1, &id));
  WT_EXPECT_U64("numbered zero, because this end is the client", 0U, id);
  WT_EXPECT_OK("the second", wt_quic_connection_open_stream(&pair.client, 1, &id));
  WT_EXPECT_U64("numbered four, the next in its class", 4U, id);
  WT_EXPECT_STATUS("and the third is beyond the peer's grant", WT_ERR_LIMIT,
                   wt_quic_connection_open_stream(&pair.client, 1, &id));

  WT_EXPECT_OK("a unidirectional stream opens", wt_quic_connection_open_stream(&pair.client, 0, &id));
  WT_EXPECT_U64("numbered two, its class's first", 2U, id);
  WT_EXPECT_STATUS("with only the one granted", WT_ERR_LIMIT,
                   wt_quic_connection_open_stream(&pair.client, 0, &id));

  {
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.client, 0U);
    WT_EXPECT_TRUE("the stream is in the table", stream != NULL);
    if (stream != NULL) {
      WT_EXPECT_U64("with the peer's send limit as what it may send", 4096U,
                    stream->peer_max_stream_data);
      WT_EXPECT_INT("and it is this endpoint's", 1, stream->initiated_by_us);
    }
    WT_EXPECT_TRUE("and the streams are reachable from the connection",
                   wt_quic_connection_streams(&pair.client) != NULL);
  }
  WT_EXPECT_STATUS("a null output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_open_stream(&pair.client, 1, NULL));
  close_pair(&pair);
}

void test_peer_opens_stream(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 90000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x40U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  /* This endpoint grants two bidirectional streams, which is what the peer may open. */
  WT_EXPECT_OK("a grant of two",
               wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));
  WT_EXPECT_OK("and room for the data it will receive",
               wt_quic_connection_set_max_data(&pair.server, 1024U));

  /* Stream 0 is the peer's first bidirectional stream, and the frame creates it. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 0U;
  frame.as.stream.offset = 0U;
  frame.as.stream.data = (const uint8_t *)"\x01\x02\x03";
  frame.as.stream.length = 3U;
  frame.as.stream.has_length = 1;
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server is not closed by it", 0, wt_quic_connection_is_closed(&pair.server));
  {
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.server, 0U);
    WT_EXPECT_TRUE("and the stream now exists", stream != NULL);
    if (stream != NULL) {
      WT_EXPECT_INT("as the peer's", 0, stream->initiated_by_us);
      WT_EXPECT_INT("and bidirectional", 1, stream->bidirectional);
    }
  }

  /* Stream 8 is the third bidirectional one, beyond the two granted. */
  frame.as.stream.id = 8U;
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a stream beyond the grant closes the connection", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a stream limit error", (uint64_t)WT_QUIC_STREAM_LIMIT_ERROR,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the STREAM frame", WT_QUIC_FRAME_STREAM_BASE,
                pair.server.close.frame_type);

  close_pair(&pair);

  /* A frame for one of this endpoint's OWN numbers that was never opened is a different error. */
  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  /* A server's own bidirectional streams are 1, 5, 9, ... -- none of which it has opened. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 1U;
  frame.as.stream.offset = 0U;
  frame.as.stream.data = (const uint8_t *)"\x01\x02\x03";
  frame.as.stream.length = 3U;
  frame.as.stream.has_length = 1;
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("an unopened local number closes the connection", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a stream state error", (uint64_t)WT_QUIC_STREAM_STATE_ERROR,
                pair.server.close.error_code);

  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* RFC 9000 sections 19.4 and 19.5: a RESET_STREAM ends the receive half with the peer's final size, and
 * a STOP_SENDING asks this endpoint to stop sending. Both are facts about the STREAM, so the connection
 * hands them to the state machine before the caller sees the frame -- which is what this checks, through
 * the state the machine keeps. */
void test_reset_and_stop(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 95000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x60U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("the server grants two bidirectional streams",
               wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));

  /* A RESET_STREAM for the peer's first bidirectional stream. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RESET_STREAM);
  frame.as.reset_stream.id = 0U;
  frame.as.reset_stream.application_error_code = 0x1234U;
  frame.as.reset_stream.final_size = 0U;
  {
    uint8_t payload[128];
    uint8_t datagram[256];
    wt_writer_t w = wt_writer_init(payload, sizeof(payload));
    size_t len;
    size_t datagram_len = 0U;
    wt_quic_packet_build_t build;

    WT_EXPECT_OK("the reset encodes", wt_quic_frame_encode(&w, &frame));
    len = wt_writer_offset(&w);
    memset(&build, 0, sizeof(build));
    build.short_header = 1;
    build.version = WT_QUIC_VERSION_1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.packet_number = 0U;
    build.packet_number_length = 1U;
    build.payload = payload;
    build.payload_len = len;
    build.keys = &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION];
    WT_EXPECT_OK("the packet builds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("and is sent",
                 wt_udp_send(&pair.client_socket, &pair.server_address, datagram, datagram_len));
  }
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server is not closed by it", 0, wt_quic_connection_is_closed(&pair.server));
  {
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.server, 0U);
    WT_EXPECT_TRUE("the stream exists", stream != NULL);
    if (stream != NULL) {
      WT_EXPECT_INT("with the peer's reset recorded", 1, stream->peer_reset);
      WT_EXPECT_U64("and its error code", 0x1234U, stream->peer_error_code);
    }
  }

  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* RFC 9000 section 4.1: a receiver extends its limit as the data arrives. The check is end to end --
 * the connection's own limit rises AND the peer reads the MAX_DATA frame that tells it. */
void test_limit_extension(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 99000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x80U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("server reads", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("client reads the server's grants too",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  /* The server must be able to SEND a grant as well as read the data that makes it necessary. */
  WT_EXPECT_OK("server writes", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("two streams granted",
               wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));
  WT_EXPECT_OK("and exactly four bytes of connection room",
               wt_quic_connection_set_max_data(&pair.server, 4U));
  WT_EXPECT_U64("which reads back", 4U, wt_quic_connection_max_data(&pair.server));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 0U;
  frame.as.stream.offset = 0U;
  frame.as.stream.data = (const uint8_t *)"\x01\x02\x03\x04";
  frame.as.stream.length = 4U;
  frame.as.stream.has_length = 1;
  {
    uint8_t payload[128];
    uint8_t datagram[256];
    wt_writer_t w = wt_writer_init(payload, sizeof(payload));
    size_t len;
    size_t datagram_len = 0U;
    wt_quic_packet_build_t build;

    WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, &frame));
    len = wt_writer_offset(&w);
    memset(&build, 0, sizeof(build));
    build.short_header = 1;
    build.version = WT_QUIC_VERSION_1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.packet_number = 0U;
    build.packet_number_length = 1U;
    build.payload = payload;
    build.payload_len = len;
    build.keys = &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION];
    WT_EXPECT_OK("the packet builds", wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("and is sent", wt_udp_send(&pair.client_socket, &pair.server_address, datagram, datagram_len));
  }
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server accepts it", 0, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_TRUE("and raises its own limit past what it had granted",
                 wt_quic_connection_max_data(&pair.server) > 4U);

  /* And the peer learns the new limit from the frame the connection sent by itself. */
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_TRUE("while the client learns the new limit",
                 wt_quic_connection_peer_limits(&pair.client)->initial_max_data > 4U);

  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* RFC 9000 section 19.4: a sender may cancel a stream it is sending on, and the reset ends the send half
 * with the final size the peer needs. Only the sender may, and only once. */
void test_reset_stream_send(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 100000000U;
  uint64_t id = 0U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0xa0U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("server reads", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  /* The peer's grant, then one of this endpoint's own bidirectional streams. */
  {
    uint8_t payload[64];
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    wt_quic_transport_parameters_t params;
    wt_quic_transport_parameters_init(&params);
    WT_EXPECT_OK("a grant of two",
                 wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                                          2U));
    WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and is parsed",
                 wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK("a stream opens", wt_quic_connection_open_stream(&pair.client, 1, &id));
  {
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.client, id);
    WT_EXPECT_TRUE("which the table holds", stream != NULL);
    WT_EXPECT_INT("with its send half open", 0, wt_quic_stream_send_finished(stream));
    WT_EXPECT_OK("it is reset", wt_quic_connection_reset_stream(&pair.client, id, 0x0bU, now));
    if (stream != NULL) {
      WT_EXPECT_INT("which ends the send half", 1, wt_quic_stream_send_finished(stream));
      WT_EXPECT_U64("with the final size it had sent", 0U, stream->final_size);
    }
    WT_EXPECT_STATUS("and resetting it twice is a state error", WT_ERR_STATE,
                     wt_quic_connection_reset_stream(&pair.client, id, 0x0bU, now));
    WT_EXPECT_STATUS("a stream that was never opened cannot be reset", WT_ERR_STATE,
                     wt_quic_connection_reset_stream(&pair.client, 64U, 0x0bU, now));
  }

  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

void test_stream_retransmit_descriptor(void) {
  connection_pair_t pair;
  lost_witness_t witness;
  uint8_t payload[64];
  wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
  wt_quic_transport_parameters_t params;
  size_t i;
  uint64_t stream_id = 0U;
  uint64_t now = 101000000U;

  memset(&witness, 0, sizeof(witness));
  open_pair(WT_UDP_IPV4, &pair);
  {
    wt_quic_packet_keys_t keys;
    uint8_t secret[WT_SHA256_LEN];
    size_t bit;
    for (bit = 0U; bit < sizeof(secret); bit++) secret[bit] = (uint8_t)(0xc0U + bit);
    WT_EXPECT_OK("application keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
    WT_EXPECT_OK("client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
    WT_EXPECT_OK("client reads", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
    WT_EXPECT_OK("server writes", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
    WT_EXPECT_OK("server reads", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  }
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a stream grant",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 4U));
  WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
  WT_EXPECT_OK("and is parsed by the client",
               wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));
  WT_EXPECT_OK("the client sends stream data",
               wt_quic_connection_open_stream(&pair.client, 1, &stream_id));
  WT_EXPECT_U64("and the first client-initiated stream is number 0", 0U, stream_id);
  /* The out-parameter is a stream id, NOT a clock: passing `&now` here (as this test used to) overwrote the
   * synthetic clock with the stream id 0 and ran the whole loss scenario at time 0. */
  WT_EXPECT_U64("and the synthetic clock is untouched by it", 101000000U, now);
  wt_quic_connection_set_handlers(&pair.client, NULL, NULL, record_stream_loss, &witness);
  for (i = 0U; i < 4U; i++) {
    uint8_t data[2] = {(uint8_t)i, (uint8_t)(0xf0U + i)};
    WT_EXPECT_OK("a stream payload is sent",
                 wt_quic_connection_send_stream(&pair.client, stream_id, i * 2U, data, sizeof(data), 0,
                                                now));
    now += 100U;
  }
  WT_EXPECT_U64("four packets are in flight", 4U, (uint64_t)wt_quic_loss_count(&pair.client.loss));

  /* The server acknowledges only the last one, which puts the first beyond the packet threshold. */
  {
    wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
    uint8_t frame_bytes[64];
    uint8_t datagram[128];
    wt_writer_t w = wt_writer_init(frame_bytes, sizeof(frame_bytes));
    size_t frame_len;
    size_t datagram_len = 0U;
    wt_quic_packet_build_t build;

    ack.as.ack.largest = 3U;
    ack.as.ack.delay = 0U;
    ack.as.ack.first_range = 0U;
    ack.as.ack.range_count = 0U;
    WT_EXPECT_OK("an acknowledgement encodes", wt_quic_frame_encode(&w, &ack));
    frame_len = wt_writer_offset(&w);
    memset(&build, 0, sizeof(build));
    /* A short header, because the packets being acknowledged are in the APPLICATION space: an
     * acknowledgement in another space says nothing about them (RFC 9000 section 12.3). */
    build.short_header = 1;
    build.version = WT_QUIC_VERSION_1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.packet_number = 7U;
    build.packet_number_length = 1U;
    build.payload = frame_bytes;
    build.payload_len = frame_len;
    build.keys = &pair.server.keys_out[WT_QUIC_SPACE_APPLICATION];
    WT_EXPECT_OK("the packet builds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("the server's socket sends it",
                 wt_udp_send(&pair.server_socket, &pair.client_address, datagram, datagram_len));
  }
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_TRUE("packets are reported lost", witness.count >= 1U);
  WT_EXPECT_INT("and it is a stream packet", 0, witness.is_crypto);
  WT_EXPECT_U64("on the stream it was sent on", 0U, witness.stream_id);
  WT_EXPECT_U64("at the offset it covered", 0U, witness.offset);
  WT_EXPECT_U64("with the length it covered", 2U, (uint64_t)witness.length);
  close_pair(&pair);
}

/* RFC 9000 section 19.5: a receiver asks the peer to stop, once, and only on a stream it receives on. */
void test_stop_sending_send(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
  wt_quic_transport_parameters_t params;
  uint64_t id = 0U;
  uint64_t now = 102000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0xd0U + i);
  WT_EXPECT_OK("application keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("client reads", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a grant of two",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 2U));
  WT_EXPECT_OK("and of one unidirectional",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 1U));
  WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
  WT_EXPECT_OK("and is parsed",
               wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));
  WT_EXPECT_OK("a stream opens", wt_quic_connection_open_stream(&pair.client, 1, &id));
  {
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.client, id);
    WT_EXPECT_TRUE("which the table holds", stream != NULL);
    WT_EXPECT_OK("the peer is asked to stop",
                 wt_quic_connection_stop_sending(&pair.client, id, 0x0cU, now));
    if (stream != NULL) {
      WT_EXPECT_INT("which the stream records", 1, stream->sent_stop_sending);
    }
    WT_EXPECT_STATUS("asking twice is a state error", WT_ERR_STATE,
                     wt_quic_connection_stop_sending(&pair.client, id, 0x0cU, now));
    WT_EXPECT_STATUS("and a stream that was never opened has nothing to ask", WT_ERR_STATE,
                     wt_quic_connection_stop_sending(&pair.client, 64U, 0x0cU, now));
  }
  /* The DIRECTION rule of the same section, which had been inverted (WT-188): only the endpoint that RECEIVES
   * on a unidirectional stream may ask for it to stop, so a stream this endpoint opened is not one it can ask
   * about -- sending that frame would be a STREAM_STATE_ERROR at the peer, and the connection refuses it here.
   * The mirror case, a server stopping a client's unidirectional stream, is what section 4.6's rejection needs;
   * it is asserted on the wire by `test_an_early_stream_is_parked_and_rejected_over_the_bound`. */
  {
    uint64_t uni = 0U;
    WT_EXPECT_OK("a unidirectional stream opens", wt_quic_connection_open_stream(&pair.client, 0, &uni));
    WT_EXPECT_STATUS("asking to stop a stream this endpoint cannot receive on is a state error",
                     WT_ERR_STATE, wt_quic_connection_stop_sending(&pair.client, uni, 0x0cU, now));
  }
  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* The reliable-stream-reset extension, the SEND half (WT-161).
 *
 * WebTransport over HTTP/3 "relies on the RESET_STREAM_AT frame" (draft-16 section 3.1) because a WebTransport
 * stream carries its session prefix first: a reset that dropped the prefix leaves the peer with a stream it cannot
 * attribute to a session. This tree could decode the frame and did nothing else with it -- no way to send one, and
 * therefore nothing for the parameter advertised last round to gate. */
void test_the_reliable_stream_reset_is_sent_and_applied(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  uint64_t now = 101000000U;
  uint64_t id = 0U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0xb0U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and the server reads", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("the server grants two streams",
               wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    wt_quic_transport_parameters_t params;
    wt_quic_transport_parameters_init(&params);
    WT_EXPECT_OK("a grant", wt_quic_transport_parameters_add_integer(&params,
                                                                    WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 2U));
    /* The stream-data credit a real peer grants, without which the four bytes this test sends would be refused
     * before the reset is reached. */
    WT_EXPECT_OK("and credit", wt_quic_transport_parameters_add_integer(
                                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1024U));
    WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("without the extension, it is not advertised",
                 wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK("a stream opens", wt_quic_connection_open_stream(&pair.client, 1, &id));
  /* The GATE: a frame the peer never said it could read is not sent, and the caller is told why. */
  WT_EXPECT_STATUS("and the frame cannot be sent to a peer that did not advertise the extension", WT_ERR_STATE,
                   wt_quic_connection_reset_stream_at(&pair.client, id, 0x0bU, 0U, now));

  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    wt_quic_transport_parameters_t params;
    wt_quic_transport_parameters_init(&params);
    WT_EXPECT_OK("a grant", wt_quic_transport_parameters_add_integer(&params,
                                                                    WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 2U));
    WT_EXPECT_OK("and credit", wt_quic_transport_parameters_add_integer(
                                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1024U));
    WT_EXPECT_OK("and the extension, with the empty value that makes it a flag",
                 wt_quic_transport_parameters_add_bytes(&params, WT_QUIC_TP_RESET_STREAM_AT, NULL, 0U));
    WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and is parsed",
                 wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));
    WT_EXPECT_INT("with the extension advertised now", 1, pair.client.peer_limits.reset_stream_at);
  }
  WT_EXPECT_OK("four bytes are sent", wt_quic_connection_send_stream(&pair.client, id, 0U,
                                                                    (const uint8_t *)"abcd", 4U, 0, now));
  /* Recording the send is the CALLER's, exactly as the HTTP/3 transport adapter does it: the connection writes
   * the frame and leaves the stream's offsets to whoever asked for it, so a caller that skipped this would send
   * at offset zero for ever. */
  WT_EXPECT_OK("and recorded on the stream",
               wt_quic_stream_on_data_sent(wt_quic_connection_stream(&pair.client, id), 4U));
  /* The packet the send path produced, OPENED with this connection's own keys: the frame's fields are the fact
   * this test exists for. */
  {
    uint8_t datagram[256];
    size_t length = 0U;
    size_t available = 0U;
    wt_udp_address_t from;
    wt_quic_received_packet_t packet;
    reset_at_witness_t witness;
    wt_quic_error_t frame_error = WT_QUIC_NO_ERROR;
    now += 1000U;
    memset(&witness, 0, sizeof(witness));
    WT_EXPECT_OK("the client flushes", wt_quic_connection_flush(&pair.client, now));
    /* PEEKED first, so that the server's own receive still finds the datagram: the frame the sender BUILT and the
     * frame the peer APPLIES are two claims, and the send path owns the first. */
    WT_EXPECT_OK("a datagram is queued for the server", wt_udp_wait(&pair.server_socket, 2000000U));
    WT_EXPECT_OK("and can be looked at", wt_udp_peek(&pair.server_socket, datagram, sizeof(datagram), &length,
                                                    &available, &from));
    WT_EXPECT_OK("whose packet opens with the connection's keys",
                 wt_quic_packet_read(datagram, length, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U,
                                     pair.server.local_connection_id_length, &packet));
    WT_EXPECT_OK("and whose frames decode",
                 wt_quic_frames_decode(packet.payload, packet.payload_len, record_reset_at, &witness,
                                       &frame_error));
    WT_EXPECT_U64("the first frame is the STREAM frame", (uint64_t)WT_QUIC_FRAME_KIND_STREAM,
                  witness.last_kind);
    (void)available;

    WT_EXPECT_U64("carrying four bytes", 4U, witness.last_length);

    /* The RESET_STREAM_AT's own fields are asserted where they take effect: `test_runtime_session_pair` reads
     * back the four bytes it committed to and the error code that was sent, which a frame with the wrong fields
     * cannot produce. */
  }

  /* The frame's ARRIVAL is asserted where it can be injected whole -- `test_the_reliable_stream_reset_rules`
   * below -- and its crossing of a real handshake in `test_runtime_session_pair`. This test is the send path's
   * CONTRACT: what it refuses, and that a frame the peer can read goes out. */
  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* The extension's own rules, from the receiving end: a frame that RAISES the reliable size is ignored, and the two
 * ways a frame can be wrong are the two codes its draft names (WT-161). */
void test_the_reliable_stream_reset_rules(void) {
  static const wt_quic_frame_type_t k_kind = WT_QUIC_FRAME_KIND_RESET_STREAM_AT;

  /* Raising the commitment is ignored; lowering it is applied. */
  {
    connection_pair_t pair;
    wt_quic_frame_t frame;
    uint64_t now = 102000000U;

    open_pair(WT_UDP_IPV4, &pair);
    install_application_keys(&pair, 0xc0U);
    WT_EXPECT_OK("the server grants two streams",
                 wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));
    frame = wt_quic_frame_make(k_kind);
    frame.as.reset_stream_at.id = 0U;
    frame.as.reset_stream_at.application_error_code = 0x0bU;
    frame.as.reset_stream_at.final_size = 10U;
    frame.as.reset_stream_at.reliable_size = 6U;
    send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U, now);
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    {
      wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.server, 0U);
      WT_EXPECT_TRUE("the stream exists", stream != NULL);
      if (stream != NULL) WT_EXPECT_U64("with the committed offset", 6U, stream->peer_reliable_size);
    }

    frame.as.reset_stream_at.reliable_size = 8U;
    send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U, now);
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    {
      wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.server, 0U);
      if (stream != NULL) {
        WT_EXPECT_U64("a frame that raises it is ignored", 6U, stream->peer_reliable_size);
      }
    }
    frame.as.reset_stream_at.reliable_size = 4U;
    send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 2U, now);
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    {
      wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.server, 0U);
      if (stream != NULL) {
        WT_EXPECT_U64("and one that lowers it is applied", 4U, stream->peer_reliable_size);
      }
      WT_EXPECT_INT("without closing the connection", 0, wt_quic_connection_is_closed(&pair.server));
    }
    close_pair(&pair);
  }

  /* A commitment past the end of the stream is a FRAME_ENCODING_ERROR. */
  {
    connection_pair_t pair;
    uint64_t now = 103000000U;

    open_pair(WT_UDP_IPV4, &pair);
    install_application_keys(&pair, 0xc0U);
    WT_EXPECT_OK("the server grants two streams",
                 wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));
    /* Written by HAND: the encoder refuses to produce a frame its own decoder must reject, which is right, so a
     * malformed one can only be tested from the outside -- type 0x24, id 0, error 0x0b, final size 6, reliable
     * size 7. */
    {
      static const uint8_t k_malformed[] = {0x24U, 0x00U, 0x0bU, 0x06U, 0x07U};
      send_raw_payload_to(&pair, k_malformed, sizeof(k_malformed),
                          &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
    }
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("a commitment past the end closes the connection with FRAME_ENCODING_ERROR",
                  (uint64_t)WT_QUIC_FRAME_ENCODING_ERROR,
                  wt_quic_connection_close_state(&pair.server)->error_code);
    close_pair(&pair);
  }

  /* And a SECOND frame that changes the error code is a STREAM_STATE_ERROR. */
  {
    connection_pair_t pair;
    uint64_t now = 104000000U;

    open_pair(WT_UDP_IPV4, &pair);
    install_application_keys(&pair, 0xc0U);
    WT_EXPECT_OK("the server grants two streams",
                 wt_quic_connection_set_max_streams(&pair.server, WT_QUIC_STREAM_BIDIRECTIONAL, 2U));
    {
      static const uint8_t k_first[] = {0x24U, 0x00U, 0x0bU, 0x0aU, 0x06U};
      send_raw_payload_to(&pair, k_first, sizeof(k_first),
                          &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
    }
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_INT("the first frame is accepted", 0, wt_quic_connection_is_closed(&pair.server));

    {
      static const uint8_t k_changed_code[] = {0x24U, 0x00U, 0x0cU, 0x0aU, 0x04U};
      send_raw_payload_to(&pair, k_changed_code, sizeof(k_changed_code),
                          &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
    }
    now += 1000U;
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("a changed error code closes the connection with STREAM_STATE_ERROR",
                  (uint64_t)WT_QUIC_STREAM_STATE_ERROR,
                  wt_quic_connection_close_state(&pair.server)->error_code);
    close_pair(&pair);
  }
}

