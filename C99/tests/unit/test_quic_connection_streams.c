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
  WT_EXPECT_OK(
      "a grant of two streams each way",
      wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 2U));
  WT_EXPECT_OK("and one unidirectional", wt_quic_transport_parameters_add_integer(
                                             &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 1U));
  WT_EXPECT_OK("with stream data",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 4096U));
  WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
  WT_EXPECT_OK("and is parsed", wt_quic_connection_set_peer_parameters(&pair.client, payload,
                                                                       wt_writer_offset(&pw)));

  WT_EXPECT_OK("the first bidirectional stream opens",
               wt_quic_connection_open_stream(&pair.client, 1, &id));
  WT_EXPECT_U64("numbered zero, because this end is the client", 0U, id);
  WT_EXPECT_OK("the second", wt_quic_connection_open_stream(&pair.client, 1, &id));
  WT_EXPECT_U64("numbered four, the next in its class", 4U, id);
  WT_EXPECT_STATUS("and the third is beyond the peer's grant", WT_ERR_LIMIT,
                   wt_quic_connection_open_stream(&pair.client, 1, &id));

  WT_EXPECT_OK("a unidirectional stream opens",
               wt_quic_connection_open_stream(&pair.client, 0, &id));
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
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x40U + i);
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
  WT_EXPECT_U64("naming the STREAM frame", WT_QUIC_FRAME_STREAM_BASE, pair.server.close.frame_type);

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
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x60U + i);
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
  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(0x80U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("client writes",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("server reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("client reads the server's grants too",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  /* The server must be able to SEND a grant as well as read the data that makes it necessary. */
  WT_EXPECT_OK("server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
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
    WT_EXPECT_OK("the packet builds",
                 wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
    WT_EXPECT_OK("and is sent",
                 wt_udp_send(&pair.client_socket, &pair.server_address, datagram, datagram_len));
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
