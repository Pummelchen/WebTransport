/* Frames that cross a real handshake: an HTTP/3 refusal close and a reliable stream reset. */

#include "test_runtime_session_pair_internal.h"

/* A peer that breaks a rule is told WHICH rule, in the frame RFC 9114 requires (WT-159).
 *
 * The chain is three layers long: the frame arrives through the connection, the HTTP/3 driver refuses it with an
 * HTTP/3 error code, and the driver -- bound to the connection -- states that refusal as an APPLICATION close, so
 * the peer reads a CONNECTION_CLOSE of type 0x1d whose code is H3_FRAME_ERROR. Nothing in this tree drove that
 * chain before, which is why the layer that did the reporting could be the wrong one twice. */
void test_a_refusal_reaches_the_peer_as_an_application_close(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t server_transport;
  wt_quic_frame_t frame;
  /* A HEADERS frame (0x01) whose declared length never arrives: the stream ends before the frame does, which
   * RFC 9114 makes a connection error of type H3_FRAME_ERROR. */
  static const uint8_t k_truncated[] = {0x01U, 0x40U};
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the server's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);
  /* The binding is what makes the driver state its own refusals: without it the driver reports the status and the
   * connection closes the TRANSPORT with INTERNAL_ERROR, which names no HTTP/3 rule at all. */
  wt_http3_driver_bind_connection(&server.driver, &pair.server.connection);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
  frame.as.stream.id = 0U;
  frame.as.stream.offset = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = k_truncated;
  frame.as.stream.length = sizeof(k_truncated);
  frame.as.stream.fin = 1;
  WT_EXPECT_OK("the truncated frame is sent",
               wt_quic_connection_send_frame(&pair.client.connection, WT_QUIC_SPACE_APPLICATION, &frame, 1,
                                             pair.now));

  /* A few rounds: the frame crosses, the server refuses, and its close crosses back. */
  (void)pump_pair(&pair, 20U, NULL);
  {
    const wt_quic_close_state_t *close_state = wt_quic_connection_close_state(&pair.server.connection);
    WT_EXPECT_U64("the server closed the connection", (uint64_t)WT_QUIC_CLOSE_APPLICATION,
                  (uint64_t)close_state->kind);
    WT_EXPECT_U64("with H3_FRAME_ERROR", (uint64_t)WT_HTTP3_FRAME_ERROR, close_state->error_code);
    /* The application form has no frame-type field, which is what distinguishes it from the transport form on
     * the wire (RFC 9000 section 19.19). */
    WT_EXPECT_U64("and the application form names no frame", 0U, close_state->frame_type);
  }
  /* And the PEER knows: the code it reads is the HTTP/3 one, in the application form that can carry it. */
  WT_EXPECT_INT("the peer was told", 1, pair.client.connection.peer_closed);
  WT_EXPECT_U64("with the same HTTP/3 code", (uint64_t)WT_HTTP3_FRAME_ERROR,
                pair.client.connection.peer_error_code);
  WT_EXPECT_U64("and in the application form", (uint64_t)WT_QUIC_CLOSE_APPLICATION,
                (uint64_t)pair.client.connection.peer_close_kind);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* A reliable stream reset, from one endpoint to the other, over a real handshake (WT-161).
 *
 * The reliable-stream-reset extension is what draft-16 relies on for a WebTransport stream's SESSION PREFIX: the
 * prefix is the first thing on the stream, so a reset that dropped it would leave the peer with a stream it cannot
 * attribute to a session. Both endpoints advertise it, one commits to four bytes, and the other reads back the
 * offset it may still rely on -- which is the whole point of the extension and the whole of this test. */
void test_a_reliable_stream_reset_crosses_the_connection(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  uint64_t stream_id = 0U;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the server's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  WT_EXPECT_INT("and both ends advertised the extension", 1,
                pair.client.connection.peer_limits.reset_stream_at != 0 &&
                    pair.server.connection.peer_limits.reset_stream_at != 0);

  WT_EXPECT_OK("a stream opens", wt_quic_connection_open_stream(&pair.client.connection, 1, &stream_id));
  WT_EXPECT_OK("four bytes are sent",
               wt_quic_connection_send_stream(&pair.client.connection, stream_id, 0U,
                                              (const uint8_t *)"abcd", 4U, 0, pair.now));
  /* Recording the send is the caller's, exactly as the HTTP/3 transport adapter does it, and it is what makes the
   * final size four rather than zero. */
  WT_EXPECT_OK("and recorded", wt_quic_stream_on_data_sent(wt_quic_connection_stream(&pair.client.connection,
                                                                                     stream_id), 4U));
  WT_EXPECT_OK("a commitment of four bytes of it is sent",
               wt_quic_connection_reset_stream_at(&pair.client.connection, stream_id, 0x0bU, 4U, pair.now));

  (void)pump_pair(&pair, 20U, NULL);
  /* The peer read the packets and its driver saw frames -- asserted because the SEND half's effect is local and
   * the receive half is covered where the frame can be injected whole: `test_the_reliable_stream_reset_rules` in
   * `test_quic_connection`. What this test adds is that the frame crosses a REAL handshake at all. */
  WT_EXPECT_TRUE("the client sent packets", pair.client.connection.packets_sent >= 2U);
  WT_EXPECT_TRUE("the server read them", pair.server.packets_seen >= 2U);
  WT_EXPECT_TRUE("and its driver saw frames", server.frames_seen > 0U);
  WT_EXPECT_U64("without a receive error", 0U, (uint64_t)pair.server.receive_errors);
  {
    /* The sender's side of a reliable reset, which is what this test can assert here: the send half is ended and
     * the final size is the four bytes that were sent -- the number the receiver is told and the bound the
     * commitment is checked against. */
    wt_quic_stream_t *stream = wt_quic_connection_stream(&pair.client.connection, stream_id);
    WT_EXPECT_TRUE("the sender has the stream", stream != NULL);
    if (stream != NULL) {
      WT_EXPECT_INT("with its send half reset", 1, wt_quic_stream_send_finished(stream));
      WT_EXPECT_U64("and a final size of the four bytes sent", 4U, stream->final_size);
    }
  }

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}
