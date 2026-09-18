/* A terminated session's streams are reset with the draft's own code (WT-182). */

#include "test_runtime_session_pair_internal.h"

/* WT-182: draft-16 section 6's reset of a terminated session's streams.
 *
 * "Upon learning that the session has been terminated, the endpoint MUST reset the send side and abort reading on
 * the receive side of all unidirectional and bidirectional streams associated with the session ... using the
 * WT_SESSION_GONE error code; it MUST NOT send any new datagrams or open any new streams."
 *
 * The session object records that a session ended; the DRIVER is what knows which streams belonged to it, so the
 * assertion has to be made where the two meet -- a real pair, a real stream, and a peer that says what it saw. The
 * code on the wire is the draft's own registered one and NOT an application error, which is the distinction
 * `webtransport/error.h` exists for (WT-181).
 */
void test_a_terminated_session_resets_its_streams(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint64_t request_stream_id = 0U;
  uint64_t stream_id = 0U;
  uint64_t finished_stream = 0U;
  size_t ended = 0U;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;
  WT_EXPECT_OK("the client's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &client));
  WT_EXPECT_OK("and the server's",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);
  wt_http3_driver_bind_connection(&client.driver, &pair.client.connection);
  wt_http3_driver_bind_connection(&server.driver, &pair.server.connection);

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the client advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("the client starts a session",
               wt_http3_driver_start_session(&client.driver, &client_transport, &settings,
                                             "example.com", "/chat", 0U, pair.now,
                                             &request_stream_id, &h3_error));
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;
  rounds = pump_pair(&pair, 400U, connect_arrived);
  WT_EXPECT_TRUE("the CONNECT arrives", rounds < 400U);
  WT_EXPECT_OK("and the server answers it",
               wt_http3_driver_send_response(&server.driver, &server_transport, request_stream_id,
                                             200U, 0U, 0, pair.now));
  {
    unsigned round;
    for (round = 0U; round < 400U && client.section_complete == 0; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_TRUE("the response arrives, so the session is established",
                 client.section_complete != 0);

  /* A WebTransport data stream, opened THROUGH the driver: that is what remembers it, with the prefix this
   * endpoint wrote (which is what section 4.4's Reliable Size commits to). */
  /* TWO streams, because the two cases are different: one still OPEN, whose send side section 6 must abort, and
   * one this endpoint already FINished, which has nothing left to abort and must not turn the call into a failure.
   * The live one is opened second so that the reset assertion below is about it. */
  WT_EXPECT_OK("the client opens a stream it finishes",
               wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0,
                                                (const uint8_t *)"done", 4U, 1, pair.now,
                                                &finished_stream));
  WT_EXPECT_OK("and one it leaves open",
               wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0,
                                                (const uint8_t *)"message", 7U, 0, pair.now,
                                                &stream_id));
  {
    unsigned round;
    for (round = 0U; round < 400U && server.stream_bytes < 11U; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_U64("both messages arrive on the peer", 11U, (uint64_t)server.stream_bytes);
  WT_EXPECT_INT("which classified the finished stream as WebTransport's", 1,
                wt_http3_driver_is_data_stream(&server.driver, finished_stream));
  WT_EXPECT_INT("and the open one too", 1,
                wt_http3_driver_is_data_stream(&server.driver, stream_id));

  /* The connection still has the stream, and the driver can read what a reset would commit to: both are what
   * section 6's reset needs, and asserting them here is what tells "the reset was refused" apart from "the stream
   * was already gone". */
  {
    uint64_t offset = 0U;
    WT_EXPECT_TRUE("the connection still holds the data stream",
                   wt_quic_connection_stream(&pair.client.connection, stream_id) != NULL);
    WT_EXPECT_OK(
        "and its send offset is readable",
        wt_quic_connection_stream_send_offset(&pair.client.connection, stream_id, &offset));
    WT_EXPECT_TRUE("with the prefix on it", offset > 0U);
  }

  /* The session ends. */
  WT_EXPECT_OK("the session's streams are ended",
               wt_http3_driver_end_session_streams(&client.driver, pair.now, &ended));
  WT_EXPECT_U64("one stream was reset", 1U, (uint64_t)ended);
  WT_EXPECT_INT("and the driver reports the session ended", 1,
                wt_http3_driver_session_ended(&client.driver));
  /* Section 6's two MUST NOTs. */
  WT_EXPECT_STATUS("a new data stream after the end is refused", WT_ERR_STATE,
                   wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0,
                                                    (const uint8_t *)"more", 4U, 1, pair.now,
                                                    NULL));
  WT_EXPECT_STATUS(
      "and so is a datagram", WT_ERR_STATE,
      wt_http3_driver_send_datagram(&client.driver, &client_transport, (const uint8_t *)"x", 1U));

  /* And the peer SEES it: a reset carrying the draft's own code. */
  {
    unsigned round;
    for (round = 0U; round < 400U && server.resets == 0U; round++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_U64("the peer saw one reset", 1U, (uint64_t)server.resets);
  WT_EXPECT_U64("carrying WT_SESSION_GONE, not an application error",
                WT_WEBTRANSPORT_ERROR_SESSION_GONE, server.last_reset_code);
  /* A second call does nothing: the streams were forgotten, so there is nothing to reset twice. */
  WT_EXPECT_OK("ending the session again is a no-op",
               wt_http3_driver_end_session_streams(&client.driver, pair.now, &ended));
  WT_EXPECT_U64("with no streams left to end", 0U, (uint64_t)ended);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}
