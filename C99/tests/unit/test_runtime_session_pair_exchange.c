/* The whole loopback exchange: the handshake, and then a CONNECT and its response. */

#include "test_runtime_session_pair_internal.h"

/* ---- the tests ------------------------------------------------------------------------------- */

void test_a_handshake_completes_over_loopback(void) {
  pair_t pair;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes under the pump", rounds < 400U);
  WT_EXPECT_STATUS("the client's handshake did not fail", WT_OK,
                   wt_runtime_session_failure(&pair.client));
  WT_EXPECT_STATUS("nor the server's", WT_OK, wt_runtime_session_failure(&pair.server));
  WT_EXPECT_INT("the client's handshake is confirmed", 1,
                wt_runtime_session_established(&pair.client));
  /* DONE and CONFIRMED are separate states (WT-142). This pair reaches both -- the server sends the
   * HANDSHAKE_DONE that confirms the client -- and the accessor exists so a caller can tell which it has: a
   * client may speak once its handshake is DONE, and waiting for CONFIRMED is what stalled the interop run. */
  WT_EXPECT_INT("the client's handshake is DONE", 1, wt_runtime_session_handshake_done(&pair.client));
  WT_EXPECT_INT("and so is the server's", 1, wt_runtime_session_handshake_done(&pair.server));
  WT_EXPECT_INT("and the server's too", 1, wt_runtime_session_established(&pair.server));
  WT_EXPECT_INT("with application keys on the client", 1,
                wt_runtime_session_keys_ready(&pair.client));
  WT_EXPECT_INT("and on the server", 1, wt_runtime_session_keys_ready(&pair.server));
  WT_EXPECT_TRUE("the client read packets", pair.client.packets_seen > 0U);
  WT_EXPECT_TRUE("and so did the server", pair.server.packets_seen > 0U);
  WT_EXPECT_U64("neither refused a packet", 0U,
                (uint64_t)(pair.client.receive_errors + pair.server.receive_errors));
  WT_EXPECT_STATUS("and both flushes were clean", WT_OK, pair.client.last_flush);
  WT_EXPECT_STATUS("on both sides", WT_OK, pair.server.last_flush);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

void test_a_connect_and_its_response_cross_the_connection(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_message_t decoded;
  wt_http3_message_t response_message;
  wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint64_t request_stream_id = 0U;
  uint8_t scratch[1024];
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);

  /* The handshake first: without it there are no application keys and HTTP/3's bytes would go nowhere. */
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  WT_EXPECT_INT("with the client confirmed", 1, wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("and the server too", 1, wt_runtime_session_established(&pair.server));

  init_side(&client, WT_HTTP3_ROLE_CLIENT);
  init_side(&server, WT_HTTP3_ROLE_SERVER);
  pair.server_side = &server;

  /* The HTTP/3 layer joins BEHIND the handshake's handler, which is what the chaining is for. */
  WT_EXPECT_OK("the client's HTTP/3 layer joins",
               wt_runtime_session_set_frame_handler(&pair.client, side_on_frame, &client));
  WT_EXPECT_OK("and the server's",
               wt_runtime_session_set_frame_handler(&pair.server, side_on_frame, &server));
  wt_http3_driver_quic_transport(&pair.client.connection, &client_transport);
  wt_http3_driver_quic_transport(&pair.server.connection, &server_transport);

  /* THE CLIENT'S OPENING SEQUENCE IN ONE CALL: its own streams, a request stream, and the extended CONNECT.
   * The sinks are told which stream carries the exchange the moment it exists, because a section cannot be
   * assembled by a side that does not know what it is looking at. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the client advertises WebTransport",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("the client starts a session",
               wt_http3_driver_start_session(&client.driver, &client_transport, &settings,
                                             "example.com", "/chat", 0U, pair.now,
                                             &request_stream_id, &h3_error));
  WT_EXPECT_U64("on its first bidirectional stream", 0U, request_stream_id);
  client.request_stream_id = request_stream_id;
  server.request_stream_id = request_stream_id;

  rounds = pump_pair(&pair, 400U, connect_arrived);
  WT_EXPECT_TRUE("the CONNECT arrives at the server", rounds < 400U);

  /* The server's side of the conversation: the CONNECT's section assembled from the driver's pieces, the
   * control stream's SETTINGS counted, and the stream tracked as a request stream by the routing. */
  WT_EXPECT_TRUE("the server's HTTP/3 layer was asked about frames", server.frames_seen > 0U);
  WT_EXPECT_U64("the control stream's frame arrived", 1U, (uint64_t)server.control_frames);
  WT_EXPECT_U64("as SETTINGS", WT_HTTP3_FRAME_SETTINGS, server.last_control_type);
  WT_EXPECT_OK("the server tracks the request stream",
               wt_http3_endpoint_request_state(&server.endpoint, request_stream_id, &state));
  WT_EXPECT_INT("expecting the request line", (int)WT_HTTP3_REQUEST_EXPECT_HEADERS, (int)state);

  /* Decoding and the draft-16 DECISION are two layers on purpose: HTTP/3 does not know what a WebTransport
   * request is, and that separation is what the whole phase has kept. */
  WT_EXPECT_OK("the section decodes off the wire",
               wt_http3_endpoint_on_request_headers(&server.endpoint, request_stream_id, server.section,
                                                    server.section_length, scratch, sizeof(scratch),
                                                    &decoded, &h3_error));
  WT_EXPECT_BYTES("as the method that was sent", (const uint8_t *)"CONNECT", decoded.method,
                  decoded.method_length);
  WT_EXPECT_BYTES("the scheme", (const uint8_t *)"https", decoded.scheme, decoded.scheme_length);
  WT_EXPECT_BYTES("the authority", (const uint8_t *)"example.com", decoded.authority,
                  decoded.authority_length);
  WT_EXPECT_BYTES("the path", (const uint8_t *)"/chat", decoded.path, decoded.path_length);
  WT_EXPECT_BYTES("and the protocol", (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN, decoded.protocol,
                  decoded.protocol_length);
  policy.authority = "example.com";
  policy.path = "/chat";
  policy.wt_enabled = 1;
  WT_EXPECT_OK("the draft-16 layer accepts it",
               wt_webtransport_session_request_validate(&decoded, &policy, &decision, &h3_error));
  WT_EXPECT_INT("as a WebTransport request", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                (int)decision.outcome);
  WT_EXPECT_OK("and the request state advances",
               wt_http3_endpoint_request_state(&server.endpoint, request_stream_id, &state));
  WT_EXPECT_INT("past the request line", (int)WT_HTTP3_REQUEST_BODY, (int)state);

  /* THE RESPONSE: the other direction of the same exchange, on the same stream, decoded with the RESPONSE
   * rules because a response is neither the request line nor a trailer. */
  WT_EXPECT_TRUE("the server has the stream to answer on",
                 wt_quic_connection_stream(&pair.server.connection, request_stream_id) != NULL);
  WT_EXPECT_OK("the server answers the CONNECT",
               wt_http3_driver_send_response(&server.driver, &server_transport, request_stream_id, 200U,
                                             0U, 0, pair.now));
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
  WT_EXPECT_TRUE("the response arrives at the client", client.section_complete != 0);
  if (client.section_complete != 0) {
    WT_EXPECT_OK("and decodes as a response",
                 wt_http3_endpoint_on_response_headers(&client.endpoint, request_stream_id,
                                                       client.section, client.section_length, scratch,
                                                       sizeof(scratch), &response_message, &h3_error));
    WT_EXPECT_INT("carrying a status", 1, response_message.has_status);
    WT_EXPECT_U64("of 200", 200U, response_message.status);
    WT_EXPECT_STATUS("a second response on the same stream is refused", WT_ERR_STATE,
                     wt_http3_endpoint_on_response_headers(&client.endpoint, request_stream_id,
                                                           client.section, client.section_length,
                                                           scratch, sizeof(scratch), &response_message,
                                                           &h3_error));
  }

  /* A MESSAGE ON A WEBTRANSPORT STREAM, which is what `--exchange stream` means: a unidirectional stream whose
   * first bytes are the draft's `0x54` prefix and the session ID, then the session's own data. The driver's
   * unidirectional path already classifies that type, so nothing new is needed to carry it -- and the bytes
   * arrive at the session sink rather than being parsed as HTTP/3 frames. */
  {
    uint8_t message[64];
    wt_writer_t w = wt_writer_init(message, sizeof(message));
    uint64_t stream_id = 0U;

    WT_EXPECT_OK("the client opens a unidirectional stream",
                 client_transport.open_stream(client_transport.context, 0, &stream_id, pair.now));
    WT_EXPECT_OK("and writes the WebTransport prefix",
                 wt_webtransport_stream_prefix_write(&w, 1, request_stream_id));
    wt_writer_bytes(&w, "message", 7U);
    WT_EXPECT_OK("then the message",
                 client_transport.send_stream(client_transport.context, stream_id, message,
                                              wt_writer_offset(&w), 0, pair.now));
    {
      unsigned round;
      for (round = 0U; round < 400U && server.stream_bytes == 0U; round++) {
        (void)wt_udp_wait(&pair.server_socket, 2000U);
        (void)wt_udp_wait(&pair.client_socket, 2000U);
        if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
        if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
        pair.now += 1000U;
      }
    }
    WT_EXPECT_U64("the server received the message", 7U, (uint64_t)server.stream_bytes);
    WT_EXPECT_BYTES("as the bytes that were sent", (const uint8_t *)"message", server.stream_data,
                    server.stream_bytes);
    WT_EXPECT_U64("on the stream it was sent on", stream_id, server.last_stream_id);
  }

  /* A MESSAGE AS A DATAGRAM, which is what `--exchange datagram` means: the draft's own framing -- a quarter
   * stream ID and the payload -- sent in a QUIC DATAGRAM frame. A datagram IS the unit, so there is no
   * reassembly and no ordering: what arrives is either the whole thing or nothing at all. */
  {
    uint8_t framed[128];
    wt_writer_t w = wt_writer_init(framed, sizeof(framed));
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    wt_http3_error_t datagram_error = WT_HTTP3_NO_ERROR;

    WT_EXPECT_OK("the datagram writes with its quarter stream ID",
                 wt_webtransport_datagram_write(&w, request_stream_id / 4U,
                                                (const uint8_t *)"ping", 4U));
    WT_EXPECT_OK("and goes out",
                 client_transport.send_datagram(client_transport.context, framed,
                                                wt_writer_offset(&w)));
    {
      unsigned round;
      for (round = 0U; round < 400U && server.datagrams == 0U; round++) {
        (void)wt_udp_wait(&pair.server_socket, 2000U);
        (void)wt_udp_wait(&pair.client_socket, 2000U);
        if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
        if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
        pair.now += 1000U;
      }
    }
    WT_EXPECT_U64("the server received a datagram", 1U, (uint64_t)server.datagrams);
    WT_EXPECT_OK("whose framing parses the way the session layer parses it",
                 wt_webtransport_datagram_parse(server.datagram, server.datagram_bytes, &quarter,
                                                &payload, &payload_length, &datagram_error));
    WT_EXPECT_U64("naming this session's quarter stream ID", request_stream_id / 4U, quarter);
    WT_EXPECT_U64("with the payload's length", 4U, (uint64_t)payload_length);
    WT_EXPECT_BYTES("and the payload", (const uint8_t *)"ping", payload, payload_length);
  }

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}
