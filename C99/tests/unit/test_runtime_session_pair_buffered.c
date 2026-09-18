/* A stream that arrives before its session: buffering, the bound, and the rejection (WT-180). */

#include "test_runtime_session_pair_internal.h"

/* SECTION 4.6'S STREAM HALF (WT-180). A client can send its CONNECT, its data streams and its datagrams in one
 * flight, so a server can receive a WebTransport stream before it has accepted the session the stream names.
 * The draft's answer is to BUFFER it and to bound what is buffered, and its own words for the bound are the
 * reason this is a reset rather than a drop: "When the number of buffered streams is exceeded, a stream MUST be
 * closed by sending a RESET_STREAM and/or STOP_SENDING with the WT_BUFFERED_STREAM_REJECTED error code."
 *
 * So the test drives the whole rule over a real pair, in the only order that makes it reachable: the client
 * opens its data streams BEFORE the server answers the CONNECT. There is no session on the server yet -- which
 * is exactly the window -- and the streams are parked, bounded, drained when the response gives them a session,
 * and one of them is rejected with the draft's code, which the client sees as a reset on the wire.
 */

typedef struct early_delivery {
  uint64_t stream_ids[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  size_t lengths[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  uint8_t bytes[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  size_t count;
} early_delivery_t;

static wt_status_t record_early_stream(void *context, uint64_t stream_id, int unidirectional,
                                       const uint8_t *data, size_t length) {
  early_delivery_t *delivery = context;
  if (delivery->count >= WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX) return WT_ERR_LIMIT;
  if (unidirectional == 0) return WT_ERR_STATE; /* the test's streams are all unidirectional */
  if (length > 0U) delivery->bytes[delivery->count] = data[0];
  delivery->stream_ids[delivery->count] = stream_id;
  delivery->lengths[delivery->count] = length;
  delivery->count++;
  return WT_OK;
}

void test_an_early_stream_is_parked_and_rejected_over_the_bound(void) {
  pair_t pair;
  http3_side_t client;
  http3_side_t server;
  wt_http3_driver_transport_t client_transport;
  wt_http3_driver_transport_t server_transport;
  wt_http3_settings_t settings;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_webtransport_buffered_t parked;
  early_delivery_t delivery;
  uint64_t request_stream_id = 0U;
  uint64_t early[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX];
  uint64_t over = 0U;
  uint64_t named = 0U;
  size_t index;
  size_t delivered = 0U;
  size_t dropped = 0U;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  memset(&delivery, 0, sizeof(delivery));
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
  /* And the server has NOT answered it: no session exists there yet, which is the window section 4.6 is
   * about. The driver was never told an ID, so it cannot check one either. */
  WT_EXPECT_INT("with no session accepted yet", 0, server.driver.session_id_set);

  /* The early flight: one more unidirectional WebTransport stream than an endpoint is willing to hold. Each
   * carries a byte, so the buffer's deliver callback can say which stream a byte came from. */
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    uint8_t payload = (uint8_t)('a' + index);
    WT_EXPECT_OK("an early stream opens",
                 wt_http3_driver_open_data_stream(&client.driver, &client_transport, 1, &payload,
                                                  1U, 0, pair.now, &early[index]));
  }
  {
    uint8_t payload = (uint8_t)('z');
    WT_EXPECT_OK("and one over the endpoint's hold",
                 wt_http3_driver_open_data_stream(&client.driver, &client_transport, 1, &payload,
                                                  1U, 0, pair.now, &over));
  }
  {
    size_t wanted = WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX + 1U;
    for (rounds = 0U; rounds < 400U && server.stream_bytes < wanted; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_U64("every early stream's byte arrives",
                (uint64_t)(WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX + 1U),
                (uint64_t)server.stream_bytes);

  /* The driver knows which session each stream names, which is what a caller needs to decide whether it can be
   * delivered -- and it knows it for a stream whose session this endpoint has NOT accepted, which is the point
   * (WT-180). */
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    named = 0U;
    WT_EXPECT_OK("an early stream's session is readable",
                 wt_http3_driver_data_stream_session_id(&server.driver, early[index], &named));
    WT_EXPECT_U64("and is the one its prefix named", request_stream_id, named);
  }

  /* Park them: section 4.6's "buffer streams ... until they can be associated with an established session". */
  wt_webtransport_buffered_init(&parked);
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    uint8_t payload = (uint8_t)('a' + index);
    WT_EXPECT_OK("an early stream parks",
                 wt_webtransport_buffered_park_stream(&parked, early[index], request_stream_id, 1,
                                                      &payload, 1U));
  }
  WT_EXPECT_U64("all of them are held", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX,
                (uint64_t)wt_webtransport_buffered_stream_count(&parked));

  /* And the one over the bound is the rejection: the status is the caller's instruction to reset, the code is
   * the section's, and the stream is named. */
  {
    uint8_t payload = (uint8_t)('z');
    WT_EXPECT_STATUS(
        "the stream over the bound is rejected", WT_ERR_LIMIT,
        wt_webtransport_buffered_park_stream(&parked, over, request_stream_id, 1, &payload, 1U));
  }
  WT_EXPECT_U64("with the code the section names", UINT64_C(0x3994bd84),
                WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED);
  WT_EXPECT_U64("counted", 1U, wt_webtransport_buffered_streams_rejected(&parked));
  WT_EXPECT_U64("and named", over, wt_webtransport_buffered_last_rejected_stream_id(&parked));

  /* The reset the rejection asks for, through the driver, which knows what it may commit to. */
  WT_EXPECT_OK("the rejected stream is reset with that code",
               wt_http3_driver_reject_data_stream(
                   &server.driver, over, WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED, pair.now));
  WT_EXPECT_STATUS(
      "and forgotten, so a second rejection is CLOSED", WT_ERR_CLOSED,
      wt_http3_driver_reject_data_stream(&server.driver, over,
                                         WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED, pair.now));
  {
    for (rounds = 0U; rounds < 400U && client.stops == 0U; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  /* The stream is the CLIENT's unidirectional one, so this endpoint has no send half on it and the section's
   * "and/or" is the STOP_SENDING: the frames are exactly the halves the stream has. */
  WT_EXPECT_U64("the peer was told to stop sending", 1U, (uint64_t)client.stops);
  WT_EXPECT_U64("carrying WT_BUFFERED_STREAM_REJECTED",
                WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED, client.last_stop_code);
  WT_EXPECT_U64("and no reset was sent, because there is nothing to reset", 0U,
                (uint64_t)client.resets);

  /* The other half of the section's "and/or": a BIDIRECTIONAL early stream HAS a send half here, so the same
   * rejection is a RESET_STREAM as well. */
  {
    uint64_t early_bidi = 0U;
    uint8_t payload = (uint8_t)'q';
    size_t wanted = (size_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX + 2U;
    WT_EXPECT_OK("a bidirectional early stream opens",
                 wt_http3_driver_open_data_stream(&client.driver, &client_transport, 0, &payload,
                                                  1U, 0, pair.now, &early_bidi));
    for (rounds = 0U; rounds < 400U && server.stream_bytes < wanted; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
    WT_EXPECT_U64("its byte arrives too", (uint64_t)wanted, (uint64_t)server.stream_bytes);
    named = 0U;
    WT_EXPECT_OK("and its session is readable",
                 wt_http3_driver_data_stream_session_id(&server.driver, early_bidi, &named));
    WT_EXPECT_U64("naming the same session", request_stream_id, named);
    WT_EXPECT_OK("it is rejected the same way",
                 wt_http3_driver_reject_data_stream(&server.driver, early_bidi,
                                                    WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED,
                                                    pair.now));
    {
      /* Both frames come from the one rejection, but the reset and the stop are two frames and need not share a
       * packet, so the wait is for BOTH rather than for the first. */
      for (rounds = 0U; rounds < 400U && (client.resets == 0U || client.stops < 2U); rounds++) {
        (void)wt_udp_wait(&pair.server_socket, 2000U);
        (void)wt_udp_wait(&pair.client_socket, 2000U);
        if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
        if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
        pair.now += 1000U;
      }
    }
    WT_EXPECT_U64("the peer saw the reset a bidirectional stream allows", 1U,
                  (uint64_t)client.resets);
    WT_EXPECT_U64("carrying WT_BUFFERED_STREAM_REJECTED",
                  WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED, client.last_reset_code);
    WT_EXPECT_U64("and was told to stop sending as well", 2U, (uint64_t)client.stops);
  }

  /* Now the server accepts, which is the moment the parked streams can be associated: they are delivered in
   * arrival order, with the bytes they carried. */
  WT_EXPECT_OK("the server accepts the session",
               wt_http3_driver_send_response(&server.driver, &server_transport, request_stream_id,
                                             200U, 0U, 0, pair.now));
  {
    for (rounds = 0U; rounds < 400U && client.section_complete == 0; rounds++) {
      (void)wt_udp_wait(&pair.server_socket, 2000U);
      (void)wt_udp_wait(&pair.client_socket, 2000U);
      if (wt_runtime_session_pump(&pair.server, pair.now) != WT_OK) break;
      if (wt_runtime_session_pump(&pair.client, pair.now) != WT_OK) break;
      pair.now += 1000U;
    }
  }
  WT_EXPECT_TRUE("and the session is established", client.section_complete != 0);
  /* The ID is known on the server too now, so the same number the parked streams carry is the one it accepted. */
  WT_EXPECT_U64("a parked stream names the session the server accepted", request_stream_id,
                parked.streams[0].session_id);

  WT_EXPECT_OK("the parked streams resolve", wt_webtransport_buffered_drain_streams(
                                                 &parked, request_stream_id, record_early_stream,
                                                 &delivery, &delivered, &dropped));
  WT_EXPECT_U64("all of them delivered", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX,
                (uint64_t)delivered);
  WT_EXPECT_U64("nothing dropped", 0U, (uint64_t)dropped);
  WT_EXPECT_U64("in arrival order", early[0], delivery.stream_ids[0]);
  WT_EXPECT_U64("the second is the second parked", early[1], delivery.stream_ids[1]);
  WT_EXPECT_U64("and the last is the last parked", early[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U],
                delivery.stream_ids[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U]);
  WT_EXPECT_U64("with the bytes each stream carried", (uint64_t)'a', (uint64_t)delivery.bytes[0]);
  WT_EXPECT_U64("in order too", (uint64_t)('a' + WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U),
                (uint64_t)delivery.bytes[WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX - 1U]);
  /* The rejected stream was never parked, so it is not delivered: the reset ended it. */
  for (index = 0U; index < delivery.count; index++) {
    WT_EXPECT_TRUE("the rejected stream is not among them", delivery.stream_ids[index] != over);
  }

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}
