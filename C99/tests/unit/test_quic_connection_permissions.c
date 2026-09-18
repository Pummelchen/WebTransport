/* The basics tests for the connection runtime. */

#include "test_quic_connection_internal.h"

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
