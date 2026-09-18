/* Fixtures shared by the test_quic_connection topic files: the recorded-frame witness, the
 * two-connection pair, and the packet builders and deliverers the tests drive. */

#include "test_quic_connection_internal.h"

const uint8_t k_dcid[8] = {0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U};

const uint8_t k_server_scid[4] = {0x0aU, 0x0bU, 0x0cU, 0x0dU};

const uint8_t k_retry_odcid[8] = {0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xffU, 0x01U, 0x02U};

const uint8_t k_retry_scid[10] = {0x11U, 0x12U, 0x13U, 0x14U, 0x15U,
                                  0x16U, 0x17U, 0x18U, 0x19U, 0x1aU};

const uint8_t k_retry_token[12] = {0xdeU, 0xadU, 0xbeU, 0xefU, 0x00U, 0x01U,
                                   0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U};

wt_status_t record_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  fs_witness_t *witness = context;
  recorded_frame_t *entry;

  /* A full witness stops recording and does not fail the walk: it is a test's notebook, and a
   * handler that refused would be refusing the connection. */
  if (witness->count >= RECORDED_MAX) return WT_OK;
  entry = &witness->frames[witness->count++];
  memset(entry, 0, sizeof(*entry));
  entry->space = space;
  entry->kind = frame->kind;
  if (frame->kind == WT_QUIC_FRAME_KIND_CRYPTO) {
    entry->offset = frame->as.crypto.offset;
    entry->length = frame->as.crypto.length;
    if (entry->length > sizeof(entry->data)) entry->length = sizeof(entry->data);
    if (frame->as.crypto.data != NULL) {
      memcpy(entry->data, frame->as.crypto.data, entry->length);
    }
  }
  /* The path frames carry eight bytes, and a test that wants to compare them with what it sent has to copy them:
   * the frame's view is into the decrypted packet buffer, which the next receive overwrites (WT-172). */
  if (frame->kind == WT_QUIC_FRAME_KIND_PATH_CHALLENGE ||
      frame->kind == WT_QUIC_FRAME_KIND_PATH_RESPONSE) {
    const uint8_t *payload = frame->kind == WT_QUIC_FRAME_KIND_PATH_CHALLENGE
                                 ? frame->as.path_challenge.data
                                 : frame->as.path_response.data;
    entry->length = WT_QUIC_PATH_CHALLENGE_LENGTH;
    if (payload != NULL) memcpy(entry->data, payload, WT_QUIC_PATH_CHALLENGE_LENGTH);
  }
  return WT_OK;
}

void record_lost(void *context, const wt_quic_tx_frame_t *frame) {
  fs_witness_t *witness = context;
  if (witness->lost_count >= RECORDED_MAX) return;
  witness->lost_offsets[witness->lost_count++] = frame->offset;
}

void open_pair(wt_udp_family_t family, connection_pair_t *pair) {
  wt_quic_connection_config_t client_config;
  wt_quic_connection_config_t server_config;
  wt_quic_packet_keys_t client_send;
  wt_quic_packet_keys_t client_receive;
  uint8_t initial_secret[WT_SHA256_LEN];
  uint16_t port = 0U;

  memset(pair, 0, sizeof(*pair));

  WT_EXPECT_OK("the client socket opens", wt_udp_socket_open(&pair->client_socket, family));
  WT_EXPECT_OK("and binds loopback", wt_udp_bind_loopback(&pair->client_socket, 0U, &port));
  wt_udp_address_loopback(family, &pair->client_address);
  pair->client_address.port = port;
  WT_EXPECT_OK("the server socket opens", wt_udp_socket_open(&pair->server_socket, family));
  WT_EXPECT_OK("and binds loopback", wt_udp_bind_loopback(&pair->server_socket, 0U, &port));
  wt_udp_address_loopback(family, &pair->server_address);
  pair->server_address.port = port;

  /* The Initial keys of RFC 9001 section 5.2, from the salt and the destination connection ID. */
  WT_EXPECT_OK("the Initial secret derives",
               wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1),
                                      k_dcid, sizeof(k_dcid), initial_secret));
  WT_EXPECT_OK("the client's keys derive",
               wt_quic_initial_packet_keys(initial_secret, 0, WT_AEAD_AES_128_GCM, &client_send));
  WT_EXPECT_OK("and the server's", wt_quic_initial_packet_keys(
                                       initial_secret, 1, WT_AEAD_AES_128_GCM, &client_receive));

  memset(&client_config, 0, sizeof(client_config));
  client_config.role = WT_QUIC_ROLE_CLIENT;
  client_config.version = WT_QUIC_VERSION_1;
  client_config.local_connection_id = k_dcid;
  client_config.local_connection_id_length = sizeof(k_dcid);
  /* The client sends to the connection ID the server answers to. Before a handshake that is the
   * original destination connection ID the client chose, which is the same value the Initial keys are
   * derived from -- so this pair uses one ID for both directions' destination checks. */
  client_config.peer_connection_id = k_dcid;
  client_config.peer_connection_id_length = sizeof(k_dcid);
  client_config.aead = WT_AEAD_AES_128_GCM;
  client_config.max_ack_delay = 25000U;
  client_config.local_max_ack_delay = 25000U;
  client_config.idle_timeout = 30000000U;
  client_config.max_datagram_size = WT_QUIC_MAX_PACKET;

  memset(&server_config, 0, sizeof(server_config));
  server_config.role = WT_QUIC_ROLE_SERVER;
  server_config.version = WT_QUIC_VERSION_1;
  /* The server answers to the client's chosen destination connection ID until it issues one of its
   * own, and sends to the client's source connection ID -- which for this pair is the same value,
   * because the client's local ID is what it sends as its source. */
  server_config.local_connection_id = k_dcid;
  server_config.local_connection_id_length = sizeof(k_dcid);
  server_config.peer_connection_id = k_dcid;
  server_config.peer_connection_id_length = sizeof(k_dcid);
  server_config.aead = WT_AEAD_AES_128_GCM;
  server_config.max_ack_delay = 25000U;
  server_config.local_max_ack_delay = 25000U;
  server_config.idle_timeout = 30000000U;
  server_config.max_datagram_size = WT_QUIC_MAX_PACKET;

  WT_EXPECT_OK("the client initialises", wt_quic_connection_init(&pair->client, &client_config));
  /* Stream data is only accepted once this endpoint has granted room for it. */
  pair->client.config.local_max_stream_data = 1024U;
  WT_EXPECT_OK("the server initialises", wt_quic_connection_init(&pair->server, &server_config));
  /* Stream data is only accepted once this endpoint has granted room for it. */
  pair->server.config.local_max_stream_data = 1024U;
  WT_EXPECT_OK(
      "the client borrows its socket",
      wt_quic_connection_attach(&pair->client, &pair->client_socket, &pair->server_address));
  WT_EXPECT_OK(
      "the server borrows its socket",
      wt_quic_connection_attach(&pair->server, &pair->server_socket, &pair->client_address));

  WT_EXPECT_OK("the client holds its send keys",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_INITIAL, 0, &client_send));
  WT_EXPECT_OK(
      "and the server's as its receive keys",
      wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_INITIAL, 1, &client_receive));
  WT_EXPECT_OK("the server holds the client's send keys",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_INITIAL, 1, &client_send));
  WT_EXPECT_OK(
      "and its own as its send keys",
      wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_INITIAL, 0, &client_receive));

  wt_quic_connection_set_handlers(&pair->client, record_frame, &pair->client_witness, record_lost,
                                  &pair->client_witness);
  wt_quic_connection_set_handlers(&pair->server, record_frame, &pair->server_witness, record_lost,
                                  &pair->server_witness);
}

/* Wait until the socket has a datagram, then read it. This is what a real event loop does -- the
 * connection's receive is non-blocking by design (WT-13's socket layer), so a caller that reads without
 * waiting gets WT_ERR_AGAIN, which is not a failure and not a packet. */
void receive_on(wt_quic_connection_t *connection, const wt_udp_socket_t *socket, uint64_t now) {
  WT_EXPECT_OK("the socket becomes readable", wt_udp_wait(socket, 2000000U));
  WT_EXPECT_OK("and the connection reads the datagram",
               wt_quic_connection_receive(connection, now));
}

void close_pair(connection_pair_t *pair) {
  wt_quic_connection_clear(&pair->client);
  wt_quic_connection_clear(&pair->server);
  wt_udp_close(&pair->client_socket);
  wt_udp_close(&pair->server_socket);
}

/* RFC 9000 section 3.2 and 4.6: a frame for a peer-initiated stream this endpoint has never seen OPENS
 * it, bounded by the count this endpoint granted; more than that is STREAM_LIMIT_ERROR, and a frame for
 * one of this endpoint's own numbers that was never opened is STREAM_STATE_ERROR. MAX_STREAM_DATA then
 * raises one stream's send allowance. */
/* Send a short-header application packet carrying exactly these bytes. A frame the ENCODER refuses to
 * produce -- because it would refuse to decode it -- can only be tested this way. */
void send_raw_payload_with_dcid(const connection_pair_t *pair, const uint8_t *payload,
                                size_t payload_length, const uint8_t *dcid, size_t dcid_length,
                                const wt_quic_packet_keys_t *keys, uint64_t packet_number) {
  uint8_t datagram[256];
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;

  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = dcid;
  build.destination_connection_id_len = dcid_length;
  build.packet_number = packet_number;
  build.packet_number_length = 1U;
  build.payload = payload;
  build.payload_len = payload_length;
  build.keys = keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("and is sent",
               wt_udp_send(&pair->client_socket, &pair->server_address, datagram, datagram_len));
}

void send_raw_payload_to(const connection_pair_t *pair, const uint8_t *payload,
                         size_t payload_length, const wt_quic_packet_keys_t *keys,
                         uint64_t packet_number) {
  send_raw_payload_with_dcid(pair, payload, payload_length, k_dcid, sizeof(k_dcid), keys,
                             packet_number);
}

void send_frame_to(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                   const wt_quic_packet_keys_t *keys, uint64_t packet_number, uint64_t now) {
  uint8_t payload[128];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));

  WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, frame));
  send_raw_payload_to(pair, payload, wt_writer_offset(&w), keys, packet_number);
  (void)now;
}

void record_stream_loss(void *context, const wt_quic_tx_frame_t *frame) {
  lost_witness_t *witness = context;
  /* The FIRST loss is the one described here: losses are reported in the order the packets were sent,
   * so the first is the oldest, and a burst reports several. */
  if (witness->count == 0U) {
    witness->stream_id = frame->stream_id;
    witness->offset = frame->offset;
    witness->length = frame->length;
    witness->is_crypto = frame->is_crypto;
  }
  witness->count++;
}

/* RFC 9000 section 19.15: a NEW_CONNECTION_ID from the peer is stored, bounded by what this endpoint
 * advertised it would store, and the section's own errors are raised rather than ignored. */
void send_application_frame(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                            const wt_quic_packet_keys_t *keys, uint64_t packet_number) {
  uint8_t payload[128];
  uint8_t datagram[256];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t len;
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;

  WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, frame));
  len = wt_writer_offset(&w);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = packet_number;
  build.packet_number_length = 1U;
  build.payload = payload;
  build.payload_len = len;
  build.keys = keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("and is sent",
               wt_udp_send(&pair->client_socket, &pair->server_address, datagram, datagram_len));
}

/* The same injection as `send_application_frame`, but a long-header Initial packet built short: it is
 * what RFC 9000 section 14.1 says a server must discard, and it has to be hand-built because this
 * library's own send path now pads every client Initial. */
void send_short_initial_frame(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                              const wt_quic_packet_keys_t *keys, uint64_t packet_number) {
  uint8_t payload[128];
  uint8_t datagram[256];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t len;
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;

  WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, frame));
  len = wt_writer_offset(&w);
  memset(&build, 0, sizeof(build));
  build.short_header = 0;
  build.type = WT_QUIC_PACKET_INITIAL;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.source_connection_id = k_dcid;
  build.source_connection_id_len = sizeof(k_dcid);
  build.packet_number = packet_number;
  build.packet_number_length = 1U;
  build.payload = payload;
  build.payload_len = len;
  build.keys = keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_TRUE("and is below the Initial minimum",
                 datagram_len < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE);
  WT_EXPECT_OK("and is sent",
               wt_udp_send(&pair->client_socket, &pair->server_address, datagram, datagram_len));
}

/* A handler that REFUSES every frame, which is what `deliver_to_handler`'s close path exists for. */
wt_status_t refuse_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  unsigned *count = context;
  (void)space;
  (void)frame;
  (*count)++;
  return WT_ERR_PROTOCOL;
}

/* A handler that names its code, so the close the peer is told about is the handler's rather than a generic one. */
wt_status_t refuse_frame_with_code(void *context, wt_quic_space_t space,
                                   const wt_quic_frame_t *frame) {
  wt_quic_connection_t *connection = context;
  (void)space;
  connection->close_code = (uint64_t)WT_QUIC_STREAM_STATE_ERROR;
  connection->close_frame_type = WT_QUIC_FRAME_CRYPTO;
  connection->close_code_set = 1;
  (void)frame;
  return WT_ERR_PROTOCOL;
}

/* An HTTP/3 refusal reaches the peer as an APPLICATION close (WT-158).
 *
 * RFC 9114 section 8 carries every HTTP/3 error in a CONNECTION_CLOSE of type 0x1d whose code is the HTTP/3 error
 * code -- H3_FRAME_ERROR for a frame that ends part way through, H3_SETTINGS_ERROR for a bad setting. A handler
 * that could only return a status closed the TRANSPORT with INTERNAL_ERROR instead: a different frame, a
 * different code, and a peer that cannot tell which rule it broke. */
wt_status_t refuse_with_h3_error(void *context, wt_quic_space_t space,
                                 const wt_quic_frame_t *frame) {
  wt_quic_connection_t *connection = context;
  (void)space;
  (void)frame;
  /* The HTTP/3 error space: H3_FRAME_ERROR is 0x107. */
  wt_quic_connection_refuse_application(connection, (uint64_t)0x107U, 0U);
  return WT_ERR_PROTOCOL;
}

wt_status_t record_reset_at(void *context, const wt_quic_frame_t *frame) {
  reset_at_witness_t *witness = context;
  witness->walked++;
  witness->last_kind = (uint64_t)frame->kind;
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM)
    witness->last_length = (uint64_t)frame->as.stream.length;
  if (frame->kind == WT_QUIC_FRAME_KIND_RESET_STREAM_AT) {
    witness->seen++;
    witness->id = frame->as.reset_stream_at.id;
    witness->error_code = frame->as.reset_stream_at.application_error_code;
    witness->final_size = frame->as.reset_stream_at.final_size;
    witness->reliable_size = frame->as.reset_stream_at.reliable_size;
  }
  return WT_OK;
}

/* Application keys for a pair, so that a frame can cross it: `open_pair` installs the Initial keys only, and the
 * app-space tests each derive their own. */
