/* Fixtures shared by the test_quic_connection topic files: the recorded-frame witness, the
 * two-connection pair, and the packet builders and deliverers the tests drive. */

#include "test_quic_connection_internal.h"

void install_application_keys(connection_pair_t *pair, uint8_t base) {
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  size_t i;

  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(base + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and the server reads with them",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
}

/* Hand one datagram to one side of the pair the way a peer's packet arrives: through its own socket, which is
 * what makes the destination connection ID check part of what is being tested. `to_server` picks the side. */
void deliver_to(connection_pair_t *pair, int to_server, const uint8_t *packet, size_t length,
                uint64_t now) {
  if (to_server != 0) {
    WT_EXPECT_OK("the packet is sent",
                 wt_udp_send(&pair->client_socket, &pair->server_address, packet, length));
    receive_on(&pair->server, &pair->server_socket, now);
  } else {
    WT_EXPECT_OK("the packet is sent",
                 wt_udp_send(&pair->server_socket, &pair->client_address, packet, length));
    receive_on(&pair->client, &pair->client_socket, now);
  }
}

/* Arm the pair's CLIENT for a Retry: a configuration whose destination is `k_retry_odcid`, the Initial keys
 * derived from that ID (RFC 9001 section 5.2), the destination recorded the way the runtime session records it,
 * and the handlers back in place because this replaces the connection `open_pair` armed. The SERVER's keys are
 * left alone: this test never asks it to read what the client sends, because what the wire carries is the
 * assertion. */
void retry_client(connection_pair_t *pair) {
  wt_quic_connection_config_t config;
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];

  memset(&config, 0, sizeof(config));
  config.role = WT_QUIC_ROLE_CLIENT;
  config.version = WT_QUIC_VERSION_1;
  config.local_connection_id = k_retry_scid;
  config.local_connection_id_length = sizeof(k_retry_scid);
  config.peer_connection_id = k_retry_odcid;
  config.peer_connection_id_length = sizeof(k_retry_odcid);
  config.aead = WT_AEAD_AES_128_GCM;
  config.max_ack_delay = 25000U;
  config.local_max_ack_delay = 25000U;
  config.idle_timeout = 30000000U;
  config.max_datagram_size = WT_QUIC_MAX_PACKET;
  WT_EXPECT_OK("the client initialises", wt_quic_connection_init(&pair->client, &config));
  WT_EXPECT_OK("and records the destination it chose",
               wt_quic_connection_set_original_destination_id(&pair->client, k_retry_odcid,
                                                              sizeof(k_retry_odcid)));
  WT_EXPECT_OK("the Initial secret derives",
               wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1),
                                      k_retry_odcid, sizeof(k_retry_odcid), secret));
  WT_EXPECT_OK("the send keys derive",
               wt_quic_initial_packet_keys(secret, 0, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("and are installed",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_INITIAL, 0, &keys));
  WT_EXPECT_OK("as are the receive keys",
               wt_quic_initial_packet_keys(secret, 1, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("on the connection",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_INITIAL, 1, &keys));
  WT_EXPECT_OK(
      "the client borrows its socket again",
      wt_quic_connection_attach(&pair->client, &pair->client_socket, &pair->server_address));
  wt_quic_connection_set_handlers(&pair->client, record_frame, &pair->client_witness, record_lost,
                                  &pair->client_witness);
}

/* One Retry packet, tag included, as the wire carries it. `token_len` of zero is the malformed case the section
 * names, and `source`/`source_len` let a caller make the Source Connection ID equal to the client's own. */
size_t build_retry(uint8_t *out, size_t capacity, const uint8_t *source, size_t source_len,
                   const uint8_t *token, size_t token_len) {
  uint8_t tag[WT_AEAD_TAG_LEN];
  wt_writer_t w = wt_writer_init(out, capacity);
  size_t written;

  /* The tag covers the ORIGINAL destination connection ID and the packet WITHOUT the tag, which is why the
   * packet is written with a placeholder first and the tag computed over that. */
  WT_EXPECT_OK("the Retry encodes", wt_quic_retry_packet_encode(
                                        &w, WT_QUIC_VERSION_1, k_retry_odcid, sizeof(k_retry_odcid),
                                        source, source_len, token, token_len, tag));
  written = wt_writer_offset(&w);
  /* The range to authenticate is the packet WITHOUT the tag: the encoder wrote a placeholder there, so it stops
   * sixteen bytes short. Getting this wrong is the mistake the A.4 extractor's own docstring warns about, and it
   * fails as an authentication failure rather than as anything more helpful. */
  WT_EXPECT_OK("its integrity tag computes",
               wt_quic_retry_integrity_tag(k_retry_odcid, sizeof(k_retry_odcid), out,
                                           written - WT_AEAD_TAG_LEN, tag));
  w = wt_writer_init(out, capacity);
  WT_EXPECT_OK("and the packet encodes with it",
               wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, k_retry_odcid,
                                           sizeof(k_retry_odcid), source, source_len, token,
                                           token_len, tag));
  return wt_writer_offset(&w);
}

/* A 1-RTT pair: one Application traffic secret both ways, and the handshake confirmed, which is what RFC 9001
 * section 6.1 requires before a key update may be initiated at all. */
void arm_application(connection_pair_t *pair, uint8_t seed) {
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  size_t i;

  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(seed + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("the server sends with them too",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and the client reads with them",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  pair->client.handshake_confirmed = 1;
  pair->server.handshake_confirmed = 1;
}

/* The next phase's keys the way the connection derives them: the secret moves forward and the HEADER PROTECTION
 * key does not (RFC 9001 section 6.1). A test that forgot the second half would build a packet no receiver could
 * unprotect, which is exactly how one of these tests failed the first time. */
void update_keys_keeping_hp(const wt_quic_packet_keys_t *current, wt_quic_packet_keys_t *out) {
  WT_EXPECT_OK("the next phase derives", wt_quic_packet_keys_update(current, out));
  memcpy(out->hp, current->hp, current->hp_len);
  out->hp_len = current->hp_len;
}

/* One short-header packet built by hand, so a test can decide its packet number, its phase bit and WHEN it is
 * delivered -- which is what a reordered packet is. `keys` must be the SENDER's send keys for the phase. */
size_t build_application_packet(const wt_quic_packet_keys_t *keys, uint64_t packet_number,
                                int key_phase, uint8_t *out, size_t capacity,
                                size_t payload_offset) {
  uint8_t payload[16];
  size_t payload_len = 0U;
  size_t length = 0U;
  wt_quic_packet_build_t build;
  size_t i;

  /* A PING, which is ack-eliciting and one byte, plus PADDING to what header protection's sample needs. */
  payload[0] = 0x01U;
  payload_len = (payload_offset > sizeof(payload)) ? sizeof(payload) : payload_offset;
  if (payload_len < 4U) payload_len = 4U;
  for (i = 1U; i < payload_len; i++)
    payload[i] = 0U;

  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = packet_number;
  build.packet_number_length = 2U;
  build.key_phase = key_phase;
  build.payload = payload;
  build.payload_len = payload_len;
  build.keys = keys;
  WT_EXPECT_OK("the packet builds", wt_quic_packet_build(&build, out, capacity, &length));
  return length;
}

void deliver_to_peer(connection_pair_t *pair, int to_server, const uint8_t *packet, size_t length,
                     uint64_t now) {
  if (to_server != 0) {
    WT_EXPECT_OK("the packet is sent",
                 wt_udp_send(&pair->client_socket, &pair->server_address, packet, length));
    receive_on(&pair->server, &pair->server_socket, now);
  } else {
    WT_EXPECT_OK("the packet is sent",
                 wt_udp_send(&pair->server_socket, &pair->client_address, packet, length));
    receive_on(&pair->client, &pair->client_socket, now);
  }
}

/* Hand one frame from one side of the pair to the other, addressed to a chosen connection ID. The frames the
 * ISSUING side sends itself -- `wt_quic_connection_issue_connection_id` sends the NEW_CONNECTION_ID -- need no
 * helper; this is for the one case a real peer cannot produce on demand: a `retire_prior_to` above zero, which
 * the library's own issuer never writes. */
void send_frame_from_side(connection_pair_t *pair, int to_client, const wt_quic_frame_t *frame,
                          const wt_quic_packet_keys_t *keys, uint64_t packet_number,
                          const uint8_t *dcid, size_t dcid_len) {
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
  build.destination_connection_id = dcid;
  build.destination_connection_id_len = dcid_len;
  build.packet_number = packet_number;
  build.packet_number_length = 2U;
  build.payload = payload;
  build.payload_len = len;
  build.keys = keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  if (to_client != 0) {
    WT_EXPECT_OK("and is sent",
                 wt_udp_send(&pair->server_socket, &pair->client_address, datagram, datagram_len));
  } else {
    WT_EXPECT_OK("and is sent",
                 wt_udp_send(&pair->client_socket, &pair->server_address, datagram, datagram_len));
  }
}

/* Take one datagram off a socket and throw it away, WITHOUT handing it to a connection: it is how a test keeps
 * the network from delivering a frame it wants to replace, which a real peer cannot do and which is the only way
 * to see a `retire_prior_to` the library's own issuer never writes. */
void discard_one_datagram(wt_udp_socket_t *socket) {
  uint8_t buffer[WT_QUIC_MAX_PACKET];
  size_t length = 0U;

  WT_EXPECT_OK("a datagram arrives to discard", wt_udp_wait(socket, 2000000U));
  WT_EXPECT_OK("and is read raw", wt_udp_receive(socket, buffer, sizeof(buffer), &length, NULL));
}

/* Both directions of the Application space, and the peer's parameters -- because issuing an ID the peer cannot
 * store is refused, so the limit it granted is part of the setup. */
void arm_for_connection_ids(connection_pair_t *pair, uint8_t seed) {
  wt_quic_packet_keys_t keys;
  wt_quic_transport_parameters_t params;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t encoded[64];
  wt_writer_t pw = wt_writer_init(encoded, sizeof(encoded));
  size_t i;

  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(seed + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the client reads",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("the client writes",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK(
      "a peer limit of four connection IDs",
      wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 4U));
  WT_EXPECT_OK("which encodes", wt_quic_transport_parameters_encode(&pw, &params));
  WT_EXPECT_OK("and is applied", wt_quic_connection_set_peer_parameters(&pair->server, encoded,
                                                                        wt_writer_offset(&pw)));
  /* And what THIS endpoint will store: the default of two counts the handshake's ID and leaves room for one
   * spare (RFC 9000 section 5.1.1), so a client that wants two spares says so. */
  pair->client.config.local_active_connection_id_limit = 4U;
}

/* Count the frames of one kind a witness recorded. */
unsigned witness_frames_of(const fs_witness_t *witness, wt_quic_frame_type_t kind) {
  unsigned found = 0U;
  size_t index;
  for (index = 0U; index < witness->count; index++) {
    if (witness->frames[index].kind == kind) found++;
  }
  return found;
}

/* Application keys in both directions from one secret, so a test can hand the receiving connection a packet built
 * with the keys it reads with. The pair's own convention, not a protocol statement. */
void arm_path_pair(connection_pair_t *pair, uint8_t seed) {
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  size_t i;

  for (i = 0U; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(seed + i);
  WT_EXPECT_OK("path keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client writes",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the client reads",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  pair->client.handshake_confirmed = 1;
  pair->server.handshake_confirmed = 1;
}

const recorded_frame_t *witness_frame(const fs_witness_t *witness, wt_quic_frame_type_t kind,
                                      unsigned occurrence) {
  size_t index;
  unsigned seen = 0U;

  for (index = 0U; index < witness->count; index++) {
    if (witness->frames[index].kind != kind) continue;
    if (seen == occurrence) return &witness->frames[index];
    seen++;
  }
  return NULL;
}

/* Send two frames in ONE packet. That is the only way to reach the decoder's reused union: it decodes every
 * frame of a packet into a single `wt_quic_frame_t`, so a frame that does not set a union member inherits
 * whatever the previous frame in the same packet left there. */
void send_two_frames_from_side(connection_pair_t *pair, const wt_quic_frame_t *first,
                               const wt_quic_frame_t *second, const wt_quic_packet_keys_t *keys,
                               uint64_t packet_number, const uint8_t *dcid, size_t dcid_len) {
  uint8_t payload[128];
  uint8_t datagram[256];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t datagram_len = 0U;
  wt_quic_packet_build_t build;

  WT_EXPECT_OK("the first frame encodes", wt_quic_frame_encode(&w, first));
  WT_EXPECT_OK("the second frame encodes", wt_quic_frame_encode(&w, second));
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = dcid;
  build.destination_connection_id_len = dcid_len;
  build.packet_number = packet_number;
  build.packet_number_length = 2U;
  build.payload = payload;
  build.payload_len = wt_writer_offset(&w);
  build.keys = keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("and is sent",
               wt_udp_send(&pair->server_socket, &pair->client_address, datagram, datagram_len));
}
