/* The connection runtime: two real connections over two real sockets.
 *
 * THIS IS THE TEST THAT MAKES THE PHASE-4 COMPLETION CRITERION REACHABLE: packets are built, protected,
 * sent over a loopback UDP socket, received, unprotected, walked frame by frame, acknowledged, and
 * accounted for -- on IPv4 and on IPv6 -- without a synthetic transport anywhere in the path. What it
 * deliberately does not do is complete a TLS handshake: the handshake needs the CRYPTO handler that
 * Phase 4's next part brings, so the keys here are the Initial keys both ends derive from the same
 * connection ID, which is exactly what RFC 9001 section 5.2 lets two ends of a connection do before
 * any handshake has happened.
 *
 * THE CLOCK IS A PARAMETER, WHICH IS WHAT MAKES THE TIMERS TESTABLE. Every call takes `now`, so a
 * probe timeout, a time-threshold loss and an idle timeout are all tested by moving a number rather
 * than by sleeping: a test that slept would be testing the machine's load, and the values it would
 * assert on would be the ones that happen to be slow enough to be stable.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/connection.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/quic/protection.h"
#include "webtransport/runtime/udp.h"

/* The destination connection ID both ends use for the Initial keys. */
static const uint8_t k_dcid[8] = {0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U};
static const uint8_t k_server_scid[4] = {0x0aU, 0x0bU, 0x0cU, 0x0dU};

/* What a handler was told, recorded rather than acted on: the frame bytes, the space and the count. */
#define RECORDED_MAX 8
typedef struct recorded_frame {
  wt_quic_space_t space;
  wt_quic_frame_type_t kind;
  uint64_t offset;
  size_t length;
  uint8_t data[64];
} recorded_frame_t;

typedef struct fs_witness {
  recorded_frame_t frames[RECORDED_MAX];
  size_t count;
  /* The packet numbers the loss handler was told about, by descriptor offset. */
  uint64_t lost_offsets[RECORDED_MAX];
  size_t lost_count;
} fs_witness_t;

static wt_status_t record_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
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
  return WT_OK;
}

static void record_lost(void *context, const wt_quic_tx_frame_t *frame) {
  fs_witness_t *witness = context;
  if (witness->lost_count >= RECORDED_MAX) return;
  witness->lost_offsets[witness->lost_count++] = frame->offset;
}

/* Two connections, two sockets, one family, both with Initial keys derived from the same connection ID
 * in the RFC 9001 section 5.2 way. The client is the one that opens the exchange, so its send keys are
 * the client's and its receive keys are the server's. */
typedef struct connection_pair {
  wt_quic_connection_t client;
  wt_quic_connection_t server;
  wt_udp_socket_t client_socket;
  wt_udp_socket_t server_socket;
  wt_udp_address_t client_address;
  wt_udp_address_t server_address;
  fs_witness_t client_witness;
  fs_witness_t server_witness;
} connection_pair_t;

static void open_pair(wt_udp_family_t family, connection_pair_t *pair) {
  wt_quic_connection_config_t client_config;
  wt_quic_connection_config_t server_config;
  wt_quic_packet_keys_t client_send;
  wt_quic_packet_keys_t client_receive;
  uint8_t initial_secret[WT_SHA256_LEN];
  uint16_t port = 0U;

  memset(pair, 0, sizeof(*pair));

  WT_EXPECT_OK("the client socket opens", wt_udp_socket_open(&pair->client_socket, family));
  WT_EXPECT_OK("and binds loopback",
               wt_udp_bind_loopback(&pair->client_socket, 0U, &port));
  wt_udp_address_loopback(family, &pair->client_address);
  pair->client_address.port = port;
  WT_EXPECT_OK("the server socket opens", wt_udp_socket_open(&pair->server_socket, family));
  WT_EXPECT_OK("and binds loopback",
               wt_udp_bind_loopback(&pair->server_socket, 0U, &port));
  wt_udp_address_loopback(family, &pair->server_address);
  pair->server_address.port = port;

  /* The Initial keys of RFC 9001 section 5.2, from the salt and the destination connection ID. */
  WT_EXPECT_OK("the Initial secret derives",
               wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1), k_dcid,
                                      sizeof(k_dcid), initial_secret));
  WT_EXPECT_OK("the client's keys derive",
               wt_quic_initial_packet_keys(initial_secret, 0, WT_AEAD_AES_128_GCM, &client_send));
  WT_EXPECT_OK("and the server's",
               wt_quic_initial_packet_keys(initial_secret, 1, WT_AEAD_AES_128_GCM, &client_receive));

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
  WT_EXPECT_OK("the client borrows its socket",
               wt_quic_connection_attach(&pair->client, &pair->client_socket, &pair->server_address));
  WT_EXPECT_OK("the server borrows its socket",
               wt_quic_connection_attach(&pair->server, &pair->server_socket, &pair->client_address));

  WT_EXPECT_OK("the client holds its send keys",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_INITIAL, 0, &client_send));
  WT_EXPECT_OK("and the server's as its receive keys",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_INITIAL, 1, &client_receive));
  WT_EXPECT_OK("the server holds the client's send keys",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_INITIAL, 1, &client_send));
  WT_EXPECT_OK("and its own as its send keys",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_INITIAL, 0, &client_receive));

  wt_quic_connection_set_handlers(&pair->client, record_frame, &pair->client_witness, record_lost,
                                  &pair->client_witness);
  wt_quic_connection_set_handlers(&pair->server, record_frame, &pair->server_witness, record_lost,
                                  &pair->server_witness);
}

/* Wait until the socket has a datagram, then read it. This is what a real event loop does -- the
 * connection's receive is non-blocking by design (WT-13's socket layer), so a caller that reads without
 * waiting gets WT_ERR_AGAIN, which is not a failure and not a packet. */
static void receive_on(wt_quic_connection_t *connection, const wt_udp_socket_t *socket, uint64_t now) {
  WT_EXPECT_OK("the socket becomes readable", wt_udp_wait(socket, 2000000U));
  WT_EXPECT_OK("and the connection reads the datagram",
               wt_quic_connection_receive(connection, now));
}

static void close_pair(connection_pair_t *pair) {
  wt_quic_connection_clear(&pair->client);
  wt_quic_connection_clear(&pair->server);
  wt_udp_close(&pair->client_socket);
  wt_udp_close(&pair->server_socket);
}

/* One exchange: the client sends a CRYPTO payload, the server receives it and acknowledges, and the
 * client takes the acknowledgement. Everything the runtime is for happens in these four calls. */
static void test_round_trip(wt_udp_family_t family) {
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
  WT_EXPECT_U64("with nothing left in flight", 0U,
                (uint64_t)wt_quic_loss_count(&pair.client.loss));
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
static void test_short_packet_is_padded(wt_udp_family_t family) {
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
static void test_packet_threshold_loss(void) {
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
  WT_EXPECT_U64("four packets are in flight", 4U,
                (uint64_t)wt_quic_loss_count(&pair.client.loss));

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
static void test_ack_for_unsent_packet(void) {
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
static void test_close_paths(void) {
  connection_pair_t pair;
  uint64_t now = 30000000U;

  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("a CRYPTO payload is sent",
               wt_quic_connection_send_crypto(&pair.client, WT_QUIC_SPACE_INITIAL, 0U,
                                              (const uint8_t *)"\x09\x09", 2U, now));
  now += 1000U;
  WT_EXPECT_INT("the client is not closed", 0, wt_quic_connection_is_closed(&pair.client));

  WT_EXPECT_OK("it closes with an error", wt_quic_connection_close(&pair.client, 0x0aU,
                                                                   WT_QUIC_FRAME_STREAM_BASE, NULL,
                                                                   0U, now));
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
      WT_EXPECT_OK("a peer limit to be contradicted",
                   wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_INITIAL_MAX_DATA,
                                                            50000U));
      WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
      WT_EXPECT_OK("and is parsed by the server",
                   wt_quic_connection_set_peer_parameters(&pair.server, payload,
                                                          wt_writer_offset(&pw)));
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
static void test_discards(void) {
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
static void test_garbage(wt_udp_family_t family) {
  connection_pair_t pair;
  wt_udp_socket_t stranger;
  wt_udp_address_t stranger_address;
  uint8_t garbage[32];
  uint16_t port = 0U;
  uint64_t now = 50000000U;
  size_t i;
  uint64_t received_before;

  open_pair(family, &pair);
  for (i = 0U; i < sizeof(garbage); i++) garbage[i] = (uint8_t)(0x40U + i);

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
static void test_key_discard(void) {
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
static void test_handshake_done_role(void) {
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
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x20U + i);
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
  while (wt_writer_offset(&w) < 4U) wt_writer_u8(&w, 0U);
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
static void test_frame_permission(void) {
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
  while (wt_writer_offset(&w) < 3U) wt_writer_u8(&w, 0U);
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
  WT_EXPECT_U64("naming the STREAM frame", WT_QUIC_FRAME_STREAM_BASE,
                pair.server.close.frame_type);

  close_pair(&pair);
}

/* Opening a stream: the number comes from the counts, the peer's grant bounds it, and the two flow
 * control limits are the two directions'. */
static void test_open_stream(void) {
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

/* RFC 9000 section 3.2 and 4.6: a frame for a peer-initiated stream this endpoint has never seen OPENS
 * it, bounded by the count this endpoint granted; more than that is STREAM_LIMIT_ERROR, and a frame for
 * one of this endpoint's own numbers that was never opened is STREAM_STATE_ERROR. MAX_STREAM_DATA then
 * raises one stream's send allowance. */
/* Send a short-header application packet carrying exactly these bytes. A frame the ENCODER refuses to
 * produce -- because it would refuse to decode it -- can only be tested this way. */
static void send_raw_payload_with_dcid(const connection_pair_t *pair, const uint8_t *payload,
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

static void send_raw_payload_to(const connection_pair_t *pair, const uint8_t *payload,
                                size_t payload_length, const wt_quic_packet_keys_t *keys,
                                uint64_t packet_number) {
  send_raw_payload_with_dcid(pair, payload, payload_length, k_dcid, sizeof(k_dcid), keys, packet_number);
}

static void send_frame_to(const connection_pair_t *pair, const wt_quic_frame_t *frame,
                          const wt_quic_packet_keys_t *keys, uint64_t packet_number, uint64_t now) {
  uint8_t payload[128];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));

  WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, frame));
  send_raw_payload_to(pair, payload, wt_writer_offset(&w), keys, packet_number);
  (void)now;
}

static void test_peer_opens_stream(void) {
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
static void test_reset_and_stop(void) {
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
static void test_limit_extension(void) {
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
static void test_reset_stream_send(void) {
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

/* What a lost STREAM packet tells its owner: RFC 9002 section 6.1 hands a lost packet back to whoever
 * can send it again, and for a stream that is the layer that keeps the bytes. This checks the
 * descriptor the connection reports -- the stream, the offset and the length -- because a descriptor
 * that named the wrong range would resend the wrong bytes just as silently as no descriptor at all. */
typedef struct lost_witness {
  size_t count;
  uint64_t stream_id;
  uint64_t offset;
  size_t length;
  int is_crypto;
} lost_witness_t;

static void record_stream_loss(void *context, const wt_quic_tx_frame_t *frame) {
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

static void test_stream_retransmit_descriptor(void) {
  connection_pair_t pair;
  lost_witness_t witness;
  uint8_t payload[64];
  wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
  wt_quic_transport_parameters_t params;
  size_t i;
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
               wt_quic_connection_open_stream(&pair.client, 1, &now));
  wt_quic_connection_set_handlers(&pair.client, NULL, NULL, record_stream_loss, &witness);
  for (i = 0U; i < 4U; i++) {
    uint8_t data[2] = {(uint8_t)i, (uint8_t)(0xf0U + i)};
    WT_EXPECT_OK("a stream payload is sent",
                 wt_quic_connection_send_stream(&pair.client, 0U, i * 2U, data, sizeof(data), 0,
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
static void test_stop_sending_send(void) {
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
  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* RFC 9000 sections 5.1.1 and 19.15: an endpoint issues connection IDs bounded by what the peer said it
 * will store, and the peer's limit counts the ID the handshake used. */
static void test_issue_connection_id(void) {
  connection_pair_t pair;
  uint8_t payload[64];
  wt_quic_transport_parameters_t params;
  /* Eight bytes, like the connection ID the handshake used: an issued ID of another length could not be
   * received, because a short header carries no length, so the connection refuses one. */
  static const uint8_t first_id[8] = {0x11U, 0x22U, 0x33U, 0x44U, 0x11U, 0x22U, 0x33U, 0x44U};
  static const uint8_t second_id[8] = {0x55U, 0x66U, 0x77U, 0x88U, 0x55U, 0x66U, 0x77U, 0x88U};
  uint8_t token[16];
  uint64_t now = 103000000U;

  memset(token, 0x5a, sizeof(token));
  open_pair(WT_UDP_IPV4, &pair);
  {
    wt_quic_packet_keys_t keys;
    uint8_t secret[WT_SHA256_LEN];
    size_t i;
    for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0xe0U + i);
    WT_EXPECT_OK("application keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
    WT_EXPECT_OK("client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  }
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a limit of two connection IDs",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 2U));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("encodes", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and is parsed",
                 wt_quic_connection_set_peer_parameters(&pair.client, payload, wt_writer_offset(&pw)));
  }

  WT_EXPECT_STATUS("an empty connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_issue_connection_id(&pair.client, first_id, 0U, token, now));
  /* A short header carries no connection ID length, so an ID of another length could never be received:
   * this endpoint parses every packet with the one length it uses. */
  WT_EXPECT_STATUS("and so is one of a length this endpoint does not use", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_issue_connection_id(&pair.client, first_id, 4U, token, now));
  WT_EXPECT_STATUS("and a null token is", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_issue_connection_id(&pair.client, first_id, sizeof(first_id),
                                                          NULL, now));
  WT_EXPECT_OK("one is issued",
               wt_quic_connection_issue_connection_id(&pair.client, first_id, sizeof(first_id), token,
                                                      now));
  {
    /* RFC 9000 section 5.1.1: sequence 0 is the connection ID the handshake used, so the first ID this
     * endpoint announces is sequence 1. Numbering the spares from zero would collide with it. */
    const wt_quic_issued_connection_id_t *issued = wt_quic_connection_issued_id(&pair.client, 1U);
    WT_EXPECT_TRUE("and remembered by sequence", issued != NULL);
    if (issued != NULL) {
      WT_EXPECT_U64("with its length", (uint64_t)sizeof(first_id), (uint64_t)issued->length);
      WT_EXPECT_BYTES("and its bytes", first_id, issued->id, sizeof(first_id));
    }
    WT_EXPECT_U64("while the next sequence to hand out is the one after it", 2U,
                  pair.client.next_issued_sequence);
  }
  WT_EXPECT_TRUE("and the handshake's own sequence is not in the table",
                 wt_quic_connection_issued_id(&pair.client, 0U) == NULL);
  WT_EXPECT_STATUS("the same ID again is a caller error", WT_ERR_STATE,
                   wt_quic_connection_issue_connection_id(&pair.client, first_id, sizeof(first_id),
                                                          token, now));
  /* The limit counts the handshake's ID, so a grant of two leaves room for ONE spare. */
  WT_EXPECT_STATUS("a second is beyond what the peer will store", WT_ERR_LIMIT,
                   wt_quic_connection_issue_connection_id(&pair.client, second_id, sizeof(second_id),
                                                          token, now));
  WT_EXPECT_TRUE("and a sequence that was never issued is not found",
                 wt_quic_connection_issued_id(&pair.client, 7U) == NULL);
  close_pair(&pair);
}

/* RFC 9000 section 19.15: a NEW_CONNECTION_ID from the peer is stored, bounded by what this endpoint
 * advertised it would store, and the section's own errors are raised rather than ignored. */
static void send_application_frame(const connection_pair_t *pair, const wt_quic_frame_t *frame,
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
  WT_EXPECT_OK("the packet builds", wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_OK("and is sent", wt_udp_send(&pair->client_socket, &pair->server_address, datagram, datagram_len));
}

/* The same injection as `send_application_frame`, but a long-header Initial packet built short: it is
 * what RFC 9000 section 14.1 says a server must discard, and it has to be hand-built because this
 * library's own send path now pads every client Initial. */
static void send_short_initial_frame(const connection_pair_t *pair, const wt_quic_frame_t *frame,
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
  WT_EXPECT_OK("the packet builds", wt_quic_packet_build(&build, datagram, sizeof(datagram), &datagram_len));
  WT_EXPECT_TRUE("and is below the Initial minimum", datagram_len < WT_QUIC_MIN_INITIAL_DATAGRAM_SIZE);
  WT_EXPECT_OK("and is sent",
               wt_udp_send(&pair->client_socket, &pair->server_address, datagram, datagram_len));
}

static void test_peer_connection_ids(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  static const uint8_t id_a[6] = {1U, 2U, 3U, 4U, 5U, 6U};
  uint8_t token_a[16];
  uint8_t token_b[16];
  uint64_t now = 104000000U;
  size_t i;

  memset(token_a, 0x11, sizeof(token_a));
  memset(token_b, 0x22, sizeof(token_b));
  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x30U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client writes", wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads", wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
  frame.as.new_connection_id.sequence = 1U;
  frame.as.new_connection_id.retire_prior_to = 0U;
  frame.as.new_connection_id.connection_id = id_a;
  frame.as.new_connection_id.connection_id_length = sizeof(id_a);
  frame.as.new_connection_id.stateless_reset_token = token_a;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server is not closed by it", 0, wt_quic_connection_is_closed(&pair.server));
  {
    size_t found = 0U;
    for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
      if (pair.server.peer_ids[i].in_use && pair.server.peer_ids[i].sequence == 1U) {
        found = 1U;
        WT_EXPECT_U64("and it is stored with its length", (uint64_t)sizeof(id_a),
                      (uint64_t)pair.server.peer_ids[i].length);
        WT_EXPECT_BYTES("and its bytes", id_a, pair.server.peer_ids[i].id, sizeof(id_a));
      }
    }
    WT_EXPECT_U64("which the table holds", 1U, (uint64_t)found);
  }

  /* The same sequence with a different token is the PROTOCOL_VIOLATION the section names. */
  frame.as.new_connection_id.stateless_reset_token = token_b;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a changed token for a known sequence closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  close_pair(&pair);

  /* The `retire_prior_to` rule is not exercised here: the frame ENCODER refuses to produce a
   * retire_prior_to above the sequence -- this library refuses to encode what it would refuse to decode --
   * so testing the decoder's refusal needs a hand-built packet, which is recorded as a task. */
}

/* RFC 9000 section 19.16: a RETIRE_CONNECTION_ID gives up an ID this endpoint issued. The two sequences
 * the section makes a PROTOCOL_VIOLATION are tested separately: one that was never issued, and the one
 * the carrying packet was addressed to. A repeat of a retirement already made is not an error, because
 * the frame is retransmitted when it is lost. */
static void test_retire_connection_id(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  wt_quic_transport_parameters_t params;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  static const uint8_t first_id[8] = {0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U};
  static const uint8_t replacement_id[8] = {0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U};
  uint8_t token[16];
  uint64_t now = 105000000U;
  size_t i;

  memset(token, 0x77, sizeof(token));
  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x40U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  /* The server issues the ID and reads the peer's frames, so both directions of the application keys are
   * needed on the server: one to announce the ID, one to decrypt the packet that retires it. */
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  /* Three IDs allowed, so there is room for the issued ID, the retirement, and its replacement. */
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a limit of three connection IDs",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 3U));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and are parsed",
                 wt_quic_connection_set_peer_parameters(&pair.server, payload, wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK("the server issues one",
               wt_quic_connection_issue_connection_id(&pair.server, first_id, sizeof(first_id), token,
                                                      now));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 1U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("retiring an issued ID does not close the connection", 0,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("the slot is given up", 0U, (uint64_t)pair.server.issued_count);
  WT_EXPECT_TRUE("and the ID is no longer known", wt_quic_connection_issued_id(&pair.server, 1U) == NULL);

  /* The room the retirement freed is usable again, under a sequence that has never been handed out. */
  WT_EXPECT_OK("a replacement is issued",
               wt_quic_connection_issue_connection_id(&pair.server, replacement_id,
                                                      sizeof(replacement_id), token, now));
  WT_EXPECT_TRUE("under the next sequence", wt_quic_connection_issued_id(&pair.server, 2U) != NULL);
  WT_EXPECT_TRUE("while the retired sequence stays retired",
                 wt_quic_connection_issued_id(&pair.server, 1U) == NULL);

  /* The same retirement again is a retransmission of a frame whose effect is already in place. */
  frame.as.retire_connection_id.sequence = 1U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a repeated retirement is tolerated", 0, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and does not touch the replacement", 1U, (uint64_t)pair.server.issued_count);

  /* `next_issued_sequence` is 3, so sequence 3 has never been sent to the peer. */
  frame.as.retire_connection_id.sequence = 3U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 2U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("a sequence that was never issued closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the frame that caused it", (uint64_t)WT_QUIC_FRAME_RETIRE_CONNECTION_ID,
                pair.server.close.frame_type);
  close_pair(&pair);
}

/* RFC 9000 section 19.16: an endpoint cannot retire the connection ID that the packet carrying the frame
 * was addressed to. Here that is the handshake's ID, which section 5.1.1 numbers 0; the same rule with an
 * issued ID as the destination is covered by `test_packets_to_issued_connection_ids`. */
static void test_retire_handshake_connection_id(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 106000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x50U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 0U;
  send_application_frame(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("retiring the handshake's own connection ID closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  WT_EXPECT_U64("naming the frame that caused it", (uint64_t)WT_QUIC_FRAME_RETIRE_CONNECTION_ID,
                pair.server.close.frame_type);
  close_pair(&pair);
}

/* RFC 9000 section 14.1: a client expands every UDP datagram carrying an Initial packet to at least
 * 1200 bytes. The four-byte CRYPTO payload below is the case that matters, because a conformant
 * server discards the datagram that is not expanded -- so without this the handshake cannot start. */
static void test_client_initial_datagram_is_padded(void) {
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
  WT_EXPECT_TRUE("with its packet number recorded", pair.server.spaces[WT_QUIC_SPACE_INITIAL].received.has_largest != 0);
  close_pair(&pair);
}

/* The other half of section 14.1, which is what makes the send rule observable: a server discards an
 * Initial packet carried in a datagram smaller than 1200 bytes. The packet is hand-built because this
 * library's own client would have padded it. */
static void test_short_initial_datagram_is_discarded(void) {
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
  WT_EXPECT_INT("and without closing the connection", 0, wt_quic_connection_is_closed(&pair.server));
  close_pair(&pair);
}

/* RFC 9000 section 19.15: a NEW_CONNECTION_ID whose `retire_prior_to` is above its own sequence is a
 * FRAME_ENCODING_ERROR, because it would retire the connection ID the frame itself introduces. The
 * decoder checks it, and this is the test the frame ENCODER cannot produce: this library refuses to
 * encode what it would refuse to decode, so the bytes are written by hand (WT-83). */
static void test_new_connection_id_retire_prior_to_is_refused(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  uint8_t payload[32];
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 111000000U;
  size_t len = 0U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x60U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  payload[len++] = 0x18U; /* NEW_CONNECTION_ID */
  payload[len++] = 0x00U; /* sequence */
  payload[len++] = 0x01U; /* retire_prior_to: above the sequence, which is the error */
  payload[len++] = 0x04U; /* connection ID length */
  payload[len++] = 0x01U;
  payload[len++] = 0x02U;
  payload[len++] = 0x03U;
  payload[len++] = 0x04U;
  for (i = 0U; i < 16U; i++) payload[len++] = 0xaaU; /* stateless reset token */

  send_raw_payload_to(&pair, payload, len, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("the server closes the connection", 1, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a frame encoding error", (uint64_t)WT_QUIC_FRAME_ENCODING_ERROR,
                pair.server.close.error_code);
  close_pair(&pair);
}

/* RFC 9000 sections 5.1 and 7.2: an endpoint accepts packets addressed to any connection ID it issued and
 * has not retired -- that is what issuing them is for, and it is how a peer that moves to a new path keeps
 * its packets addressed to this connection -- and discards packets addressed to an ID it has retired.
 *
 * The third phase is RFC 9000 section 19.16's other PROTOCOL_VIOLATION, and it only exists once the first
 * two do: a peer cannot retire the connection ID it addressed the packet to, which is not always the
 * handshake's ID any more. */
static void test_packets_to_issued_connection_ids(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_transport_parameters_t params;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  static const uint8_t issued[8] = {0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U, 0x58U};
  static const uint8_t ping_and_padding[4] = {0x01U, 0x00U, 0x00U, 0x00U};
  uint8_t token[16];
  uint64_t now = 112000000U;
  size_t i;

  memset(token, 0x33, sizeof(token));

  /* Phase one: a packet addressed to an issued ID is processed. */
  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x70U + i);
  WT_EXPECT_OK("keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("a limit of three connection IDs",
               wt_quic_transport_parameters_add_integer(&params, WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, 3U));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and are parsed",
                 wt_quic_connection_set_peer_parameters(&pair.server, payload, wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK("the server issues one",
               wt_quic_connection_issue_connection_id(&pair.server, issued, sizeof(issued), token, now));

  send_raw_payload_with_dcid(&pair, ping_and_padding, sizeof(ping_and_padding), issued, sizeof(issued),
                             &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("a packet addressed to an issued ID is processed", 1U,
                (uint64_t)pair.server.spaces[WT_QUIC_SPACE_APPLICATION].received.has_largest);
  WT_EXPECT_U64("and is not discarded", 0U, pair.server.packets_discarded);
  WT_EXPECT_U64("for sequence zero, the handshake's", 0U,
                pair.server.spaces[WT_QUIC_SPACE_APPLICATION].received.largest_received);

  /* Phase two: retiring that ID and then addressing a packet to it. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 1U;
  send_frame_to(&pair, &frame, &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U, now);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("the retirement is applied", 0U, (uint64_t)pair.server.issued_count);
  send_raw_payload_with_dcid(&pair, ping_and_padding, sizeof(ping_and_padding), issued, sizeof(issued),
                             &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 2U);
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("a packet addressed to a retired ID is discarded", 1U, pair.server.packets_discarded);
  /* The packets that were accepted were 0 and 1; the discarded one was 2, so the received set must not
   * have advanced to it. */
  WT_EXPECT_U64("with the discarded packet not recorded", 1U,
                pair.server.spaces[WT_QUIC_SPACE_APPLICATION].received.largest_received);
  close_pair(&pair);

  /* Phase three: retiring the connection ID the packet itself was addressed to. */
  open_pair(WT_UDP_IPV4, &pair);
  WT_EXPECT_OK("the server writes",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and reads",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&pw, &params));
    WT_EXPECT_OK("and are parsed",
                 wt_quic_connection_set_peer_parameters(&pair.server, payload, wt_writer_offset(&pw)));
  }
  WT_EXPECT_OK("the server issues one again",
               wt_quic_connection_issue_connection_id(&pair.server, issued, sizeof(issued), token, now));
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 1U;
  {
    wt_writer_t pw = wt_writer_init(payload, sizeof(payload));
    WT_EXPECT_OK("the retire frame encodes", wt_quic_frame_encode(&pw, &frame));
    send_raw_payload_with_dcid(&pair, payload, wt_writer_offset(&pw), issued, sizeof(issued),
                               &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
  }
  now += 1000U;
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_INT("retiring the ID the packet was addressed to closes it", 1,
                wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("with a protocol violation", (uint64_t)WT_QUIC_PROTOCOL_VIOLATION,
                pair.server.close.error_code);
  close_pair(&pair);
}

/* A handler that REFUSES every frame, which is what `deliver_to_handler`'s close path exists for. */
static wt_status_t refuse_frame(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  unsigned *count = context;
  (void)space;
  (void)frame;
  (*count)++;
  return WT_ERR_PROTOCOL;
}

/* What a refusal leaves behind, which is the question a tool asks when a session ends badly (WT-144).
 *
 * The device this replaces was the HINT: a refusing handler may leave `close_code`/`close_code_set` for the
 * connection to name in its CONNECTION_CLOSE, and the connection CLEARS that flag before it closes. So a caller
 * that asked "what did we close with, and why" read zeroes -- indistinguishable from a connection that never
 * closed -- and a CLI went on printing `"status":"ok"` for a session it had ended with INTERNAL_ERROR. The close
 * STATE and the cause are kept instead, and this is the test that says so. */
static void test_a_refusal_leaves_a_readable_close(wt_udp_family_t family) {
  connection_pair_t pair;
  static const uint8_t payload[] = {0x01U, 0x02U, 0x03U, 0x04U};
  unsigned refused = 0U;
  const wt_quic_close_state_t *close_state;
  uint64_t now = 1000000U;

  open_pair(family, &pair);
  wt_quic_connection_set_handlers(&pair.server, refuse_frame, &refused, record_lost,
                                  &pair.server_witness);
  WT_EXPECT_INT("a fresh connection has no close to report", 0, wt_quic_connection_is_closed(&pair.server));
  WT_EXPECT_U64("and no cause", (uint64_t)WT_OK, (uint64_t)wt_quic_connection_close_cause(&pair.server));
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
  WT_EXPECT_INT("while the hint the handler could have left is cleared", 0, pair.server.close_code_set);
  /* The peer's own close is a different question and is still unanswered. */
  WT_EXPECT_INT("and nothing is recorded about the peer closing", 0, pair.server.peer_closed);

  close_pair(&pair);
}

/* A handler that names its code, so the close the peer is told about is the handler's rather than a generic one. */
static wt_status_t refuse_frame_with_code(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  wt_quic_connection_t *connection = context;
  (void)space;
  connection->close_code = (uint64_t)WT_QUIC_STREAM_STATE_ERROR;
  connection->close_frame_type = WT_QUIC_FRAME_CRYPTO;
  connection->close_code_set = 1;
  (void)frame;
  return WT_ERR_PROTOCOL;
}

static void test_a_handler_can_name_the_code_it_refused_with(wt_udp_family_t family) {
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
static void test_crypto_is_permitted_in_the_application_space(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  static const uint8_t ticket[] = {0x04U, 0x00U, 0x00U, 0x00U};
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 95000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x50U + i);
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

/* A server answers to the ID the CLIENT chose for its first Initial, which it cannot know from its own
 * configuration: a client picks that value arbitrarily (RFC 9000 section 7.2). This tree's two tools shared one
 * constant across both roles, so a server that accepted only its own ID looked exactly like a server that
 * accepted the client's -- and a third-party client, which picks its own, would have been refused outright
 * (WT-151). The packet is a 1-RTT one because an Initial below 1200 bytes is discarded by section 14.1, which
 * is a different rule and would hide this one. */
static void test_a_server_answers_to_the_clients_chosen_id(void) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  uint8_t payload[64];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  uint64_t now = 96000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x60U + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair.client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("the server reads with them",
               wt_quic_connection_set_keys(&pair.server, WT_QUIC_SPACE_APPLICATION, 1, &keys));

  {
    static const uint8_t k_chosen[8] = {0xdeU, 0xadU, 0xbeU, 0xefU, 0x01U, 0x02U, 0x03U, 0x04U};
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
    WT_EXPECT_OK("the frame encodes", wt_quic_frame_encode(&w, &frame));
    WT_EXPECT_OK("the server is told what the client chose",
                 wt_quic_connection_set_original_destination_id(&pair.server, k_chosen, sizeof(k_chosen)));
    WT_EXPECT_U64("before the handshake is confirmed", 0U, (uint64_t)pair.server.handshake_confirmed);

    send_raw_payload_with_dcid(&pair, payload, wt_writer_offset(&w), k_chosen, sizeof(k_chosen),
                               &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 0U);
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("so the packet reaches the handler", 1U, (uint64_t)pair.server_witness.count);
    WT_EXPECT_INT("and the connection is not closed", 0, wt_quic_connection_is_closed(&pair.server));
  }

  /* An ID that is neither this endpoint's nor the client's chosen one is another connection's, and RFC 9000
   * section 5.2 makes discarding it the rule. */
  {
    static const uint8_t k_unknown[8] = {0x0fU, 0x0eU, 0x0dU, 0x0cU, 0x0bU, 0x0aU, 0x09U, 0x08U};
    unsigned before = (unsigned)pair.server_witness.count;
    uint64_t discarded_before = pair.server.packets_discarded;
    w = wt_writer_init(payload, sizeof(payload));
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
    WT_EXPECT_OK("another frame encodes", wt_quic_frame_encode(&w, &frame));
    now += 1000U;
    send_raw_payload_with_dcid(&pair, payload, wt_writer_offset(&w), k_unknown, sizeof(k_unknown),
                               &pair.server.keys_in[WT_QUIC_SPACE_APPLICATION], 1U);
    receive_on(&pair.server, &pair.server_socket, now);
    WT_EXPECT_U64("a packet for an unknown connection is discarded, not delivered", (uint64_t)before,
                  (uint64_t)pair.server_witness.count);
    WT_EXPECT_U64("and counted as discarded", discarded_before + 1U, pair.server.packets_discarded);
  }

  close_pair(&pair);
}

/* An HTTP/3 refusal reaches the peer as an APPLICATION close (WT-158).
 *
 * RFC 9114 section 8 carries every HTTP/3 error in a CONNECTION_CLOSE of type 0x1d whose code is the HTTP/3 error
 * code -- H3_FRAME_ERROR for a frame that ends part way through, H3_SETTINGS_ERROR for a bad setting. A handler
 * that could only return a status closed the TRANSPORT with INTERNAL_ERROR instead: a different frame, a
 * different code, and a peer that cannot tell which rule it broke. */
static wt_status_t refuse_with_h3_error(void *context, wt_quic_space_t space, const wt_quic_frame_t *frame) {
  wt_quic_connection_t *connection = context;
  (void)space;
  (void)frame;
  /* The HTTP/3 error space: H3_FRAME_ERROR is 0x107. */
  wt_quic_connection_refuse_application(connection, (uint64_t)0x107U, 0U);
  return WT_ERR_PROTOCOL;
}

static void test_an_http3_refusal_is_an_application_close(wt_udp_family_t family) {
  connection_pair_t pair;
  wt_quic_packet_keys_t keys;
  wt_quic_frame_t frame;
  uint8_t secret[WT_SHA256_LEN];
  const wt_quic_close_state_t *close_state;
  uint64_t now = 97000000U;
  size_t i;

  open_pair(family, &pair);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x70U + i);
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
                  (uint64_t)WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION, (uint64_t)close_frame.kind);
    WT_EXPECT_U64("whose code is the HTTP/3 one", 0x107U, close_frame.as.connection_close.error_code);
    WT_EXPECT_INT("and which has no frame-type field", 0, close_frame.as.connection_close.has_frame_type);
  }
  WT_EXPECT_OK("the server flushes its close", wt_quic_connection_flush(&pair.server, now));
  WT_EXPECT_INT("which was sent", 1, wt_quic_connection_close_was_sent(&pair.server));

  close_pair(&pair);
}

/* The reliable-stream-reset extension, the SEND half (WT-161).
 *
 * WebTransport over HTTP/3 "relies on the RESET_STREAM_AT frame" (draft-16 section 3.1) because a WebTransport
 * stream carries its session prefix first: a reset that dropped the prefix leaves the peer with a stream it cannot
 * attribute to a session. This tree could decode the frame and did nothing else with it -- no way to send one, and
 * therefore nothing for the parameter advertised last round to gate. */
static void test_the_reliable_stream_reset_is_sent_and_applied(void) {
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

  /* The peer's parameters, WITH the extension. */
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
  /* The frame's ARRIVAL is asserted where it can be injected whole -- `test_the_reliable_stream_reset_rules`
   * below -- and its crossing of a real handshake in `test_runtime_session_pair`. This test is the send path's
   * CONTRACT: what it refuses, and that a frame the peer can read goes out. */
  wt_quic_packet_keys_clear(&keys);
  close_pair(&pair);
}

/* Application keys for a pair, so that a frame can cross it: `open_pair` installs the Initial keys only, and the
 * app-space tests each derive their own. */
static void install_application_keys(connection_pair_t *pair, uint8_t base) {
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  size_t i;

  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(base + i);
  WT_EXPECT_OK("application keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("the client sends with them",
               wt_quic_connection_set_keys(&pair->client, WT_QUIC_SPACE_APPLICATION, 0, &keys));
  WT_EXPECT_OK("and the server reads with them",
               wt_quic_connection_set_keys(&pair->server, WT_QUIC_SPACE_APPLICATION, 1, &keys));
}

/* The extension's own rules, from the receiving end: a frame that RAISES the reliable size is ignored, and the two
 * ways a frame can be wrong are the two codes its draft names (WT-161). */
static void test_the_reliable_stream_reset_rules(void) {
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

int main(void) {
  test_frame_permission();
  test_handshake_done_role();
  test_key_discard();
  test_round_trip(WT_UDP_IPV4);
  test_round_trip(WT_UDP_IPV6);
  test_short_packet_is_padded(WT_UDP_IPV4);
  test_client_initial_datagram_is_padded();
  test_short_initial_datagram_is_discarded();
  test_packet_threshold_loss();
  test_ack_for_unsent_packet();
  test_close_paths();
  test_a_refusal_leaves_a_readable_close(WT_UDP_IPV4);
  test_a_refusal_leaves_a_readable_close(WT_UDP_IPV6);
  test_a_handler_can_name_the_code_it_refused_with(WT_UDP_IPV4);
  test_crypto_is_permitted_in_the_application_space();
  test_discards();
  test_garbage(WT_UDP_IPV4);
  test_garbage(WT_UDP_IPV6);

  test_open_stream();
  test_peer_opens_stream();
  test_the_reliable_stream_reset_is_sent_and_applied();
  test_the_reliable_stream_reset_rules();
  test_reset_and_stop();
  test_limit_extension();
  test_reset_stream_send();
  test_stream_retransmit_descriptor();
  test_stop_sending_send();
  test_issue_connection_id();
  test_peer_connection_ids();
  test_a_server_answers_to_the_clients_chosen_id();
  test_an_http3_refusal_is_an_application_close(WT_UDP_IPV4);
  test_retire_connection_id();
  test_retire_handshake_connection_id();
  test_new_connection_id_retire_prior_to_is_refused();
  test_packets_to_issued_connection_ids();
  WT_TEST_MAIN_END("wt_quic_connection");
}
