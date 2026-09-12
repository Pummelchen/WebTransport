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
  WT_EXPECT_OK("the server initialises", wt_quic_connection_init(&pair->server, &server_config));
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

int main(void) {
  test_key_discard();
  test_round_trip(WT_UDP_IPV4);
  test_round_trip(WT_UDP_IPV6);
  test_short_packet_is_padded(WT_UDP_IPV4);
  test_packet_threshold_loss();
  test_ack_for_unsent_packet();
  test_close_paths();
  test_discards();
  test_garbage(WT_UDP_IPV4);
  test_garbage(WT_UDP_IPV6);

  WT_TEST_MAIN_END("wt_quic_connection");
}
