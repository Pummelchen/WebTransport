/* A whole TLS 1.3 handshake between two connections over loopback sockets.
 *
 * THIS IS THE PHASE'S COMPLETION CRITERION IN ONE TEST. Two QUIC connections, two real UDP sockets on one
 * machine, a real certificate and a real signature: the ClientHello travels in an Initial packet, the
 * ServerHello in another, the rest of the server's flight under the handshake keys the ServerHello
 * derived, the client's Finished under the same, and the server's confirmation under the application
 * keys -- each level installed by the handshake driver at the moment the handshake made it available,
 * and each datagram protected, sent, received, unprotected and reassembled by the layers below. IPv4 and
 * IPv6 are both run, because "loopback works" is a statement about the family and not about the code.
 *
 * THE CLOCK IS SYNTHETIC AND THE SOCKET IS REAL. Every call takes the test's own microsecond value, so
 * the round trip arithmetic and the timers are deterministic, while the bytes really do go through the
 * kernel. What the test must not do is sleep: `wt_udp_wait` is given a short timeout and a timeout is
 * treated as "nothing has arrived yet", which is what a real event loop does with it.
 *
 * The certificates are the repository's trust fixtures -- a leaf for example.com, the CA that signs it,
 * and the leaf's private key -- which is why the client validates with a STORE holding that CA and the
 * host name the leaf was issued for. A test that pinned nothing and validated nothing would pass while
 * the handshake did no authentication at all.
 */

#include <stdio.h>
#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/connection.h"
#include "webtransport/quic/handshake.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/protection.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/runtime/udp.h"
#include "webtransport/writer.h"

#ifndef WT_TRUST_FIXTURE_DIR
#error "WT_TRUST_FIXTURE_DIR must name the directory holding the trust fixtures"
#endif

static const uint8_t k_connection_id[8] = {0x83U, 0x94U, 0xc8U, 0xf0U, 0x3eU, 0x51U, 0x57U, 0x08U};
/* The transport parameters BOTH ends send, built with the codec rather than written by hand: they are
 * the real thing now, so the limits the connection parses out of the peer's copy are the limits the
 * handshake carrier. `g_now` is the clock the composed frame handler hands to the connection. */
static uint8_t g_parameters[256];
/* What the server's composed handler saw of the last STREAM frame: the wire half of sending on a
 * stream is what this records. */
static uint64_t g_stream_id;
static uint64_t g_stream_offset;
static size_t g_stream_length;
static int g_stream_fin;
static uint8_t g_stream_data[64];
static uint64_t g_max_data;
static uint64_t g_max_streams;
static int g_max_streams_direction;
static size_t g_parameters_len;
static uint64_t g_now;

static void build_test_parameters(void) {
  wt_quic_transport_parameters_t params;
  wt_writer_t w = wt_writer_init(g_parameters, sizeof(g_parameters));

  wt_quic_transport_parameters_init(&params);
  WT_EXPECT_OK("initial_max_data", wt_quic_transport_parameters_add_integer(
                                       &params, WT_QUIC_TP_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_OK("initial_max_stream_data_bidi_local",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 1000U));
  WT_EXPECT_OK("initial_max_stream_data_uni",
               wt_quic_transport_parameters_add_integer(
                   &params, WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 1000U));
  WT_EXPECT_OK("initial_max_streams_bidi", wt_quic_transport_parameters_add_integer(
                                               &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 4U));
  WT_EXPECT_OK("initial_max_streams_uni", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, 4U));
  WT_EXPECT_OK("max_datagram_frame_size", wt_quic_transport_parameters_add_integer(
                                              &params, WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 1200U));
  WT_EXPECT_OK("the parameters encode", wt_quic_transport_parameters_encode(&w, &params));
  g_parameters_len = wt_writer_offset(&w);
  WT_EXPECT_TRUE("with bytes in them", g_parameters_len > 0U);
}
/* The protocol name as bytes: a string literal is char, which this tree treats as the different type it
 * is, and this one is compared byte for byte with what the handshake negotiated. */
static const uint8_t k_alpn_h3[2] = {'h', '3'};

static size_t read_fixture(const char *name, uint8_t *out, size_t capacity) {
  char path[512];
  FILE *file;
  size_t used;

  if (snprintf(path, sizeof(path), "%s/%s", WT_TRUST_FIXTURE_DIR, name) < 0) return 0U;
  file = fopen(path, "rb");
  if (file == NULL) return 0U;
  used = fread(out, 1U, capacity, file);
  fclose(file);
  return used;
}

typedef struct fixtures {
  uint8_t leaf[4096];
  size_t leaf_len;
  uint8_t ca_bundle[8192];
  size_t ca_bundle_len;
  uint8_t private_key[4096];
  size_t private_key_len;
} fixtures_t;

static int load_fixtures(fixtures_t *fixtures) {
  memset(fixtures, 0, sizeof(*fixtures));
  fixtures->leaf_len = read_fixture("leaf.der", fixtures->leaf, sizeof(fixtures->leaf));
  fixtures->ca_bundle_len =
      read_fixture("ca.pem", fixtures->ca_bundle, sizeof(fixtures->ca_bundle));
  fixtures->private_key_len =
      read_fixture("leaf-key.der", fixtures->private_key, sizeof(fixtures->private_key));
  return fixtures->leaf_len != 0U && fixtures->ca_bundle_len != 0U &&
         fixtures->private_key_len != 0U;
}

typedef struct endpoint {
  wt_quic_connection_t connection;
  wt_quic_handshake_t handshake;
  wt_udp_socket_t socket;
  wt_udp_address_t address;
  wt_udp_address_t peer;
} endpoint_t;

/* A datagram if one is waiting, and nothing if not: a timeout from the wait is the ordinary case in an
 * event loop and not a failure, so it is reported through `out_received` rather than as a status. */
static wt_status_t pump(endpoint_t *receiver, uint64_t now, int *out_received) {
  wt_status_t status = wt_udp_wait(&receiver->socket, 20000U);

  if (out_received != NULL) *out_received = 0;
  if (status == WT_ERR_TIMEOUT) return WT_OK;
  if (status != WT_OK) return status;
  status = wt_quic_connection_receive(&receiver->connection, now);
  if (status != WT_OK) return status;
  if (out_received != NULL) *out_received = 1;
  return WT_OK;
}

static void connection_config(wt_quic_connection_config_t *config, wt_quic_role_t role,
                              const endpoint_t *peer) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = k_connection_id;
  config->local_connection_id_length = sizeof(k_connection_id);
  /* Both ends answer to the same connection ID here, which is what makes the Initial keys -- derived
   * from the connection ID -- the same at both ends. A real handshake replaces the peer's ID with the
   * one the server chooses; that is the connection ID management the runtime still needs. */
  config->peer_connection_id = k_connection_id;
  config->peer_connection_id_length = sizeof(k_connection_id);
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = WT_QUIC_MAX_PACKET;
  (void)peer;
}

static void client_tls_config(wt_tls_client_config_t *config, const fixtures_t *fixtures) {
  static const char *const alpn_h3[] = {"h3"};

  memset(config, 0, sizeof(*config));
  config->host_name = "example.com";
  config->alpn = alpn_h3;
  config->alpn_count = 1U;
  config->require_transport_parameters = 1;
  config->transport_parameters = g_parameters;
  config->transport_parameters_len = g_parameters_len;
  config->trust.mode = WT_TLS_TRUST_STORE;
  config->trust.ca_bundle = fixtures->ca_bundle;
  config->trust.ca_bundle_len = fixtures->ca_bundle_len;
  config->trust.host_name = "example.com";
}

static void server_tls_config(wt_tls_server_config_t *config, const fixtures_t *fixtures,
                              wt_tls_server_identity_t *identity) {
  memset(identity, 0, sizeof(*identity));
  identity->certificate[0] = fixtures->leaf;
  identity->certificate_len[0] = fixtures->leaf_len;
  identity->certificate_count = 1U;
  identity->private_key = fixtures->private_key;
  identity->private_key_len = fixtures->private_key_len;
  identity->signature_scheme = WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256;

  memset(config, 0, sizeof(*config));
  config->identity = identity;
  config->alpn = "h3";
  config->require_transport_parameters = 1;
  config->transport_parameters = g_parameters;
  config->transport_parameters_len = g_parameters_len;
}

/* Bring one endpoint up: a socket on loopback, a connection with the Initial keys both ends derive from
 * the same connection ID, and the handshake driver installed as the connection's frame handler. */
static void open_endpoint(wt_udp_family_t family, endpoint_t *endpoint, endpoint_t *peer,
                          wt_quic_role_t role) {
  wt_quic_connection_config_t config;
  wt_quic_packet_keys_t keys;
  uint8_t initial_secret[WT_SHA256_LEN];
  uint16_t port = 0U;

  WT_EXPECT_OK("a socket opens", wt_udp_socket_open(&endpoint->socket, family));
  WT_EXPECT_OK("and binds loopback", wt_udp_bind_loopback(&endpoint->socket, 0U, &port));
  wt_udp_address_loopback(family, &endpoint->address);
  endpoint->address.port = port;
  if (peer != NULL) endpoint->peer = peer->address;

  connection_config(&config, role, endpoint);
  WT_EXPECT_OK("the connection initialises",
               wt_quic_connection_init(&endpoint->connection, &config));
  endpoint->connection.config.local_max_stream_data = 512U;
  WT_EXPECT_OK("and borrows the socket",
               wt_quic_connection_attach(&endpoint->connection, &endpoint->socket,
                                         peer == NULL ? NULL : &peer->address));

  /* The Initial keys: RFC 9001 section 5.2 derives them from the connection ID, and this direction's
   * keys are the peer's opposite, which is what the `from_server` flag says. */
  WT_EXPECT_OK("the Initial secret derives",
               wt_quic_initial_secret(wt_quic_initial_salt_v1, sizeof(wt_quic_initial_salt_v1),
                                      k_connection_id, sizeof(k_connection_id), initial_secret));
  WT_EXPECT_OK("the send keys derive",
               wt_quic_initial_packet_keys(initial_secret, role == WT_QUIC_ROLE_SERVER,
                                           WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("and are installed",
               wt_quic_connection_set_keys(&endpoint->connection, WT_QUIC_SPACE_INITIAL, 0, &keys));
  WT_EXPECT_OK("the receive keys derive",
               wt_quic_initial_packet_keys(initial_secret, role != WT_QUIC_ROLE_SERVER,
                                           WT_AEAD_AES_128_GCM, &keys));
  WT_EXPECT_OK("and are installed",
               wt_quic_connection_set_keys(&endpoint->connection, WT_QUIC_SPACE_INITIAL, 1, &keys));
  wt_quic_packet_keys_clear(&keys);
}

/* The frame handler a real application installs: the handshake layer first, then whatever the
 * application needs. A DATAGRAM frame is not the handshake's business, so the driver answers WT_OK for
 * it and this hands it to the connection's bounded queue. */
static wt_status_t endpoint_on_frame(void *context, wt_quic_space_t space,
                                     const wt_quic_frame_t *frame) {
  endpoint_t *endpoint = context;
  wt_status_t status = wt_quic_handshake_on_frame(&endpoint->handshake, space, frame);

  if (status != WT_OK) return status;
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM) {
    g_stream_id = frame->as.stream.id;
    g_stream_offset = frame->as.stream.offset;
    g_stream_length = frame->as.stream.length;
    g_stream_fin = frame->as.stream.fin;
    if (frame->as.stream.length <= sizeof(g_stream_data) && frame->as.stream.data != NULL) {
      memcpy(g_stream_data, frame->as.stream.data, frame->as.stream.length);
    }
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_MAX_DATA) {
    g_max_data = frame->as.max_data.maximum;
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_MAX_STREAMS) {
    g_max_streams = frame->as.max_streams.maximum;
    g_max_streams_direction = (int)frame->as.max_streams.direction;
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_DATAGRAM) {
    return wt_quic_connection_on_datagram(&endpoint->connection, frame->as.datagram.data,
                                          frame->as.datagram.length, g_now);
  }
  return WT_OK;
}

static void close_endpoint(endpoint_t *endpoint) {
  wt_quic_handshake_clear(&endpoint->handshake);
  wt_quic_connection_clear(&endpoint->connection);
  wt_udp_close(&endpoint->socket);
}

/* Alternate the two ends until both handshakes are complete, giving each flush and each direction of
 * the socket a turn. The step bound is what keeps a handshake that never converges from looping: the
 * test fails on the assertions below rather than hanging. */
static void run_until_connected(endpoint_t *client, endpoint_t *server) {
  uint64_t now = 1000000U;
  int step;

  for (step = 0; step < 60; step++) {
    wt_status_t status;
    int received = 0;

    if (wt_quic_handshake_pending(&client->handshake)) {
      status = wt_quic_handshake_flush(&client->handshake, now);
      if (status != WT_OK) {
        WT_EXPECT_OK("the client can flush", status);
        return;
      }
    }
    status = pump(server, now, &received);
    if (status != WT_OK) {
      WT_EXPECT_OK("the server can receive", status);
      return;
    }
    if (wt_quic_handshake_pending(&server->handshake)) {
      status = wt_quic_handshake_flush(&server->handshake, now);
      if (status != WT_OK) {
        WT_EXPECT_OK("the server can flush", status);
        return;
      }
    }
    status = pump(client, now, &received);
    if (status != WT_OK) {
      WT_EXPECT_OK("the client can receive", status);
      return;
    }
    /* A step reads one datagram from each direction, and the handshake takes a few: the loop simply
     * runs until both ends have nothing left to say. */
    status = pump(server, now, &received);
    if (status != WT_OK) {
      WT_EXPECT_OK("the server can receive again", status);
      return;
    }
    now += 1000U;
    if (wt_quic_handshake_is_connected(&client->handshake) &&
        wt_quic_handshake_is_connected(&server->handshake)) {
      return;
    }
  }
}

static void test_handshake(wt_udp_family_t family) {
  fixtures_t fixtures;
  endpoint_t client;
  endpoint_t server;
  wt_tls_client_config_t client_tls;
  wt_tls_server_config_t server_tls;
  wt_tls_server_identity_t identity;
  const uint8_t *alpn = NULL;
  const uint8_t *parameters = NULL;
  size_t alpn_len = 0U;
  size_t parameters_len = 0U;
  uint64_t now = 5000000U;

  WT_EXPECT_INT("the trust fixtures load", 1, load_fixtures(&fixtures));
  if (fixtures.leaf_len == 0U) return;
  build_test_parameters();

  memset(&client, 0, sizeof(client));
  memset(&server, 0, sizeof(server));
  open_endpoint(family, &server, NULL, WT_QUIC_ROLE_SERVER);
  open_endpoint(family, &client, &server, WT_QUIC_ROLE_CLIENT);
  server.peer = client.address;
  WT_EXPECT_OK("the server learns its peer's address",
               wt_quic_connection_attach(&server.connection, &server.socket, &client.address));

  client_tls_config(&client_tls, &fixtures);
  server_tls_config(&server_tls, &fixtures, &identity);

  /* The driver is the connection's frame handler and its lost handler, which is the seam the connection
   * layer was built with: the packet layer knows nothing about TLS and the handshake knows nothing
   * about packets. */
  wt_quic_connection_set_handlers(&client.connection, endpoint_on_frame, &client,
                                  wt_quic_handshake_on_lost, &client.handshake);
  wt_quic_connection_set_handlers(&server.connection, endpoint_on_frame, &server,
                                  wt_quic_handshake_on_lost, &server.handshake);

  WT_EXPECT_OK("the server handshake starts",
               wt_quic_handshake_start_server(&server.handshake, &server.connection, &server_tls));
  WT_EXPECT_OK("the client handshake starts and builds its ClientHello",
               wt_quic_handshake_start_client(&client.handshake, &client.connection, &client_tls));
  WT_EXPECT_INT("with the ClientHello waiting to be sent", 1,
                wt_quic_handshake_pending(&client.handshake));
  WT_EXPECT_U64("and the client in the waiting state", (uint64_t)WT_QUIC_HANDSHAKE_CLIENT_WAITING,
                (uint64_t)wt_quic_handshake_state(&client.handshake));

  run_until_connected(&client, &server);

  WT_EXPECT_INT("the client's handshake completed", 1,
                wt_quic_handshake_is_connected(&client.handshake));
  WT_EXPECT_INT("the server's handshake completed", 1,
                wt_quic_handshake_is_connected(&server.handshake));
  if (wt_quic_handshake_is_connected(&client.handshake) &&
      wt_quic_handshake_is_connected(&server.handshake)) {
    /* The protocol both ends agreed on, read from the message that carried it. */
    alpn = wt_quic_handshake_alpn(&client.handshake, &alpn_len);
    WT_EXPECT_U64("the client negotiated a protocol", 2U, (uint64_t)alpn_len);
    WT_EXPECT_BYTES("which is h3", k_alpn_h3, alpn, 2U);
    alpn = wt_quic_handshake_alpn(&server.handshake, &alpn_len);
    WT_EXPECT_U64("and so did the server", 2U, (uint64_t)alpn_len);
    WT_EXPECT_BYTES("with the same answer", k_alpn_h3, alpn, 2U);

    /* The peer's transport parameters survived the handshake unchanged, which is what the QUIC layer
     * will read its limits out of. */
    parameters = wt_quic_handshake_peer_transport_parameters(&client.handshake, &parameters_len);
    WT_EXPECT_U64("the client has the server's parameters", (uint64_t)g_parameters_len,
                  (uint64_t)parameters_len);
    WT_EXPECT_BYTES("unchanged", g_parameters, parameters, parameters_len);

    /* The server confirmed the handshake, and the client learned it from HANDSHAKE_DONE. */
    WT_EXPECT_INT("the server considers the handshake confirmed", 1, server.handshake.confirmed);
    WT_EXPECT_INT("and the client does too", 1, client.handshake.confirmed);
    WT_EXPECT_INT("which is what the connection records", 1, client.connection.handshake_confirmed);

    /* RFC 9001 section 4.9's discards are a MUST, and they are visible from outside: the Initial keys
     * go when a Handshake packet is first processed, and the Handshake keys when the handshake is
     * confirmed. What is left is the application level. */
    WT_EXPECT_INT("the client's Initial keys are gone", 0,
                  client.connection.has_keys_in[WT_QUIC_SPACE_INITIAL]);
    WT_EXPECT_INT("in both directions", 0, client.connection.has_keys_out[WT_QUIC_SPACE_INITIAL]);
    WT_EXPECT_INT("and so are its Handshake keys", 0,
                  client.connection.has_keys_in[WT_QUIC_SPACE_HANDSHAKE]);
    WT_EXPECT_INT("the server's too", 0, server.connection.has_keys_in[WT_QUIC_SPACE_INITIAL]);
    WT_EXPECT_INT("and its Handshake keys", 0,
                  server.connection.has_keys_out[WT_QUIC_SPACE_HANDSHAKE]);
    WT_EXPECT_INT("with the application keys kept", 1,
                  client.connection.has_keys_out[WT_QUIC_SPACE_APPLICATION]);
    WT_EXPECT_INT("on both ends", 1, server.connection.has_keys_in[WT_QUIC_SPACE_APPLICATION]);

    /* The parameters the handshake carried become the limits each end obeys. */
    WT_EXPECT_OK(
        "the client parses the server's parameters",
        wt_quic_connection_set_peer_parameters(&client.connection, g_parameters, g_parameters_len));
    WT_EXPECT_OK(
        "and the server parses the client's",
        wt_quic_connection_set_peer_parameters(&server.connection, g_parameters, g_parameters_len));
    WT_EXPECT_U64("with the data limit they state", 100000U,
                  wt_quic_connection_peer_limits(&client.connection)->initial_max_data);
    WT_EXPECT_U64("and the stream count", 4U,
                  wt_quic_connection_peer_limits(&client.connection)->initial_max_streams_bidi);
    WT_EXPECT_U64("and the datagram size", 1200U,
                  wt_quic_connection_peer_limits(&client.connection)->max_datagram_frame_size);
    /* The bigger of the two bounds is the peer's frame limit, so the payload is that limit minus the
     * packet overhead this connection reserves for the header, the packet number, the frame's own
     * fields and the tag. */
    WT_EXPECT_U64("so a datagram payload is bounded by both limits", 1200U - 64U,
                  wt_quic_connection_max_datagram_payload(&client.connection));

    /* The wire half of sending on a stream: the frame's fields are the ones the caller gave, and the
     * stream number is bounded by what the peer granted. */
    {
      static const uint8_t k_stream[6] = {0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U};
      int arrived = 0;

      /* The server must grant the streams ITS OWN transport parameters advertised (four each way), or
       * the receive path is right to refuse a STREAM frame for one of them (RFC 9000 section 4.6). */
      WT_EXPECT_OK(
          "the server grants what it advertised",
          wt_quic_connection_set_max_streams(&server.connection, WT_QUIC_STREAM_BIDIRECTIONAL, 4U));
      WT_EXPECT_OK("in both directions",
                   wt_quic_connection_set_max_streams(&server.connection,
                                                      WT_QUIC_STREAM_UNIDIRECTIONAL, 2U));
      WT_EXPECT_OK("the server grants connection-level room",
                   wt_quic_connection_set_max_data(&server.connection, 65536U));
      g_stream_length = 0U;
      WT_EXPECT_OK("the client sends stream data",
                   wt_quic_connection_send_stream(&client.connection, 0U, 0U, k_stream,
                                                  sizeof(k_stream), 1, now));
      now += 1000U;
      g_now = now;
      WT_EXPECT_OK("the server reads a datagram", pump(&server, now, &arrived));
      WT_EXPECT_INT("which arrived", 1, arrived);
      WT_EXPECT_U64("with the stream it was sent on", 0U, g_stream_id);
      WT_EXPECT_U64("at its offset", 0U, g_stream_offset);
      WT_EXPECT_U64("with its bytes", (uint64_t)sizeof(k_stream), (uint64_t)g_stream_length);
      WT_EXPECT_BYTES("byte for byte", k_stream, g_stream_data, sizeof(k_stream));
      WT_EXPECT_INT("and the end of the stream marked", 1, g_stream_fin);

      /* A stream number the peer did not grant is refused: the parameters above grant four
       * client-initiated bidirectional streams, so index four is one too many. */
      WT_EXPECT_STATUS(
          "a stream beyond the peer's grant is a limit", WT_ERR_LIMIT,
          wt_quic_connection_send_stream(&client.connection, 16U, 0U, k_stream, 1U, 0, now));
      /* Stream 3 is the SERVER's unidirectional stream: a unidirectional stream carries data one way,
       * and that way is the server's, so the client may not send on it. This end's own unidirectional
       * streams would be 2, 6, 10 (RFC 9000 section 2.1). */
      WT_EXPECT_STATUS(
          "a peer's unidirectional stream is not this end's to send on", WT_ERR_LIMIT,
          wt_quic_connection_send_stream(&client.connection, 3U, 0U, k_stream, 1U, 0, now));
    }

    /* The limit this endpoint GRANTS the peer is the other direction from the one it obeys: it has to
     * be seeded with what this endpoint advertised, may only ever rise (RFC 9000 section 4.1 makes a
     * limit that falls a protocol error), and travels as a MAX_DATA frame. */
    {
      int arrived = 0;
      /* The limit is already seeded -- the receive path needed room before it would accept stream
       * data -- so what this checks is the rule that matters: it may only ever rise. */
      WT_EXPECT_U64("the seeded limit reads back", 65536U,
                    wt_quic_connection_max_data(&server.connection));
      /* Below what is already granted, so it is the lowering the RFC makes a protocol error rather
       * than a raise -- and it is not sent, so the client sees exactly one MAX_DATA frame. */
      WT_EXPECT_STATUS("lowering it is refused", WT_ERR_LIMIT,
                       wt_quic_connection_send_max_data(&server.connection, 1024U, now));
      WT_EXPECT_OK("raising it is what a reader does",
                   wt_quic_connection_send_max_data(&server.connection, 200000U, now));
      WT_EXPECT_U64("and is remembered", 200000U, wt_quic_connection_max_data(&server.connection));
      now += 1000U;
      g_now = now;
      WT_EXPECT_OK("the client reads the frame", pump(&client, now, &arrived));
      WT_EXPECT_INT("which arrived", 1, arrived);
      /* The connection ACTS on the frame rather than handing it to the handler: the limit the peer
       * grants is what this endpoint may send, so it is the connection's business. */
      WT_EXPECT_U64("with the raised limit taken as the peer's", 200000U,
                    wt_quic_connection_peer_limits(&client.connection)->initial_max_data);
      WT_EXPECT_STATUS("and a null connection is refused", WT_ERR_INVALID_ARGUMENT,
                       wt_quic_connection_set_max_data(NULL, 1U));
    }

    /* The stream counts this endpoint grants have the same shape and the same rule: they may only rise
     * (RFC 9000 section 4.6), and the two directions are counted separately. */
    {
      int arrived = 0;
      /* The counts are already seeded above -- the receive path needs them there, because a STREAM
       * frame for a stream this endpoint granted arrives before this block runs -- so what is checked
       * here is the raising, which is what an application that has finished with streams does. */
      WT_EXPECT_U64(
          "which read back separately", 4U,
          wt_quic_connection_max_streams(&server.connection, WT_QUIC_STREAM_BIDIRECTIONAL));
      WT_EXPECT_U64(
          "as they should", 2U,
          wt_quic_connection_max_streams(&server.connection, WT_QUIC_STREAM_UNIDIRECTIONAL));
      WT_EXPECT_STATUS("lowering one is refused", WT_ERR_LIMIT,
                       wt_quic_connection_send_max_streams(&server.connection,
                                                           WT_QUIC_STREAM_BIDIRECTIONAL, 3U, now));
      WT_EXPECT_OK("raising it is what accepting streams does",
                   wt_quic_connection_send_max_streams(&server.connection,
                                                       WT_QUIC_STREAM_BIDIRECTIONAL, 8U, now));
      WT_EXPECT_U64(
          "and is remembered", 8U,
          wt_quic_connection_max_streams(&server.connection, WT_QUIC_STREAM_BIDIRECTIONAL));
      now += 1000U;
      g_now = now;
      WT_EXPECT_OK("the client reads the frame", pump(&client, now, &arrived));
      WT_EXPECT_INT("which arrived", 1, arrived);
      /* The direction the frame names is the one that moves: the bidirectional count is the new one and
       * the unidirectional count is still what the handshake's parameters said. */
      WT_EXPECT_U64("with the raised bidirectional count", 8U,
                    wt_quic_connection_peer_limits(&client.connection)->initial_max_streams_bidi);
      WT_EXPECT_U64("and the other direction untouched", 4U,
                    wt_quic_connection_peer_limits(&client.connection)->initial_max_streams_uni);
      WT_EXPECT_STATUS("and a direction that is not one is refused", WT_ERR_INVALID_ARGUMENT,
                       wt_quic_connection_send_max_streams(&server.connection,
                                                           (wt_quic_stream_direction_t)7, 9U, now));
    }

    /* A datagram travels under the application keys and is not retransmitted. */
    {
      static const uint8_t k_datagram[5] = {0xdeU, 0xadU, 0xbeU, 0xefU, 0x01U};
      uint8_t received[64];
      size_t received_len = 0U;
      uint64_t received_at = 0U;
      int arrived = 0;

      WT_EXPECT_OK("the client sends a datagram",
                   wt_quic_connection_send_datagram(&client.connection, k_datagram,
                                                    sizeof(k_datagram), now));
      now += 1000U;
      g_now = now;
      WT_EXPECT_OK("the server reads a datagram", pump(&server, now, &arrived));
      WT_EXPECT_INT("which arrived", 1, arrived);
      WT_EXPECT_OK("and is queued", wt_quic_connection_receive_datagram(
                                        &server.connection, received, sizeof(received),
                                        &received_len, &received_at));
      WT_EXPECT_U64("whole", (uint64_t)sizeof(k_datagram), (uint64_t)received_len);
      WT_EXPECT_BYTES("byte for byte", k_datagram, received, sizeof(k_datagram));
      WT_EXPECT_U64("with the time it arrived", now, received_at);
      WT_EXPECT_STATUS("and no second one", WT_ERR_AGAIN,
                       wt_quic_connection_receive_datagram(&server.connection, received,
                                                           sizeof(received), &received_len,
                                                           &received_at));
      /* A datagram larger than the peer's limit is refused before it is sent. */
      WT_EXPECT_STATUS("an oversized datagram is a limit", WT_ERR_LIMIT,
                       wt_quic_connection_send_datagram(&client.connection, received,
                                                        (size_t)WT_QUIC_DATAGRAM_MAX + 1U, now));
    }

    /* Both directions' application keys work: a frame the client sends under them is read by the
     * server, which is the whole point of the handshake having produced them. */
    {
      wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
      uint64_t received_before = server.connection.packets_received;
      WT_EXPECT_OK("the client sends a 1-RTT frame",
                   wt_quic_connection_send_frame(&client.connection, WT_QUIC_SPACE_APPLICATION,
                                                 &ping, 1, now));
      now += 1000U;
      {
        int received = 0;
        WT_EXPECT_OK("and the server reads a datagram", pump(&server, now, &received));
        WT_EXPECT_INT("which arrived", 1, received);
        WT_EXPECT_U64("as the frame's packet", received_before + 1U,
                      server.connection.packets_received);
      }
      WT_EXPECT_U64("and it is not discarded", 0U, server.connection.packets_discarded);
    }

    /* RFC 9000 section 7.3: the peer's initial_source_connection_id MUST match the Source Connection ID of
     * the Initial packets it sent. The packets above were real, so the connection recorded the server's SCID;
     * a parameter naming a DIFFERENT ID is a connection error rather than a destination this endpoint adopts,
     * while the value the packets actually carried is still accepted (the same comparison, not a blanket
     * refusal of the parameter). */
    {
      static const uint8_t k_other_source[4] = {0xdeU, 0xadU, 0xbeU, 0xefU};
      wt_quic_transport_parameters_t params;
      uint8_t encoded[64];
      wt_writer_t w;

      wt_quic_transport_parameters_init(&params);
      WT_EXPECT_OK("a mismatching initial_source_connection_id builds",
                   wt_quic_transport_parameters_add_bytes(&params,
                                                          WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                                                          k_other_source, sizeof(k_other_source)));
      w = wt_writer_init(encoded, sizeof(encoded));
      WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
      WT_EXPECT_STATUS("an initial_source_connection_id that is not the packets' SCID is refused",
                       WT_ERR_PROTOCOL,
                       wt_quic_connection_set_peer_parameters(&client.connection, encoded,
                                                              wt_writer_offset(&w)));

      wt_quic_transport_parameters_init(&params);
      WT_EXPECT_OK(
          "the packets' own initial_source_connection_id builds",
          wt_quic_transport_parameters_add_bytes(&params, WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                                                 k_connection_id, sizeof(k_connection_id)));
      w = wt_writer_init(encoded, sizeof(encoded));
      WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
      WT_EXPECT_STATUS("and the value the packets carried is accepted", WT_OK,
                       wt_quic_connection_set_peer_parameters(&client.connection, encoded,
                                                              wt_writer_offset(&w)));

      /* The server's half of the same rule: it recorded the client's Initial SCID, so the client's
       * parameter must match that too. */
      wt_quic_transport_parameters_init(&params);
      WT_EXPECT_OK("a mismatching client initial_source_connection_id builds",
                   wt_quic_transport_parameters_add_bytes(&params,
                                                          WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                                                          k_other_source, sizeof(k_other_source)));
      w = wt_writer_init(encoded, sizeof(encoded));
      WT_EXPECT_OK("and encodes", wt_quic_transport_parameters_encode(&w, &params));
      WT_EXPECT_STATUS("the server refuses a client's mismatching initial_source_connection_id",
                       WT_ERR_PROTOCOL,
                       wt_quic_connection_set_peer_parameters(&server.connection, encoded,
                                                              wt_writer_offset(&w)));
    }
  }

  close_endpoint(&client);
  close_endpoint(&server);
}

/* The driver's own edges, without a peer: what it does with a frame that is not its business, with a
 * handshake message that has only half arrived, and with a handshake that does not fit the window it
 * holds. */
static void test_driver_edges(void) {
  fixtures_t fixtures;
  endpoint_t client;
  wt_tls_client_config_t client_tls;
  wt_quic_frame_t frame;
  uint8_t partial[8];
  uint8_t big[WT_QUIC_CRYPTO_BUFFER_MAX + 64U];

  /* A ServerHello header -- type 2, length 0x20 -- with only the header arrived: a message the driver
   * must hold rather than parse. */
  partial[0] = 0x02U;
  partial[1] = 0x00U;
  partial[2] = 0x00U;
  partial[3] = 0x20U;
  memset(partial + 4, 0x5a, sizeof(partial) - 4U);
  memset(big, 0x41U, sizeof(big));

  WT_EXPECT_INT("the fixtures load", 1, load_fixtures(&fixtures));
  memset(&client, 0, sizeof(client));
  open_endpoint(WT_UDP_IPV4, &client, &client, WT_QUIC_ROLE_CLIENT);
  client_tls_config(&client_tls, &fixtures);

  WT_EXPECT_OK("the handshake starts",
               wt_quic_handshake_start_client(&client.handshake, &client.connection, &client_tls));
  WT_EXPECT_INT("with the ClientHello pending", 1, wt_quic_handshake_pending(&client.handshake));
  WT_EXPECT_OK("which flushes", wt_quic_handshake_flush(&client.handshake, 1000U));
  WT_EXPECT_INT("leaving nothing pending", 0, wt_quic_handshake_pending(&client.handshake));
  WT_EXPECT_U64("and one packet on the wire", 1U, client.connection.packets_sent);

  /* A frame this layer does not own is answered WT_OK, which is what lets a composition of handlers
   * pass it on. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  WT_EXPECT_OK("a PING is not this layer's business",
               wt_quic_handshake_on_frame(&client.handshake, WT_QUIC_SPACE_INITIAL, &frame));
  WT_EXPECT_STATUS("and a null frame is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_handshake_on_frame(&client.handshake, WT_QUIC_SPACE_INITIAL, NULL));
  WT_EXPECT_STATUS("and a null handshake is too", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_handshake_on_frame(NULL, WT_QUIC_SPACE_INITIAL, &frame));

  /* Half a message is held: the bytes are delivered by the reassembler but not consumed by the
   * driver, because TLS has not been given a message it could parse. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CRYPTO);
  frame.as.crypto.offset = 0U;
  frame.as.crypto.data = partial;
  frame.as.crypto.length = sizeof(partial);
  WT_EXPECT_OK("a partial message is accepted",
               wt_quic_handshake_on_frame(&client.handshake, WT_QUIC_SPACE_INITIAL, &frame));
  WT_EXPECT_INT("and changes no state", (int)WT_QUIC_HANDSHAKE_CLIENT_WAITING,
                (int)wt_quic_handshake_state(&client.handshake));
  WT_EXPECT_U64("with the bytes held", (uint64_t)sizeof(partial),
                (uint64_t)client.handshake.recv[WT_QUIC_SPACE_INITIAL].length);
  {
    const uint8_t *data = NULL;
    WT_EXPECT_U64("and delivered but not consumed", (uint64_t)sizeof(partial),
                  (uint64_t)wt_quic_crypto_recv_available(
                      &client.handshake.recv[WT_QUIC_SPACE_INITIAL], &data));
    (void)data;
  }

  /* A handshake that does not fit the window: the driver fails and names RFC 9000 section 20.1's code
   * for it, which is what the connection then puts in the CONNECTION_CLOSE it sends. */
  frame.as.crypto.offset = 0U;
  frame.as.crypto.data = big;
  frame.as.crypto.length = sizeof(big);
  WT_EXPECT_STATUS("a handshake that does not fit is refused", WT_ERR_LIMIT,
                   wt_quic_handshake_on_frame(&client.handshake, WT_QUIC_SPACE_INITIAL, &frame));
  WT_EXPECT_INT("and the handshake fails", (int)WT_QUIC_HANDSHAKE_FAILED,
                (int)wt_quic_handshake_state(&client.handshake));
  WT_EXPECT_U64("with the code the RFC gives this case", (uint64_t)WT_QUIC_CRYPTO_BUFFER_EXCEEDED,
                client.handshake.error_code);
  WT_EXPECT_INT("which the connection is told about", 1, client.connection.close_code_set);
  WT_EXPECT_U64("as that code", (uint64_t)WT_QUIC_CRYPTO_BUFFER_EXCEEDED,
                client.connection.close_code);
  WT_EXPECT_INT("and a failed handshake has nothing pending", 0,
                wt_quic_handshake_pending(&client.handshake));

  close_endpoint(&client);
}

int main(void) {
  test_handshake(WT_UDP_IPV4);
  test_handshake(WT_UDP_IPV6);
  test_driver_edges();

  WT_TEST_MAIN_END("wt_quic_handshake");
}
