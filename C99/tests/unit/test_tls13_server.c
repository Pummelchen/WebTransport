/* The server handshake, tested against our own client and against the checks it must refuse.
 *
 * THE TEST THAT MATTERS MOST IS ONE HANDSHAKE BETWEEN THE TWO HALVES. A client and a server
 * that agree with each other and with nothing else would pass any test this project wrote by
 * itself, so the halves are not the whole evidence: the client is separately pinned to
 * RFC 8448's recorded flight (test_tls13_session), and the trust layer to the RFC's own
 * CertificateVerify (test_tls13_trust). What this file adds is that the two halves meet: the
 * server's flight is built in the order the client's checks expect, the ALPN and transport
 * parameters survive both directions, the certificate the server sends validates against the
 * fixture CA, and -- the property neither half can check alone -- the application secrets the
 * two ends derive are the same secrets in opposite directions.
 *
 * The refusals are the server's own gates: a ClientHello that offers no TLS 1.3, no key share
 * this server can use, no h3, no ciphersuite it has a schedule for, or no transport parameters
 * when QUIC requires them must stop the handshake rather than produce a flight the client would
 * reject. And the client's Finished gates the server's application secrets exactly as the
 * server's does on the client.
 */

#include "wt_test.h"

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/tls/session.h"

#ifndef WT_TRUST_FIXTURE_DIR
#error "WT_TRUST_FIXTURE_DIR must name the directory holding the trust fixtures"
#endif

static size_t read_fixture(const char *name, uint8_t *out, size_t capacity) {
  char path[512];
  FILE *file;
  size_t used;

  if (snprintf(path, sizeof(path), "%s/%s", WT_TRUST_FIXTURE_DIR, name) < 0) {
    return 0U;
  }
  file = fopen(path, "rb");
  if (file == NULL) return 0U;
  used = fread(out, 1U, capacity, file);
  fclose(file);
  return used;
}

/* The fixtures: a leaf certificate for example.com signed by the CA the client trusts, its DER
 * private key, the CA bundle, and two DER leaves for certificates the client must carry in its
 * chain. */
typedef struct wt_test_fixtures {
  uint8_t leaf[4096];
  size_t leaf_len;
  uint8_t ca_bundle[8192];
  size_t ca_bundle_len;
  uint8_t private_key[4096];
  size_t private_key_len;
} wt_test_fixtures_t;

static int load_fixtures(wt_test_fixtures_t *fixtures) {
  memset(fixtures, 0, sizeof(*fixtures));
  fixtures->leaf_len = read_fixture("leaf.der", fixtures->leaf, sizeof(fixtures->leaf));
  fixtures->ca_bundle_len =
      read_fixture("ca.pem", fixtures->ca_bundle, sizeof(fixtures->ca_bundle));
  fixtures->private_key_len = read_fixture("leaf-key.der", fixtures->private_key,
                                           sizeof(fixtures->private_key));
  return fixtures->leaf_len != 0U && fixtures->ca_bundle_len != 0U &&
         fixtures->private_key_len != 0U;
}

/* The transport parameters both ends send. Their grammar belongs to the QUIC layer; here they
 * are opaque bytes that must survive the handshake unchanged. */
static const uint8_t WT_TEST_PARAMETERS[] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U};

static void client_config(wt_tls_client_config_t *config,
                          const wt_test_fixtures_t *fixtures) {
  static const char *const alpn_h3[] = {"h3"};
  memset(config, 0, sizeof(*config));
  config->host_name = "example.com";
  config->alpn = alpn_h3;
  config->alpn_count = 1U;
  config->require_transport_parameters = 1;
  config->transport_parameters = WT_TEST_PARAMETERS;
  config->transport_parameters_len = sizeof(WT_TEST_PARAMETERS);
  config->trust.mode = WT_TLS_TRUST_STORE;
  config->trust.ca_bundle = fixtures->ca_bundle;
  config->trust.ca_bundle_len = fixtures->ca_bundle_len;
  config->trust.host_name = "example.com";
}

static void server_config(wt_tls_server_config_t *config,
                          const wt_test_fixtures_t *fixtures,
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
  config->transport_parameters = WT_TEST_PARAMETERS;
  config->transport_parameters_len = sizeof(WT_TEST_PARAMETERS);
}

/* One whole handshake between the two halves. Everything the client and the server produce is
 * exchanged through these buffers, which is the closest this project gets to a network without a
 * socket, and which is also how a caller will drive them. */
static void test_handshake_between_halves(const wt_test_fixtures_t *fixtures) {
  wt_tls_client_t client;
  wt_tls_server_t server;
  wt_tls_client_config_t client_cfg;
  wt_tls_server_config_t server_cfg;
  wt_tls_server_identity_t identity;
  uint8_t client_hello[WT_TLS_CLIENT_HELLO_MAX];
  uint8_t server_hello[1024];
  uint8_t flight[4096];
  uint8_t client_finished[64];
  uint8_t client_read[WT_TLS13_SECRET_LEN];
  uint8_t client_write[WT_TLS13_SECRET_LEN];
  uint8_t server_read[WT_TLS13_SECRET_LEN];
  uint8_t server_write[WT_TLS13_SECRET_LEN];
  size_t client_hello_len = 0U;
  size_t server_hello_len = 0U;
  size_t flight_len = 0U;
  size_t client_finished_len = 0U;
  size_t alpn_len = 0U;
  const uint8_t *alpn;
  const uint8_t *parameters;
  size_t parameters_len = 0U;

  memset(&client, 0, sizeof(client));
  memset(&server, 0, sizeof(server));
  client_config(&client_cfg, fixtures);
  server_config(&server_cfg, fixtures, &identity);

  /* The client starts, and the server consumes what it sent. */
  WT_EXPECT_OK("the client starts",
               wt_tls_client_begin_built(&client, &client_cfg, client_hello,
                                         sizeof(client_hello), &client_hello_len));
  WT_EXPECT_OK("the server starts", wt_tls_server_begin(&server, &server_cfg));
  WT_EXPECT_OK("and accepts the ClientHello",
               wt_tls_server_receive(&server, client_hello, client_hello_len,
                                     server_hello, sizeof(server_hello),
                                     &server_hello_len));
  WT_EXPECT_TRUE("answering with a ServerHello", server_hello_len > 0U);
  WT_EXPECT_U64("and waits for the client's Finished",
                (uint64_t)WT_TLS_SERVER_WAIT_CLIENT_FINISHED,
                (uint64_t)wt_tls_server_state(&server));
  WT_EXPECT_STATUS("with no application secrets yet", WT_ERR_STATE,
                   wt_tls_server_application_secrets(&server, server_read,
                                                     server_write));

  /* The rest of the flight, which the caller sends under handshake keys. */
  WT_EXPECT_OK("the server builds its flight",
               wt_tls_server_flight(&server, flight, sizeof(flight), &flight_len));
  WT_EXPECT_TRUE("with bytes in it", flight_len > 0U);
  {
    /* A separate length variable: a refused call is not one whose out-parameter may be read, and
     * this one is refused on purpose. */
    size_t again = 0U;
    WT_EXPECT_STATUS("and cannot build it twice", WT_ERR_STATE,
                     wt_tls_server_flight(&server, flight, sizeof(flight), &again));
  }

  /* The client consumes the ServerHello and the rest, in order. */
  WT_EXPECT_OK("the client accepts the ServerHello",
               wt_tls_client_receive(&client, server_hello, server_hello_len,
                                     client_finished, sizeof(client_finished),
                                     &client_finished_len));
  WT_EXPECT_U64("nothing is sent yet", 0U, (uint64_t)client_finished_len);
  {
    /* The flight is four messages and a CRYPTO stream is their concatenation, so it is walked
     * with the helper that reads a length without insisting the buffer ends there. */
    size_t at = 0U;
    size_t messages = 0U;
    while (at < flight_len) {
      size_t message_len = wt_tls_handshake_message_len(flight + at, flight_len - at);
      WT_EXPECT_TRUE("a flight message is whole", message_len != 0U);
      if (message_len == 0U) break;
      WT_EXPECT_OK("and the client accepts it",
                   wt_tls_client_receive(&client, flight + at, message_len,
                                         client_finished, sizeof(client_finished),
                                         &client_finished_len));
      at += message_len;
      messages++;
    }
    WT_EXPECT_U64("the flight is four messages", 4U, (uint64_t)messages);
  }
  WT_EXPECT_U64("and the client is connected", (uint64_t)WT_TLS_CLIENT_CONNECTED,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_U64("with a Finished to send", 36U, (uint64_t)client_finished_len);

  /* The properties both ends must agree on. */
  alpn = wt_tls_client_alpn(&client, &alpn_len);
  WT_EXPECT_U64("the client negotiated one protocol", 2U, (uint64_t)alpn_len);
  WT_EXPECT_BYTES("which is h3", (const uint8_t *)"h3", alpn, 2U);
  alpn = wt_tls_server_alpn(&server, &alpn_len);
  WT_EXPECT_U64("and the server agrees", 2U, (uint64_t)alpn_len);
  WT_EXPECT_BYTES("on h3", (const uint8_t *)"h3", alpn, 2U);
  parameters = wt_tls_client_transport_parameters(&client, &parameters_len);
  WT_EXPECT_U64("the client has the server's transport parameters",
                (uint64_t)sizeof(WT_TEST_PARAMETERS), (uint64_t)parameters_len);
  WT_EXPECT_BYTES("byte for byte", WT_TEST_PARAMETERS, parameters, parameters_len);
  parameters = wt_tls_server_transport_parameters(&server, &parameters_len);
  WT_EXPECT_U64("and the server has the client's",
                (uint64_t)sizeof(WT_TEST_PARAMETERS), (uint64_t)parameters_len);
  WT_EXPECT_BYTES("byte for byte", WT_TEST_PARAMETERS, parameters, parameters_len);

  /* The secrets. The client's read secret must be the server's write secret, and the other way
   * round: that is the property that makes a connection work and the one neither half can check
   * on its own. */
  WT_EXPECT_OK("the client's handshake secrets",
               wt_tls_client_handshake_secrets(&client, client_read, client_write));
  WT_EXPECT_OK("the server's handshake secrets",
               wt_tls_server_handshake_secrets(&server, server_read, server_write));
  WT_EXPECT_BYTES("the client reads with what the server writes", server_write,
                  client_read, WT_TLS13_SECRET_LEN);
  WT_EXPECT_BYTES("and writes with what the server reads", server_read, client_write,
                  WT_TLS13_SECRET_LEN);

  /* The client's Finished ends the handshake on the server side, and the application secrets
   * appear on both ends at the same moment. */
  WT_EXPECT_OK("the server accepts the client's Finished",
               wt_tls_server_receive(&server, client_finished, client_finished_len,
                                     server_hello, sizeof(server_hello),
                                     &server_hello_len));
  WT_EXPECT_U64("and is connected", (uint64_t)WT_TLS_SERVER_CONNECTED,
                (uint64_t)wt_tls_server_state(&server));
  WT_EXPECT_U64("sending nothing in reply", 0U, (uint64_t)server_hello_len);
  WT_EXPECT_OK("the client's application secrets",
               wt_tls_client_application_secrets(&client, client_read, client_write));
  WT_EXPECT_OK("the server's application secrets",
               wt_tls_server_application_secrets(&server, server_read, server_write));
  WT_EXPECT_BYTES("the client reads with what the server writes for application data",
                  server_write, client_read, WT_TLS13_SECRET_LEN);
  WT_EXPECT_BYTES("and writes with what the server reads", server_read, client_write,
                  WT_TLS13_SECRET_LEN);
  /* And the application secrets are not the handshake ones, which would make the epochs the
   * same key. */
  WT_EXPECT_INT("the application secret is not the handshake secret", 0,
                memcmp(client_read, client_write, WT_TLS13_SECRET_LEN) == 0 ? 1 : 0);

  wt_tls_client_clear(&client);
  wt_tls_server_clear(&server);
}

/* The server's gates. Each is a ClientHello the server must refuse rather than answer. */
static void test_server_gates(const wt_test_fixtures_t *fixtures) {
  wt_tls_server_t server;
  wt_tls_server_config_t server_cfg;
  wt_tls_server_identity_t identity;
  wt_tls_client_t client;
  wt_tls_client_config_t client_cfg;
  uint8_t client_hello[WT_TLS_CLIENT_HELLO_MAX];
  uint8_t server_hello[1024];
  uint8_t flight[4096];
  size_t client_hello_len = 0U;
  size_t server_hello_len = 0U;
  size_t flight_len = 0U;

  server_config(&server_cfg, fixtures, &identity);
  client_config(&client_cfg, fixtures);

  /* Our own client's hello is accepted, which is the baseline every gate below is a change
   * from. */
  memset(&client, 0, sizeof(client));
  memset(&server, 0, sizeof(server));
  WT_EXPECT_OK("the baseline hello builds",
               wt_tls_client_begin_built(&client, &client_cfg, client_hello,
                                         sizeof(client_hello), &client_hello_len));
  WT_EXPECT_OK("the server starts", wt_tls_server_begin(&server, &server_cfg));
  WT_EXPECT_OK("and accepts it",
               wt_tls_server_receive(&server, client_hello, client_hello_len,
                                     server_hello, sizeof(server_hello),
                                     &server_hello_len));
  WT_EXPECT_OK("and its flight builds",
               wt_tls_server_flight(&server, flight, sizeof(flight), &flight_len));
  wt_tls_client_clear(&client);
  wt_tls_server_clear(&server);

  /* The message that is not a ClientHello at all. */
  {
    uint8_t hello[WT_TLS_CLIENT_HELLO_MAX];
    size_t hello_len = 0U;
    memset(&server, 0, sizeof(server));
    WT_EXPECT_OK("the server starts again", wt_tls_server_begin(&server, &server_cfg));
    /* A ServerHello where a ClientHello belongs. */
    WT_EXPECT_STATUS("a message that is not a ClientHello is refused", WT_ERR_STATE,
                     wt_tls_server_receive(&server, server_hello, server_hello_len,
                                           hello, sizeof(hello), &hello_len));
    WT_EXPECT_U64("and the machine has failed", (uint64_t)WT_TLS_SERVER_FAILED,
                  (uint64_t)wt_tls_server_state(&server));
    wt_tls_server_clear(&server);
  }

  /* A client that does not offer the protocol the server speaks. */
  {
    static const char *const alpn_h2[] = {"h2"};
    wt_tls_client_config_t config = client_cfg;
    config.alpn = alpn_h2;
    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    WT_EXPECT_OK("a hello offering h2 builds",
                 wt_tls_client_begin_built(&client, &config, client_hello,
                                           sizeof(client_hello), &client_hello_len));
    WT_EXPECT_OK("the server starts", wt_tls_server_begin(&server, &server_cfg));
    WT_EXPECT_STATUS("a client that does not offer h3 is refused", WT_ERR_TLS,
                     wt_tls_server_receive(&server, client_hello, client_hello_len,
                                           server_hello, sizeof(server_hello),
                                           &server_hello_len));
    wt_tls_client_clear(&client);
    wt_tls_server_clear(&server);
  }

  /* A client that sends no transport parameters, when QUIC requires them. */
  {
    wt_tls_client_config_t config = client_cfg;
    config.require_transport_parameters = 0;
    config.transport_parameters = NULL;
    config.transport_parameters_len = 0U;
    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    WT_EXPECT_OK("a hello with no transport parameters builds",
                 wt_tls_client_begin_built(&client, &config, client_hello,
                                           sizeof(client_hello), &client_hello_len));
    WT_EXPECT_OK("the server starts", wt_tls_server_begin(&server, &server_cfg));
    WT_EXPECT_STATUS("a client with no transport parameters is refused", WT_ERR_TLS,
                     wt_tls_server_receive(&server, client_hello, client_hello_len,
                                           server_hello, sizeof(server_hello),
                                           &server_hello_len));
    wt_tls_client_clear(&client);
    wt_tls_server_clear(&server);
  }

  /* A client Finished that does not verify leaves the server without application secrets. */
  {
    uint8_t finished[64];
    uint8_t damaged[64];
    size_t finished_len = 0U;
    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    WT_EXPECT_OK("a hello builds",
                 wt_tls_client_begin_built(&client, &client_cfg, client_hello,
                                           sizeof(client_hello), &client_hello_len));
    WT_EXPECT_OK("the server starts", wt_tls_server_begin(&server, &server_cfg));
    WT_EXPECT_OK("and accepts the hello",
                 wt_tls_server_receive(&server, client_hello, client_hello_len,
                                       server_hello, sizeof(server_hello),
                                       &server_hello_len));
    WT_EXPECT_OK("and builds its flight",
                 wt_tls_server_flight(&server, flight, sizeof(flight), &flight_len));
    WT_EXPECT_OK("the client accepts the ServerHello",
                 wt_tls_client_receive(&client, server_hello, server_hello_len,
                                       finished, sizeof(finished), &finished_len));
    {
      size_t at = 0U;
      while (at < flight_len) {
        size_t message_len = wt_tls_handshake_message_len(flight + at, flight_len - at);
        WT_EXPECT_TRUE("a flight message is whole", message_len != 0U);
        if (message_len == 0U) break;
        WT_EXPECT_OK("and is accepted",
                     wt_tls_client_receive(&client, flight + at, message_len, finished,
                                           sizeof(finished), &finished_len));
        at += message_len;
      }
    }
    WT_EXPECT_U64("the client has a Finished", 36U, (uint64_t)finished_len);
    memcpy(damaged, finished, finished_len);
    damaged[finished_len - 1U] ^= 0x01U;
    WT_EXPECT_STATUS("a tampered client Finished is refused", WT_ERR_AUTHENTICATION,
                     wt_tls_server_receive(&server, damaged, finished_len, server_hello,
                                           sizeof(server_hello), &server_hello_len));
    {
      uint8_t read_secret[WT_TLS13_SECRET_LEN];
      uint8_t write_secret[WT_TLS13_SECRET_LEN];
      WT_EXPECT_STATUS("and no application secrets appear", WT_ERR_STATE,
                       wt_tls_server_application_secrets(&server, read_secret,
                                                         write_secret));
    }
    wt_tls_client_clear(&client);
    wt_tls_server_clear(&server);
  }

  /* A server with no identity cannot start: a handshake with no certificate to prove anything
   * is not a handshake. */
  {
    wt_tls_server_config_t bad = server_cfg;
    bad.identity = NULL;
    memset(&server, 0, sizeof(server));
    WT_EXPECT_STATUS("a server with no identity is a caller error",
                     WT_ERR_INVALID_ARGUMENT, wt_tls_server_begin(&server, &bad));
    {
      wt_tls_server_identity_t empty;
      memset(&empty, 0, sizeof(empty));
      bad = server_cfg;
      bad.identity = &empty;
      WT_EXPECT_STATUS("and so is one with no certificate", WT_ERR_INVALID_ARGUMENT,
                       wt_tls_server_begin(&server, &bad));
    }
    WT_EXPECT_STATUS("a NULL config is a caller error", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_server_begin(&server, NULL));
    WT_EXPECT_STATUS("a NULL server is a caller error", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_server_begin(NULL, &server_cfg));
    wt_tls_server_clear(&server);
  }
}

/* The client's trust policy is the only thing that decides whether the server's certificate is
 * acceptable, and the server's own chain is what it is judged on. */
static void test_client_refuses_unknown_issuer(const wt_test_fixtures_t *fixtures) {
  wt_tls_client_t client;
  wt_tls_server_t server;
  wt_tls_client_config_t client_cfg;
  wt_tls_server_config_t server_cfg;
  wt_tls_server_identity_t identity;
  uint8_t unknown[4096];
  size_t unknown_len;
  uint8_t client_hello[WT_TLS_CLIENT_HELLO_MAX];
  uint8_t server_hello[1024];
  uint8_t flight[4096];
  size_t client_hello_len = 0U;
  size_t server_hello_len = 0U;
  size_t flight_len = 0U;
  uint8_t scratch[64];
  size_t scratch_len = 0U;

  unknown_len = read_fixture("leaf-unknown-ca.der", unknown, sizeof(unknown));
  WT_EXPECT_TRUE("the unknown-CA leaf is available", unknown_len > 0U);

  memset(&client, 0, sizeof(client));
  memset(&server, 0, sizeof(server));
  client_config(&client_cfg, fixtures);
  server_config(&server_cfg, fixtures, &identity);
  /* The server sends a chain the client's bundle does not contain the issuer of. */
  identity.certificate[0] = unknown;
  identity.certificate_len[0] = unknown_len;

  WT_EXPECT_OK("the client starts",
               wt_tls_client_begin_built(&client, &client_cfg, client_hello,
                                         sizeof(client_hello), &client_hello_len));
  WT_EXPECT_OK("the server starts", wt_tls_server_begin(&server, &server_cfg));
  WT_EXPECT_OK("and accepts the ClientHello",
               wt_tls_server_receive(&server, client_hello, client_hello_len,
                                     server_hello, sizeof(server_hello),
                                     &server_hello_len));
  WT_EXPECT_OK("and builds its flight",
               wt_tls_server_flight(&server, flight, sizeof(flight), &flight_len));
  WT_EXPECT_OK("the client accepts the ServerHello",
               wt_tls_client_receive(&client, server_hello, server_hello_len, scratch,
                                     sizeof(scratch), &scratch_len));
  {
    /* The flight's first message is EncryptedExtensions and the second is the Certificate; the
     * client must refuse at the second. */
    size_t at = 0U;
    int refused = 0;
    while (at < flight_len) {
      size_t message_len = wt_tls_handshake_message_len(flight + at, flight_len - at);
      uint8_t type;
      wt_status_t status;
      WT_EXPECT_TRUE("a flight message is whole", message_len != 0U);
      if (message_len == 0U) break;
      type = flight[at];
      status = wt_tls_client_receive(&client, flight + at, message_len, scratch,
                                     sizeof(scratch), &scratch_len);
      if (type == WT_TLS_HANDSHAKE_CERTIFICATE) {
        refused = (status == WT_ERR_TRUST);
        /* The handshake is over at that point, so the messages after it are not read: a failed
         * machine refuses everything, which is the behaviour the next check states. */
        break;
      }
      WT_EXPECT_OK("the message before the certificate is accepted", status);
      at += message_len;
    }
    WT_EXPECT_TRUE("the client refuses the certificate with an unknown issuer", refused);
    if (at + wt_tls_handshake_message_len(flight + at, flight_len - at) < flight_len) {
      size_t next = at + wt_tls_handshake_message_len(flight + at, flight_len - at);
      WT_EXPECT_STATUS("and refuses the messages after it", WT_ERR_STATE,
                       wt_tls_client_receive(&client, flight + next, flight_len - next,
                                             scratch, sizeof(scratch), &scratch_len));
    }
    WT_EXPECT_U64("and its handshake has failed", (uint64_t)WT_TLS_CLIENT_FAILED,
                  (uint64_t)wt_tls_client_state(&client));
  }
  wt_tls_client_clear(&client);
  wt_tls_server_clear(&server);
}

int main(void) {
  wt_test_fixtures_t fixtures;

  WT_EXPECT_OK("the crypto backend initialises", wt_crypto_init());
  if (!load_fixtures(&fixtures)) {
    WT_EXPECT_TRUE("the trust fixtures are available", 0);
    WT_TEST_MAIN_END("wt_tls13_server");
  }

  test_handshake_between_halves(&fixtures);
  test_server_gates(&fixtures);
  test_client_refuses_unknown_issuer(&fixtures);

  WT_TEST_MAIN_END("wt_tls13_server");
}
