/* The client handshake, driven through RFC 8448's recorded server flight.
 *
 * THE STRONGEST TEST IN THIS PHASE, AND THE SIMPLEST TO DESCRIBE. RFC 8448 section 3 prints
 * a whole handshake: the ClientHello, the server's ServerHello, EncryptedExtensions,
 * Certificate, CertificateVerify and Finished, and every secret the schedule derives from
 * them. This file starts the machine with the RFC's ClientHello and the RFC's client private
 * key -- which is why the machine takes the hello as bytes rather than building one and
 * assuming -- and then feeds it the server's messages in order. If the machine's transcript,
 * key schedule, trust check, signature check, Finished check and Finished construction are
 * all right, the secrets it produces are the RFC's secrets and the Finished it sends is the
 * RFC's Finished. Nothing here would notice a mistake shared by all of those steps; nothing
 * here can pass with a mistake in any one of them.
 *
 * The gates are the other half. A certificate the policy refuses must stop the handshake
 * before any secret is available, an ALPN the caller did not offer must stop it, missing
 * transport parameters must stop it when the caller says it is a QUIC handshake, and the
 * application secrets must be unavailable in every state but CONNECTED. The plan's
 * completion criterion for this phase is that application keys are unavailable until every
 * security condition is satisfied, and each condition is a test here rather than a claim.
 */

#include "wt_test.h"

#include "webtransport/tls/session.h"

#include "rfc8448_vectors.h"

/* The configuration RFC 8448's flight is acceptable under: no ALPN is required and no
 * transport parameters are required, because the trace is a plain TLS handshake rather than
 * a QUIC one, and the development trust policy is used because the RFC's certificate is
 * self-signed and expired (the trust layer's own test covers the modes).
 *
 * The client private key is the RFC's, because a server flight recorded against one client
 * key can only be completed by the client that holds it. */
static void rfc8448_config(wt_tls_client_config_t *config) {
  memset(config, 0, sizeof(*config));
  config->host_name = "localhost";
  config->trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
  config->trust.host_name = "localhost";
  config->x25519_private = WT_RFC8448_CLIENT_X25519_PRIVATE;
}

static void test_rfc8448_handshake(void) {
  wt_tls_client_t client;
  wt_tls_client_config_t config;
  uint8_t finished[64];
  size_t finished_len = 0U;
  uint8_t read_secret[WT_TLS13_SECRET_LEN];
  uint8_t write_secret[WT_TLS13_SECRET_LEN];

  rfc8448_config(&config);
  /* Zeroed rather than left to the stack: the point of the two checks below is that a
   * machine that has not started holds no secrets, and reading an indeterminate struct to
   * say so would be testing the stack rather than the code. */
  memset(&client, 0, sizeof(client));

  /* Before anything: no secrets, and the state says so. */
  WT_EXPECT_STATUS("no application secrets before the handshake",
                   WT_ERR_STATE,
                   wt_tls_client_application_secrets(&client, read_secret,
                                                     write_secret));
  WT_EXPECT_STATUS("and no handshake secrets either", WT_ERR_STATE,
                   wt_tls_client_handshake_secrets(&client, read_secret,
                                                   write_secret));

  WT_EXPECT_OK("the handshake starts from the RFC's ClientHello",
               wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                   WT_RFC8448_CLIENT_HELLO_LEN));
  WT_EXPECT_U64("and waits for the ServerHello", (uint64_t)WT_TLS_CLIENT_WAIT_SERVER_HELLO,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_STATUS("with still no handshake secrets", WT_ERR_STATE,
                   wt_tls_client_handshake_secrets(&client, read_secret,
                                                   write_secret));

  /* The ServerHello. Its key share is the RFC's server public key, so the shared secret the
   * machine derives is the RFC's ECDHE value and the traffic secrets are the RFC's. */
  WT_EXPECT_OK("the ServerHello is accepted",
               wt_tls_client_receive(&client, WT_RFC8448_SERVER_HELLO,
                                     WT_RFC8448_SERVER_HELLO_LEN, finished,
                                     sizeof(finished), &finished_len));
  WT_EXPECT_U64("nothing is sent in reply", 0U, (uint64_t)finished_len);
  WT_EXPECT_U64("and it waits for EncryptedExtensions",
                (uint64_t)WT_TLS_CLIENT_WAIT_ENCRYPTED_EXTENSIONS,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_OK("the handshake secrets are available",
               wt_tls_client_handshake_secrets(&client, read_secret, write_secret));
  WT_EXPECT_BYTES("the read secret is the RFC's server handshake secret",
                  WT_RFC8448_SERVER_HANDSHAKE_SECRET, read_secret,
                  WT_TLS13_SECRET_LEN);
  WT_EXPECT_BYTES("and the write secret is the RFC's client handshake secret",
                  WT_RFC8448_CLIENT_HANDSHAKE_SECRET, write_secret,
                  WT_TLS13_SECRET_LEN);
  WT_EXPECT_STATUS("the application secrets are still unavailable", WT_ERR_STATE,
                   wt_tls_client_application_secrets(&client, read_secret,
                                                     write_secret));

  WT_EXPECT_OK("EncryptedExtensions are accepted",
               wt_tls_client_receive(&client, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                     WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN, finished,
                                     sizeof(finished), &finished_len));
  WT_EXPECT_U64("and it waits for the Certificate",
                (uint64_t)WT_TLS_CLIENT_WAIT_CERTIFICATE,
                (uint64_t)wt_tls_client_state(&client));

  /* The certificate is self-signed and expired, and the development policy accepts it on a
   * loopback name; a policy that refuses it is tested below. */
  WT_EXPECT_OK("the Certificate is accepted",
               wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE,
                                     WT_RFC8448_CERTIFICATE_LEN, finished,
                                     sizeof(finished), &finished_len));
  WT_EXPECT_U64("and it waits for CertificateVerify",
                (uint64_t)WT_TLS_CLIENT_WAIT_CERTIFICATE_VERIFY,
                (uint64_t)wt_tls_client_state(&client));

  WT_EXPECT_OK("the CertificateVerify is accepted",
               wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE_VERIFY,
                                     WT_RFC8448_CERTIFICATE_VERIFY_LEN, finished,
                                     sizeof(finished), &finished_len));
  WT_EXPECT_U64("and it waits for the server's Finished",
                (uint64_t)WT_TLS_CLIENT_WAIT_FINISHED,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_STATUS("the application secrets are still unavailable", WT_ERR_STATE,
                   wt_tls_client_application_secrets(&client, read_secret,
                                                     write_secret));

  /* The server's Finished. The reply is the client's Finished, and the RFC prints it. */
  WT_EXPECT_OK("the server's Finished is accepted",
               wt_tls_client_receive(&client, WT_RFC8448_SERVER_FINISHED_MESSAGE,
                                     WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN, finished,
                                     sizeof(finished), &finished_len));
  WT_EXPECT_U64("and the handshake is complete",
                (uint64_t)WT_TLS_CLIENT_CONNECTED,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_U64("with a Finished to send", 36U, (uint64_t)finished_len);
  WT_EXPECT_BYTES("which is the RFC's client Finished", WT_RFC8448_CLIENT_FINISHED_MESSAGE,
                  finished, WT_RFC8448_CLIENT_FINISHED_MESSAGE_LEN);

  /* And now, and only now, the application secrets. */
  WT_EXPECT_OK("the application secrets are available",
               wt_tls_client_application_secrets(&client, read_secret, write_secret));
  WT_EXPECT_BYTES("the read secret is the RFC's server application secret",
                  WT_RFC8448_SERVER_APPLICATION_SECRET, read_secret,
                  WT_TLS13_SECRET_LEN);
  WT_EXPECT_BYTES("and the write secret is the RFC's client application secret",
                  WT_RFC8448_CLIENT_APPLICATION_SECRET, write_secret,
                  WT_TLS13_SECRET_LEN);

  /* A message after the handshake is a state error rather than a second handshake. */
  WT_EXPECT_STATUS("another message is refused", WT_ERR_STATE,
                   wt_tls_client_receive(&client, WT_RFC8448_SERVER_FINISHED_MESSAGE,
                                         WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN,
                                         finished, sizeof(finished), &finished_len));
  WT_EXPECT_U64("and the machine has failed", (uint64_t)WT_TLS_CLIENT_FAILED,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_STATUS("so the secrets are gone", WT_ERR_STATE,
                   wt_tls_client_application_secrets(&client, read_secret,
                                                     write_secret));
  wt_tls_client_clear(&client);
}

/* The gates, each one condition that must stop the handshake. */
static void test_gates(void) {
  wt_tls_client_t client;
  wt_tls_client_config_t config;
  uint8_t finished[64];
  size_t finished_len = 0U;
  uint8_t read_secret[WT_TLS13_SECRET_LEN];
  uint8_t write_secret[WT_TLS13_SECRET_LEN];

  /* A certificate the policy refuses stops the handshake at the Certificate, and nothing is
   * derived from it. */
  {
    static const char *const alpn_h3[] = {"h3"};
    rfc8448_config(&config);
    /* The trust policy is a store that cannot contain the RFC's self-signed certificate. */
    config.trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
    config.trust.fingerprint_count = 1U;
    memset(config.trust.fingerprints[0], 0x11, WT_SHA256_LEN);

    WT_EXPECT_OK("the handshake starts",
                 wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                     WT_RFC8448_CLIENT_HELLO_LEN));
    WT_EXPECT_OK("the ServerHello is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_SERVER_HELLO,
                                       WT_RFC8448_SERVER_HELLO_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_OK("EncryptedExtensions are accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                       WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_STATUS("a certificate that is not pinned is refused", WT_ERR_TRUST,
                     wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE,
                                           WT_RFC8448_CERTIFICATE_LEN, finished,
                                           sizeof(finished), &finished_len));
    WT_EXPECT_U64("and the handshake has failed",
                  (uint64_t)WT_TLS_CLIENT_FAILED,
                  (uint64_t)wt_tls_client_state(&client));
    WT_EXPECT_STATUS("with no application secrets", WT_ERR_STATE,
                     wt_tls_client_application_secrets(&client, read_secret,
                                                       write_secret));
    wt_tls_client_clear(&client);
    (void)alpn_h3;
  }

  /* ALPN: a caller that asks for h3 and gets a server with no ALPN answer must fail. RFC
   * 8448's EncryptedExtensions carries none. */
  {
    static const char *const alpn_h3[] = {"h3"};
    rfc8448_config(&config);
    config.alpn = alpn_h3;
    config.alpn_count = 1U;
    WT_EXPECT_OK("the handshake starts asking for h3",
                 wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                     WT_RFC8448_CLIENT_HELLO_LEN));
    WT_EXPECT_OK("the ServerHello is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_SERVER_HELLO,
                                       WT_RFC8448_SERVER_HELLO_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_STATUS("a server that answers no protocol is refused", WT_ERR_TLS,
                     wt_tls_client_receive(&client, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                           WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN,
                                           finished, sizeof(finished), &finished_len));
    wt_tls_client_clear(&client);
  }

  /* Transport parameters: the same flight, with the caller saying it is a QUIC handshake.
   * The RFC's trace has none, so the handshake must stop. */
  {
    rfc8448_config(&config);
    config.require_transport_parameters = 1;
    WT_EXPECT_OK("the handshake starts requiring transport parameters",
                 wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                     WT_RFC8448_CLIENT_HELLO_LEN));
    WT_EXPECT_OK("the ServerHello is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_SERVER_HELLO,
                                       WT_RFC8448_SERVER_HELLO_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_STATUS("a server that sends none is refused", WT_ERR_TLS,
                     wt_tls_client_receive(&client, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                           WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN,
                                           finished, sizeof(finished), &finished_len));
    wt_tls_client_clear(&client);
  }

  /* The order is the machine's business: a message that arrives early is a state error, not
   * a message to be stashed and used later. */
  {
    rfc8448_config(&config);
    WT_EXPECT_OK("the handshake starts",
                 wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                     WT_RFC8448_CLIENT_HELLO_LEN));
    WT_EXPECT_STATUS("a Certificate before the ServerHello is refused", WT_ERR_STATE,
                     wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE,
                                           WT_RFC8448_CERTIFICATE_LEN, finished,
                                           sizeof(finished), &finished_len));
    wt_tls_client_clear(&client);
  }

  /* A Finished that does not verify stops the handshake and leaves no application
   * secrets. */
  {
    uint8_t damaged[WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN];
    rfc8448_config(&config);
    WT_EXPECT_OK("the handshake starts",
                 wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                     WT_RFC8448_CLIENT_HELLO_LEN));
    WT_EXPECT_OK("the ServerHello is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_SERVER_HELLO,
                                       WT_RFC8448_SERVER_HELLO_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_OK("EncryptedExtensions are accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                       WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_OK("the Certificate is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE,
                                       WT_RFC8448_CERTIFICATE_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_OK("the CertificateVerify is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE_VERIFY,
                                       WT_RFC8448_CERTIFICATE_VERIFY_LEN, finished,
                                       sizeof(finished), &finished_len));
    memcpy(damaged, WT_RFC8448_SERVER_FINISHED_MESSAGE, sizeof(damaged));
    damaged[WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN - 1U] ^= 0x01U;
    WT_EXPECT_STATUS("a Finished that does not verify is refused",
                     WT_ERR_AUTHENTICATION,
                     wt_tls_client_receive(&client, damaged, sizeof(damaged), finished,
                                           sizeof(finished), &finished_len));
    WT_EXPECT_STATUS("and no application secrets appear", WT_ERR_STATE,
                     wt_tls_client_application_secrets(&client, read_secret,
                                                       write_secret));
    wt_tls_client_clear(&client);
  }

  /* A CertificateVerify that does not verify is refused at that step rather than later. */
  {
    uint8_t damaged[WT_RFC8448_CERTIFICATE_VERIFY_LEN];
    rfc8448_config(&config);
    WT_EXPECT_OK("the handshake starts",
                 wt_tls_client_begin(&client, &config, WT_RFC8448_CLIENT_HELLO,
                                     WT_RFC8448_CLIENT_HELLO_LEN));
    WT_EXPECT_OK("the ServerHello is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_SERVER_HELLO,
                                       WT_RFC8448_SERVER_HELLO_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_OK("EncryptedExtensions are accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_ENCRYPTED_EXTENSIONS,
                                       WT_RFC8448_ENCRYPTED_EXTENSIONS_LEN, finished,
                                       sizeof(finished), &finished_len));
    WT_EXPECT_OK("the Certificate is accepted",
                 wt_tls_client_receive(&client, WT_RFC8448_CERTIFICATE,
                                       WT_RFC8448_CERTIFICATE_LEN, finished,
                                       sizeof(finished), &finished_len));
    memcpy(damaged, WT_RFC8448_CERTIFICATE_VERIFY, sizeof(damaged));
    damaged[WT_RFC8448_CERTIFICATE_VERIFY_LEN - 1U] ^= 0x01U;
    WT_EXPECT_STATUS("a CertificateVerify that does not verify is refused",
                     WT_ERR_AUTHENTICATION,
                     wt_tls_client_receive(&client, damaged, sizeof(damaged), finished,
                                           sizeof(finished), &finished_len));
    wt_tls_client_clear(&client);
  }
}

/* The ClientHello this implementation builds, which is what a caller with no recorded
 * handshake uses. It is checked by parsing it back and by the fields the machine put in it. */
static void test_built_client_hello(void) {
  wt_tls_client_t client;
  wt_tls_client_config_t config;
  static const char *const alpn_h3[] = {"h3"};
  static const uint16_t transports[] = {0x0001U};
  uint8_t hello[WT_TLS_CLIENT_HELLO_MAX];
  uint8_t session_id[32];
  size_t hello_len = 0U;
  wt_tls_client_hello_t parsed;
  const wt_tls_extension_t *extension;

  memset(session_id, 0x33, sizeof(session_id));
  memset(&config, 0, sizeof(config));
  config.host_name = "example.com";
  config.alpn = alpn_h3;
  config.alpn_count = 1U;
  config.transport_parameters = (const uint8_t *)transports;
  config.transport_parameters_len = sizeof(transports);
  config.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
  config.trust.host_name = "localhost";
  config.session_id = session_id;
  config.session_id_len = sizeof(session_id);

  memset(&client, 0, sizeof(client));
  WT_EXPECT_OK("the ClientHello builds",
               wt_tls_client_begin_built(&client, &config, hello, sizeof(hello),
                                         &hello_len));
  WT_EXPECT_U64("and waits for the ServerHello", (uint64_t)WT_TLS_CLIENT_WAIT_SERVER_HELLO,
                (uint64_t)wt_tls_client_state(&client));
  WT_EXPECT_TRUE("with bytes in it", hello_len > 0U);

  WT_EXPECT_OK("and parses back", wt_tls_client_hello_parse(hello, hello_len, &parsed));
  WT_EXPECT_U64("with the session id we offered", sizeof(session_id),
                (uint64_t)parsed.session_id_len);
  WT_EXPECT_BYTES("byte for byte", session_id, parsed.session_id, sizeof(session_id));
  WT_EXPECT_U64("one ciphersuite", (uint64_t)WT_TLS_CIPHER_AES_128_GCM_SHA256,
                (uint64_t)parsed.cipher_suites[0]);
  WT_EXPECT_TRUE("with a server_name",
                 wt_tls_extensions_contains(&parsed.extensions,
                                            WT_TLS_EXTENSION_SERVER_NAME));
  WT_EXPECT_TRUE("a key share",
                 wt_tls_extensions_contains(&parsed.extensions,
                                            WT_TLS_EXTENSION_KEY_SHARE));
  WT_EXPECT_TRUE("ALPN",
                 wt_tls_extensions_contains(&parsed.extensions,
                                            WT_TLS_EXTENSION_ALPN));
  WT_EXPECT_TRUE("and our transport parameters",
                 wt_tls_extensions_contains(
                     &parsed.extensions,
                     WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS));
  /* Exactly one group is offered, because a group offered without a key share invites a
   * HelloRetryRequest this implementation refuses. */
  extension = wt_tls_extensions_find(&parsed.extensions,
                                     WT_TLS_EXTENSION_SUPPORTED_GROUPS);
  {
    uint16_t groups[WT_TLS_MAX_NAMED_GROUPS];
    size_t count = 0U;
    WT_EXPECT_OK("the groups read",
                 wt_tls_u16_list_parse(extension, groups, WT_TLS_MAX_NAMED_GROUPS,
                                       &count));
    WT_EXPECT_U64("one group", 1U, (uint64_t)count);
    WT_EXPECT_U64("and it is x25519", (uint64_t)WT_TLS_GROUP_X25519,
                  (uint64_t)groups[0]);
  }

  /* Two calls with the same configuration offer different key shares, because the machine
   * generates a key: a hello that repeated would mean the generator is not generating. */
  {
    wt_tls_client_t other;
    uint8_t other_hello[WT_TLS_CLIENT_HELLO_MAX];
    size_t other_len = 0U;
    wt_tls_client_hello_t other_parsed;
    wt_tls_key_share_t first_share;
    wt_tls_key_share_t second_share;

    memset(&other, 0, sizeof(other));
    WT_EXPECT_OK("a second ClientHello builds",
                 wt_tls_client_begin_built(&other, &config, other_hello,
                                           sizeof(other_hello), &other_len));
    WT_EXPECT_OK("and parses", wt_tls_client_hello_parse(other_hello, other_len,
                                                         &other_parsed));
    WT_EXPECT_OK("the first key share reads",
                 wt_tls_key_share_client(
                     wt_tls_extensions_find(&parsed.extensions,
                                            WT_TLS_EXTENSION_KEY_SHARE),
                     &first_share, 1U, &hello_len));
    WT_EXPECT_OK("and the second",
                 wt_tls_key_share_client(
                     wt_tls_extensions_find(&other_parsed.extensions,
                                            WT_TLS_EXTENSION_KEY_SHARE),
                     &second_share, 1U, &other_len));
    WT_EXPECT_INT("the two key shares differ", 0,
                  memcmp(first_share.key, second_share.key, 32U) == 0 ? 1 : 0);
    wt_tls_client_clear(&other);
  }

  /* A caller error is a caller error rather than a failed handshake. The machine is CLEARED
   * between attempts rather than memset, because it may be holding a transcript: zeroing a
   * live machine would lose the hash context, which is the one thing `clear` exists to
   * release. */
  {
    size_t out_len = 0U;
    wt_tls_client_clear(&client);
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_begin_built(&client, &config, NULL, 64U, &out_len));
    WT_EXPECT_STATUS("a NULL config is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_begin_built(&client, NULL, hello, sizeof(hello),
                                               &out_len));
    WT_EXPECT_STATUS("a buffer too small is refused", WT_ERR_LIMIT,
                     wt_tls_client_begin_built(&client, &config, hello, 4U, &out_len));
    /* A failed begin holds nothing, so the next attempt is allowed without a clear; and a
     * machine that is mid-handshake may also start over, because beginning again releases
     * what the abandoned handshake held rather than leaking it. */
    WT_EXPECT_OK("and the machine can be used again",
                 wt_tls_client_begin_built(&client, &config, hello, sizeof(hello),
                                           &out_len));
    WT_EXPECT_OK("and may start over mid-handshake",
                 wt_tls_client_begin_built(&client, &config, hello, sizeof(hello),
                                           &out_len));
    wt_tls_client_clear(&client);
    {
      wt_tls_client_config_t bad = config;
      uint8_t too_long[64];
      bad.session_id = too_long;
      bad.session_id_len = 64U;
      WT_EXPECT_STATUS("a session id that is too long is refused", WT_ERR_LIMIT,
                       wt_tls_client_begin_built(&client, &bad, hello, sizeof(hello),
                                                 &out_len));
      wt_tls_client_clear(&client);
    }
  }
  wt_tls_client_clear(&client);
}

int main(void) {
  WT_EXPECT_OK("the crypto backend initialises", wt_crypto_init());

  test_rfc8448_handshake();
  test_gates();
  test_built_client_hello();

  WT_TEST_MAIN_END("wt_tls13_session");
}
