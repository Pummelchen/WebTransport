#include "rfc8448_vectors.h"
#include "test_tls13_handshake_messages_support.h"
#include "webtransport/tls/extension.h"
#include "webtransport/tls/handshake.h"
#include "wt_test.h"

static void test_handshake_framing(void) {
  uint8_t buffer[64];
  uint8_t framed[64];
  wt_writer_t w = wt_writer_init(framed, sizeof(framed));
  wt_cursor_t cursor;
  wt_tls_handshake_header_t header;

  WT_EXPECT_OK("a header is written",
               wt_tls_handshake_header_encode(&w, WT_TLS_HANDSHAKE_FINISHED, 0U));
  WT_EXPECT_U64("and nothing else", 4U, (uint64_t)wt_writer_offset(&w));

  /* A header for an empty body is four bytes and parses on its own. */
  cursor = wt_cursor_init(framed, 4U);
  WT_EXPECT_OK("a header parses", wt_tls_handshake_header_parse(&cursor, &header));
  WT_EXPECT_U64("with its type", (uint64_t)WT_TLS_HANDSHAKE_FINISHED, (uint64_t)header.type);
  WT_EXPECT_U64("and its length", 0U, (uint64_t)header.length);

  /* A header whose length is not the rest of the buffer is a fabricated frame: the
   * twelve bytes below claim a body that is not there. */
  {
    static const uint8_t claims_twelve[] = {0x14U, 0x00U, 0x00U, 0x0cU};
    cursor = wt_cursor_init(claims_twelve, sizeof(claims_twelve));
    WT_EXPECT_STATUS("a length that disagrees with the buffer is refused", WT_ERR_PROTOCOL,
                     wt_tls_handshake_header_parse(&cursor, &header));
  }
  cursor = wt_cursor_init(framed, 3U);
  WT_EXPECT_STATUS("a header that does not fit is refused", WT_ERR_TRUNCATED,
                   wt_tls_handshake_header_parse(&cursor, &header));
  WT_EXPECT_STATUS("a NULL header output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_handshake_header_parse(&cursor, NULL));

  /* The largest body a three-octet length can hold, and one more. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_STATUS("a body length above three octets is refused", WT_ERR_LIMIT,
                   wt_tls_handshake_header_encode(&w, 1U, WT_TLS_HANDSHAKE_MAX_BODY + 1U));
  WT_EXPECT_U64("and nothing was written", 0U, (uint64_t)wt_writer_offset(&w));

  WT_EXPECT_STR("finished is named", "finished",
                wt_tls_handshake_type_name(WT_TLS_HANDSHAKE_FINISHED));
  WT_EXPECT_STR("client hello is named", "client-hello",
                wt_tls_handshake_type_name(WT_TLS_HANDSHAKE_CLIENT_HELLO));
  WT_EXPECT_STR("an unknown type is named", "unknown", wt_tls_handshake_type_name(0x7fU));
}
static void test_client_hello_from_rfc(void) {
  wt_tls_client_hello_t hello;
  const wt_tls_extension_t *extension;
  uint8_t rebuilt[WT_RFC8448_CLIENT_HELLO_LEN + 16U];
  uint8_t random[WT_TLS_RANDOM_LEN];
  wt_writer_t w;
  uint16_t versions[4];
  uint16_t groups[WT_TLS_MAX_NAMED_GROUPS];
  uint16_t schemes[WT_TLS_MAX_SIGNATURE_SCHEMES];
  wt_tls_key_share_t shares[WT_TLS_MAX_KEY_SHARES];
  size_t count = 0U;

  WT_EXPECT_OK(
      "the RFC's ClientHello parses",
      wt_tls_client_hello_parse(WT_RFC8448_CLIENT_HELLO, WT_RFC8448_CLIENT_HELLO_LEN, &hello));
  /* RFC 8446 section 4.1.2: the legacy version is 0x0303 and the compression methods
   * are exactly one zero. */
  WT_EXPECT_U64("with legacy version 0x0303", 0x0303U, (uint64_t)hello.legacy_version);
  /* The RFC's client offers three suites, the first of which is the mandatory one. */
  WT_EXPECT_U64("three cipher suites", 3U, (uint64_t)hello.cipher_suite_count);
  WT_EXPECT_U64("the first of which is TLS_AES_128_GCM_SHA256",
                (uint64_t)WT_TLS_CIPHER_AES_128_GCM_SHA256, (uint64_t)hello.cipher_suites[0]);
  WT_EXPECT_U64("one compression method", 1U, (uint64_t)hello.compression_method_count);
  WT_EXPECT_U64("which is zero", 0U, (uint64_t)hello.compression_methods[0]);
  WT_EXPECT_U64("an empty session id", 0U, (uint64_t)hello.session_id_len);

  /* The extensions the RFC's ClientHello carries. Two of them are not implemented
   * here, which is the point: a parsed message keeps them as views. */
  WT_EXPECT_U64("nine extensions", 9U, (uint64_t)hello.extensions.count);
  WT_EXPECT_TRUE("including a key_share",
                 wt_tls_extensions_contains(&hello.extensions, WT_TLS_EXTENSION_KEY_SHARE));
  WT_EXPECT_TRUE("and an unimplemented one",
                 wt_tls_extensions_contains(&hello.extensions, 0xff01U));

  /* supported_versions: RFC 8448's client offers TLS 1.3. */
  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  WT_EXPECT_OK("the supported versions read",
               wt_tls_supported_versions_client(extension, versions, 4U, &count));
  WT_EXPECT_U64("one version", 1U, (uint64_t)count);
  WT_EXPECT_U64("which is TLS 1.3", (uint64_t)WT_TLS_VERSION_1_3, (uint64_t)versions[0]);

  /* supported_groups and signature_algorithms are the same shape. */
  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_SUPPORTED_GROUPS);
  WT_EXPECT_OK("the supported groups read",
               wt_tls_u16_list_parse(extension, groups, WT_TLS_MAX_NAMED_GROUPS, &count));
  WT_EXPECT_U64("nine groups", 9U, (uint64_t)count);
  WT_EXPECT_U64("the first of which is x25519", (uint64_t)WT_TLS_GROUP_X25519, (uint64_t)groups[0]);

  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_SIGNATURE_ALGORITHMS);
  WT_EXPECT_OK("the signature algorithms read",
               wt_tls_u16_list_parse(extension, schemes, WT_TLS_MAX_SIGNATURE_SCHEMES, &count));
  WT_EXPECT_U64("fifteen schemes", 15U, (uint64_t)count);

  /* key_share: one x25519 share whose key is the RFC's public key. */
  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_KEY_SHARE);
  WT_EXPECT_OK("the client key shares read",
               wt_tls_key_share_client(extension, shares, WT_TLS_MAX_KEY_SHARES, &count));
  WT_EXPECT_U64("one share", 1U, (uint64_t)count);
  WT_EXPECT_U64("for x25519", (uint64_t)WT_TLS_GROUP_X25519, (uint64_t)shares[0].group);
  WT_EXPECT_U64("with a 32-byte key", 32U, (uint64_t)shares[0].key_len);
  /* RFC 8448 prints the client's public key beside the ClientHello. */
  {
    static const uint8_t expected[32] = {0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43,
                                         0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe,
                                         0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d,
                                         0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c};
    WT_EXPECT_BYTES("and it is the RFC's public key", expected, shares[0].key, 32U);
  }

  /* A parsed message re-encodes to the same bytes, unknown extensions included. */
  w = wt_writer_init(rebuilt, sizeof(rebuilt));
  WT_EXPECT_OK("the parsed ClientHello re-encodes", wt_tls_client_hello_encode(&hello, &w));
  WT_EXPECT_U64("to the same length", (uint64_t)WT_RFC8448_CLIENT_HELLO_LEN,
                (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_BYTES("and the same bytes", WT_RFC8448_CLIENT_HELLO, rebuilt,
                  WT_RFC8448_CLIENT_HELLO_LEN);

  /* The random is read from the right place: the RFC prints the ClientHello, whose
   * random starts after the four-byte header and the two-byte legacy version. */
  memcpy(random, hello.random, sizeof(random));
  WT_EXPECT_BYTES("the random is the message's own bytes", WT_RFC8448_CLIENT_HELLO + 6U, random,
                  WT_TLS_RANDOM_LEN);
}
static void test_server_hello_from_rfc(void) {
  wt_tls_server_hello_t hello;
  const wt_tls_extension_t *extension;
  uint8_t rebuilt[WT_RFC8448_SERVER_HELLO_LEN + 16U];
  wt_writer_t w;
  uint16_t version = 0U;
  wt_tls_key_share_t share;

  WT_EXPECT_OK(
      "the RFC's ServerHello parses",
      wt_tls_server_hello_parse(WT_RFC8448_SERVER_HELLO, WT_RFC8448_SERVER_HELLO_LEN, &hello));
  WT_EXPECT_U64("with legacy version 0x0303", 0x0303U, (uint64_t)hello.legacy_version);
  WT_EXPECT_U64("the ciphersuite the RFC chose", (uint64_t)WT_TLS_CIPHER_AES_128_GCM_SHA256,
                (uint64_t)hello.cipher_suite);
  WT_EXPECT_U64("one compression method", 0U, (uint64_t)hello.compression_method);
  WT_EXPECT_U64("two extensions", 2U, (uint64_t)hello.extensions.count);

  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  WT_EXPECT_OK("the server's version reads", wt_tls_supported_versions_server(extension, &version));
  WT_EXPECT_U64("and is TLS 1.3", (uint64_t)WT_TLS_VERSION_1_3, (uint64_t)version);

  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_KEY_SHARE);
  WT_EXPECT_OK("the server's key share reads", wt_tls_key_share_server(extension, &share));
  WT_EXPECT_U64("for x25519", (uint64_t)WT_TLS_GROUP_X25519, (uint64_t)share.group);
  WT_EXPECT_U64("with a 32-byte key", 32U, (uint64_t)share.key_len);
  {
    static const uint8_t expected[32] = {0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe,
                                         0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1,
                                         0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1,
                                         0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f};
    WT_EXPECT_BYTES("and it is the RFC's public key", expected, share.key, 32U);
  }

  w = wt_writer_init(rebuilt, sizeof(rebuilt));
  WT_EXPECT_OK("the parsed ServerHello re-encodes", wt_tls_server_hello_encode(&hello, &w));
  WT_EXPECT_U64("to the same length", (uint64_t)WT_RFC8448_SERVER_HELLO_LEN,
                (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_BYTES("and the same bytes", WT_RFC8448_SERVER_HELLO, rebuilt,
                  WT_RFC8448_SERVER_HELLO_LEN);
}
static void test_build_and_parse_back(void) {
  uint8_t message[512];
  uint8_t random[WT_TLS_RANDOM_LEN];
  uint8_t session_id[32];
  wt_tls_key_share_t shares[1];
  wt_tls_client_hello_params_t params;
  wt_tls_client_hello_t hello;
  size_t message_len = 0U;

  memset(random, 0x5a, sizeof(random));
  memset(session_id, 0x11, sizeof(session_id));
  shares[0].group = WT_TLS_GROUP_X25519;
  shares[0].key = WT_TEST_KEY_SHARE_KEY;
  shares[0].key_len = sizeof(WT_TEST_KEY_SHARE_KEY);

  memset(&params, 0, sizeof(params));
  params.random = random;
  params.session_id = session_id;
  params.session_id_len = sizeof(session_id);
  params.cipher_suites = WT_TEST_CIPHER_SUITES;
  params.cipher_suite_count = 1U;
  params.host_name = "example.com";
  params.supported_groups = WT_TEST_GROUPS;
  params.supported_group_count = 2U;
  params.signature_schemes = WT_TEST_SIGNATURES;
  params.signature_scheme_count = 3U;
  params.key_shares = shares;
  params.key_share_count = 1U;
  params.alpn = WT_TEST_ALPN;
  params.alpn_count = 1U;
  params.transport_parameters = WT_TEST_TRANSPORT_PARAMETERS;
  params.transport_parameters_len = sizeof(WT_TEST_TRANSPORT_PARAMETERS);

  WT_EXPECT_OK("our ClientHello builds",
               wt_tls_client_hello_build(&params, message, sizeof(message), &message_len));
  WT_EXPECT_TRUE("and is not empty", message_len > 0U);
  WT_EXPECT_U64("with the ClientHello type", (uint64_t)WT_TLS_HANDSHAKE_CLIENT_HELLO,
                (uint64_t)message[0]);
  /* The header's length is the body's, which is what a peer checks. */
  WT_EXPECT_U64(
      "and a length that fits the buffer", (uint64_t)(message_len - WT_TLS_HANDSHAKE_HEADER_LEN),
      (uint64_t)(((size_t)message[1] << 16) | ((size_t)message[2] << 8) | (size_t)message[3]));

  WT_EXPECT_OK("and parses back", wt_tls_client_hello_parse(message, message_len, &hello));
  WT_EXPECT_BYTES("with the random we chose", random, hello.random, WT_TLS_RANDOM_LEN);
  WT_EXPECT_U64("the session id we chose", sizeof(session_id), (uint64_t)hello.session_id_len);
  WT_EXPECT_BYTES("byte for byte", session_id, hello.session_id, sizeof(session_id));
  WT_EXPECT_U64("the ciphersuite we chose", (uint64_t)WT_TLS_CIPHER_AES_128_GCM_SHA256,
                (uint64_t)hello.cipher_suites[0]);
  /* server_name, supported_groups, signature_algorithms, supported_versions,
   * key_share, ALPN, psk_key_exchange_modes and quic_transport_parameters. */
  WT_EXPECT_U64("and every extension we asked for", 8U, (uint64_t)hello.extensions.count);

  /* The typed readers see what the builder wrote. */
  {
    const wt_tls_extension_t *extension;
    wt_tls_alpn_t alpn;
    uint16_t groups[WT_TLS_MAX_NAMED_GROUPS];
    size_t count = 0U;
    const uint8_t *parameters = NULL;
    size_t parameters_len = 0U;
    wt_tls_key_share_t parsed[WT_TLS_MAX_KEY_SHARES];
    wt_tls_key_share_t server_share;
    uint16_t version = 0U;

    extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_ALPN);
    WT_EXPECT_OK("the ALPN extension reads", wt_tls_alpn_parse(extension, &alpn));
    WT_EXPECT_U64("one protocol", 1U, (uint64_t)alpn.count);
    WT_EXPECT_U64("two bytes long", 2U, (uint64_t)alpn.lengths[0]);
    WT_EXPECT_BYTES("and it is h3", (const uint8_t *)"h3", alpn.names[0], 2U);

    extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_SUPPORTED_GROUPS);
    WT_EXPECT_OK("the groups read",
                 wt_tls_u16_list_parse(extension, groups, WT_TLS_MAX_NAMED_GROUPS, &count));
    WT_EXPECT_U64("two of them", 2U, (uint64_t)count);
    WT_EXPECT_U64("x25519 first", (uint64_t)WT_TLS_GROUP_X25519, (uint64_t)groups[0]);

    extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_KEY_SHARE);
    WT_EXPECT_OK("the key shares read",
                 wt_tls_key_share_client(extension, parsed, WT_TLS_MAX_KEY_SHARES, &count));
    WT_EXPECT_U64("one share", 1U, (uint64_t)count);
    WT_EXPECT_BYTES("with the key we put in", WT_TEST_KEY_SHARE_KEY, parsed[0].key, 32U);

    extension =
        wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    WT_EXPECT_OK("the transport parameters read",
                 wt_tls_transport_parameters(extension, &parameters, &parameters_len));
    WT_EXPECT_U64("at the length we put in", (uint64_t)sizeof(WT_TEST_TRANSPORT_PARAMETERS),
                  (uint64_t)parameters_len);
    WT_EXPECT_BYTES("with the bytes we put in", WT_TEST_TRANSPORT_PARAMETERS, parameters,
                    parameters_len);
    (void)server_share;
    (void)version;
  }

  /* And the server's answer, built and parsed back. */
  {
    wt_tls_server_hello_params_t server_params;
    wt_tls_server_hello_t server;
    wt_tls_key_share_t server_share;
    size_t server_len = 0U;
    uint8_t server_random[WT_TLS_RANDOM_LEN];
    uint16_t version = 0U;

    memset(server_random, 0xa5, sizeof(server_random));
    server_share.group = WT_TLS_GROUP_X25519;
    server_share.key = WT_TEST_KEY_SHARE_KEY;
    server_share.key_len = sizeof(WT_TEST_KEY_SHARE_KEY);
    memset(&server_params, 0, sizeof(server_params));
    server_params.random = server_random;
    server_params.session_id = session_id;
    server_params.session_id_len = sizeof(session_id);
    server_params.cipher_suite = WT_TLS_CIPHER_AES_128_GCM_SHA256;
    server_params.key_share = &server_share;
    server_params.supported_version = WT_TLS_VERSION_1_3;

    WT_EXPECT_OK("our ServerHello builds",
                 wt_tls_server_hello_build(&server_params, message, sizeof(message), &server_len));
    WT_EXPECT_OK("and parses back", wt_tls_server_hello_parse(message, server_len, &server));
    WT_EXPECT_BYTES("with the random we chose", server_random, server.random, WT_TLS_RANDOM_LEN);
    WT_EXPECT_U64("the session id echoed", sizeof(session_id), (uint64_t)server.session_id_len);
    WT_EXPECT_BYTES("byte for byte", session_id, server.session_id, sizeof(session_id));
    {
      const wt_tls_extension_t *extension =
          wt_tls_extensions_find(&server.extensions, WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
      WT_EXPECT_OK("and the version extension",
                   wt_tls_supported_versions_server(extension, &version));
      WT_EXPECT_U64("saying TLS 1.3", (uint64_t)WT_TLS_VERSION_1_3, (uint64_t)version);
    }
    {
      const wt_tls_extension_t *extension =
          wt_tls_extensions_find(&server.extensions, WT_TLS_EXTENSION_KEY_SHARE);
      WT_EXPECT_OK("and the key share", wt_tls_key_share_server(extension, &server_share));
      WT_EXPECT_BYTES("with the key we put in", WT_TEST_KEY_SHARE_KEY, server_share.key, 32U);
    }
  }

  /* A buffer one byte too small is refused rather than filled. */
  {
    size_t short_len = 0U;
    WT_EXPECT_STATUS("a buffer too small is refused", WT_ERR_LIMIT,
                     wt_tls_client_hello_build(&params, message, message_len - 1U, &short_len));
    WT_EXPECT_U64("and no length is reported", 0U, (uint64_t)short_len);
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_hello_build(&params, NULL, 64U, &short_len));
    WT_EXPECT_STATUS("a NULL length output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_hello_build(&params, message, sizeof(message), NULL));
    WT_EXPECT_STATUS("a NULL parameter block is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_hello_build(NULL, message, sizeof(message), &short_len));
  }
}
int main(void) {
  test_handshake_framing();
  test_client_hello_from_rfc();
  test_server_hello_from_rfc();
  test_build_and_parse_back();
  WT_TEST_MAIN_END("test_tls13_handshake");
}
