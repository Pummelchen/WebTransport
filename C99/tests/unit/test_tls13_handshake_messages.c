#include "rfc8448_vectors.h"
#include "test_tls13_handshake_messages_support.h"
#include "webtransport/tls/extension.h"
#include "webtransport/tls/handshake.h"
#include "wt_test.h"

static void test_extension_refusals(void) {
  wt_tls_extension_list_t list;
  wt_cursor_t cursor;
  uint8_t buffer[64];
  wt_writer_t w;

  /* A duplicate extension type (RFC 8446 section 4.2) is refused: the two endpoints
   * would otherwise disagree about which one applies. */
  {
    static const uint8_t duplicated[] = {
        0x00, 0x0a,                         /* block length: ten bytes, which is both extensions */
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, /* supported_versions */
        0x00, 0x2b, 0x00, 0x00              /* and again */
    };
    cursor = wt_cursor_init(duplicated, sizeof(duplicated));
    WT_EXPECT_STATUS("a duplicate extension is refused", WT_ERR_PROTOCOL,
                     wt_tls_extensions_parse(&cursor, &list));
  }
  /* A block whose inner lengths do not fill it. */
  {
    static const uint8_t trailing[] = {0x00, 0x05, 0x00, 0x2b, 0x00, 0x00, 0xff};
    cursor = wt_cursor_init(trailing, sizeof(trailing));
    WT_EXPECT_STATUS("a block with trailing bytes is refused", WT_ERR_PROTOCOL,
                     wt_tls_extensions_parse(&cursor, &list));
  }
  /* An extension header that claims more than the block holds. */
  {
    static const uint8_t oversized[] = {0x00, 0x04, 0x00, 0x2b, 0x00, 0x10};
    cursor = wt_cursor_init(oversized, sizeof(oversized));
    WT_EXPECT_STATUS("an extension longer than its block is refused", WT_ERR_PROTOCOL,
                     wt_tls_extensions_parse(&cursor, &list));
  }
  /* More extensions than the list can hold. The count is a peer's choice, so this is
   * the bound rather than an impossible input. */
  {
    uint8_t many[4U + 4U * (WT_TLS_MAX_EXTENSIONS + 1U)];
    size_t i;
    size_t at = 0U;
    many[0] = 0U;
    many[1] = (uint8_t)(4U * (WT_TLS_MAX_EXTENSIONS + 1U));
    at = 2U;
    for (i = 0U; i < WT_TLS_MAX_EXTENSIONS + 1U; i++) {
      many[at++] = 0U;
      many[at++] = (uint8_t)(0x10U + i);
      many[at++] = 0U;
      many[at++] = 0U;
    }
    cursor = wt_cursor_init(many, at);
    WT_EXPECT_STATUS("more extensions than the list holds is refused", WT_ERR_LIMIT,
                     wt_tls_extensions_parse(&cursor, &list));
  }

  /* An empty list is legal to write and to read; the message layer is where a minimum
   * is enforced. */
  {
    uint8_t empty[] = {0x00, 0x00};
    cursor = wt_cursor_init(empty, sizeof(empty));
    WT_EXPECT_OK("an empty extension block parses", wt_tls_extensions_parse(&cursor, &list));
    WT_EXPECT_U64("with no entries", 0U, (uint64_t)list.count);
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_OK("and re-encodes", wt_tls_extensions_encode(&w, &list));
    WT_EXPECT_U64("to two bytes", 2U, (uint64_t)wt_writer_offset(&w));
    WT_EXPECT_BYTES("which are zero", empty, buffer, 2U);
  }

  WT_EXPECT_STATUS("a NULL list is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_extensions_parse(&cursor, NULL));
  WT_EXPECT_STATUS("a NULL writer is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_extensions_encode(NULL, &list));
  WT_EXPECT_STATUS("and a NULL list to encode", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_extensions_encode(&w, NULL));
  WT_EXPECT_TRUE("an unknown type is not found", wt_tls_extensions_find(&list, 0x1234U) == NULL);
}
static void test_message_refusals(void) {
  wt_tls_client_hello_t hello;
  wt_tls_server_hello_t server;
  uint8_t message[WT_RFC8448_CLIENT_HELLO_LEN];
  const wt_tls_extension_t *extension;

  /* A message whose header length is not its size, and then the fields inside a message
   * whose framing is complete: an inner length that overruns its region is a decode error
   * rather than truncation, because the bytes are all there and the length is wrong. */
  memcpy(message, WT_RFC8448_CLIENT_HELLO, sizeof(message));
  message[3] = (uint8_t)(message[3] - 1U);
  WT_EXPECT_STATUS("a ClientHello whose length is short is refused", WT_ERR_PROTOCOL,
                   wt_tls_client_hello_parse(message, sizeof(message), &hello));

  /* The wrong message type for the parser. */
  WT_EXPECT_STATUS(
      "a ServerHello parsed as a ClientHello is refused", WT_ERR_PROTOCOL,
      wt_tls_client_hello_parse(WT_RFC8448_SERVER_HELLO, WT_RFC8448_SERVER_HELLO_LEN, &hello));
  WT_EXPECT_STATUS(
      "and the other way round", WT_ERR_PROTOCOL,
      wt_tls_server_hello_parse(WT_RFC8448_CLIENT_HELLO, WT_RFC8448_CLIENT_HELLO_LEN, &server));
  WT_EXPECT_STATUS("a message shorter than a header is refused", WT_ERR_TRUNCATED,
                   wt_tls_client_hello_parse(WT_RFC8448_CLIENT_HELLO, 3U, &hello));

  /* A legacy version that is not 0x0303. */
  memcpy(message, WT_RFC8448_CLIENT_HELLO, sizeof(message));
  message[4] = 0x03U;
  message[5] = 0x01U;
  WT_EXPECT_STATUS("a legacy version that is not 0x0303 is refused", WT_ERR_PROTOCOL,
                   wt_tls_client_hello_parse(message, sizeof(message), &hello));

  /* A compression method that is not a single zero (RFC 8446 section 4.1.2). The
   * field is at a known offset in the RFC's message: after the header, the version,
   * the random, the session id length and the cipher suite list. */
  WT_EXPECT_OK(
      "the RFC's ClientHello parses for the offset check",
      wt_tls_client_hello_parse(WT_RFC8448_CLIENT_HELLO, WT_RFC8448_CLIENT_HELLO_LEN, &hello));
  {
    /* Its layout is 4 header + 2 version + 32 random + 1 + 0 session + 2 + 2 cipher +
     * 1 compression methods. */
    const size_t compression_at = 4U + 2U + 32U + 1U + 2U + 6U;
    memcpy(message, WT_RFC8448_CLIENT_HELLO, sizeof(message));
    message[compression_at] = 2U; /* two methods where TLS 1.3 allows one */
    WT_EXPECT_STATUS("two compression methods are refused", WT_ERR_PROTOCOL,
                     wt_tls_client_hello_parse(message, sizeof(message), &hello));
    memcpy(message, WT_RFC8448_CLIENT_HELLO, sizeof(message));
    message[compression_at + 1U] = 1U; /* a non-zero method */
    WT_EXPECT_STATUS("a non-zero compression method is refused", WT_ERR_PROTOCOL,
                     wt_tls_client_hello_parse(message, sizeof(message), &hello));
  }

  /* RFC 8446 section 4.1.2: the cipher suite vector is 2..2^16-2 bytes, so it is at least
   * one suite and an even number of bytes. AUD-0028: that refusal had no test -- line
   * coverage showed it never executed -- and it is reachable from the server, which parses
   * whatever a peer sends (`session_server.c`).
   *
   * The message is REBUILT rather than mutated in place, and that is the point: shortening
   * the vector inside the RFC's bytes misaligns everything after it, so a later rule refuses
   * the message and the test would pass with this check deleted. Splicing the compression
   * methods and extensions directly behind a length of 0 or 1 leaves a message whose ONLY
   * fault is the vector's length, so removing the check makes both of these parse. */
  {
    const size_t cipher_len_at = 4U + 2U + 32U + 1U; /* the RFC's session id is empty */
    const size_t compression_at = 4U + 2U + 32U + 1U + 2U + 6U;
    const size_t tail_len = WT_RFC8448_CLIENT_HELLO_LEN - compression_at;
    static const uint16_t vector_lengths[2] = {0U, 1U}; /* empty, and odd */
    static const char *const labels[2] = {"an empty cipher suite vector is refused",
                                          "an odd cipher suite vector length is refused"};
    size_t i;

    WT_EXPECT_U64("the RFC's cipher suite length is where this test thinks it is", 6U,
                  (uint64_t)(((size_t)WT_RFC8448_CLIENT_HELLO[cipher_len_at] << 8) |
                             (size_t)WT_RFC8448_CLIENT_HELLO[cipher_len_at + 1U]));
    for (i = 0U; i < 2U; i++) {
      size_t rebuilt_len = cipher_len_at + 2U + tail_len;
      size_t body_len = rebuilt_len - 4U;

      memcpy(message, WT_RFC8448_CLIENT_HELLO, cipher_len_at);
      message[cipher_len_at] = (uint8_t)(vector_lengths[i] >> 8);
      message[cipher_len_at + 1U] = (uint8_t)(vector_lengths[i] & 0xffU);
      memcpy(message + cipher_len_at + 2U, WT_RFC8448_CLIENT_HELLO + compression_at, tail_len);
      message[1] = (uint8_t)(body_len >> 16);
      message[2] = (uint8_t)((body_len >> 8) & 0xffU);
      message[3] = (uint8_t)(body_len & 0xffU);
      WT_EXPECT_STATUS(labels[i], WT_ERR_PROTOCOL,
                       wt_tls_client_hello_parse(message, rebuilt_len, &hello));
    }
  }

  /* Extension readers refuse a body that is not their shape. */
  {
    wt_tls_extension_t bogus;
    uint16_t values[4];
    size_t count = 0U;
    uint16_t version = 0U;
    wt_tls_key_share_t share;
    static const uint8_t odd[] = {0x00, 0x03, 0x03, 0x04, 0x00};
    static const uint8_t empty[] = {0x00, 0x00};
    static const uint8_t zero_key[] = {0x00, 0x1d, 0x00, 0x00};
    static const uint8_t short_key[] = {0x1d, 0x00, 0x20, 0x01};

    bogus.type = WT_TLS_EXTENSION_SUPPORTED_GROUPS;
    bogus.data = odd;
    bogus.len = sizeof(odd);
    WT_EXPECT_STATUS("an odd-length group list is refused", WT_ERR_PROTOCOL,
                     wt_tls_u16_list_parse(&bogus, values, 4U, &count));
    bogus.data = empty;
    bogus.len = sizeof(empty);
    WT_EXPECT_STATUS("an empty group list is refused", WT_ERR_PROTOCOL,
                     wt_tls_u16_list_parse(&bogus, values, 4U, &count));
    WT_EXPECT_STATUS("a capacity of zero is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_u16_list_parse(&bogus, values, 0U, &count));

    bogus.type = WT_TLS_EXTENSION_SUPPORTED_VERSIONS;
    bogus.data = empty;
    bogus.len = sizeof(empty);
    WT_EXPECT_STATUS("an empty supported_versions is refused", WT_ERR_PROTOCOL,
                     wt_tls_supported_versions_client(&bogus, values, 4U, &count));
    bogus.type = WT_TLS_EXTENSION_SUPPORTED_VERSIONS;
    bogus.data = odd;
    bogus.len = 1U;
    WT_EXPECT_STATUS("a one-byte server version is refused", WT_ERR_PROTOCOL,
                     wt_tls_supported_versions_server(&bogus, &version));

    bogus.type = WT_TLS_EXTENSION_KEY_SHARE;
    bogus.data = zero_key;
    bogus.len = sizeof(zero_key);
    WT_EXPECT_STATUS("a zero-length key share is refused", WT_ERR_PROTOCOL,
                     wt_tls_key_share_server(&bogus, &share));
    bogus.data = short_key;
    bogus.len = sizeof(short_key);
    WT_EXPECT_STATUS("a key share shorter than its key is refused", WT_ERR_PROTOCOL,
                     wt_tls_key_share_server(&bogus, &share));
    WT_EXPECT_STATUS("a NULL key share output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_key_share_server(&bogus, NULL));
    WT_EXPECT_STATUS("a NULL extension is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_u16_list_parse(NULL, values, 4U, &count));
  }

  /* The encoders refuse a structure the parser could never have produced. */
  {
    wt_tls_client_hello_t broken;
    uint8_t out[512];
    wt_writer_t w = wt_writer_init(out, sizeof(out));
    WT_EXPECT_OK(
        "the RFC's ClientHello parses again",
        wt_tls_client_hello_parse(WT_RFC8448_CLIENT_HELLO, WT_RFC8448_CLIENT_HELLO_LEN, &hello));
    broken = hello;
    broken.cipher_suite_count = 0U;
    WT_EXPECT_STATUS("a ClientHello with no ciphersuite is refused", WT_ERR_LIMIT,
                     wt_tls_client_hello_encode(&broken, &w));
    broken = hello;
    broken.session_id_len = WT_TLS_SESSION_ID_MAX + 1U;
    WT_EXPECT_STATUS("a session id that is too long is refused", WT_ERR_LIMIT,
                     wt_tls_client_hello_encode(&broken, &w));
    WT_EXPECT_STATUS("a NULL ClientHello is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_hello_encode(NULL, &w));
    WT_EXPECT_STATUS("a NULL writer is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_client_hello_encode(&hello, NULL));
  }

  /* A ServerHello with a compression method that is not zero. */
  {
    uint8_t server_message[WT_RFC8448_SERVER_HELLO_LEN];
    const size_t compression_at = 4U + 2U + 32U + 1U + 2U;
    memcpy(server_message, WT_RFC8448_SERVER_HELLO, sizeof(server_message));
    server_message[compression_at] = 1U;
    WT_EXPECT_STATUS("a non-zero server compression method is refused", WT_ERR_PROTOCOL,
                     wt_tls_server_hello_parse(server_message, sizeof(server_message), &server));
  }

  /* A ClientHello with no extensions at all: legal to parse, and the missing mandatory
   * extensions are the handshake layer's business rather than the codec's. */
  {
    uint8_t minimal[4U + 2U + 32U + 1U + 2U + 2U + 1U + 1U + 2U];
    size_t at = 0U;
    wt_tls_client_hello_t parsed;
    memset(minimal, 0, sizeof(minimal));
    minimal[at++] = WT_TLS_HANDSHAKE_CLIENT_HELLO;
    minimal[at++] = 0U;
    minimal[at++] = 0U;
    minimal[at++] = (uint8_t)(sizeof(minimal) - 4U);
    minimal[at++] = 0x03U;
    minimal[at++] = 0x03U;
    at += 32U;          /* random */
    minimal[at++] = 0U; /* empty session id */
    minimal[at++] = 0U; /* cipher suites: two bytes */
    minimal[at++] = 0x02U;
    minimal[at++] = 0x13U;
    minimal[at++] = 0x01U;
    minimal[at++] = 1U; /* one compression method */
    minimal[at++] = 0U;
    minimal[at++] = 0U; /* no extensions */
    minimal[at++] = 0U;
    WT_EXPECT_U64("the minimal message is as long as it should be", at, (uint64_t)sizeof(minimal));
    WT_EXPECT_OK("a ClientHello with no extensions parses",
                 wt_tls_client_hello_parse(minimal, sizeof(minimal), &parsed));
    WT_EXPECT_U64("with no extensions", 0U, (uint64_t)parsed.extensions.count);
    extension = wt_tls_extensions_find(&parsed.extensions, WT_TLS_EXTENSION_KEY_SHARE);
    WT_EXPECT_TRUE("and no key share to find", extension == NULL);
  }
}
static void test_certificate_messages(void) {
  wt_tls_certificate_t certificate;
  wt_tls_certificate_verify_t verify;
  uint8_t rebuilt[WT_RFC8448_CERTIFICATE_LEN + 16U];
  uint8_t finished[WT_TLS13_FINISHED_LEN];
  wt_writer_t w;

  /* RFC 8448's Certificate: one entry, an empty request context, and the DER of a real
   * certificate. */
  WT_EXPECT_OK(
      "the RFC's Certificate parses",
      wt_tls_certificate_parse(WT_RFC8448_CERTIFICATE, WT_RFC8448_CERTIFICATE_LEN, &certificate));
  WT_EXPECT_U64("with no request context", 0U, (uint64_t)certificate.request_context_len);
  WT_EXPECT_U64("one entry", 1U, (uint64_t)certificate.count);
  WT_EXPECT_U64("whose DER is 432 bytes", 432U, (uint64_t)certificate.entries[0].der_len);
  WT_EXPECT_U64("an X.509 SEQUENCE", 0x30U, (uint64_t)certificate.entries[0].der[0]);
  WT_EXPECT_U64("with no entry extensions", 0U, (uint64_t)certificate.entries[0].extensions_len);

  w = wt_writer_init(rebuilt, sizeof(rebuilt));
  WT_EXPECT_OK("and it re-encodes", wt_tls_certificate_encode(&certificate, &w));
  WT_EXPECT_U64("to the same length", (uint64_t)WT_RFC8448_CERTIFICATE_LEN,
                (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_BYTES("and the same bytes", WT_RFC8448_CERTIFICATE, rebuilt,
                  WT_RFC8448_CERTIFICATE_LEN);

  /* A client with nothing to offer sends an empty chain, which RFC 8446 section 4.4.2
   * requires rather than allowing the message to be omitted. */
  {
    wt_tls_certificate_params_t params;
    wt_tls_certificate_t parsed;
    uint8_t message[16];
    size_t message_len = 0U;
    memset(&params, 0, sizeof(params));
    WT_EXPECT_OK("an empty chain builds",
                 wt_tls_certificate_build(&params, message, sizeof(message), &message_len));
    WT_EXPECT_U64("as eight bytes", 8U, (uint64_t)message_len);
    WT_EXPECT_OK("and parses back", wt_tls_certificate_parse(message, message_len, &parsed));
    WT_EXPECT_U64("with no entries", 0U, (uint64_t)parsed.count);
  }

  /* CertificateVerify: the RFC's scheme is rsa_pss_rsae_sha256 over a 128-byte
   * signature. */
  WT_EXPECT_OK("the RFC's CertificateVerify parses",
               wt_tls_certificate_verify_parse(WT_RFC8448_CERTIFICATE_VERIFY,
                                               WT_RFC8448_CERTIFICATE_VERIFY_LEN, &verify));
  WT_EXPECT_U64("with the scheme the RFC used", (uint64_t)WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                (uint64_t)verify.scheme);
  WT_EXPECT_U64("and a 128-byte signature", 128U, (uint64_t)verify.signature_len);
  w = wt_writer_init(rebuilt, sizeof(rebuilt));
  WT_EXPECT_OK("and it re-encodes", wt_tls_certificate_verify_encode(&verify, &w));
  WT_EXPECT_U64("to the same length", (uint64_t)WT_RFC8448_CERTIFICATE_VERIFY_LEN,
                (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_BYTES("and the same bytes", WT_RFC8448_CERTIFICATE_VERIFY, rebuilt,
                  WT_RFC8448_CERTIFICATE_VERIFY_LEN);

  /* The build convenience form. It composes the same message from its parts, and
   * before this test nothing in the tree called it (F-repo-ops-08). The RFC's own
   * message is the expectation, so a builder that agrees with the encoder but not
   * with the document fails here. */
  {
    uint8_t message[WT_RFC8448_CERTIFICATE_VERIFY_LEN];
    size_t message_len = 0U;

    WT_EXPECT_OK("the CertificateVerify builder reproduces the RFC's message",
                 wt_tls_certificate_verify_build(verify.scheme, verify.signature,
                                                 verify.signature_len, message, sizeof(message),
                                                 &message_len));
    WT_EXPECT_U64("as the same length", (uint64_t)WT_RFC8448_CERTIFICATE_VERIFY_LEN,
                  (uint64_t)message_len);
    WT_EXPECT_BYTES("and the same bytes", WT_RFC8448_CERTIFICATE_VERIFY, message,
                    WT_RFC8448_CERTIFICATE_VERIFY_LEN);

    WT_EXPECT_STATUS("a buffer too small for the message is refused", WT_ERR_LIMIT,
                     wt_tls_certificate_verify_build(verify.scheme, verify.signature,
                                                     verify.signature_len, message, 4U,
                                                     &message_len));
    WT_EXPECT_U64("and no length is reported", 0U, (uint64_t)message_len);
    WT_EXPECT_STATUS("a NULL output buffer is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_certificate_verify_build(verify.scheme, verify.signature,
                                                     verify.signature_len, NULL, sizeof(message),
                                                     &message_len));
  }

  /* Finished: the RFC's message carries the verify data the key schedule test uses. */
  WT_EXPECT_OK("the RFC's Finished parses",
               wt_tls_finished_parse(WT_RFC8448_SERVER_FINISHED_MESSAGE,
                                     WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN, finished));
  WT_EXPECT_BYTES("to the verify data the key schedule derives", WT_RFC8448_SERVER_FINISHED,
                  finished, WT_TLS13_FINISHED_LEN);
  {
    uint8_t message[WT_TLS13_FINISHED_LEN + WT_TLS_HANDSHAKE_HEADER_LEN];
    size_t message_len = 0U;
    WT_EXPECT_OK("and it builds", wt_tls_finished_build(WT_RFC8448_SERVER_FINISHED, message,
                                                        sizeof(message), &message_len));
    WT_EXPECT_BYTES("byte for byte", WT_RFC8448_SERVER_FINISHED_MESSAGE, message,
                    WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN);
  }

  /* The refusals. */
  {
    uint8_t broken[WT_RFC8448_CERTIFICATE_LEN];
    uint8_t small[8];
    size_t small_len = 0U;
    memcpy(broken, WT_RFC8448_CERTIFICATE, sizeof(broken));

    /* The list length claims more than the body holds. */
    broken[5] = (uint8_t)(broken[5] + 1U);
    WT_EXPECT_STATUS("a certificate list that overruns is refused", WT_ERR_PROTOCOL,
                     wt_tls_certificate_parse(broken, sizeof(broken), &certificate));

    /* A Finished whose body is not Hash.length. */
    memcpy(broken, WT_RFC8448_SERVER_FINISHED_MESSAGE,
           WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN > sizeof(broken)
               ? sizeof(broken)
               : WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN);
    broken[3] = 31U; /* a body one byte short */
    WT_EXPECT_STATUS("a short Finished is refused", WT_ERR_PROTOCOL,
                     wt_tls_finished_parse(broken, 35U, finished));
    WT_EXPECT_STATUS("a NULL Finished output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_tls_finished_parse(WT_RFC8448_SERVER_FINISHED_MESSAGE,
                                           WT_RFC8448_SERVER_FINISHED_MESSAGE_LEN, NULL));

    {
      wt_tls_certificate_entry_t entry;
      wt_tls_certificate_params_t params;
      entry.der = WT_RFC8448_CERTIFICATE + 8U; /* the DER inside the RFC's message */
      entry.der_len = 432U;
      entry.extensions = NULL;
      entry.extensions_len = 0U;
      params.request_context = NULL;
      params.request_context_len = 0U;
      params.entries = &entry;
      params.count = 1U;
      WT_EXPECT_STATUS("a buffer too small for a certificate is refused", WT_ERR_LIMIT,
                       wt_tls_certificate_build(&params, small, sizeof(small), &small_len));
      WT_EXPECT_U64("and no length is reported", 0U, (uint64_t)small_len);
      WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                       wt_tls_certificate_build(&params, NULL, 0U, &small_len));
      WT_EXPECT_STATUS("a NULL length output is refused", WT_ERR_INVALID_ARGUMENT,
                       wt_tls_certificate_build(&params, small, sizeof(small), NULL));
    }

    /* An empty chain with no entries is the form RFC 8446 section 4.4.2 gives a client with no
     * certificate to offer, and it is the call where a NULL entry array must not reach memcpy --
     * the guard in the builder is what keeps it legal. */
    {
      wt_tls_certificate_t parsed;
      wt_tls_certificate_params_t params;
      uint8_t empty[16];
      size_t empty_len = 0U;
      params.request_context = NULL;
      params.request_context_len = 0U;
      params.entries = NULL;
      params.count = 0U;
      WT_EXPECT_OK("an empty chain with no entries is built",
                   wt_tls_certificate_build(&params, empty, sizeof(empty), &empty_len));
      /* The handshake header is four bytes (type and a three-byte length) and the body is
       * four more: an empty request context and an empty certificate list. */
      WT_EXPECT_U64("as an eight-byte message", 8U, (uint64_t)empty_len);
      WT_EXPECT_OK("and it parses back", wt_tls_certificate_parse(empty, empty_len, &parsed));
      WT_EXPECT_U64("with no entries", 0U, (uint64_t)parsed.count);
      WT_EXPECT_U64("and no request context", 0U, (uint64_t)parsed.request_context_len);
    }

    /* A certificate entry with no DER is not an empty chain. */
    {
      wt_tls_certificate_entry_t entry;
      wt_tls_certificate_params_t params;
      uint8_t message[64];
      size_t message_len = 0U;
      entry.der = NULL;
      entry.der_len = 0U;
      entry.extensions = NULL;
      entry.extensions_len = 0U;
      params.request_context = NULL;
      params.request_context_len = 0U;
      params.entries = &entry;
      params.count = 1U;
      WT_EXPECT_STATUS("an entry with no certificate is refused", WT_ERR_INVALID_ARGUMENT,
                       wt_tls_certificate_build(&params, message, sizeof(message), &message_len));
    }

    /* A CertificateVerify whose signature length overruns its body. */
    {
      static const uint8_t overrun[] = {0x0fU, 0x00U, 0x00U, 0x06U, 0x08U,
                                        0x04U, 0x00U, 0x10U, 0x00U, 0x00U};
      WT_EXPECT_STATUS("a signature that overruns is refused", WT_ERR_PROTOCOL,
                       wt_tls_certificate_verify_parse(overrun, sizeof(overrun), &verify));
    }
  }
}
static void test_encrypted_extensions_build(void) {
  static const uint8_t alpn[] = {0x00U, 0x03U, 0x02U, 'h', '3'};
  static const uint8_t transport_parameters[] = {0x01U, 0x02U};
  wt_tls_extension_list_t list;
  wt_tls_extension_list_t parsed;
  uint8_t message[64];
  uint8_t encoded[64];
  size_t message_len = 0U;
  size_t encoded_len = 0U;
  wt_writer_t w;
  const wt_tls_extension_t *extension;

  memset(&list, 0, sizeof(list));
  list.count = 2U;
  list.entries[0].type = WT_TLS_EXTENSION_ALPN;
  list.entries[0].data = alpn;
  list.entries[0].len = sizeof(alpn);
  list.entries[1].type = WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS;
  list.entries[1].data = transport_parameters;
  list.entries[1].len = sizeof(transport_parameters);

  WT_EXPECT_OK("EncryptedExtensions builds",
               wt_tls_encrypted_extensions_build(&list, message, sizeof(message), &message_len));
  w = wt_writer_init(encoded, sizeof(encoded));
  WT_EXPECT_OK("the encoder writes the same message",
               wt_tls_encrypted_extensions_encode(&list, &w));
  encoded_len = wt_writer_offset(&w);
  WT_EXPECT_U64("to the same length", (uint64_t)encoded_len, (uint64_t)message_len);
  WT_EXPECT_BYTES("and the same bytes", message, encoded, message_len);

  WT_EXPECT_OK("and it parses back",
               wt_tls_encrypted_extensions_parse(message, message_len, &parsed));
  WT_EXPECT_U64("with both extensions", 2U, (uint64_t)parsed.count);
  extension = wt_tls_extensions_find(&parsed, WT_TLS_EXTENSION_ALPN);
  WT_EXPECT_TRUE("including the ALPN", extension != NULL);
  if (extension != NULL) {
    WT_EXPECT_BYTES("whose body round-trips", alpn, extension->data, sizeof(alpn));
  }
  extension = wt_tls_extensions_find(&parsed, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
  WT_EXPECT_TRUE("and the transport parameters", extension != NULL);
  if (extension != NULL) {
    WT_EXPECT_BYTES("whose body round-trips too", transport_parameters, extension->data,
                    sizeof(transport_parameters));
  }

  WT_EXPECT_STATUS("a NULL extension list is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_tls_encrypted_extensions_build(NULL, message, sizeof(message), &message_len));
  WT_EXPECT_STATUS("a short buffer is refused", WT_ERR_LIMIT,
                   wt_tls_encrypted_extensions_build(&list, message, 4U, &message_len));
  WT_EXPECT_U64("and no length is reported", 0U, (uint64_t)message_len);
}
int main(void) {
  test_extension_refusals();
  test_message_refusals();
  test_certificate_messages();
  test_encrypted_extensions_build();
  WT_TEST_MAIN_END("test_tls13_handshake_messages");
}
