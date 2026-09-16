/* The TLS 1.3 server handshake. See webtransport/tls/session.h. */

#include "webtransport/tls/session.h"

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/crypto/crypto.h"

#include <string.h>

#include "tls_session_internal.h"

/* =============================================================== the server
 *
 * The other half of the same handshake, and deliberately the same shape: the ClientHello is
 * checked for the version, the ciphersuite, a key share this server can use, the ALPN it is
 * willing to speak and the transport parameters QUIC requires; the flight is built in the
 * order the client's checks expect; and the client's Finished gates the application secrets
 * exactly as the server's does on the client. A server that skipped one of those checks would
 * produce a handshake a client refuses, and the mismatch would surface as a tag failure rather
 * than as the missing check.
 */

/* The marker `wt_tls_server_t.live` carries, for the same reason the client has one. */
#define WT_TLS_SERVER_LIVE UINT64_C(0x3c9e51a7b0d4f286)

static void server_scrub(wt_tls_server_t *server) {
  wt_secure_zero(server->handshake_secret, sizeof(server->handshake_secret));
  wt_secure_zero(server->master_secret, sizeof(server->master_secret));
  wt_secure_zero(server->client_handshake_secret, sizeof(server->client_handshake_secret));
  wt_secure_zero(server->server_handshake_secret, sizeof(server->server_handshake_secret));
  wt_secure_zero(server->client_application_secret, sizeof(server->client_application_secret));
  wt_secure_zero(server->server_application_secret, sizeof(server->server_application_secret));
  wt_secure_zero(server->private_key, sizeof(server->private_key));
}

static wt_status_t server_fail(wt_tls_server_t *server, wt_status_t status) {
  wt_tls13_transcript_clear(&server->transcript);
  server_scrub(server);
  server->state = WT_TLS_SERVER_FAILED;
  return status;
}

static wt_status_t server_live(const wt_tls_server_t *server) {
  if (server == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (server->state == WT_TLS_SERVER_FAILED) return WT_ERR_STATE;
  return WT_OK;
}

/* Whether the client offered the ciphersuite this implementation has a schedule for. */
static int offers_cipher_suite(const wt_tls_client_hello_t *hello) {
  size_t i;
  for (i = 0U; i < hello->cipher_suite_count; i++) {
    if (hello->cipher_suites[i] == WT_TLS_CIPHER_SUITE) return 1;
  }
  return 0;
}

/* The client's x25519 key share. RFC 8446 section 4.2.8 allows a client to send shares for
 * several groups; this server can complete one of them, and a client that offered no share it
 * can use would need a HelloRetryRequest to be asked for one -- which this implementation
 * refuses rather than sending. */
static wt_status_t client_x25519_share(const wt_tls_client_hello_t *hello,
                                       wt_tls_key_share_t *out) {
  const wt_tls_extension_t *extension;
  wt_tls_key_share_t shares[WT_TLS_MAX_KEY_SHARES];
  size_t count = 0U;
  size_t i;
  wt_status_t status;

  extension = wt_tls_extensions_find(&hello->extensions, WT_TLS_EXTENSION_KEY_SHARE);
  if (extension == NULL) return WT_ERR_TLS;
  status = wt_tls_key_share_client(extension, shares, WT_TLS_MAX_KEY_SHARES, &count);
  if (status != WT_OK) return status;
  for (i = 0U; i < count; i++) {
    if (shares[i].group == WT_TLS_GROUP_X25519) {
      *out = shares[i];
      return WT_OK;
    }
  }
  return WT_ERR_TLS;
}

/* The ALPN we are willing to speak, and the client's transport parameters when QUIC requires
 * them. Both are views into the client's message, valid until the next call. */
static wt_status_t check_client_extensions(wt_tls_server_t *server,
                                           const wt_tls_client_hello_t *hello) {
  const wt_tls_extension_t *extension;
  wt_status_t status;

  if (server->config.alpn != NULL) {
    wt_tls_alpn_t alpn;
    size_t wanted = strlen(server->config.alpn);
    size_t i;
    int offered = 0;

    extension = wt_tls_extensions_find(&hello->extensions, WT_TLS_EXTENSION_ALPN);
    /* RFC 8446 section 4.2: a server must not select a protocol the client did not offer, and a
     * client that offered none cannot be answered with one. */
    if (extension == NULL) return WT_ERR_TLS;
    status = wt_tls_alpn_parse(extension, &alpn);
    if (status != WT_OK) return status;
    for (i = 0U; i < alpn.count; i++) {
      if ((size_t)alpn.lengths[i] == wanted &&
          memcmp(alpn.names[i], server->config.alpn, wanted) == 0) {
        offered = 1;
        server->negotiated_alpn = alpn.names[i];
        server->negotiated_alpn_len = (size_t)alpn.lengths[i];
      }
    }
    if (!offered) return WT_ERR_TLS;
  }

  if (server->config.require_transport_parameters) {
    const uint8_t *parameters = NULL;
    size_t parameters_len = 0U;
    extension = wt_tls_extensions_find(
        &hello->extensions, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    /* RFC 9001 section 8.2: their absence is a handshake failure, not a peer with none. */
    if (extension == NULL) return WT_ERR_TLS;
    status = wt_tls_transport_parameters(extension, &parameters, &parameters_len);
    if (status != WT_OK) return status;
    if (parameters_len == 0U) return WT_ERR_TLS;
    server->peer_transport_parameters = parameters;
    server->peer_transport_parameters_len = parameters_len;
  }
  return WT_OK;
}

/* The handshake secrets, from the client's key share. The transcript has already absorbed the
 * ClientHello and the ServerHello, because RFC 8446 section 7.1 derives the handshake traffic
 * secrets from the transcript through the ServerHello. */
static wt_status_t server_derive_handshake(wt_tls_server_t *server,
                                           const wt_tls_key_share_t *share) {
  uint8_t early_secret[WT_TLS13_SECRET_LEN];
  uint8_t ecdhe[WT_TLS_X25519_KEY_LEN];
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls_key_share_shared_secret(WT_TLS_GROUP_X25519, server->private_key,
                                         share->key, share->key_len, ecdhe);
  if (status != WT_OK) return status;
  status = wt_tls13_early_secret(NULL, 0U, early_secret);
  if (status != WT_OK) {
    wt_secure_zero(ecdhe, sizeof(ecdhe));
    return status;
  }
  status = wt_tls13_handshake_secret(early_secret, ecdhe, sizeof(ecdhe),
                                     server->handshake_secret);
  wt_secure_zero(early_secret, sizeof(early_secret));
  wt_secure_zero(ecdhe, sizeof(ecdhe));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_handshake_traffic_secrets(
      server->handshake_secret, transcript_hash, server->client_handshake_secret,
      server->server_handshake_secret);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  return wt_tls13_master_secret(server->handshake_secret, server->master_secret);
}

/* The two application secrets, from the transcript through the server's Finished. */
static wt_status_t server_derive_application(wt_tls_server_t *server) {
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_application_traffic_secrets(
      server->master_secret, transcript_hash, server->client_application_secret,
      server->server_application_secret);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  return status;
}

/* The EncryptedExtensions' extension list, built from the configuration. The caller supplies
 * the two data buffers the views point into, so nothing outlives the call. */
static wt_status_t server_encrypted_extensions(
    const wt_tls_server_t *server, uint8_t *alpn_buffer, size_t alpn_capacity,
    wt_tls_extension_list_t *out) {
  memset(out, 0, sizeof(*out));
  if (server->config.alpn != NULL) {
    size_t length = strlen(server->config.alpn);
    /* RFC 7301 section 3.1: the extension data is a ProtocolNameList -- a two-byte list length,
     * then a one-byte name length and the name. A server that wrote only the name and its own
     * length would send three bytes where five belong, and the client's parser would refuse the
     * extension: well-formed enough to look like a protocol name, and not one. */
    if (length == 0U || length > alpn_capacity - 3U) return WT_ERR_INVALID_ARGUMENT;
    alpn_buffer[0] = (uint8_t)((1U + length) >> 8);
    alpn_buffer[1] = (uint8_t)((1U + length) & 0xFFU);
    alpn_buffer[2] = (uint8_t)length;
    memcpy(alpn_buffer + 3U, server->config.alpn, length);
    out->entries[out->count].type = WT_TLS_EXTENSION_ALPN;
    out->entries[out->count].data = alpn_buffer;
    out->entries[out->count].len = 3U + length;
    out->count++;
  }
  if (server->config.transport_parameters_len != 0U) {
    out->entries[out->count].type = WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS;
    out->entries[out->count].data = server->config.transport_parameters;
    out->entries[out->count].len = server->config.transport_parameters_len;
    out->count++;
  }
  return WT_OK;
}

static wt_status_t server_receive_client_hello(wt_tls_server_t *server,
                                               const uint8_t *message, size_t len,
                                               uint8_t *out, size_t out_capacity,
                                               size_t *out_len) {
  wt_tls_client_hello_t hello;
  const wt_tls_extension_t *extension;
  wt_tls_key_share_t share;
  wt_tls_server_hello_params_t params;
  wt_tls_key_share_t ours;
  uint16_t versions[WT_TLS_MAX_NAMED_GROUPS];
  size_t version_count = 0U;
  size_t i;
  int offers_13 = 0;
  wt_status_t status;

  status = wt_tls_client_hello_parse(message, len, &hello);
  if (status != WT_OK) return status;
  if (!offers_cipher_suite(&hello)) return WT_ERR_TLS;
  /* RFC 8446 section 4.2.1: a TLS 1.3 client says 0x0303 in legacy_version and offers 1.3 in
   * supported_versions, so the extension is the only place the version is really negotiated. */
  extension = wt_tls_extensions_find(&hello.extensions,
                                     WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  if (extension == NULL) return WT_ERR_TLS;
  status = wt_tls_supported_versions_client(extension, versions,
                                            WT_TLS_MAX_NAMED_GROUPS, &version_count);
  if (status != WT_OK) return status;
  for (i = 0U; i < version_count; i++) {
    if (versions[i] == WT_TLS_VERSION_1_3) offers_13 = 1;
  }
  if (!offers_13) return WT_ERR_TLS;
  status = client_x25519_share(&hello, &share);
  if (status != WT_OK) return status;
  status = check_client_extensions(server, &hello);
  if (status != WT_OK) return status;

  /* Our own key pair: supplied by the caller, or generated for this handshake. */
  if (server->config.x25519_private != NULL) {
    memcpy(server->private_key, server->config.x25519_private, WT_TLS_X25519_KEY_LEN);
    status = wt_tls_key_share_public_key(WT_TLS_GROUP_X25519, server->private_key,
                                         server->public_key);
  } else {
    status = wt_tls_key_share_generate(WT_TLS_GROUP_X25519, server->private_key,
                                       server->public_key);
  }
  if (status != WT_OK) return status;

  /* The session id is echoed, which is how the client knows this ServerHello answers its
   * ClientHello (RFC 8446 section 4.1.3). */
  memcpy(server->session_id, hello.session_id, hello.session_id_len);
  server->session_id_len = hello.session_id_len;

  ours.group = WT_TLS_GROUP_X25519;
  ours.key = server->public_key;
  ours.key_len = sizeof(server->public_key);
  memset(&params, 0, sizeof(params));
  params.random = server->server_random;
  params.session_id = server->session_id;
  params.session_id_len = server->session_id_len;
  params.cipher_suite = WT_TLS_CIPHER_SUITE;
  params.supported_version = WT_TLS_VERSION_1_3;
  params.key_share = &ours;
  status = wt_tls_server_hello_build(&params, out, out_capacity, out_len);
  if (status != WT_OK) return status;

  /* Both messages are absorbed before the secrets are derived, because the handshake traffic
   * secrets are over the transcript through the ServerHello. */
  status = wt_tls13_transcript_append(&server->transcript, message, len);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&server->transcript, out, *out_len);
  if (status != WT_OK) return status;
  status = server_derive_handshake(server, &share);
  if (status != WT_OK) return status;
  server->state = WT_TLS_SERVER_WAIT_CLIENT_FINISHED;
  return WT_OK;
}

static wt_status_t server_receive_finished(wt_tls_server_t *server,
                                           const uint8_t *message, size_t len) {
  uint8_t verify_data[WT_TLS13_FINISHED_LEN];
  uint8_t through_server_finished[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls_finished_parse(message, len, verify_data);
  if (status != WT_OK) return status;
  /* The client's Finished is over the transcript through the server's Finished, which is what
   * the transcript holds now: the flight has been absorbed and this message has not. */
  status = wt_tls13_transcript_hash(&server->transcript, through_server_finished);
  if (status != WT_OK) return status;
  status = wt_tls13_finished_check(server->client_handshake_secret,
                                   through_server_finished, verify_data,
                                   sizeof(verify_data));
  wt_secure_zero(through_server_finished, sizeof(through_server_finished));
  if (status != WT_OK) return status;
  /* The application secrets come from the transcript through the server's Finished, which is
   * still the current state: the client's Finished is not part of them. */
  status = server_derive_application(server);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&server->transcript, message, len);
  if (status != WT_OK) return status;
  server->state = WT_TLS_SERVER_CONNECTED;
  return WT_OK;
}

wt_status_t wt_tls_server_begin(wt_tls_server_t *server,
                                const wt_tls_server_config_t *config) {
  wt_status_t status;

  if (server == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (config->identity == NULL || config->identity->certificate_count == 0U ||
      config->identity->certificate_count > WT_TLS_CERTIFICATE_MAX_ENTRIES) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->identity->private_key == NULL || config->identity->private_key_len == 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->transport_parameters == NULL && config->transport_parameters_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* Anything a previous handshake left is released first, exactly as on the client. */
  if (server->live == WT_TLS_SERVER_LIVE) {
    wt_tls13_transcript_clear(&server->transcript);
  }
  memset(server, 0, sizeof(*server));
  server->config = *config;
  status = wt_random_bytes(server->server_random, sizeof(server->server_random));
  if (status != WT_OK) {
    server->state = WT_TLS_SERVER_FAILED;
    return status;
  }
  status = wt_tls13_transcript_init(&server->transcript);
  if (status != WT_OK) {
    server->state = WT_TLS_SERVER_FAILED;
    return status;
  }
  server->live = WT_TLS_SERVER_LIVE;
  server->state = WT_TLS_SERVER_WAIT_CLIENT_HELLO;
  return WT_OK;
}

wt_status_t wt_tls_server_flight(wt_tls_server_t *server, uint8_t *out,
                                 size_t out_capacity, size_t *out_len) {
  const wt_tls_server_identity_t *identity;
  wt_tls_extension_list_t encrypted;
  /* A ProtocolNameList for one name: two bytes of list length, one of name length, the name. */
  uint8_t alpn_buffer[WT_TLS_MAX_PROTOCOL_NAME + 3U];
  uint8_t content[WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN];
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  uint8_t signature[1024];
  uint8_t verify_data[WT_TLS13_FINISHED_LEN];
  uint8_t finished[WT_TLS13_FINISHED_LEN + WT_TLS_HANDSHAKE_HEADER_LEN];
  size_t signature_len = 0U;
  size_t finished_len = 0U;
  size_t mark;
  wt_writer_t w;
  wt_status_t status;

  if (server == NULL || out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  status = server_live(server);
  if (status != WT_OK) return status;
  if (server->state != WT_TLS_SERVER_WAIT_CLIENT_FINISHED) return WT_ERR_STATE;
  /* Once: RSA-PSS signatures are randomised, so a second flight would not match the transcript
   * the first one signed. QUIC retransmits CRYPTO data from its own buffer. */
  if (server->flight_built) return WT_ERR_STATE;
  identity = server->config.identity;

  w = wt_writer_init(out, out_capacity);

  /* EncryptedExtensions. Absorbed as soon as it is written, because the CertificateVerify's
   * signature is over the transcript that includes it. */
  status = server_encrypted_extensions(server, alpn_buffer, sizeof(alpn_buffer),
                                       &encrypted);
  if (status != WT_OK) return status;
  status = wt_tls_encrypted_extensions_encode(&encrypted, &w);
  if (status != WT_OK) return status;
  mark = 0U;
  status = wt_tls13_transcript_append(&server->transcript, out,
                                      wt_writer_offset(&w) - mark);
  if (status != WT_OK) return status;

  /* Certificate. */
  {
    wt_tls_certificate_t certificate;
    size_t i;
    memset(&certificate, 0, sizeof(certificate));
    certificate.count = identity->certificate_count;
    for (i = 0U; i < identity->certificate_count; i++) {
      certificate.entries[i].der = identity->certificate[i];
      certificate.entries[i].der_len = identity->certificate_len[i];
    }
    mark = wt_writer_offset(&w);
    status = wt_tls_certificate_encode(&certificate, &w);
    if (status != WT_OK) return status;
    status = wt_tls13_transcript_append(&server->transcript, out + mark,
                                        wt_writer_offset(&w) - mark);
    if (status != WT_OK) return status;
  }

  /* CertificateVerify: the signature is over the transcript through the Certificate. */
  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls_certificate_verify_content(1, transcript_hash, content);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  status = wt_tls_signature_sign(identity->private_key, identity->private_key_len,
                                 identity->signature_scheme, content, sizeof(content),
                                 signature, sizeof(signature), &signature_len);
  wt_secure_zero(content, sizeof(content));
  if (status != WT_OK) return status;
  {
    wt_tls_certificate_verify_t certificate_verify;
    certificate_verify.scheme = identity->signature_scheme;
    certificate_verify.signature = signature;
    certificate_verify.signature_len = signature_len;
    mark = wt_writer_offset(&w);
    status = wt_tls_certificate_verify_encode(&certificate_verify, &w);
  }
  wt_secure_zero(signature, sizeof(signature));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&server->transcript, out + mark,
                                      wt_writer_offset(&w) - mark);
  if (status != WT_OK) return status;

  /* Finished: over the transcript through the CertificateVerify this flight just wrote. */
  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_finished_verify_data(server->server_handshake_secret, transcript_hash,
                                         verify_data);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  status = wt_tls_finished_build(verify_data, finished, sizeof(finished), &finished_len);
  wt_secure_zero(verify_data, sizeof(verify_data));
  if (status != WT_OK) return status;
  wt_writer_bytes(&w, finished, finished_len);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;
  status = wt_tls13_transcript_append(&server->transcript, finished, finished_len);
  if (status != WT_OK) return status;

  server->flight_built = 1;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

wt_status_t wt_tls_server_receive(wt_tls_server_t *server, const uint8_t *message,
                                  size_t len, uint8_t *out, size_t out_capacity,
                                  size_t *out_len) {
  wt_tls_handshake_header_t header;
  wt_cursor_t cursor;
  wt_status_t status;

  if (out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  status = server_live(server);
  if (status != WT_OK) return status;
  if (message == NULL || len < WT_TLS_HANDSHAKE_HEADER_LEN) {
    return server_fail(server, WT_ERR_TRUNCATED);
  }
  cursor = wt_cursor_init(message, len);
  status = wt_tls_handshake_header_parse(&cursor, &header);
  if (status != WT_OK) return server_fail(server, status);

  switch (server->state) {
    case WT_TLS_SERVER_WAIT_CLIENT_HELLO:
      if (header.type != WT_TLS_HANDSHAKE_CLIENT_HELLO) {
        return server_fail(server, WT_ERR_STATE);
      }
      status = server_receive_client_hello(server, message, len, out, out_capacity,
                                           out_len);
      break;
    case WT_TLS_SERVER_WAIT_CLIENT_FINISHED:
      if (header.type != WT_TLS_HANDSHAKE_FINISHED) {
        return server_fail(server, WT_ERR_STATE);
      }
      status = server_receive_finished(server, message, len);
      break;
    case WT_TLS_SERVER_START:
    case WT_TLS_SERVER_CONNECTED:
    case WT_TLS_SERVER_FAILED:
    default:
      return server_fail(server, WT_ERR_STATE);
  }
  if (status != WT_OK) return server_fail(server, status);
  return WT_OK;
}

wt_tls_server_state_t wt_tls_server_state(const wt_tls_server_t *server) {
  return (server == NULL) ? WT_TLS_SERVER_FAILED : server->state;
}

wt_status_t wt_tls_server_handshake_secrets(const wt_tls_server_t *server,
                                            uint8_t read_out[WT_TLS13_SECRET_LEN],
                                            uint8_t write_out[WT_TLS13_SECRET_LEN]) {
  if (server == NULL || read_out == NULL || write_out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (server->state != WT_TLS_SERVER_WAIT_CLIENT_FINISHED &&
      server->state != WT_TLS_SERVER_CONNECTED) {
    return WT_ERR_STATE;
  }
  memcpy(read_out, server->client_handshake_secret, WT_TLS13_SECRET_LEN);
  memcpy(write_out, server->server_handshake_secret, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

wt_status_t wt_tls_server_application_secrets(
    const wt_tls_server_t *server, uint8_t read_out[WT_TLS13_SECRET_LEN],
    uint8_t write_out[WT_TLS13_SECRET_LEN]) {
  if (server == NULL || read_out == NULL || write_out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (server->state != WT_TLS_SERVER_CONNECTED) return WT_ERR_STATE;
  memcpy(read_out, server->client_application_secret, WT_TLS13_SECRET_LEN);
  memcpy(write_out, server->server_application_secret, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

const uint8_t *wt_tls_server_alpn(const wt_tls_server_t *server, size_t *out_len) {
  if (server == NULL || out_len == NULL) return NULL;
  *out_len = server->negotiated_alpn_len;
  return server->negotiated_alpn;
}

const uint8_t *wt_tls_server_transport_parameters(const wt_tls_server_t *server,
                                                  size_t *out_len) {
  if (server == NULL || out_len == NULL) return NULL;
  *out_len = server->peer_transport_parameters_len;
  return server->peer_transport_parameters;
}

void wt_tls_server_clear(wt_tls_server_t *server) {
  if (server == NULL) return;
  wt_tls13_transcript_clear(&server->transcript);
  wt_secure_zero(server, sizeof(*server));
}
