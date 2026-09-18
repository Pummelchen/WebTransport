/* TLS 1.3 handshake messages. See webtransport/tls/handshake.h. */

#include "webtransport/tls/handshake.h"

#include <string.h>

#include "handshake_internal.h"

/* ==================================== Certificate, CertificateVerify, Finished
 *
 * The three messages whose bodies are a certificate chain, a signature and a verify
 * value. Each is written by one body function, measured and then written, exactly like
 * the Hellos above. Nothing here looks inside a certificate or a signature: framing is
 * this layer's question, trust is the layer above.
 */

static void certificate_body(const wt_tls_certificate_t *certificate, wt_writer_t *w) {
  size_t i;
  size_t list_len = 0U;

  for (i = 0U; i < certificate->count; i++) {
    list_len += 3U + certificate->entries[i].der_len + 2U + certificate->entries[i].extensions_len;
  }
  wt_writer_u8(w, (uint8_t)certificate->request_context_len);
  wt_writer_bytes(w, certificate->request_context, certificate->request_context_len);
  wt_writer_u24(w, (uint32_t)list_len);
  for (i = 0U; i < certificate->count; i++) {
    const wt_tls_certificate_entry_t *entry = &certificate->entries[i];
    wt_writer_u24(w, (uint32_t)entry->der_len);
    wt_writer_bytes(w, entry->der, entry->der_len);
    wt_writer_u16(w, (uint16_t)entry->extensions_len);
    wt_writer_bytes(w, entry->extensions, entry->extensions_len);
  }
}

static void certificate_verify_body(const wt_tls_certificate_verify_t *certificate_verify,
                                    wt_writer_t *w) {
  wt_writer_u16(w, certificate_verify->scheme);
  wt_writer_u16(w, (uint16_t)certificate_verify->signature_len);
  wt_writer_bytes(w, certificate_verify->signature, certificate_verify->signature_len);
}

/* The same measure-then-write shape every encoder here uses. `body` writes the body and
 * returns the status the values themselves deserve; the framing checks only need to
 * happen once, before the measuring pass. */
static wt_status_t frame_and_write(const void *structure, void (*body)(const void *, wt_writer_t *),
                                   uint8_t type, wt_writer_t *w) {
  wt_writer_t measure;
  size_t body_len;

  if (structure == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  measure = wt_writer_measure();
  body(structure, &measure);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  if (wt_tls_handshake_header_encode(w, type, body_len) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  body(structure, w);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

static void certificate_body_thunk(const void *structure, wt_writer_t *w) {
  certificate_body((const wt_tls_certificate_t *)structure, w);
}

static void certificate_verify_body_thunk(const void *structure, wt_writer_t *w) {
  certificate_verify_body((const wt_tls_certificate_verify_t *)structure, w);
}

/* The framing this layer refuses before anything is written: a count or a length that
 * cannot be expressed in the field that will hold it. */
static wt_status_t certificate_check(const wt_tls_certificate_t *certificate) {
  size_t i;
  size_t list_len = 0U;

  if (certificate->request_context == NULL && certificate->request_context_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* RFC 8446 section 4.4.2: the context is 0..255 bytes, one length octet. */
  if (certificate->request_context_len > 255U) return WT_ERR_LIMIT;
  if (certificate->count > WT_TLS_CERTIFICATE_MAX_ENTRIES) return WT_ERR_LIMIT;
  for (i = 0U; i < certificate->count; i++) {
    const wt_tls_certificate_entry_t *entry = &certificate->entries[i];
    if (entry->der == NULL || entry->der_len == 0U) {
      /* An entry with no certificate is not an empty certificate: RFC 8446 section 4.4.2
       * frames each one as a three-octet length, and zero is a malformed entry rather
       * than a chain with a hole in it. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    if (entry->der_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
    if (entry->extensions == NULL && entry->extensions_len != 0U) {
      return WT_ERR_INVALID_ARGUMENT;
    }
    if (entry->extensions_len > 0xFFFFU) return WT_ERR_LIMIT;
    list_len += 3U + entry->der_len + 2U + entry->extensions_len;
  }
  if (list_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  return WT_OK;
}

wt_status_t wt_tls_certificate_encode(const wt_tls_certificate_t *certificate, wt_writer_t *w) {
  wt_status_t status;
  if (certificate == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = certificate_check(certificate);
  if (status != WT_OK) return status;
  return frame_and_write(certificate, certificate_body_thunk, WT_TLS_HANDSHAKE_CERTIFICATE, w);
}

wt_status_t wt_tls_certificate_build(const wt_tls_certificate_params_t *params, uint8_t *out,
                                     size_t capacity, size_t *out_len) {
  wt_tls_certificate_t certificate;

  if (params == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (params->entries == NULL && params->count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->count > WT_TLS_CERTIFICATE_MAX_ENTRIES) return WT_ERR_LIMIT;

  memset(&certificate, 0, sizeof(certificate));
  certificate.request_context = params->request_context;
  certificate.request_context_len = params->request_context_len;
  certificate.count = params->count;
  /* An empty certificate list is legal, so the copy is guarded: that is what keeps
   * a NULL with a zero count away from `memcpy`'s nonnull parameters. */
  if (params->count != 0U) {
    memcpy(certificate.entries, params->entries, params->count * sizeof(certificate.entries[0]));
  }

  {
    wt_writer_t w = wt_writer_init(out, capacity);
    wt_status_t status = wt_tls_certificate_encode(&certificate, &w);
    if (status != WT_OK) {
      memset(out, 0, capacity < 64U ? capacity : 64U);
      return status;
    }
    *out_len = wt_writer_offset(&w);
  }
  return WT_OK;
}

wt_status_t wt_tls_certificate_verify_encode(const wt_tls_certificate_verify_t *certificate_verify,
                                             wt_writer_t *w) {
  if (certificate_verify == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (certificate_verify->signature == NULL && certificate_verify->signature_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* RFC 8446 section 4.4.3: the signature is 0..2^16-1 bytes. Zero is legal for an
   * algorithm with an empty signature, and the trust layer is what refuses a scheme it
   * does not implement. */
  if (certificate_verify->signature_len > 0xFFFFU) return WT_ERR_LIMIT;
  return frame_and_write(certificate_verify, certificate_verify_body_thunk,
                         WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY, w);
}

wt_status_t wt_tls_certificate_verify_build(uint16_t scheme, const uint8_t *signature,
                                            size_t signature_len, uint8_t *out, size_t capacity,
                                            size_t *out_len) {
  wt_tls_certificate_verify_t certificate_verify;
  wt_writer_t w;
  wt_status_t status;

  if (out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  if (signature == NULL && signature_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  certificate_verify.scheme = scheme;
  certificate_verify.signature = signature;
  certificate_verify.signature_len = signature_len;
  w = wt_writer_init(out, capacity);
  status = wt_tls_certificate_verify_encode(&certificate_verify, &w);
  if (status != WT_OK) return status;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

wt_status_t wt_tls_finished_build(const uint8_t verify_data[WT_TLS13_FINISHED_LEN], uint8_t *out,
                                  size_t capacity, size_t *out_len) {
  wt_writer_t w;

  if (verify_data == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (capacity < WT_TLS13_FINISHED_LEN + WT_TLS_HANDSHAKE_HEADER_LEN) {
    return WT_ERR_LIMIT;
  }
  w = wt_writer_init(out, capacity);
  if (wt_tls_handshake_header_encode(&w, WT_TLS_HANDSHAKE_FINISHED, WT_TLS13_FINISHED_LEN) !=
      WT_OK) {
    return WT_ERR_LIMIT;
  }
  wt_writer_bytes(&w, verify_data, WT_TLS13_FINISHED_LEN);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

/* ------------------------------------------------------------------ parsing */

wt_status_t wt_tls_certificate_parse(const uint8_t *message, size_t len,
                                     wt_tls_certificate_t *out) {
  wt_cursor_t body;
  uint8_t context_len;
  uint32_t list_len;
  wt_cursor_t entries;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_CERTIFICATE, &body);
  if (status != WT_OK) return status;
  context_len = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  out->request_context = wt_cursor_bytes(&body, (size_t)context_len);
  if (out->request_context == NULL) return WT_ERR_PROTOCOL;
  out->request_context_len = (size_t)context_len;
  list_len = wt_cursor_u24(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  {
    wt_status_t region = sub_cursor(&body, (size_t)list_len, &entries);
    if (region != WT_OK) return region;
  }

  while (!wt_cursor_at_end(&entries)) {
    uint32_t der_len;
    uint16_t extensions_len;
    wt_tls_certificate_entry_t *entry;

    if (out->count == WT_TLS_CERTIFICATE_MAX_ENTRIES) return WT_ERR_LIMIT;
    entry = &out->entries[out->count];
    der_len = wt_cursor_u24(&entries);
    if (wt_cursor_failed(&entries)) return WT_ERR_PROTOCOL;
    if (der_len == 0U) return WT_ERR_PROTOCOL;
    entry->der = wt_cursor_bytes(&entries, (size_t)der_len);
    if (entry->der == NULL) return WT_ERR_PROTOCOL;
    entry->der_len = (size_t)der_len;
    extensions_len = wt_cursor_u16(&entries);
    if (wt_cursor_failed(&entries)) return WT_ERR_PROTOCOL;
    entry->extensions = wt_cursor_bytes(&entries, (size_t)extensions_len);
    if (entry->extensions == NULL) return WT_ERR_PROTOCOL;
    entry->extensions_len = (size_t)extensions_len;
    out->count++;
  }
  /* The body ends where the entry list does. */
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_certificate_verify_parse(const uint8_t *message, size_t len,
                                            wt_tls_certificate_verify_t *out) {
  wt_cursor_t body;
  uint16_t signature_len;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY, &body);
  if (status != WT_OK) return status;
  out->scheme = wt_cursor_u16(&body);
  signature_len = wt_cursor_u16(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  out->signature = wt_cursor_bytes(&body, (size_t)signature_len);
  if (out->signature == NULL) return WT_ERR_PROTOCOL;
  out->signature_len = (size_t)signature_len;
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_finished_parse(const uint8_t *message, size_t len,
                                  uint8_t out[WT_TLS13_FINISHED_LEN]) {
  wt_cursor_t body;
  const uint8_t *verify_data;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = message_body(message, len, WT_TLS_HANDSHAKE_FINISHED, &body);
  if (status != WT_OK) return status;
  /* RFC 8446 section 4.4.4: the body is exactly Hash.length bytes. A longer one is not a
   * Finished with extra data, it is a different message. */
  if (body.len != WT_TLS13_FINISHED_LEN) return WT_ERR_PROTOCOL;
  verify_data = wt_cursor_bytes(&body, WT_TLS13_FINISHED_LEN);
  if (verify_data == NULL) return WT_ERR_PROTOCOL;
  memcpy(out, verify_data, WT_TLS13_FINISHED_LEN);
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_encrypted_extensions_encode(const wt_tls_extension_list_t *extensions,
                                               wt_writer_t *w) {
  wt_writer_t measure;
  size_t body_len;

  if (extensions == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  measure = wt_writer_measure();
  (void)wt_tls_extensions_encode(&measure, extensions);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  if (wt_tls_handshake_header_encode(w, WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, body_len) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  if (wt_tls_extensions_encode(w, extensions) != WT_OK) return WT_ERR_LIMIT;
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_tls_encrypted_extensions_build(const wt_tls_extension_list_t *extensions,
                                              uint8_t *out, size_t capacity, size_t *out_len) {
  wt_writer_t w;
  wt_status_t status;

  if (extensions == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  w = wt_writer_init(out, capacity);
  status = wt_tls_encrypted_extensions_encode(extensions, &w);
  if (status != WT_OK) return status;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

wt_status_t wt_tls_encrypted_extensions_parse(const uint8_t *message, size_t len,
                                              wt_tls_extension_list_t *out) {
  wt_cursor_t body;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, &body);
  if (status != WT_OK) return status;
  status = wt_tls_extensions_parse(&body, out);
  if (status != WT_OK) return status;
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}
