/* WebTransport capsules (draft-ietf-webtrans-http3-16 section 5). */

#include "webtransport/webtransport/capsule.h"

#include "webtransport/quic/varint.h"

wt_status_t wt_webtransport_capsule_decode(wt_cursor_t *c, size_t max_length,
                                           wt_webtransport_capsule_t *out,
                                           wt_http3_error_t *out_error) {
  uint64_t type;
  uint64_t length;
  const uint8_t *value;
  size_t before;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (c == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;

  before = wt_cursor_remaining(c);
  if (wt_quic_varint_decode(c, &type) != WT_OK) {
    /* Not even the type is here: the capsule has not arrived, which is ordinary on a
     * stream (RFC 9297 section 3.2's receivers buffer). */
    return WT_ERR_TRUNCATED;
  }
  if (wt_quic_varint_decode(c, &length) != WT_OK) return WT_ERR_TRUNCATED;

  /* The length is the peer's to choose and this endpoint's to bound: a capsule longer
   * than the caller will buffer is refused rather than allocated for. */
  if (length > (uint64_t)max_length) {
    if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
    return WT_ERR_LIMIT;
  }
  value = wt_cursor_bytes(c, (size_t)length);
  if (value == NULL && length != 0U) return WT_ERR_TRUNCATED;

  out->type = type;
  out->value = value;
  out->value_length = (size_t)length;
  out->bytes_consumed = before - wt_cursor_remaining(c);
  return WT_OK;
}

wt_status_t wt_webtransport_capsule_encode(wt_writer_t *w, const wt_webtransport_capsule_t *capsule) {
  if (w == NULL || capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->value == NULL && capsule->value_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  if ((uint64_t)capsule->value_length > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;

  (void)wt_quic_writer_varint(w, capsule->type);
  (void)wt_quic_writer_varint(w, (uint64_t)capsule->value_length);
  if (capsule->value_length != 0U) wt_writer_bytes(w, capsule->value, capsule->value_length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_close_session_write(wt_writer_t *w, uint32_t error_code,
                                                const uint8_t *reason, size_t reason_length) {
  uint8_t code[4];

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (reason == NULL && reason_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* Section 5.4's ceiling, enforced at the writer so this build cannot send a capsule
   * its own reader would refuse. */
  if (reason_length > (size_t)WT_CAPSULE_CLOSE_MAX_REASON) return WT_ERR_LIMIT;

  /* The value is the four-byte code followed by the reason, so the length covers both
   * and the code is written big-endian (section 5.4 fixes the order). */
  code[0] = (uint8_t)(error_code >> 24);
  code[1] = (uint8_t)((error_code >> 16) & 0xffU);
  code[2] = (uint8_t)((error_code >> 8) & 0xffU);
  code[3] = (uint8_t)(error_code & 0xffU);

  (void)wt_quic_writer_varint(w, WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION);
  (void)wt_quic_writer_varint(w, (uint64_t)4U + (uint64_t)reason_length);
  wt_writer_bytes(w, code, sizeof(code));
  if (reason_length != 0U) wt_writer_bytes(w, reason, reason_length);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_close_session_parse(const wt_webtransport_capsule_t *capsule,
                                                uint32_t *out_error_code, const uint8_t **out_reason,
                                                size_t *out_reason_length,
                                                wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (capsule == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (capsule->type != WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The four-byte code is mandatory, so a shorter value is a malformed capsule rather
   * than one with nothing to say. */
  if (capsule->value_length < 4U) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (capsule->value_length - 4U > (size_t)WT_CAPSULE_CLOSE_MAX_REASON) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (out_error_code != NULL) {
    *out_error_code = ((uint32_t)capsule->value[0] << 24) | ((uint32_t)capsule->value[1] << 16) |
                      ((uint32_t)capsule->value[2] << 8) | (uint32_t)capsule->value[3];
  }
  if (out_reason != NULL) *out_reason = capsule->value + 4U;
  if (out_reason_length != NULL) *out_reason_length = capsule->value_length - 4U;
  return WT_OK;
}

wt_status_t wt_webtransport_drain_session_write(wt_writer_t *w) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  (void)wt_quic_writer_varint(w, WT_CAPSULE_DRAIN_SESSION);
  (void)wt_quic_writer_varint(w, 0U);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}
