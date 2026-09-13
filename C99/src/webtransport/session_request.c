/* The WebTransport session request (draft-ietf-webtrans-http3-16 section 3.1). */

#include "webtransport/webtransport/session_request.h"

#include <string.h>

static int token_is(const uint8_t *bytes, size_t length, const char *text) {
  size_t text_length = strlen(text);
  return length == text_length && memcmp(bytes, text, text_length) == 0;
}

wt_status_t wt_webtransport_session_request_validate(
    const wt_http3_message_t *message, const wt_webtransport_request_policy_t *policy,
    wt_webtransport_session_request_t *out, wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (message == NULL || policy == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;

  memset(out, 0, sizeof(*out));
  out->status = WT_WEBTRANSPORT_REJECT_NOT_FOUND;

  /* Not a request, or not a CONNECT: not this layer's business. An ordinary GET is a
   * perfectly good request that simply is not a session. */
  if (message->type != WT_HTTP3_HEADER_REQUEST || message->method_length != 7U ||
      memcmp(message->method, "CONNECT", 7U) != 0) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT;
    return WT_OK;
  }

  /* A CONNECT with no :protocol is RFC 9114's plain CONNECT -- a tunnel, not a
   * session -- and a :protocol naming something else belongs to whoever defined it. */
  if (message->protocol_length == 0U ||
      !token_is(message->protocol, message->protocol_length, WT_WEBTRANSPORT_PROTOCOL_TOKEN)) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT;
    return WT_OK;
  }

  /* It IS a WebTransport request, so from here the draft applies. An extended CONNECT
   * carries :scheme, :authority and :path; the message decoder required only the
   * authority, because that is all a plain CONNECT requires. */
  if (message->scheme_length == 0U || message->authority_length == 0U ||
      message->path_length == 0U) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    out->status = WT_WEBTRANSPORT_REJECT_NOT_FOUND;
    return WT_OK;
  }

  /* A server that did not advertise WT_ENABLED must not accept a session: the client
   * could not have known this endpoint serves WebTransport, and accepting anyway would
   * make the setting meaningless. */
  if (!policy->wt_enabled) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    out->status = WT_WEBTRANSPORT_REJECT_NOT_IMPLEMENTED;
    return WT_OK;
  }

  if (!token_is(message->authority, message->authority_length, policy->authority) ||
      !token_is(message->path, message->path_length, policy->path)) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    out->status = WT_WEBTRANSPORT_REJECT_NOT_FOUND;
    return WT_OK;
  }

  out->outcome = WT_WEBTRANSPORT_REQUEST_ACCEPT;
  out->authority = message->authority;
  out->authority_length = message->authority_length;
  out->path = message->path;
  out->path_length = message->path_length;
  return WT_OK;
}

wt_status_t wt_webtransport_session_request_negotiate(wt_webtransport_session_request_t *decision,
                                                      const wt_webtransport_protocol_list_t *offered,
                                                      const wt_webtransport_protocol_list_t *supported,
                                                      int require_selection) {
  wt_webtransport_protocol_token_t selected;
  wt_status_t status;

  if (decision == NULL || offered == NULL || supported == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Both lists come from the wire or from a configuration, so both are validated here: a caller that decoded
   * a field section and forgot to check it must not be able to negotiate with nonsense. */
  status = wt_webtransport_protocol_validate(offered);
  if (status != WT_OK) return status;
  status = wt_webtransport_protocol_validate(supported);
  if (status != WT_OK) return status;

  /* A request this server has already refused is not negotiated with: its answer is the refusal, and changing
   * it here would give the caller two different answers to send. */
  if (decision->outcome != WT_WEBTRANSPORT_REQUEST_ACCEPT) return WT_OK;

  if (wt_webtransport_protocol_select(offered, supported, &selected) != 0) {
    decision->selected_protocol = selected.bytes;
    decision->selected_protocol_length = selected.length;
    return WT_OK;
  }

  if (require_selection) {
    decision->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    decision->status = WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED;
    decision->selected_protocol = NULL;
    decision->selected_protocol_length = 0U;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_session_response_selected_protocol(
    const uint8_t *value, size_t length, const wt_webtransport_protocol_list_t *offered,
    wt_webtransport_protocol_token_t *out) {
  wt_webtransport_protocol_token_t selected;
  size_t index;
  wt_status_t status;

  if (offered == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_webtransport_protocol_decode_item(value, length, &selected);
  if (status != WT_OK) return status;
  for (index = 0U; index < offered->count; index++) {
    if (offered->tokens[index].length == selected.length &&
        memcmp(offered->tokens[index].bytes, selected.bytes, selected.length) == 0) {
      *out = selected;
      return WT_OK;
    }
  }
  /* The server named a sub-protocol this client never offered. Accepting it would leave the two ends speaking
   * different protocols, which is the failure the negotiation exists to prevent. */
  out->bytes = NULL;
  out->length = 0U;
  return WT_ERR_PROTOCOL;
}
