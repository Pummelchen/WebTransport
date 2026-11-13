/* The WebTransport session request (draft-ietf-webtrans-http3-17 section 3.1). */

#include "webtransport/webtransport/session_request.h"

#include <string.h>

static int token_is(const uint8_t *bytes, size_t length, const char *text) {
  size_t text_length = strlen(text);
  return length == text_length && memcmp(bytes, text, text_length) == 0;
}

/* Whether `bytes` is `https`, compared the way a URI scheme is: RFC 3986 section 3.1 makes schemes
 * case-insensitive, so `HTTPS`, `Https` and `https` are the same scheme and the same target resource. */
static int scheme_is_https(const uint8_t *bytes, size_t length) {
  static const char k_https[] = "https";
  size_t i;

  if (length != 5U) return 0;
  for (i = 0U; i < length; i++) {
    uint8_t lower = bytes[i];
    if (lower >= (uint8_t)'A' && lower <= (uint8_t)'Z') lower = (uint8_t)(lower + 32U);
    if (lower != (uint8_t)k_https[i]) return 0;
  }
  return 1;
}

const char *wt_webtransport_upgrade_token_value(wt_webtransport_upgrade_token_t token) {
  /* The two selections are the only two strings, and the default is the draft-16 token: a value that is not the
   * legacy one -- including an out-of-range int a caller cast -- sends the current token rather than a NULL. */
  return token == WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY ? WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY
                                                       : WT_WEBTRANSPORT_PROTOCOL_TOKEN;
}

/* Whether a request's `:authority` names the host this server serves.
 *
 * RFC 9114 section 4.3.1 makes `:authority` the authority of the target URI, and an authority carries the port
 * whenever it is not the scheme's default -- `localhost:54070`, `[::1]:8443`. The policy names a HOST, because
 * that is what a server can know about itself; comparing the whole authority refused every real client that named
 * the port it was actually talking to, which is every real client (WT-153). A NULL or empty policy means this
 * server serves any authority, which is the honest default for a listener: the transport has already proved the
 * client reached this port.
 *
 * The port is found from the END, and only outside a bracketed IPv6 literal, because `::1` is full of colons that
 * are not port separators. */
static int authority_matches(const uint8_t *bytes, size_t length, const char *expected) {
  size_t host_length = length;
  size_t i;
  size_t bracket = 0U;
  int has_bracket = 0;

  if (expected == NULL || expected[0] == '\0') return 1;
  for (i = length; i > 0U; i--) {
    if (bytes[i - 1U] == ']') {
      bracket = i - 1U;
      has_bracket = 1;
      break;
    }
  }
  for (i = length; i > 0U; i--) {
    if (bytes[i - 1U] == ':') {
      /* A colon after the closing bracket is the port; inside one it is part of the address. */
      if (!has_bracket || (i - 1U) > bracket) host_length = i - 1U;
      break;
    }
  }
  return token_is(bytes, host_length, expected);
}

wt_status_t wt_webtransport_settings_apply(wt_http3_settings_t *settings, int is_server) {
  /* The DUAL profile is the default posture: it is the only one that reaches the draft-16 peers this
   * tree interoperates with, so the long-standing entry point keeps meaning it. */
  return wt_webtransport_settings_apply_profile(settings, is_server, WT_WEBTRANSPORT_PROFILE_DUAL);
}

wt_status_t wt_webtransport_settings_apply_profile(wt_http3_settings_t *settings, int is_server,
                                                   wt_webtransport_version_profile_t profile) {
  wt_status_t status;

  if (settings == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* Section 3.1's list for BOTH roles, and the first is the one this function exists because of: an endpoint
   * that omits SETTINGS_H3_DATAGRAM is not a WebTransport endpoint in the draft's terms, and a peer that checks
   * -- `web-transport`'s `supports_webtransport()` requires it plus a WebTransport setting -- will not accept
   * the session at all (WT-145). */
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U);
  if (status != WT_OK) return status;

  /* The version codepoints of sections 3.1 and 7.1. A server always advertises the codepoint section 9.2
   * registers; an endpoint that also serves a draft version sends that draft's codepoint beside it, one per
   * version (section 7.1). A client of the FINAL profile sends NO SETTINGS_WT_ENABLED at all -- section 3.1's
   * client list carries none -- while a client that also supports draft-16 sends both codepoints so the server
   * can identify which version it will use. */
  if (is_server != 0) {
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
    if (status != WT_OK) return status;
    if (profile != WT_WEBTRANSPORT_PROFILE_FINAL) {
      status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
      if (status != WT_OK) return status;
    }
  } else if (profile != WT_WEBTRANSPORT_PROFILE_FINAL) {
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
    if (status != WT_OK) return status;
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
    if (status != WT_OK) return status;
  }

  /* Section 5.1's three INITIAL flow-control limits, advertised here because this function is where a
   * WebTransport endpoint's SETTINGS are assembled and because an endpoint that wants the session's own flow
   * control has to open the negotiation before a peer may send a grant: an endpoint that omits all three is
   * not doing flow control, and a receiver that did not negotiate it MUST ignore the flow-control capsules
   * (WT-252). The numbers are the limits the tools put in force with
   * `wt_runtime_session_advertise(&session, 100000, 4096, 8, 8)`, and they must stay equal to it:
   * INITIAL_MAX_DATA is the connection-level DATA limit (100000), INITIAL_MAX_STREAMS_BIDI is the number of
   * bidirectional streams (8) and INITIAL_MAX_STREAMS_UNI the number of unidirectional ones (8). The middle
   * value of that runtime call, 4096, is the PER-STREAM data limit: section 5.1 carries no setting for it (it
   * is a QUIC transport parameter, and section 5.4 prohibits the per-stream capsules), so no third number
   * belongs here. A caller that uses this function thereby claims flow control and must put those limits in
   * force with `wt_runtime_session_advertise`. */
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 100000U);
  if (status != WT_OK) return status;
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 8U);
  if (status != WT_OK) return status;
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI, 8U);
  if (status != WT_OK) return status;

  /* The same negotiation for a peer that predates the rename: one codepoint per version, which is what section
   * 7.1 asks of an endpoint that supports several. The value is the number of sessions this endpoint will
   * accept on the connection, and one is what this tree's tools serve. */
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U);
  if (status != WT_OK) return status;
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  if (status != WT_OK) return status;
  if (is_server) {
    /* Only the server sets this half of the pair it replaced: the client sends ENABLE, the server answers with a
     * limit. */
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS_DEPRECATED, 1U);
    if (status != WT_OK) return status;
    /* RFC 9220 section 3: a client may only send `:protocol` once the server has advertised that it handles
     * extended CONNECT, so a server that serves WebTransport at all has to say so (section 3.1's server list). */
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_session_request_validate(const wt_http3_message_t *message,
                                                     const wt_webtransport_request_policy_t *policy,
                                                     wt_webtransport_session_request_t *out,
                                                     wt_http3_error_t *out_error) {
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
  /* BOTH tokens name a WebTransport request. Draft-16 section 3.2 defines `webtransport-h3` and the drafts before
   * it used `webtransport`; refusing either one makes this server unreachable from a conforming peer of the other
   * era -- the Swift implementation and the browsers send the draft-16 token, and four of this tree's five
   * interop peers send the older one. Accepting both is what "interoperable" has to mean at a server. */
  if (message->protocol_length == 0U ||
      !(token_is(message->protocol, message->protocol_length, WT_WEBTRANSPORT_PROTOCOL_TOKEN) ||
        token_is(message->protocol, message->protocol_length,
                 WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY))) {
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

  /* Section 3.2: "The :scheme field MUST be https." A WebTransport session is identified by the https URI
   * scheme, so a request carrying any other scheme names something this endpoint does not serve -- the same
   * rejection a missing scheme gets, not a request that belongs to another protocol. The comparison is
   * case-insensitive because RFC 3986 section 3.1 makes schemes so. */
  if (!scheme_is_https(message->scheme, message->scheme_length)) {
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

  if (!authority_matches(message->authority, message->authority_length, policy->authority) ||
      (policy->path != NULL && policy->path[0] != '\0' &&
       !token_is(message->path, message->path_length, policy->path))) {
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

wt_status_t wt_webtransport_session_request_negotiate(
    wt_webtransport_session_request_t *decision, const wt_webtransport_protocol_list_t *offered,
    const wt_webtransport_protocol_list_t *supported, int require_selection) {
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

wt_status_t
wt_webtransport_session_response_selected_protocol(const uint8_t *value, size_t length,
                                                   const wt_webtransport_protocol_list_t *offered,
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

wt_status_t wt_webtransport_version_select(const wt_http3_settings_t *client_settings,
                                           wt_webtransport_version_t *out_version,
                                           wt_http3_error_t *out_error) {
  int final_present = 0;
  int draft_present = 0;
  int legacy_enable_present = 0;
  int legacy_sessions_present = 0;
  uint64_t draft_value = 0U;
  uint64_t legacy_enable_value = 0U;
  uint64_t legacy_sessions_value = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (client_settings == NULL || out_version == NULL) return WT_ERR_INVALID_ARGUMENT;

  (void)wt_http3_settings_get(client_settings, WT_HTTP3_SETTING_WT_ENABLED, &final_present);
  draft_value =
      wt_http3_settings_get(client_settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, &draft_present);
  legacy_enable_value = wt_http3_settings_get(
      client_settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, &legacy_enable_present);
  legacy_sessions_value = wt_http3_settings_get(client_settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS,
                                                &legacy_sessions_present);

  /* The draft-16 codepoint names its sender a draft-16 client, and a draft client sends the value 1 --
   * the value is how the era's `SETTINGS_WT_ENABLED` said "this endpoint serves WebTransport". A value
   * other than 1 is not a version selection; it is the connection error section 3.1 gives the setting. */
  if (draft_present != 0 && draft_value != 1U) {
    if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
    return WT_ERR_PROTOCOL;
  }
  /* The section 9.2 codepoint selects the final version, and its VALUE is ignored: section 3.1 makes
   * SETTINGS_WT_ENABLED meaningless from a client, and section 7.1's exception is about WHICH codepoints
   * were sent, not about what they carry. */
  if (final_present != 0) {
    *out_version = WT_WEBTRANSPORT_VERSION_FINAL;
    return WT_OK;
  }
  if (draft_present != 0) {
    /* Only a draft-16 client sends only the draft-16 codepoint, so the draft-16 version is selected. */
    *out_version = WT_WEBTRANSPORT_VERSION_DRAFT16;
    return WT_OK;
  }
  if ((legacy_enable_present != 0 && legacy_enable_value == 1U) ||
      (legacy_sessions_present != 0 && legacy_sessions_value == 1U)) {
    /* The earlier drafts' advertisement, and nothing newer: a pre-draft-16 client, which is not a
     * final client -- those send no SETTINGS_WT_ENABLED at all -- and is not a draft-16 client either.
     * The session runs that era's rules; the wt2 server-direction proofs are exactly such clients
     * (pywebtransport, quic-go), measured against the deployed peers on 13 November 2026. */
    *out_version = WT_WEBTRANSPORT_VERSION_LEGACY;
    return WT_OK;
  }
  /* No codepoint at all is a FINAL client: section 3.1's client list carries no SETTINGS_WT_ENABLED,
   * so silence selects the final version rather than refusing the connection. */
  *out_version = WT_WEBTRANSPORT_VERSION_FINAL;
  return WT_OK;
}

wt_status_t wt_webtransport_client_version(const wt_http3_settings_t *server_settings,
                                           wt_webtransport_version_profile_t profile,
                                           wt_webtransport_version_t *out_version,
                                           wt_http3_error_t *out_error) {
  int final_present = 0;
  int draft_present = 0;
  uint64_t final_value = 0U;
  uint64_t draft_value = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (server_settings == NULL || out_version == NULL) return WT_ERR_INVALID_ARGUMENT;

  final_value = wt_http3_settings_get(server_settings, WT_HTTP3_SETTING_WT_ENABLED, &final_present);
  draft_value =
      wt_http3_settings_get(server_settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, &draft_present);

  /* Section 3.1: "Clients MUST treat values greater than 1 as a connection error of type
   * H3_SETTINGS_ERROR." Read before anything else, because a value the client must treat as a
   * connection error is not an advertisement to weigh against the draft codepoint. */
  if (final_present != 0 && final_value > 1U) {
    if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (final_present != 0 && final_value == 1U) {
    /* The final version, preferred over any draft codepoint beside it: the higher version is the one
     * section 7.1 selects. */
    *out_version = WT_WEBTRANSPORT_VERSION_FINAL;
    return WT_OK;
  }
  if (profile != WT_WEBTRANSPORT_PROFILE_FINAL && draft_present != 0 && draft_value == 1U) {
    /* The section 9.2 codepoint was absent, so the draft-16 codepoint is the only advertisement left,
     * and a DUAL profile accepts it. A FINAL profile does not: a server that sent none of the
     * codepoints this profile requires does not serve WebTransport for it. */
    *out_version = WT_WEBTRANSPORT_VERSION_DRAFT16;
    return WT_OK;
  }
  if (profile != WT_WEBTRANSPORT_PROFILE_FINAL) {
    int legacy_enable_present = 0;
    int legacy_sessions_present = 0;
    uint64_t legacy_enable_value = 0U;
    uint64_t legacy_sessions_value = 0U;

    legacy_enable_value = wt_http3_settings_get(
        server_settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, &legacy_enable_present);
    legacy_sessions_value = wt_http3_settings_get(server_settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS,
                                                  &legacy_sessions_present);
    if ((legacy_enable_present != 0 && legacy_enable_value == 1U) ||
        (legacy_sessions_present != 0 && legacy_sessions_value == 1U)) {
      /* The earlier drafts' advertisement, and no newer codepoint: a pre-draft-16 server. The DUAL
       * profile serves it -- every third-party peer this tree interoperates with still advertises
       * exactly this (measured against the five deployed peers on 13 November 2026) -- and the
       * session runs that era's rules. A FINAL profile does not: the strict posture means what it
       * says. */
      *out_version = WT_WEBTRANSPORT_VERSION_LEGACY;
      return WT_OK;
    }
  }
  /* The default value of SETTINGS_WT_ENABLED is 0, "meaning that the server does not support
   * WebTransport" (section 3.1): no session may be attempted on this connection. */
  return WT_ERR_STATE;
}

wt_status_t wt_webtransport_peer_advertised_version(const wt_http3_settings_t *peer_settings,
                                                    wt_webtransport_version_t *out_version,
                                                    wt_http3_error_t *out_error) {
  int final_present = 0;
  int draft_present = 0;
  int legacy_enable_present = 0;
  int legacy_sessions_present = 0;
  uint64_t draft_value = 0U;
  uint64_t legacy_enable_value = 0U;
  uint64_t legacy_sessions_value = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (peer_settings == NULL || out_version == NULL) return WT_ERR_INVALID_ARGUMENT;

  (void)wt_http3_settings_get(peer_settings, WT_HTTP3_SETTING_WT_ENABLED, &final_present);
  draft_value =
      wt_http3_settings_get(peer_settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, &draft_present);
  legacy_enable_value = wt_http3_settings_get(peer_settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED,
                                              &legacy_enable_present);
  legacy_sessions_value = wt_http3_settings_get(peer_settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS,
                                                &legacy_sessions_present);

  if (final_present != 0) {
    /* FINAL, and the codepoint's VALUE is not this function's business: section 3.1 makes
     * SETTINGS_WT_ENABLED meaningless from a client, so the server side ignores it, and the
     * client side's >1 connection error is the 2xx gate's rule
     * (`wt_webtransport_client_version`), not the rule selector's. */
    *out_version = WT_WEBTRANSPORT_VERSION_FINAL;
    return WT_OK;
  }
  if (draft_present != 0 && draft_value != 1U) {
    /* A draft advertisement carries its era's "supported" value, 1; anything else is the
     * connection error, which both halves' gates also enforce. */
    if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (draft_present != 0) {
    *out_version = WT_WEBTRANSPORT_VERSION_DRAFT16;
    return WT_OK;
  }
  if ((legacy_enable_present != 0 && legacy_enable_value == 1U) ||
      (legacy_sessions_present != 0 && legacy_sessions_value == 1U)) {
    *out_version = WT_WEBTRANSPORT_VERSION_LEGACY;
    return WT_OK;
  }
  return WT_ERR_STATE;
}
