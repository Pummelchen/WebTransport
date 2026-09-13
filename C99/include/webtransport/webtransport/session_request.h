/* The WebTransport session request: an extended CONNECT (draft-ietf-webtrans-http3-16
 * section 3.1, over RFC 9220's extended CONNECT).
 *
 * A WebTransport session begins with a request that is a CONNECT carrying the
 * `:protocol` pseudo-header with the value `webtransport`. Four rules decide what a
 * decoded request is, and only the last is this layer's own:
 *
 *   - a CONNECT without `:protocol` is an ordinary CONNECT, which is not this layer's
 *     business at all;
 *   - a `:protocol` naming another protocol belongs to that protocol, and RFC 9220
 *     section 3 has the server answer it with a status rather than an error;
 *   - an extended CONNECT carries `:scheme`, `:authority` and `:path` -- RFC 9114
 *     section 4.1's CONNECT exception covers the plain CONNECT, so requiring the scheme
 *     and path is this layer's job;
 *   - and the draft has a server refuse a session it did not advertise support for.
 *
 * The outcome is a DECISION rather than an error: "not mine" and "mine, but refused"
 * are ordinary answers with status codes, and a malformed request is already the
 * message error the HTTP/3 layer raised.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H
#define WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/message.h"
#include "webtransport/webtransport/protocol.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The `:protocol` value that makes a CONNECT a WebTransport request (section 3.1). */
#define WT_WEBTRANSPORT_PROTOCOL_TOKEN "webtransport"

/* The draft-16 setting a server advertises to say it can serve WebTransport at all. */
#define WT_HTTP3_SETTING_WT_ENABLED ((uint64_t)0x2c7cf000)

/* The draft-16 settings that carry a session's INITIAL flow-control limits (section 5.1).
 * They are what turns the session's own flow control on: an endpoint that omits all three
 * is not doing it, and a session enabled by one of them starts the other two at zero. */
#define WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA ((uint64_t)0x2b61)
#define WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI ((uint64_t)0x2b64)
#define WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI ((uint64_t)0x2b65)

/* The status a refusal carries when the authority or path is not one this server
 * serves. */
#define WT_WEBTRANSPORT_REJECT_NOT_FOUND ((uint32_t)404)
/* And when the request is WebTransport but this server did not advertise it. */
#define WT_WEBTRANSPORT_REJECT_NOT_IMPLEMENTED ((uint32_t)501)
/* And when a sub-protocol was REQUIRED and the two lists do not meet (section 3.2). */
#define WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED ((uint32_t)400)

typedef enum wt_webtransport_request_outcome {
  /* A WebTransport request this server accepts. */
  WT_WEBTRANSPORT_REQUEST_ACCEPT = 0,
  /* Not a WebTransport request: an ordinary request, or an extended CONNECT for
   * another protocol. The caller answers it as it would any other request. */
  WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT = 1,
  /* A WebTransport request this server refuses, with `status` as the answer. */
  WT_WEBTRANSPORT_REQUEST_REJECT = 2
} wt_webtransport_request_outcome_t;

/* What the server is willing to serve, and whether it said so. */
typedef struct wt_webtransport_request_policy {
  /* The authority and path this server serves, compared EXACTLY: a prefix match would
   * let one host's request be served as another's. */
  const char *authority;
  const char *path;
  /* False when the server did not advertise WT_ENABLED, which the draft makes a reason
   * to refuse a session rather than serve one the client could not have known about. */
  int wt_enabled;
} wt_webtransport_request_policy_t;

typedef struct wt_webtransport_session_request {
  wt_webtransport_request_outcome_t outcome;
  const uint8_t *authority;
  size_t authority_length;
  const uint8_t *path;
  size_t path_length;
  /* The answer to send when the outcome is a rejection. */
  uint32_t status;
  /* The sub-protocol selected from the request's list, as a view into the caller's bytes (section 3.2).
   * Absent -- NULL with length zero -- when nothing was offered, nothing matched, or none was required. */
  const uint8_t *selected_protocol;
  size_t selected_protocol_length;
} wt_webtransport_session_request_t;

/* The sub-protocol decision, which needs the request's `wt-protocol` field and therefore a parsed list
 * rather than the pseudo-headers `validate` sees (section 3.2).
 *
 * `offered` is what the request carried and `supported` is this server's configuration; both are lists of
 * tokens, and the answer is the FIRST token offered that is supported, so a client and a server compute the
 * same choice from the same two lists. A rejection the caller already decided is left alone: a request this
 * server will not serve is not negotiated with.
 *
 * When nothing can be selected and `require_selection` is set, the decision becomes a rejection with
 * WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED -- the draft's own "requirements not met" answer -- rather than a
 * session that quietly speaks no sub-protocol while the client believes one was chosen. */
wt_status_t wt_webtransport_session_request_negotiate(wt_webtransport_session_request_t *decision,
                                                      const wt_webtransport_protocol_list_t *offered,
                                                      const wt_webtransport_protocol_list_t *supported,
                                                      int require_selection);

/* The client's side of the same conversation: the response's `wt-protocol` value, which must name a token
 * THIS CLIENT offered. A value that names anything else is WT_ERR_PROTOCOL, because accepting it would leave
 * the two ends speaking different sub-protocols. */
wt_status_t wt_webtransport_session_response_selected_protocol(
    const uint8_t *value, size_t length, const wt_webtransport_protocol_list_t *offered,
    wt_webtransport_protocol_token_t *out);

/* Decide what a decoded request is. `message` must have come from
 * `wt_http3_message_decode` with WT_HTTP3_HEADER_REQUEST. */
wt_status_t wt_webtransport_session_request_validate(
    const wt_http3_message_t *message, const wt_webtransport_request_policy_t *policy,
    wt_webtransport_session_request_t *out, wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H */
