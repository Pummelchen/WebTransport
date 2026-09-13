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
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The `:protocol` value that makes a CONNECT a WebTransport request (section 3.1). */
#define WT_WEBTRANSPORT_PROTOCOL_TOKEN "webtransport"

/* The draft-16 setting a server advertises to say it can serve WebTransport at all. */
#define WT_HTTP3_SETTING_WT_ENABLED ((uint64_t)0x2c7cf000)

/* The status a refusal carries when the authority or path is not one this server
 * serves. */
#define WT_WEBTRANSPORT_REJECT_NOT_FOUND ((uint32_t)404)
/* And when the request is WebTransport but this server did not advertise it. */
#define WT_WEBTRANSPORT_REJECT_NOT_IMPLEMENTED ((uint32_t)501)

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
} wt_webtransport_session_request_t;

/* Decide what a decoded request is. `message` must have come from
 * `wt_http3_message_decode` with WT_HTTP3_HEADER_REQUEST. */
wt_status_t wt_webtransport_session_request_validate(
    const wt_http3_message_t *message, const wt_webtransport_request_policy_t *policy,
    wt_webtransport_session_request_t *out, wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H */
