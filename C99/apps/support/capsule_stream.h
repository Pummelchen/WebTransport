/* The CONNECT stream's capsules, as an application sees them (draft-ietf-webtrans-http3-16 section 5).
 *
 * A WebTransport session's control messages -- drain, close, and the flow-control grants -- travel on the CONNECT
 * stream as CAPSULES once that stream's one HEADERS frame has passed, and the HTTP/3 driver routes those bytes to
 * the stream-data sink rather than framing them (WT-164). What is left is an application's job, and it is the same
 * job in both applications this tree builds: keep the bytes that have not completed a capsule, walk what has, apply
 * the session's own capsules to the session, and hand the rest to whoever owns them.
 *
 * The BYTES are kept here rather than in the session because a capsule may be split across STREAM frames and be
 * several to a frame, and because the bound on one capsule belongs to whoever owns the memory. The peer's
 * flow-control account is kept here too, for the same reason: the capsule codec gives the limits to the caller, and
 * `wt_capsule_stream_apply_flow` is the observer that fills them -- so a caller that wants the grants applied and
 * nothing else has nothing to write.
 */

#ifndef WT_SUPPORT_CAPSULE_STREAM_H
#define WT_SUPPORT_CAPSULE_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session.h"

/* How much of the capsule stream one application will hold. A capsule longer than this is a bound this endpoint
 * enforces rather than a buffer it grows, and the value is the caller's to raise with its own copy. */
#define WT_CAPSULE_STREAM_MAX 1024U

typedef struct wt_capsule_stream {
  /* The session those capsules belong to, with the state a drain or a close moves. */
  wt_webtransport_session_t session;
  /* The limits the peer granted, which is what the caller enforces against. */
  wt_webtransport_flow_limits_t peer_limits;
  uint8_t bytes[WT_CAPSULE_STREAM_MAX];
  size_t length;
  /* How many capsules were walked and how many were refused. Counted rather than inferred, because "the peer sent
   * none" and "the peer's capsules were dropped" leave the same state behind. */
  unsigned walked;
  unsigned refused;
} wt_capsule_stream_t;

/* An observer for the capsules the session's lifecycle machine does not apply. It may refuse one by returning a
 * status and naming the rule in `out_error`, and the walk stops there. */
typedef wt_status_t (*wt_capsule_stream_fn)(void *context, const wt_webtransport_capsule_t *capsule,
                                            wt_http3_error_t *out_error);

void wt_capsule_stream_init(wt_capsule_stream_t *stream);

/* The session is established: the response has arrived (a client) or gone out (a server). */
void wt_capsule_stream_established(wt_capsule_stream_t *stream);

/* One delivery of bytes the driver routed off the CONNECT stream, with the stream's end on the last one.
 *
 * `observe` is called for every capsule the session does not own, and the context is the caller's -- pass
 * `wt_capsule_stream_apply_flow` with `&stream->peer_limits` to have the grants applied. WT_ERR_TRUNCATED is
 * returned when the stream ENDS part way through a capsule: an incomplete capsule at FIN is a refusal, the same
 * rule an incomplete HTTP/3 frame follows (WT-158). A capsule that has merely not arrived is kept and this returns
 * WT_OK, so the caller's next delivery completes it. */
wt_status_t wt_capsule_stream_on_bytes(wt_capsule_stream_t *stream, const uint8_t *data, size_t length, int fin,
                                       wt_capsule_stream_fn observe, void *context);

/* Apply the connection-level grants: MAX_DATA and both MAX_STREAMS. The context is a
 * `wt_webtransport_flow_limits_t *`, so the usual call is `(observe, &stream->peer_limits)`.
 *
 * MAX_STREAM_DATA and the blocked signals are accepted and dropped: the first names a stream only the QUIC layer
 * holds, and the rest are requests rather than grants. RFC 9297 section 2 makes ignoring a capsule a receiver does
 * not understand correct, and a caller with no per-stream account has nothing to apply them to. A limit that does
 * not strictly increase is section 5.1's flow-control error, which this reports as WT_ERR_PROTOCOL. */
wt_status_t wt_capsule_stream_apply_flow(void *context, const wt_webtransport_capsule_t *capsule,
                                         wt_http3_error_t *out_error);

#endif /* WT_SUPPORT_CAPSULE_STREAM_H */
