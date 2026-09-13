/* The session handle's layout, shared by the API's translation units.
 *
 * This header is NOT installed and NOT public: `api/session.h` declares `wt_session_t` as
 * an incomplete type deliberately, so the layout may change between releases. Only the
 * files that make up the API see it. */

#ifndef WEBTRANSPORT_API_SESSION_INTERNAL_H
#define WEBTRANSPORT_API_SESSION_INTERNAL_H

#include "webtransport/api/events.h"
#include "webtransport/webtransport/session.h"

#define WT_SESSION_AUTHORITY_MAX 128U

/* A peer stream this handle is tracking. */
typedef struct wt_session_stream_slot {
  uint64_t stream_id;
  int unidirectional;
} wt_session_stream_slot_t;

struct wt_session {
  wt_webtransport_session_t machine;
  wt_session_error_t error;
  /* The CONNECT stream ID this session lives on, which is what a datagram's quarter
   * stream ID and a WebTransport stream's prefix must both name. */
  uint64_t session_id;
  size_t max_capsule_bytes;
  size_t max_datagram_bytes;
  size_t max_streams;
  char authority[WT_SESSION_AUTHORITY_MAX];
  char path[WT_SESSION_AUTHORITY_MAX];
  wt_session_callbacks_t callbacks;
  /* Fixed, because a stream table that grows with a peer is a heap exhaustion path with a
   * peer's name on it. */
  wt_session_stream_slot_t streams[WT_SESSION_STREAM_MAX];
  size_t stream_count;
};

/* Record the last failure. Used by both translation units so a session's error surface
 * cannot drift between them. */
void wt_session_set_error(wt_session_t *session, wt_status_t status, uint64_t code);

/* Find a tracked peer stream, or NULL. */
wt_session_stream_slot_t *wt_session_find_stream(wt_session_t *session, uint64_t stream_id);

/* Stop tracking a stream. */
void wt_session_forget_stream(wt_session_t *session, uint64_t stream_id);

#endif /* WEBTRANSPORT_API_SESSION_INTERNAL_H */
