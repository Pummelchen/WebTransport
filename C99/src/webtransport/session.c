/* A WebTransport session's lifecycle (draft-ietf-webtrans-http3-16 sections 3 to 5). */

#include "webtransport/webtransport/session.h"

void wt_webtransport_session_init(wt_webtransport_session_t *session) {
  if (session == NULL) return;
  session->state = WT_WEBTRANSPORT_SESSION_ESTABLISHING;
  session->close_error_code = 0U;
  session->close_error_set = 0;
  session->drain_sent = 0;
  session->drain_received = 0;
  session->close_sent = 0;
  session->close_received = 0;
}

wt_status_t wt_webtransport_session_established(wt_webtransport_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Only from the establishing state: a session that is draining or closed cannot be
   * established by a late response, and saying so is better than silently ignoring it. */
  if (session->state != WT_WEBTRANSPORT_SESSION_ESTABLISHING) return WT_ERR_STATE;
  session->state = WT_WEBTRANSPORT_SESSION_ESTABLISHED;
  return WT_OK;
}

wt_status_t wt_webtransport_session_on_drain(wt_webtransport_session_t *session, int sent) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;
  if (sent) {
    session->drain_sent = 1;
  } else {
    session->drain_received = 1;
  }
  /* A drain is only meaningful once the session exists; from the establishing state it
   * still records what happened, and the state stays where it is because the session is
   * not yet usable either way. */
  if (session->state == WT_WEBTRANSPORT_SESSION_ESTABLISHED) {
    session->state = WT_WEBTRANSPORT_SESSION_DRAINING;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_session_on_close(wt_webtransport_session_t *session, int sent,
                                             uint32_t error_code) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (sent) {
    session->close_sent = 1;
  } else {
    session->close_received = 1;
  }
  /* The first close's code is the session's: a second close, from either side, is
   * accepted and does not rewrite what the session ended with. */
  if (!session->close_error_set) {
    session->close_error_code = error_code;
    session->close_error_set = 1;
  }
  session->state = WT_WEBTRANSPORT_SESSION_CLOSED;
  return WT_OK;
}

wt_status_t wt_webtransport_session_on_stream_end(wt_webtransport_session_t *session) {
  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;
  /* No capsule came with the end, so there is no application code to report -- which is
   * different from a close whose code happens to be zero, and the flag above is what
   * keeps the two apart. */
  session->state = WT_WEBTRANSPORT_SESSION_CLOSED;
  return WT_OK;
}

int wt_webtransport_session_allows_new_streams(const wt_webtransport_session_t *session) {
  if (session == NULL) return 0;
  return session->state == WT_WEBTRANSPORT_SESSION_ESTABLISHED;
}

wt_status_t wt_webtransport_session_write_drain(wt_webtransport_session_t *session, wt_writer_t *w) {
  wt_status_t status;

  if (session == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;

  status = wt_webtransport_drain_session_write(w);
  if (status != WT_OK) return status;
  return wt_webtransport_session_on_drain(session, 1);
}

wt_status_t wt_webtransport_session_write_close(wt_webtransport_session_t *session, wt_writer_t *w,
                                               uint32_t error_code, const uint8_t *reason,
                                               size_t reason_length) {
  wt_status_t status;

  if (session == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (session->state == WT_WEBTRANSPORT_SESSION_CLOSED) return WT_ERR_STATE;
  /* Never established: the session never existed, so there is nothing to close. */
  if (session->state == WT_WEBTRANSPORT_SESSION_ESTABLISHING) return WT_ERR_STATE;

  status = wt_webtransport_close_session_write(w, error_code, reason, reason_length);
  if (status != WT_OK) return status;
  return wt_webtransport_session_on_close(session, 1, error_code);
}
