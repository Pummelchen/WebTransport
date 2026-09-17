/* The public session handle (Phase 8). */

#include "webtransport/api/session.h"

#include <string.h>

#include "session_internal.h"
#include "webtransport/http3/frame.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/writer.h"

/* The handle's definition is in session_internal.h: the header declares the type opaque,
 * and the seam in events.c has to see the same layout. */
void wt_session_set_error(wt_session_t *session, wt_status_t status, uint64_t code) {
  session->error.status = status;
  session->error.code = code;
}

wt_session_config_t wt_session_config_default(void) {
  wt_session_config_t config;
  config.authority = NULL;
  config.path = NULL;
  config.session_id = 0U;
  config.max_capsule_bytes = 16384U;
  config.max_datagram_bytes = (size_t)WT_SESSION_DATAGRAM_MAX;
  config.max_streams = (size_t)WT_SESSION_STREAM_MAX;
  return config;
}

const char *wt_session_status_name(wt_status_t status) {
  /* wt_status_name is the library's own; this wrapper exists so the API has one name for
   * it and a consumer does not have to know which module owns it. */
  return wt_status_name(status);
}

wt_status_t wt_session_create(const wt_session_config_t *config, const wt_allocator_t *allocator,
                              wt_session_t **out) {
  wt_session_t *session;

  if (config == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (config->authority == NULL || config->path == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (strlen(config->authority) >= sizeof(session->authority) ||
      strlen(config->path) >= sizeof(session->path)) {
    /* The bound is this API's, and a caller that exceeds it is told rather than
     * truncated: a truncated authority would name a DIFFERENT session. */
    return WT_ERR_LIMIT;
  }
  /* Two configuration bounds are the handle's own table and would have to be silently
   * clamped to be honoured, so they are refused instead: a caller that asks for more
   * streams than this build can track must be told, not quietly given fewer. */
  if (config->max_streams > (size_t)WT_SESSION_STREAM_MAX) return WT_ERR_LIMIT;
  if (config->max_datagram_bytes > (size_t)WT_SESSION_DATAGRAM_MAX) return WT_ERR_LIMIT;

  session = (wt_session_t *)wt_alloc(allocator, sizeof(*session));
  if (session == NULL) return WT_ERR_OUT_OF_MEMORY;
  memset(session, 0, sizeof(*session));
  wt_webtransport_session_init(&session->machine);
  wt_webtransport_flow_limits_init(&session->limits);
  session->session_id = config->session_id;
  session->max_capsule_bytes = config->max_capsule_bytes;
  session->max_datagram_bytes =
      config->max_datagram_bytes == 0U ? (size_t)WT_SESSION_DATAGRAM_MAX
                                                              : config->max_datagram_bytes;
  session->max_streams = config->max_streams == 0U ? (size_t)WT_SESSION_STREAM_MAX : config->max_streams;
  memcpy(session->authority, config->authority, strlen(config->authority) + 1U);
  memcpy(session->path, config->path, strlen(config->path) + 1U);
  wt_session_set_error(session, WT_OK, 0U);
  *out = session;
  return WT_OK;
}

void wt_session_destroy(wt_session_t *session, const wt_allocator_t *allocator) {
  if (session == NULL) return;
  /* Zeroed first: a handle that is about to be freed should not leave a session's
   * contents in a pool for the next object to find. */
  memset(session, 0, sizeof(*session));
  wt_dealloc(allocator, session, sizeof(*session));
}

uint64_t wt_session_id(const wt_session_t *session) {
  if (session == NULL) return 0U;
  return session->session_id;
}

wt_session_state_t wt_session_state(const wt_session_t *session) {
  if (session == NULL) return WT_SESSION_CLOSED;
  /* Mapped member by member rather than cast: a cast would silently renumber this API if
   * the machine's enum ever changed order, and -Wswitch-enum makes the omission a
   * compile error instead. The two enums are deliberately separate: this one is a
   * published contract, that one is an implementation detail. */
  switch (session->machine.state) {
    case WT_WEBTRANSPORT_SESSION_ESTABLISHING: return WT_SESSION_ESTABLISHING;
    case WT_WEBTRANSPORT_SESSION_ESTABLISHED: return WT_SESSION_ESTABLISHED;
    case WT_WEBTRANSPORT_SESSION_DRAINING: return WT_SESSION_DRAINING;
    case WT_WEBTRANSPORT_SESSION_CLOSED: return WT_SESSION_CLOSED;
  }
  return WT_SESSION_CLOSED;
}

wt_session_error_t wt_session_last_error(const wt_session_t *session) {
  wt_session_error_t none;
  none.status = WT_OK;
  none.code = 0U;
  if (session == NULL) return none;
  return session->error;
}

wt_status_t wt_session_established(wt_session_t *session) {
  wt_status_t status;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_webtransport_session_established(&session->machine);
  wt_session_set_error(session, status, 0U);
  return status;
}

/* Section 6's terminal state, applied where a flow-control violation is found. Sections 5.6.2 and 5.6.3 say the
 * recipient of an over-limit Maximum Streams "MUST close the WebTransport session with a WT_FLOW_CONTROL_ERROR
 * error code"; this API owns no writer of its own, so it makes the transition a close capsule would make and
 * leaves the code where `wt_session_last_error` reports it. `sent` is recorded -- the endpoint that found the
 * violation is the one ending the session, and the peer's capsule is not a close. */
static void wt_session_close_for_flow_error(wt_session_t *session) {
  (void)wt_webtransport_session_on_close(&session->machine, 1,
                                         (uint32_t)WT_WEBTRANSPORT_FLOW_CONTROL_ERROR);
}

wt_status_t wt_session_on_capsule(wt_session_t *session, const uint8_t *bytes, size_t length) {
  wt_cursor_t c;
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  wt_status_t status;
  uint32_t code = 0U;

  if (session == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (bytes == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  if (session->machine.state == WT_WEBTRANSPORT_SESSION_CLOSED && length != 0U) {
    /* Section 6: "If any additional stream data is received on the CONNECT stream after receiving a
     * WT_CLOSE_SESSION capsule, the stream MUST be reset with code H3_MESSAGE_ERROR." This is the same gate
     * `wt_webtransport_session_on_capsule_bytes` applies on entry, repeated here because this entry point
     * decodes without that walker; the two must agree about identical bytes, and without the gate a peer could
     * close the session and then send a grant this endpoint would honour. An EMPTY delivery is the ordinary FIN
     * after the close, not a capsule, and is left to the decoder below. */
    wt_session_set_error(session, WT_ERR_PROTOCOL, (uint64_t)WT_HTTP3_MESSAGE_ERROR);
    return WT_ERR_PROTOCOL;
  }

  c = wt_cursor_init(bytes, length);
  status = wt_webtransport_capsule_decode(&c, session->max_capsule_bytes, &capsule, &h3_error);
  if (status != WT_OK) {
    /* The bound is reported as WT_ERR_LIMIT, and the error code says excessive load; a
     * caller can tell it from a malformed capsule. */
    wt_session_set_error(session, status, (uint64_t)h3_error);
    return status;
  }

  if (capsule.type == WT_CAPSULE_MAX_STREAM_DATA || capsule.type == WT_CAPSULE_STREAM_DATA_BLOCKED) {
    /* Draft-16 section 5.4 PROHIBITS these two: stream-level flow control is WebTransport's own, and a peer that
     * sends either is telling this endpoint about a limit it must not act on. Receipt is a session error of type
     * WT_FLOW_CONTROL_ERROR, and the first version let the session layer ignore them as unknown capsules -- a
     * prohibited instruction accepted in silence, which is the one answer the draft rules out. */
    wt_session_set_error(session, WT_ERR_PROTOCOL, (uint64_t)WT_WEBTRANSPORT_FLOW_CONTROL_ERROR);
    return WT_ERR_PROTOCOL;
  }
  if (capsule.type == WT_CAPSULE_DRAIN_SESSION) {
    /* Section 4.7 Figure 5 fixes the capsule at "Length (i) = 0", so a value is a capsule this layer cannot read
     * rather than one it may ignore -- exactly the rule the walker's drain branch applies. */
    if (capsule.value_length != 0U) {
      wt_session_set_error(session, WT_ERR_PROTOCOL, (uint64_t)WT_HTTP3_MESSAGE_ERROR);
      return WT_ERR_PROTOCOL;
    }
    status = wt_webtransport_session_on_drain(&session->machine, 0);
    /* The error surface is recorded BEFORE the callback, and the callback is the LAST thing this function does
     * to the session. Both halves matter: the first means the consumer that reads `wt_session_last_error` from
     * inside the callback sees this call's result rather than the previous one's, and the second means the
     * library does not write through a handle the callback may have released -- `on_close` followed by
     * `wt_session_destroy` is the pattern a consumer reaches for first, and it used to be a use-after-free. The
     * contract in `webtransport/api/events.h` still forbids calling back into the session, because the DRIVER
     * that invoked this function owns the handle next; what is fixed here is the library's own write. */
    wt_session_set_error(session, status, 0U);
    if (status == WT_OK && session->callbacks.on_drain != NULL) {
      session->callbacks.on_drain(session->callbacks.context);
    }
    return status;
  }
  if (capsule.type == WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION) {
    status = wt_webtransport_close_session_parse(&capsule, &code, NULL, NULL, &h3_error);
    if (status != WT_OK) {
      wt_session_set_error(session, status, (uint64_t)h3_error);
      return status;
    }
    status = wt_webtransport_session_on_close(&session->machine, 0, code);
    /* The peer's code travels to the caller: that is what "the refusal keeps the peer's code" means at this
     * surface -- and it is recorded BEFORE `on_close` runs, so the callback reads this call's result and the
     * handle is not written through after the callback returns (see the drain branch above). */
    wt_session_set_error(session, status, (uint64_t)code);
    if (status == WT_OK && session->callbacks.on_close != NULL) {
      session->callbacks.on_close(session->callbacks.context, code);
    }
    return status;
  }

  /* The session's own flow control arrives the same way. With flow control off the
   * capsule is IGNORED rather than refused -- the draft makes it conditional on SETTINGS,
   * and a peer that sends one anyway is not breaking anything this endpoint relies on. */
  if (capsule.type == WT_CAPSULE_MAX_DATA) {
    uint64_t maximum = 0U;
    status = wt_webtransport_max_data_parse(&capsule, &maximum, &h3_error);
    if (status != WT_OK) {
      wt_session_set_error(session, status, (uint64_t)h3_error);
      return status;
    }
    if (session->flow_enabled == 0) {
      /* Ignored, and that is a RESULT rather than a failure: `wt_session_last_error` answers "what the last
       * operation left behind", so leaving the previous call's error standing would report a failure for a call
       * that returned WT_OK. */
      wt_session_set_error(session, WT_OK, 0U);
      return WT_OK;
    }
    {
      uint64_t flow_error = 0U;
      status = wt_webtransport_flow_on_max_data(&session->limits, maximum, &flow_error);
      wt_session_set_error(session, status, flow_error);
      return status;
    }
  }
  if (capsule.type == WT_CAPSULE_MAX_STREAMS_BIDI || capsule.type == WT_CAPSULE_MAX_STREAMS_UNI) {
    uint64_t maximum = 0U;
    int bidirectional = capsule.type == WT_CAPSULE_MAX_STREAMS_BIDI;
    status = wt_webtransport_max_streams_parse(&capsule, &maximum, &h3_error);
    if (status != WT_OK) {
      wt_session_set_error(session, status, (uint64_t)h3_error);
      /* Sections 5.6.2 and 5.6.3: an over-limit Maximum Streams is a SESSION error, not a syntax error, and
       * the recipient MUST close the session with it. */
      if ((uint64_t)h3_error == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR) {
        wt_session_close_for_flow_error(session);
      }
      return status;
    }
    if (session->flow_enabled == 0) {
      wt_session_set_error(session, WT_OK, 0U);
      return WT_OK;
    }
    {
      uint64_t flow_error = 0U;
      status = wt_webtransport_flow_on_max_streams(&session->limits, bidirectional, maximum,
                                                   &flow_error);
      wt_session_set_error(session, status, flow_error);
      return status;
    }
  }
  if (capsule.type == WT_CAPSULE_STREAMS_BLOCKED_BIDI || capsule.type == WT_CAPSULE_STREAMS_BLOCKED_UNI) {
    uint64_t maximum = 0U;
    status = wt_webtransport_streams_blocked_parse(&capsule, &maximum, &h3_error);
    if (status != WT_OK) {
      wt_session_set_error(session, status, (uint64_t)h3_error);
      if ((uint64_t)h3_error == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR) {
        wt_session_close_for_flow_error(session);
      }
      return status;
    }
    /* A well-formed WT_STREAMS_BLOCKED is informational (section 5.6.3): it says the peer is blocked on a limit
     * this endpoint granted, and the only rule it carries that this layer must act on is the ceiling above. It is
     * accepted and dropped, like any other capsule this API does not apply. */
    wt_session_set_error(session, WT_OK, 0U);
    return WT_OK;
  }

  /* Any other capsule is accepted and left alone: RFC 9297 has a receiver ignore what it
   * does not understand, and a public API must not be the layer that starts refusing. */
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}

wt_status_t wt_session_write_drain(wt_session_t *session, uint8_t *out, size_t capacity,
                                   size_t *out_length) {
  wt_writer_t w;
  wt_status_t status;
  size_t payload_length;
  size_t frame_length = 0U;

  if (session == NULL || out == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;
  /* The capsule is written AFTER the reservation and then wrapped: RFC 9114 section 4.4 permits only DATA frames
   * on the stream that carried CONNECT, and RFC 9297 section 3.2 makes the capsule protocol their contents, so the
   * capsule's own bytes are not what goes on the wire. The reservation is what makes one buffer enough -- a
   * capsule's length is inside the capsule, so the frame header cannot be written first. */
  w = wt_http3_frame_data_writer(out, capacity);
  status = wt_webtransport_session_write_drain(&session->machine, &w);
  if (status != WT_OK) {
    wt_session_set_error(session, status, 0U);
    return status;
  }
  payload_length = wt_writer_offset(&w);
  status = wt_http3_frame_wrap_data_in_place(out, capacity, payload_length, &frame_length);
  if (status != WT_OK) {
    wt_session_set_error(session, status, 0U);
    return status;
  }
  *out_length = frame_length;
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}

wt_status_t wt_session_write_close(wt_session_t *session, uint32_t error_code, const char *reason,
                                   uint8_t *out, size_t capacity, size_t *out_length) {
  wt_writer_t w;
  wt_status_t status;
  size_t reason_length = reason == NULL ? 0U : strlen(reason);
  size_t payload_length;
  size_t frame_length = 0U;

  if (session == NULL || out == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;
  w = wt_http3_frame_data_writer(out, capacity);
  status = wt_webtransport_session_write_close(&session->machine, &w, error_code,
                                              (const uint8_t *)reason, reason_length);
  if (status != WT_OK) {
    wt_session_set_error(session, status, 0U);
    return status;
  }
  payload_length = wt_writer_offset(&w);
  status = wt_http3_frame_wrap_data_in_place(out, capacity, payload_length, &frame_length);
  if (status != WT_OK) {
    wt_session_set_error(session, status, 0U);
    return status;
  }
  *out_length = frame_length;
  wt_session_set_error(session, WT_OK, 0U);
  return WT_OK;
}
