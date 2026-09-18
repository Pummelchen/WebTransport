/* Driving an HTTP/3 endpoint from a connection (Phase 9): the driver's own state and its accessors.
 *
 * The driver is now four translation units, split along what each part is rather than by size:
 * this one holds the driver's tables -- the data streams it remembers, the refusals it applies to
 * them, the streams it has ended, and the capsule marks -- plus the once-only control and QPACK
 * stream prefixes. `driver_stream.c` reassembles a stream's type prefix and its HTTP/3 frames,
 * `driver_route.c` turns a connection's frames into calls on those, and `driver_send.c` is the
 * outbound half. The four helpers the parts share are declared in "driver_internal.h". */

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/http3/driver.h"

#include "webtransport/webtransport/error.h"

#include "webtransport/cursor.h"
#include <string.h>

#include "webtransport/quic/stream.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

#include "driver_internal.h"

void wt_http3_driver_init(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint) {
  if (driver == NULL) return;
  /* Zeroed WHOLE rather than field by field. Naming every field was here so that adding one would force this
   * function to be revisited -- and it did not work: `data_stream_count` was added and left holding whatever the
   * caller's stack had, which is a segfault the moment the receive path asks how many data streams there are.
   * Zeroing the struct makes a forgotten field impossible, and the one field that is not zero is named here. */
  memset(driver, 0, sizeof(*driver));
  driver->endpoint = endpoint;
  /* Named rather than left zeroed, because "no error" is NOT zero in the HTTP/3 error space: WT_HTTP3_NO_ERROR is
   * 0x100, so a zeroed field would read as a refusal with code 0 and the caller would report one. This is the same
   * trap the connection-ID work hit from the other side -- a memset is right for everything whose zero is the
   * default, and wrong for a value whose zero means something else (WT-158). */
  driver->last_error = WT_HTTP3_NO_ERROR;
}

/* Remember a stream whose prefix is settled: this endpoint opened it, or the peer did and the prefix said
 * WebTransport. One table, one rule -- the bytes after the prefix are the session's. `our_prefix_length` is what
 * THIS endpoint wrote on that stream (0 for one the peer opened), kept for the reset section 4.4 requires.
 * `session_id` is the session the prefix named, or `session_id_set` 0 when there is none to name (WT-180). */
wt_status_t remember_data_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                 uint64_t our_prefix_length, uint64_t session_id,
                                 int session_id_set) {
  if (driver->data_stream_count >= WT_HTTP3_DRIVER_DATA_STREAMS_MAX) return WT_ERR_LIMIT;
  driver->data_streams[driver->data_stream_count].stream_id = stream_id;
  driver->data_streams[driver->data_stream_count].prefix_length = our_prefix_length;
  driver->data_streams[driver->data_stream_count].session_id = session_id;
  driver->data_streams[driver->data_stream_count].session_id_set = session_id_set != 0 ? 1 : 0;
  driver->data_stream_count++;
  return WT_OK;
}

void wt_http3_driver_set_session_id(wt_http3_driver_t *driver, uint64_t session_id) {
  if (driver == NULL) return;
  driver->session_id = session_id;
  driver->session_id_set = 1;
}

void wt_http3_driver_set_upgrade_token(wt_http3_driver_t *driver,
                                       wt_webtransport_upgrade_token_t token) {
  if (driver == NULL) return;
  driver->upgrade_token = token;
}

size_t wt_http3_driver_pending_count(const wt_http3_driver_t *driver) {
  if (driver == NULL) return 0U;
  return driver->pending_count;
}

wt_status_t wt_http3_driver_start_control(wt_http3_driver_t *driver,
                                          const wt_http3_settings_t *settings, uint8_t *scratch,
                                          size_t scratch_capacity, wt_writer_t *w) {
  wt_writer_t payload;
  wt_http3_frame_t frame;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || settings == NULL || scratch == NULL ||
      w == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The prefix first, through the endpoint's once-only rule: a caller that starts a second
   * control stream should find out before any bytes go out. */
  status = wt_http3_endpoint_write_prefix(driver->endpoint, WT_HTTP3_ENDPOINT_STREAM_CONTROL, w);
  if (status != WT_OK) return status;

  /* Pass one: measure the SETTINGS payload into the caller's scratch. */
  payload = wt_writer_init(scratch, scratch_capacity);
  status = wt_http3_settings_encode_payload(&payload, settings);
  if (status != WT_OK) return status;
  if (!wt_writer_ok(&payload)) return WT_ERR_LIMIT;

  /* Pass two: the frame around it, now that its length is known rather than guessed. */
  frame = wt_http3_frame_make(WT_HTTP3_FRAME_SETTINGS);
  frame.payload = scratch;
  frame.length = wt_writer_offset(&payload);
  return wt_http3_frame_encode(w, &frame);
}

wt_status_t wt_http3_driver_start_qpack_stream(wt_http3_driver_t *driver, int encoder,
                                               wt_writer_t *w) {
  if (driver == NULL || driver->endpoint == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_http3_endpoint_write_prefix(driver->endpoint,
                                        encoder != 0 ? WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER
                                                     : WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER,
                                        w);
}

wt_http3_driver_pending_t *find_pending(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->pending_count; i++) {
    if (driver->pending[i].stream_id == stream_id) return &driver->pending[i];
  }
  return NULL;
}

void forget_pending(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->pending_count; i++) {
    if (driver->pending[i].stream_id == stream_id) {
      driver->pending[i] = driver->pending[driver->pending_count - 1U];
      driver->pending_count--;
      return;
    }
  }
}

/* Whether THIS endpoint has a SEND half on `stream_id`, so that a RESET_STREAM is a frame the stream machine
 * can apply: every bidirectional stream, and a unidirectional one this endpoint opened. A peer's unidirectional
 * stream is receive-only here, which is why section 4.6 says "RESET_STREAM and/or STOP_SENDING" rather than both:
 * for that stream the rejection IS the STOP_SENDING. */
static int has_send_half(const wt_quic_connection_t *connection, uint64_t stream_id) {
  if (wt_quic_stream_id_is_bidirectional(stream_id) != 0) return 1;
  return wt_quic_stream_id_from_client(stream_id) ==
         (connection->config.role == WT_QUIC_ROLE_CLIENT);
}

/* And the other half: whether this endpoint can receive on it, so a STOP_SENDING is a frame the peer will
 * understand as "stop sending on this stream". */
static int has_receive_half(const wt_quic_connection_t *connection, uint64_t stream_id) {
  if (wt_quic_stream_id_is_bidirectional(stream_id) != 0) return 1;
  return wt_quic_stream_id_from_client(stream_id) !=
         (connection->config.role == WT_QUIC_ROLE_CLIENT);
}

wt_status_t wt_http3_driver_end_session_streams(wt_http3_driver_t *driver, uint64_t now,
                                                size_t *out_streams_ended) {
  size_t index;
  size_t ended = 0U;
  wt_status_t first_refusal = WT_OK;

  if (out_streams_ended != NULL) *out_streams_ended = 0U;
  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A reset is a frame, so this needs the connection a refusal would be stated to as well (WT-158, WT-159): the
   * driver is where the code is known and the connection is where the frame goes. */
  if (driver->connection == NULL) return WT_ERR_STATE;

  /* The session is over from here on, whatever happens below: section 6's "MUST NOT send any new datagrams or
   * open any new streams" is about the session's state, not about how many resets succeeded. */
  driver->session_ended = 1;

  for (index = 0U; index < driver->data_stream_count; index++) {
    uint64_t stream_id = driver->data_streams[index].stream_id;
    uint64_t send_offset = 0U;
    uint64_t reliable_size;
    int skip_reset = 0;
    wt_status_t status;

    /* Section 4.4: a reset of a WebTransport stream commits to at least the prefix that associates it, and a
     * commitment past what has been sent is a FRAME_ENCODING_ERROR at the peer -- so the commitment is the prefix
     * capped by the bytes actually sent. A stream the peer opened has no prefix of ours (0), and one this endpoint
     * wrote a prefix on has sent at least those bytes. */
    reliable_size = driver->data_streams[index].prefix_length;
    if (wt_quic_connection_stream_send_offset(driver->connection, stream_id, &send_offset) ==
            WT_OK &&
        reliable_size > send_offset) {
      reliable_size = send_offset;
    }

    /* A stream whose SEND half is already finished -- or already reset -- has nothing for section 6 to abort, and
     * the stream machine refuses a second reset with WT_ERR_STATE. Skipping it is not a refusal: a stream this
     * endpoint ended cleanly is ended, and the peer learns the session is gone from the streams that were still
     * open (and from this endpoint's own close). Its RECEIVE half is still aborted below, which is the half the
     * section speaks about separately. */
    {
      const wt_quic_stream_t *stream = wt_quic_connection_stream(driver->connection, stream_id);
      if (stream != NULL && (stream->send_state == WT_QUIC_SEND_DATA_SENT ||
                             stream->send_state == WT_QUIC_SEND_DATA_RECVD ||
                             stream->send_state == WT_QUIC_SEND_RESET_SENT ||
                             stream->send_state == WT_QUIC_SEND_RESET_RECVD)) {
        skip_reset = 1;
      }
    }

    status = (skip_reset != 0 || has_send_half(driver->connection, stream_id) == 0)
                 ? WT_OK
                 : wt_quic_connection_reset_stream_at(driver->connection, stream_id,
                                                      WT_WEBTRANSPORT_ERROR_SESSION_GONE,
                                                      reliable_size, now);
    if (status == WT_OK) {
      if (skip_reset == 0) ended++;
    } else if (first_refusal == WT_OK) {
      /* A stream the connection no longer has, one this endpoint may not reset, or a peer that did not negotiate
       * the reliable reset: the first refusal is reported and the rest of the streams are still attempted, because
       * one stream that cannot be reset does not excuse the others. */
      first_refusal = status;
    }

    /* And the receive side: "abort reading on the receive side". A STOP_SENDING the connection refuses (a stream
     * this endpoint cannot receive on, or one already ended) is not an error of this call. */
    if (has_receive_half(driver->connection, stream_id) != 0) {
      (void)wt_quic_connection_stop_sending(driver->connection, stream_id,
                                            WT_WEBTRANSPORT_ERROR_SESSION_GONE, now);
    }

    /* Forgotten, so that a second call is a no-op rather than a second reset of a stream that is already gone. */
    driver->data_streams[index].stream_id = 0U;
    driver->data_streams[index].prefix_length = 0U;
  }
  driver->data_stream_count = 0U;
  if (out_streams_ended != NULL) *out_streams_ended = ended;
  return first_refusal;
}

int wt_http3_driver_session_ended(const wt_http3_driver_t *driver) {
  return driver != NULL ? driver->session_ended : 0;
}

wt_http3_error_t wt_http3_driver_last_error(const wt_http3_driver_t *driver) {
  if (driver == NULL) return WT_HTTP3_NO_ERROR;
  return driver->last_error;
}

int wt_http3_driver_is_data_stream(const wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t index;

  if (driver == NULL) return 0;
  for (index = 0U; index < driver->data_stream_count; index++) {
    if (driver->data_streams[index].stream_id == stream_id) return 1;
  }
  return 0;
}

wt_status_t wt_http3_driver_data_stream_session_id(const wt_http3_driver_t *driver,
                                                   uint64_t stream_id, uint64_t *out_session_id) {
  size_t index;

  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  for (index = 0U; index < driver->data_stream_count; index++) {
    if (driver->data_streams[index].stream_id != stream_id) continue;
    if (driver->data_streams[index].session_id_set == 0) {
      /* Remembered, but this endpoint wrote the prefix and has not been told which session it serves, so
       * there is no ID to hand back. Saying so is the difference between "not mine" and "not known yet". */
      return WT_ERR_STATE;
    }
    if (out_session_id != NULL) *out_session_id = driver->data_streams[index].session_id;
    return WT_OK;
  }
  return WT_ERR_CLOSED;
}

/* Forget one remembered data stream. The table's order carries no meaning -- it is walked to reset what it
 * holds -- so the last entry fills the hole rather than everything after it moving down. */
static void forget_data_stream(wt_http3_driver_t *driver, size_t index) {
  driver->data_streams[index] = driver->data_streams[driver->data_stream_count - 1U];
  driver->data_stream_count--;
}

wt_status_t wt_http3_driver_reject_data_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t error_code, uint64_t now) {
  size_t index;
  uint64_t send_offset = 0U;
  uint64_t reliable_size;
  wt_status_t status;

  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (driver->connection == NULL) return WT_ERR_STATE;

  for (index = 0U; index < driver->data_stream_count; index++) {
    if (driver->data_streams[index].stream_id == stream_id) break;
  }
  if (index == driver->data_stream_count) return WT_ERR_CLOSED;

  /* The Reliable Size rule of section 4.4, exactly as `wt_http3_driver_end_session_streams` applies it: a
   * reset commits to at least the prefix that associates the stream with the session, capped by what has
   * actually been sent, because a commitment past the send offset is a FRAME_ENCODING_ERROR at the peer. */
  reliable_size = driver->data_streams[index].prefix_length;
  if (wt_quic_connection_stream_send_offset(driver->connection, stream_id, &send_offset) == WT_OK &&
      reliable_size > send_offset) {
    reliable_size = send_offset;
  }

  /* The section's "RESET_STREAM and/or STOP_SENDING": whichever halves this endpoint has. A peer's
   * unidirectional stream has no send half here, so the rejection is its STOP_SENDING, and asking the
   * connection for a reset would be WT_ERR_STATE rather than a frame. */
  status = has_send_half(driver->connection, stream_id) != 0
               ? wt_quic_connection_reset_stream_at(driver->connection, stream_id, error_code,
                                                    reliable_size, now)
               : WT_OK;

  /* And the receive side: the peer's bytes on a stream this endpoint is rejecting are refused too. A stream
   * this endpoint cannot receive on refuses the STOP_SENDING, and that is not this call's error. */
  if (has_receive_half(driver->connection, stream_id) != 0) {
    (void)wt_quic_connection_stop_sending(driver->connection, stream_id, error_code, now);
  }

  forget_data_stream(driver, index);
  return status;
}

/* The marked CONNECT stream `stream_id`, or NULL. One function looks a stream up, so the mark and the question
 * cannot disagree about what "settled" means. */
static wt_http3_driver_capsule_stream_t *find_capsule_stream(wt_http3_driver_t *driver,
                                                             uint64_t stream_id) {
  size_t index;

  if (driver == NULL) return NULL;
  for (index = 0U; index < driver->capsule_stream_count; index++) {
    if (driver->capsule_streams[index].stream_id == stream_id)
      return &driver->capsule_streams[index];
  }
  return NULL;
}

wt_status_t wt_http3_driver_mark_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                                int headers_pending) {
  wt_http3_driver_capsule_stream_t *marked;

  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  marked = find_capsule_stream(driver, stream_id);
  if (marked != NULL) {
    /* Already marked: the FIRST mark's state stands. A caller that marked a stream whose HEADERS frame has not
     * arrived and then marks it again has not made that frame arrive sooner, and letting the second call settle it
     * early would route the HEADERS frame itself as capsules. */
    return WT_OK;
  }
  if (driver->capsule_stream_count >= WT_HTTP3_DRIVER_CAPSULE_STREAMS_MAX) return WT_ERR_LIMIT;
  driver->capsule_streams[driver->capsule_stream_count].stream_id = stream_id;
  driver->capsule_streams[driver->capsule_stream_count].headers_pending =
      headers_pending != 0 ? 1 : 0;
  driver->capsule_stream_count++;
  return WT_OK;
}

int wt_http3_driver_is_capsule_stream(const wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t index;

  if (driver == NULL) return 0;
  for (index = 0U; index < driver->capsule_stream_count; index++) {
    if (driver->capsule_streams[index].stream_id == stream_id) {
      return driver->capsule_streams[index].headers_pending == 0 ? 1 : 0;
    }
  }
  return 0;
}

/* The HEADERS frame of a marked CONNECT stream has been delivered: the stream's capsules begin here. Any frame
 * state is dropped with the mark, because a stream that is no longer framed must not keep a half-read frame header
 * that a later capsule byte would be appended to. */
void settle_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id) {
  wt_http3_driver_capsule_stream_t *marked = find_capsule_stream(driver, stream_id);

  if (marked == NULL || marked->headers_pending == 0) return;
  marked->headers_pending = 0;
  (void)wt_http3_driver_forget_frame(driver, stream_id);
}
