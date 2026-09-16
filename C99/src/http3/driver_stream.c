/* Driving an HTTP/3 endpoint from a connection (Phase 9): stream prefixes and frame boundaries.
 *
 * A unidirectional stream's type prefix and, for the draft's WebTransport type, the session ID that
 * follows it are reassembled here, across as many STREAM frames as the peer chose to use; the same
 * file turns an HTTP/3 stream's bytes into frames and reports each one's payload to the sink. This
 * is the receiving half of the driver; `driver.c` owns the tables it holds bytes in. */

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/http3/driver.h"

#include "webtransport/webtransport/error.h"

#include "webtransport/cursor.h"
#include <string.h>

#include "webtransport/quic/stream.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/quic/varint.h"

#include "driver_internal.h"


/* How much of `bytes` completes a varint from `have` bytes already held, or zero when the
 * prefix is still incomplete. The bound is the varint's own length encoding: the first byte's
 * top two bits say how many bytes the whole thing takes, so a prefix can never need more
 * than eight. */
static size_t prefix_needed(const uint8_t *bytes, size_t have) {
  uint8_t first = bytes[0];
  size_t width = (size_t)1U << (first >> 6);
  (void)have;
  return width;
}

/* How many bytes the WHOLE prefix of a unidirectional stream needs, given `have` bytes assembled so far. The
 * prefix is the stream TYPE varint and -- for the draft's WebTransport type -- the SESSION ID varint that
 * follows it (draft-16 section 4.2); the session ID is part of the prefix, not payload, so it is reassembled
 * here exactly as the type is. The answer never exceeds 8 + 8 = 16, which is the pending table's own bound, and
 * a value larger than `have` means more bytes are needed. */
static size_t uni_prefix_length(const uint8_t *bytes, size_t have) {
  size_t type_width;
  wt_cursor_t cursor;
  uint64_t type = 0U;

  if (have == 0U) return 1U; /* wait for the type's first byte */
  type_width = prefix_needed(bytes, have);
  if (have < type_width) return type_width;
  cursor = wt_cursor_init(bytes, type_width);
  if (wt_quic_varint_decode(&cursor, &type) != WT_OK) return type_width;
  if (type != WT_WEBTRANSPORT_STREAM_UNI) return type_width;
  if (have == type_width) return type_width + 1U; /* wait for the session ID's first byte */
  return type_width + prefix_needed(bytes + type_width, have - type_width);
}

wt_status_t wt_http3_driver_on_uni_stream_data(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t offset, const uint8_t *data, size_t length,
                                               wt_http3_endpoint_stream_kind_t *out_kind,
                                               const uint8_t **out_payload,
                                               size_t *out_payload_length,
                                               size_t *out_prefix_consumed,
                                               wt_http3_error_t *out_error) {
  wt_http3_driver_pending_t *pending;
  /* `have` is the contract: only the first `have` bytes are ever read, and `uni_prefix_length`
   * returns before touching a byte when `have == 0`, so the copy below can be skipped. That is
   * true of the code but was not provable to cppcheck, which reported `uninitvar` at the
   * `uni_prefix_length(prefix, have)` call and failed the gate (`--error-exitcode=1`). Sixteen
   * bytes of zeroing make it provable, and the check still fails on a real uninitialised read. */
  uint8_t prefix[WT_HTTP3_DRIVER_PREFIX_MAX] = {0};
  size_t have = 0U;
  size_t needed;
  size_t take = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (out_kind != NULL) *out_kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  if (out_payload != NULL) *out_payload = NULL;
  if (out_payload_length != NULL) *out_payload_length = 0U;
  if (out_prefix_consumed != NULL) *out_prefix_consumed = 0U;
  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  pending = find_pending(driver, stream_id);
  if (pending != NULL) {
    /* The claim has to hold for the whole stream: a prefix that started at offset zero and
     * resumes at anything else means the caller is not replaying the stream in order. */
    if (offset != pending->length) return WT_ERR_STATE;
    have = pending->length;
  } else if (offset != 0U) {
    /* The stream's first byte was never seen, so nothing here can be classified. This is the
     * caller's accounting, not the peer's. */
    return WT_ERR_STATE;
  }

  if (length == 0U) {
    /* No bytes: nothing to add, nothing classified. A peer may send an empty STREAM frame. */
    return WT_OK;
  }

  /* Hold the prefix in one place while it is read, so the two sources (what was held and
   * what just arrived) look the same to the classifier. */
  if (have > 0U) {
    size_t i;
    for (i = 0U; i < have; i++) prefix[i] = pending->bytes[i];
  }

  /* Assemble the WHOLE prefix -- the stream type and, for the draft's WebTransport type, the session ID that
   * follows it -- before anything is classified. Classifying the type as soon as IT was complete is the defect
   * this loop closes: a frame carrying only the type marked the stream WEBTRANSPORT in the endpoint and then
   * returned WT_ERR_TRUNCATED, so the connection closed with INTERNAL_ERROR for a legal fragmented prefix, and
   * the later frame that completed it saw a stored WEBTRANSPORT kind and handed the session ID's bytes to the
   * session with no session check at all. A QUIC peer may put the type and the session ID in separate STREAM
   * frames, so the held bytes are reassembled here and the type is decoded only when both varints are in. */
  for (;;) {
    needed = uni_prefix_length(prefix, have);
    if (have >= needed) break;
    {
      size_t want = needed - have;
      size_t i;
      if (want > length - take) want = length - take;
      for (i = 0U; i < want; i++) prefix[have + i] = data[take + i];
      have += want;
      take += want;
      if (out_prefix_consumed != NULL) *out_prefix_consumed = take;
      if (want == 0U) break;
    }
  }

  if (have < needed) {
    /* Still incomplete, and incomplete is not malformed on a stream: hold what there is and
     * wait. The table is fixed, so a peer that opens more streams than this has run into the
     * endpoint's bound rather than the protocol's. */
    if (pending == NULL) {
      if (driver->pending_count >= WT_HTTP3_DRIVER_PENDING_MAX) return WT_ERR_LIMIT;
      pending = &driver->pending[driver->pending_count];
      pending->stream_id = stream_id;
      pending->length = 0U;
      driver->pending_count++;
    }
    {
      size_t i;
      for (i = 0U; i < have; i++) pending->bytes[i] = prefix[i];
    }
    pending->length = have;
    return WT_OK;
  }

  /* The prefix is complete, so the local copy above replaces the held bytes: the table entry goes whether or
   * not classification succeeds. */
  if (pending != NULL) forget_pending(driver, stream_id);

  {
    wt_cursor_t type_cursor = wt_cursor_init(prefix, have);
    uint64_t type = 0U;
    uint64_t session_id = 0U;
    int is_webtransport = 0;

    if (wt_quic_varint_decode(&type_cursor, &type) != WT_OK) return WT_ERR_TRUNCATED;
    if (type == WT_WEBTRANSPORT_STREAM_UNI) {
      size_t type_bytes = have - wt_cursor_remaining(&type_cursor);
      wt_cursor_t session_cursor = wt_cursor_init(prefix + type_bytes, have - type_bytes);
      if (wt_quic_varint_decode(&session_cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
      /* The session the prefix names must be THIS session, and the check is here -- BEFORE the endpoint is told
       * the stream's kind -- because classification is what makes a later frame on this stream skip the prefix
       * entirely, and because a stream for somebody else must leave no trace in the endpoint table. Sessions on
       * one connection are mutually hostile: the draft says a stream that names a session this endpoint does
       * not have is H3_ID_ERROR, and a data stream is the easiest place to smuggle one. */
      if (driver->session_id_set != 0 && session_id != driver->session_id) {
        if (out_error != NULL) *out_error = WT_HTTP3_ID_ERROR;
        return WT_ERR_PROTOCOL;
      }
      is_webtransport = 1;
    }

    /* The prefix is settled. Classify it through the endpoint, which applies the rules that belong to a stream
     * of that type -- one control stream, one of each QPACK stream, and the draft's WebTransport type claimed
     * for the layer above. */
    status = wt_http3_endpoint_on_uni_stream(driver->endpoint, stream_id, prefix, have, NULL, out_kind,
                                             out_error);
    if (status != WT_OK) return status;

    if (is_webtransport != 0) {
      /* The stream is remembered, with the session its prefix named (WT-180). A peer's unidirectional
       * WebTransport stream is a data stream like a bidirectional one -- section 4.6's buffering rule and
       * section 6's reset both apply to it -- and the ID in its prefix is what a caller asks for when it needs
       * to know whether the session is known yet. Remembering it also means the bytes that follow are routed as
       * the session's rather than classified a second time. */
      wt_status_t remembered = remember_data_stream(driver, stream_id, 0U, session_id, 1);
      if (remembered != WT_OK) return remembered;
    }
  }

  if (out_payload != NULL) *out_payload = data + take;
  if (out_payload_length != NULL) *out_payload_length = length - take;
  return WT_OK;
}

wt_status_t wt_http3_driver_on_uni_stream_end(wt_http3_driver_t *driver, uint64_t stream_id,
                                              wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (find_pending(driver, stream_id) != NULL) {
    /* The stream ended before its type prefix was complete, so it never became a stream of
     * any type and there is nothing for the endpoint's rules to apply to. */
    forget_pending(driver, stream_id);
    (void)wt_http3_driver_forget_frame(driver, stream_id);
    return WT_OK;
  }
  {
    /* The stream is over, so any frame state it had goes with it: this is one of the two release points (the
     * other is the fin path in `on_stream_bytes`), and without them the eight-slot table filled up and stayed
     * full. */
    wt_status_t status = wt_http3_endpoint_on_uni_stream_end(driver->endpoint, stream_id, out_error);
    (void)wt_http3_driver_forget_frame(driver, stream_id);
    return status;
  }
}

/* ---------------------------------------------- frame boundaries */

static wt_http3_driver_frame_state_t *find_frame_state(wt_http3_driver_t *driver,
                                                       uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->frame_count; i++) {
    if (driver->frames[i].stream_id == stream_id) return &driver->frames[i];
  }
  return NULL;
}

int wt_http3_driver_forget_frame(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;

  if (driver == NULL) return 0;
  for (i = 0U; i < driver->frame_count; i++) {
    if (driver->frames[i].stream_id == stream_id) {
      int was_in_frame = driver->frames[i].in_frame;
      /* RELEASED, not merely cleared. The comment here used to say "the slot is kept while the stream lives",
       * which is right -- and the stream's END is exactly when that stops being true, except that nothing on the
       * request path called this at all: eight streams that began and ended left the table full and the ninth
       * stream was refused WT_ERR_LIMIT, which an audit reproduced with eight empty DATA frames. The table is
       * unordered, so the last entry fills the hole. */
      driver->frames[i] = driver->frames[driver->frame_count - 1U];
      driver->frame_count--;
      return was_in_frame;
    }
  }
  return 0;
}

/* A varint at the start of `bytes`, and how many bytes it took, or zero when it is not yet
 * complete. */
static size_t read_varint(const uint8_t *bytes, size_t length, uint64_t *out) {
  wt_cursor_t c = wt_cursor_init(bytes, length);
  uint64_t value = 0U;
  if (wt_quic_varint_decode(&c, &value) != WT_OK) return 0U;
  *out = value;
  return length - wt_cursor_remaining(&c);
}

wt_status_t wt_http3_driver_on_stream_bytes(wt_http3_driver_t *driver, uint64_t stream_id,
                                            const uint8_t *data, size_t length, int fin,
                                            uint64_t max_frame_bytes,
                                            const wt_http3_driver_sink_t *sink,
                                            wt_http3_error_t *out_error) {
  wt_http3_driver_frame_state_t *state;
  size_t position = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  /* A WebTransport CONNECT stream whose one HEADERS frame has passed carries the SESSION's capsules, not HTTP/3
   * frames (draft-16 section 5): a capsule's type is a varint this parser would read as a frame type and its
   * length as a frame length, and for a flow-control capsule -- an UNKNOWN frame type -- that means the grant is
   * skipped in silence (WT-164). The stream-data sink is where the session's own bytes go, and capsules are
   * exactly that; which stream they belong to is the caller's to know, and it does.
   *
   * The check is here AND at the top of the loop below, and the loop's copy is not redundant: the mark can settle
   * DURING this call, because the sink marks the stream from inside the HEADERS frame's own delivery -- a server
   * marks when it accepts the request, and a client's mark settles as its response is delivered. A single check
   * before the loop would frame the capsules that arrived in the same STREAM frame as that HEADERS. */
  if (wt_http3_driver_is_capsule_stream(driver, stream_id)) {
    if (sink == NULL || sink->on_stream_data == NULL || (length == 0U && fin == 0)) return WT_OK;
    return sink->on_stream_data(sink->context, stream_id, length == 0U ? NULL : data, length, fin);
  }

  state = find_frame_state(driver, stream_id);
  if (state == NULL) {
    if (driver->frame_count >= WT_HTTP3_DRIVER_FRAMES_MAX) return WT_ERR_LIMIT;
    state = &driver->frames[driver->frame_count];
    state->stream_id = stream_id;
    state->header_length = 0U;
    state->in_frame = 0;
    driver->frame_count++;
  }

  while (position < length) {
    if (wt_http3_driver_is_capsule_stream(driver, stream_id)) {
      if (sink == NULL || sink->on_stream_data == NULL) return WT_OK;
      return sink->on_stream_data(sink->context, stream_id, data + position, length - position, fin);
    }
    if (!state->in_frame) {
      /* Fill the header before the payload: the length is what says how much payload to
       * expect, so the header has to be complete first. */
      while (position < length &&
             state->header_length < (size_t)WT_HTTP3_DRIVER_FRAME_HEADER_MAX) {
        state->header[state->header_length] = data[position];
        state->header_length++;
        position++;
        {
          uint64_t type = 0U;
          uint64_t payload_length = 0U;
          size_t type_bytes = read_varint(state->header, state->header_length, &type);
          size_t length_bytes;
          if (type_bytes == 0U) continue;
          length_bytes = read_varint(state->header + type_bytes, state->header_length - type_bytes,
                                     &payload_length);
          if (length_bytes == 0U) continue;
          if (payload_length > max_frame_bytes) {
            /* The peer's declared length is over what this endpoint will deliver, so it is
             * excessive load rather than a buffer to allocate. */
            state->header_length = 0U;
            if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
            return WT_ERR_LIMIT;
          }
          state->type = type;
          state->payload_length = payload_length;
          state->payload_received = 0U;
          state->in_frame = 1;
          /* The header loop appends ONE byte at a time and breaks the moment both varints
           * parse, so header_length == type_bytes + length_bytes here and there is never a
           * remainder to shift down. The clear is still required: the payload path below reads
           * a non-zero header_length as "payload bytes arrived with the header". A copy loop
           * sized by the (always zero) remainder was here and is gone. */
          state->header_length = 0U;
          break;
        }
      }
      if (!state->in_frame) continue;
    }

    /* Inside a frame: deliver what has arrived, up to what is left of it. */
    {
      uint64_t remaining = state->payload_length - state->payload_received;
      size_t available = length - position;
      size_t take = available;
      int last;

      if (state->header_length > 0U) {
        /* Bytes that arrived with the header are the payload's start. */
        size_t from_header = state->header_length;
        if ((uint64_t)from_header >= remaining) from_header = (size_t)remaining;
        if (sink != NULL && sink->on_frame_payload != NULL) {
          last = ((uint64_t)from_header == remaining) ? 1 : 0;
          {
            wt_status_t status = sink->on_frame_payload(sink->context, stream_id, state->type,
                                                       state->header, from_header, last);
            if (status != WT_OK) return status;
          }
        }
        state->payload_received += (uint64_t)from_header;
        state->header_length = 0U;
        if (state->payload_received == state->payload_length) {
          /* The frame is over, so the flag is cleared BEFORE the stream may be settled below. Settling calls
           * `wt_http3_driver_forget_frame`, which RELEASES this stream's slot and fills it with the table's last
           * entry -- another live stream, possibly mid-frame. Writing `state->in_frame = 0` after that would
           * clear THAT stream's flag through the stale pointer and desynchronise its framing. */
          state->in_frame = 0;
          if (state->type == (uint64_t)WT_HTTP3_FRAME_HEADERS) settle_capsule_stream(driver, stream_id);
          continue;
        }
      }

      if ((uint64_t)take > remaining) take = (size_t)remaining;
      if (take > 0U) {
        if (sink != NULL && sink->on_frame_payload != NULL) {
          last = ((uint64_t)take == remaining) ? 1 : 0;
          {
            wt_status_t status = sink->on_frame_payload(sink->context, stream_id, state->type,
                                                       data + position, take, last);
            if (status != WT_OK) return status;
          }
        }
        state->payload_received += (uint64_t)take;
        position += take;
      }
      if (state->payload_received == state->payload_length) {
        if (state->payload_length == 0U && sink != NULL && sink->on_frame_payload != NULL) {
          /* An empty frame is still a frame: report it once, with nothing in it. */
          wt_status_t status = sink->on_frame_payload(sink->context, stream_id, state->type, NULL,
                                                      0U, 1);
          if (status != WT_OK) return status;
        }
        /* Cleared BEFORE the settle, for the reason given at the other completion point above: the settle
         * releases this slot and refills it from the table's tail. */
        state->in_frame = 0;
        if (state->type == (uint64_t)WT_HTTP3_FRAME_HEADERS) settle_capsule_stream(driver, stream_id);
      }
    }
  }

  /* The stream's own end, on a CONNECT stream whose capsules have begun: there is no frame state to report, but
   * the session has to be told the stream is over. This is also where a mark that settled on the last byte of this
   * buffer is honoured -- the loop above has no bytes left to test it with. */
  if (fin != 0 && wt_http3_driver_is_capsule_stream(driver, stream_id)) {
    if (sink == NULL || sink->on_stream_data == NULL) return WT_OK;
    return sink->on_stream_data(sink->context, stream_id, NULL, 0U, fin);
  }

  if (fin != 0) {
    /* The stream ended part way through a frame -- and a partial frame HEADER counts, which is the case a naive
     * implementation misses: one byte of a two-varint header is exactly as incomplete as one byte of a payload.
     * Nothing more is coming, which is what turns the wait into a refusal. Read BEFORE the slot is released,
     * because `state` points into the table. */
    int incomplete = state->in_frame || state->header_length > 0U;
    (void)wt_http3_driver_forget_frame(driver, stream_id);
    if (incomplete) {
      if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
      return WT_ERR_TRUNCATED;
    }
  }
  return WT_OK;
}
