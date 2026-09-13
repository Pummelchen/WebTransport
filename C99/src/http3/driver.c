/* Driving an HTTP/3 endpoint from a connection (Phase 9). */

#include "webtransport/http3/driver.h"

#include "webtransport/cursor.h"
#include <string.h>

#include "webtransport/quic/stream.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/quic/varint.h"

void wt_http3_driver_init(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint) {
  size_t i;

  if (driver == NULL) return;
  driver->endpoint = endpoint;
  driver->pending_count = 0U;
  driver->frame_count = 0U;
  for (i = 0U; i < WT_HTTP3_DRIVER_FRAMES_MAX; i++) {
    driver->frames[i].stream_id = 0U;
    driver->frames[i].header_length = 0U;
    driver->frames[i].in_frame = 0;
  }
  for (i = 0U; i < WT_HTTP3_DRIVER_PENDING_MAX; i++) {
    driver->pending[i].stream_id = 0U;
    driver->pending[i].length = 0U;
  }
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
  return wt_http3_endpoint_write_prefix(
      driver->endpoint,
      encoder != 0 ? WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER : WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER,
      w);
}

static wt_http3_driver_pending_t *find_pending(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->pending_count; i++) {
    if (driver->pending[i].stream_id == stream_id) return &driver->pending[i];
  }
  return NULL;
}

static void forget_pending(wt_http3_driver_t *driver, uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < driver->pending_count; i++) {
    if (driver->pending[i].stream_id == stream_id) {
      driver->pending[i] = driver->pending[driver->pending_count - 1U];
      driver->pending_count--;
      return;
    }
  }
}

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

wt_status_t wt_http3_driver_on_uni_stream_data(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t offset, const uint8_t *data, size_t length,
                                               wt_http3_endpoint_stream_kind_t *out_kind,
                                               const uint8_t **out_payload,
                                               size_t *out_payload_length,
                                               size_t *out_prefix_consumed,
                                               wt_http3_error_t *out_error) {
  wt_http3_driver_pending_t *pending;
  uint8_t prefix[WT_HTTP3_DRIVER_PREFIX_MAX];
  size_t have = 0U;
  size_t needed;
  size_t take;
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
  needed = prefix_needed(have > 0U ? prefix : data, have);
  take = needed > have ? needed - have : 0U;
  if (take > length) take = length;
  {
    size_t i;
    for (i = 0U; i < take; i++) prefix[have + i] = data[i];
  }
  have += take;
  if (out_prefix_consumed != NULL) *out_prefix_consumed = take;

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

  /* The prefix is complete. Classify it through the endpoint, which applies the rules that
   * belong to a stream of that type -- one control stream, one of each QPACK stream, and the
   * draft's WebTransport type claimed for the layer above. */
  status = wt_http3_endpoint_on_uni_stream(driver->endpoint, stream_id, prefix, have, NULL,
                                           out_kind, out_error);
  if (pending != NULL) forget_pending(driver, stream_id);
  if (status != WT_OK) return status;

  /* A WEBTRANSPORT stream's prefix is the TYPE and then the session ID (draft-16 section 4.2), and the type
   * classifier above reads only the type. The session ID is part of the prefix, so the bytes the session is
   * handed must start AFTER it -- the first version of this path passed it along as data, which arrived as one
   * leading byte nobody could explain. It must arrive in the same frame as the type here: a session ID split
   * across frames would need the pending table's reassembly for a varint, and the honest answer until then is
   * WT_ERR_TRUNCATED rather than a byte of somebody's session ID in the payload. */
  if (out_kind != NULL && *out_kind == WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT) {
    wt_cursor_t session_cursor;
    uint64_t session_id = 0U;
    size_t session_bytes;

    if (take >= length) {
      /* The type used the whole frame: the session ID has not arrived. */
      return WT_ERR_TRUNCATED;
    }
    session_cursor = wt_cursor_init(data + take, length - take);
    if (wt_quic_varint_decode(&session_cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
    session_bytes = (length - take) - wt_cursor_remaining(&session_cursor);
    take += session_bytes;
    /* The caller is told how much of ITS frame went to the whole prefix -- type and session ID -- because
     * that is the number it needs to continue at the right offset. */
    if (out_prefix_consumed != NULL) *out_prefix_consumed = take;
    (void)session_id;
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
    return WT_OK;
  }
  return wt_http3_endpoint_on_uni_stream_end(driver->endpoint, stream_id, out_error);
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
      driver->frames[i].in_frame = 0;
      driver->frames[i].header_length = 0U;
      driver->frames[i].payload_received = 0U;
      driver->frames[i].payload_length = 0U;
      /* The slot is kept while the stream lives: a stream's frames are its own sequence. */
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
          /* The header's bytes are consumed; what is left of it in the buffer is the start of
           * the payload, which the loop below delivers. */
          {
            size_t header_bytes = type_bytes + length_bytes;
            size_t leftover = state->header_length - header_bytes;
            size_t i;
            for (i = 0U; i < leftover; i++) state->header[i] = state->header[header_bytes + i];
            state->header_length = leftover;
          }
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
          state->in_frame = 0;
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
        state->in_frame = 0;
      }
    }
  }

  if (fin != 0 && (state->in_frame || state->header_length > 0U)) {
    /* The stream ended part way through a frame -- and a partial frame HEADER counts, which is
     * the case a naive implementation misses: one byte of a two-varint header is exactly as
     * incomplete as one byte of a payload. Nothing more is coming, which is what turns the
     * wait into a refusal. */
    state->in_frame = 0;
    state->header_length = 0U;
    if (out_error != NULL) *out_error = WT_HTTP3_FRAME_ERROR;
    return WT_ERR_TRUNCATED;
  }
  return WT_OK;
}

/* ---------------------------------------------- routing a connection's frames */

/* Whether this endpoint is the one that opens a stream with this ID: the low bit of a QUIC
 * stream ID says which side initiated it (RFC 9000 section 2.1). */
static int stream_is_ours(const wt_http3_endpoint_t *endpoint, uint64_t stream_id) {
  int from_client = wt_quic_stream_id_from_client(stream_id);
  return endpoint->role == WT_HTTP3_ROLE_CLIENT ? from_client : !from_client;
}

wt_status_t wt_http3_driver_on_quic_frame(void *context, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame,
                                          const wt_http3_driver_sink_t *sink,
                                          uint64_t max_frame_bytes) {
  wt_http3_driver_t *driver = context;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_status_t status;

  (void)space;
  if (driver == NULL || driver->endpoint == NULL || frame == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* An if-chain rather than a switch, and the reason is the compiler: -Wswitch-enum requires
   * every enumerator of a switch to be named, and this handler deliberately acts on two of
   * them and ignores the rest. Naming twenty-one no-op cases to satisfy the warning would
   * make the two that matter harder to find, which is the opposite of what the warning is
   * for. */
  if (frame->kind == WT_QUIC_FRAME_KIND_STREAM) {
      uint64_t stream_id = frame->as.stream.id;
      if (stream_is_ours(driver->endpoint, stream_id) &&
          !wt_quic_stream_id_is_bidirectional(stream_id)) {
        /* A UNIDIRECTIONAL stream this endpoint opened: the peer cannot write on it, so there is nothing to
         * route. A BIDIRECTIONAL one is a different matter, and dropping it here (which this code did) is why
         * the response never reached the caller: the peer's frames on a stream WE opened ARE the response, and
         * RFC 9114 section 4.1 gives the two directions of one exchange their own HEADERS frames on that same
         * stream. The connection delivered the frame, the chain called this layer, and this early return said
         * there was nothing to route. */
        return WT_OK;
      }
      if (wt_quic_stream_id_is_bidirectional(stream_id)) {
        /* A bidirectional stream is a request stream -- and there are TWO ways this layer meets one. If the
         * endpoint already tracks it, this endpoint OPENED it and what arrives is the RESPONSE, which is the
         * other direction of the same exchange (RFC 9114 section 4.1 gives each direction its own HEADERS).
         * If it does not, the peer initiated it and it becomes a request stream now.
         *
         * Getting this wrong is what stopped the response from arriving: routing a tracked stream through
         * `on_request_stream` again is refused as a duplicate, and the refusal ABORTED the frame routing, so
         * the response was never reported to the caller at all. */
        wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
        if (wt_http3_endpoint_request_state(driver->endpoint, stream_id, &state) != WT_OK) {
          status = wt_http3_endpoint_on_request_stream(driver->endpoint, stream_id, &error);
          if (status != WT_OK) return status;
        }
        return wt_http3_driver_on_stream_bytes(driver, stream_id, frame->as.stream.data,
                                               frame->as.stream.length, frame->as.stream.fin,
                                               max_frame_bytes, sink, &error);
      }

      /* A peer-initiated unidirectional stream: its type prefix first, then whichever of the
       * two kinds of bytes the type says follow it. */
      {
        wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
        const uint8_t *payload = NULL;
        size_t payload_length = 0U;
        size_t consumed = 0U;
        int finished_prefix;

        /* A stream the endpoint already classified does not carry a prefix any more. */
        kind = wt_http3_endpoint_stream_kind(driver->endpoint, stream_id);
        finished_prefix = kind != WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
        if (finished_prefix) {
          payload = frame->as.stream.data;
          payload_length = frame->as.stream.length;
        } else {
          status = wt_http3_driver_on_uni_stream_data(driver, stream_id, frame->as.stream.offset,
                                                      frame->as.stream.data, frame->as.stream.length,
                                                      &kind, &payload, &payload_length, &consumed,
                                                      &error);
          if (status != WT_OK) return status;
          if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN) {
            /* The prefix is still not complete: the bytes are held, and nothing is routed. */
            return WT_OK;
          }
        }

        if (kind == WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT) {
          /* The session's own stream: its bytes are not HTTP/3 frames, so they go to the
           * session as they are. */
          if (sink != NULL && sink->on_stream_data != NULL && payload_length > 0U) {
            return sink->on_stream_data(sink->context, stream_id, payload, payload_length,
                                        frame->as.stream.fin);
          }
          return WT_OK;
        }
        if (kind == WT_HTTP3_ENDPOINT_STREAM_UNKNOWN) {
          /* A stream type this build does not know: section 6.2.1 says stop reading it, so its
           * bytes are dropped and its end is still reported to the endpoint. */
          if (frame->as.stream.fin != 0) {
            return wt_http3_driver_on_uni_stream_end(driver, stream_id, &error);
          }
          return WT_OK;
        }

        /* HTTP/3's own streams carry frames, and the frame boundary is reassembled for them
         * the same way it is for a request stream. */
        if (payload_length > 0U || frame->as.stream.fin != 0) {
          status = wt_http3_driver_on_stream_bytes(driver, stream_id, payload, payload_length,
                                                   frame->as.stream.fin, max_frame_bytes, sink,
                                                   &error);
          if (status != WT_OK) return status;
        }
        if (frame->as.stream.fin != 0) {
          return wt_http3_driver_on_uni_stream_end(driver, stream_id, &error);
        }
        return WT_OK;
      }
  }
  if (frame->kind == WT_QUIC_FRAME_KIND_DATAGRAM) {
    /* The payload is the session's, and this layer does not look inside it: what a datagram
     * means is the draft's framing, which the session layer reads. */
    if (sink != NULL && sink->on_datagram != NULL) {
      return sink->on_datagram(sink->context, frame->as.datagram.data, frame->as.datagram.length);
    }
    return WT_OK;
  }
  /* Every other kind belongs to the connection or to nobody here. */
  return WT_OK;
}

/* ---------------------------------------------- sending through a transport */

wt_status_t wt_http3_driver_start_own_streams(wt_http3_driver_t *driver,
                                              const wt_http3_driver_transport_t *transport,
                                              const wt_http3_settings_t *settings, uint64_t now) {
  uint64_t stream_id = 0U;
  wt_writer_t w;
  size_t length;
  wt_status_t status;
  int i;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || transport->send_stream == NULL || settings == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* Each stream is BUILT before it is opened, and that order is deliberate: the once-per-
   * connection rules are applied while the bytes are built, so a second call refuses without
   * opening a stream it would then have nothing to send on. An orphaned stream is a stream the
   * peer sees and this endpoint cannot explain.
   *
   * The frame goes into the first half of the scratch and its payload into the second, so the
   * two cannot overlap while a payload is smaller than half the buffer -- which the SETTINGS
   * encoder's own bound enforces. */
  w = wt_writer_init(driver->scratch, sizeof(driver->scratch) / 2U);
  status = wt_http3_driver_start_control(driver, settings,
                                         driver->scratch + sizeof(driver->scratch) / 2U,
                                         sizeof(driver->scratch) / 2U, &w);
  if (status != WT_OK) return status;
  length = wt_writer_offset(&w);
  status = transport->open_stream(transport->context, 0, &stream_id, now);
  if (status != WT_OK) return status;
  status = transport->send_stream(transport->context, stream_id, driver->scratch, length, 0, now);
  if (status != WT_OK) return status;

  /* The two QPACK streams: their prefixes alone, since what follows on them is the QPACK
   * layer's to write. */
  for (i = 0; i < 2; i++) {
    w = wt_writer_init(driver->scratch, sizeof(driver->scratch) / 2U);
    status = wt_http3_driver_start_qpack_stream(driver, i == 0 ? 1 : 0, &w);
    if (status != WT_OK) return status;
    length = wt_writer_offset(&w);
    status = transport->open_stream(transport->context, 0, &stream_id, now);
    if (status != WT_OK) return status;
    status = transport->send_stream(transport->context, stream_id, driver->scratch, length, 0, now);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}

wt_status_t wt_http3_driver_open_request(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport, uint64_t now,
                                         uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || out_stream_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* A request stream is BIDIRECTIONAL and this endpoint initiates it: HTTP/3 has no server-initiated
   * request, which the endpoint's own rule also enforces. */
  status = transport->open_stream(transport->context, 1, &stream_id, now);
  if (status != WT_OK) return status;
  status = wt_http3_endpoint_open_request(driver->endpoint, stream_id, out_error);
  if (status != WT_OK) return status;
  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_message(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport,
                                         uint64_t stream_id, const wt_http3_message_t *message,
                                         uint64_t peer_max_entries, int fin, uint64_t now) {
  wt_writer_t w;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  w = wt_writer_init(driver->scratch, sizeof(driver->scratch));
  status = wt_http3_endpoint_write_headers(driver->endpoint, message, peer_max_entries,
                                           driver->scratch + 256U,
                                           sizeof(driver->scratch) - 256U, &w, NULL);
  if (status != WT_OK) return status;
  return transport->send_stream(transport->context, stream_id, driver->scratch,
                                wt_writer_offset(&w), fin, now);
}

wt_status_t wt_http3_driver_classify_bidi_start(const uint8_t *bytes, size_t length,
                                                wt_http3_bidi_start_kind_t *out_kind,
                                                uint64_t *out_session_id, size_t *out_consumed) {
  wt_cursor_t cursor;
  uint64_t type = 0U;
  uint64_t session_id = 0U;
  size_t type_bytes;
  size_t session_bytes;

  if (out_kind == NULL || out_session_id == NULL || out_consumed == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_kind = WT_HTTP3_BIDI_START_REQUEST;
  *out_session_id = 0U;
  *out_consumed = 0U;
  if (bytes == NULL) return length == 0U ? WT_OK : WT_ERR_INVALID_ARGUMENT;

  cursor = wt_cursor_init(bytes, length);
  if (wt_quic_varint_decode(&cursor, &type) != WT_OK) {
    /* Not even the type has arrived. On a stream that is a wait: the caller comes back with more bytes. */
    return WT_ERR_TRUNCATED;
  }
  if (type != WT_WEBTRANSPORT_STREAM_BIDI) {
    /* An HTTP/3 request stream, and the type varint it "has" is really the first byte of a QPACK prefix. */
    return WT_OK;
  }
  type_bytes = length - wt_cursor_remaining(&cursor);
  if (wt_quic_varint_decode(&cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
  session_bytes = (length - type_bytes) - wt_cursor_remaining(&cursor);
  *out_kind = WT_HTTP3_BIDI_START_WEBTRANSPORT;
  *out_session_id = session_id;
  *out_consumed = type_bytes + session_bytes;
  return WT_OK;
}

wt_status_t wt_http3_driver_start_session(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const wt_http3_settings_t *settings, const char *authority,
                                          const char *path, uint64_t peer_max_entries, uint64_t now,
                                          uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  wt_http3_message_t request;
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL || settings == NULL ||
      authority == NULL || path == NULL || out_stream_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The endpoint's own streams first: a CONNECT cannot be interpreted by a peer that has not been told what
   * this endpoint's SETTINGS say, and the QPACK streams are what any field section may reference. */
  status = wt_http3_driver_start_own_streams(driver, transport, settings, now);
  if (status != WT_OK) return status;

  status = wt_http3_driver_open_request(driver, transport, now, &stream_id, out_error);
  if (status != WT_OK) return status;

  /* The extended CONNECT of draft-16 section 3.1, as the fields the request line needs: CONNECT with a
   * :protocol, over https, for the authority and path the caller named. */
  memset(&request, 0, sizeof(request));
  request.type = WT_HTTP3_HEADER_REQUEST;
  request.method = (const uint8_t *)"CONNECT";
  request.method_length = 7U;
  request.scheme = (const uint8_t *)"https";
  request.scheme_length = 5U;
  request.authority = (const uint8_t *)authority;
  request.authority_length = strlen(authority);
  request.path = (const uint8_t *)path;
  request.path_length = strlen(path);
  request.protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
  request.protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);

  status = wt_http3_driver_send_message(driver, transport, stream_id, &request, peer_max_entries, 0,
                                        now);
  if (status != WT_OK) return status;
  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_response(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          uint64_t stream_id, uint32_t status, uint64_t peer_max_entries,
                                          int fin, uint64_t now) {
  wt_http3_message_t response;

  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(&response, 0, sizeof(response));
  response.type = WT_HTTP3_HEADER_RESPONSE;
  response.status = (uint64_t)status;
  response.has_status = 1;
  return wt_http3_driver_send_message(driver, transport, stream_id, &response, peer_max_entries, fin,
                                      now);
}

wt_status_t wt_http3_driver_send_datagram(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const uint8_t *data, size_t length) {
  if (driver == NULL || transport == NULL || transport->send_datagram == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  return transport->send_datagram(transport->context, data, length);
}
