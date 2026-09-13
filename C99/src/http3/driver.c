/* Driving an HTTP/3 endpoint from a connection (Phase 9). */

#include "webtransport/http3/driver.h"

#include "webtransport/quic/varint.h"

void wt_http3_driver_init(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint) {
  size_t i;

  if (driver == NULL) return;
  driver->endpoint = endpoint;
  driver->pending_count = 0U;
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
