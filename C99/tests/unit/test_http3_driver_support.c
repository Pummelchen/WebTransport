/* The recording sinks shared by the split `test_http3_driver` translation units.
 *
 * Each is a sink the driver hands a frame's payload, a stream's bytes or a datagram to, and each
 * records rather than acts so a test can assert what crossed the boundary. They are here rather
 * than in a topic file because more than one topic asserts against them; the types they fill are
 * in test_http3_driver_internal.h. */

#include "test_http3_driver_internal.h"

wt_status_t record_frame(void *context, uint64_t stream_id, uint64_t type, const uint8_t *payload,
                         size_t length, int last) {
  frame_log_t *log = context;
  (void)stream_id;
  if (length > 0U && log->total_bytes == 0U) log->first_byte = payload[0];
  log->total_bytes += length;
  if (last != 0) {
    log->frames++;
    log->last_type = type;
    log->last_was_last = 1U;
  }
  return WT_OK;
}

wt_status_t record_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                               size_t length, int fin) {
  session_log_t *log = context;
  (void)data;
  (void)fin;
  log->streams++;
  log->stream_bytes += length;
  log->last_stream_id = stream_id;
  return WT_OK;
}

wt_status_t record_datagram(void *context, const uint8_t *data, size_t length) {
  session_log_t *log = context;
  (void)data;
  log->datagrams++;
  log->datagram_bytes += length;
  return WT_OK;
}
