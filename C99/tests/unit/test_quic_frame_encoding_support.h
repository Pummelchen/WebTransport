/* Shared by the two halves of test_quic_frame.c.
 * Static FUNCTIONS become `static inline` so a unit that does not call one is not
 * warned about it; static data and the fake types stay as they are, one copy per
 * translation unit. A file-static helper cannot cross a translation unit, which is
 * why this header exists. */
#ifndef TEST_QUIC_FRAME_ACK_RANGES_SUPPORT_H
#define TEST_QUIC_FRAME_ACK_RANGES_SUPPORT_H

#include "vectors/rfc9001_client_initial.h"
#include "webtransport/quic/frame.h"
#include "wt_test.h"
static inline size_t encode_ok(const char *label, const wt_quic_frame_t *frame, uint8_t *buffer,
                               size_t capacity) {
  wt_writer_t w = wt_writer_init(buffer, capacity);
  wt_status_t status = wt_quic_frame_encode(&w, frame);
  WT_EXPECT_STATUS(label, WT_OK, status);
  WT_EXPECT_INT("  the writer did not overflow", 1, wt_writer_ok(&w));
  return wt_writer_offset(&w);
}
static inline wt_status_t round_trip(const char *label, const wt_quic_frame_t *frame,
                                     wt_quic_frame_t *out, uint8_t *buffer, size_t capacity) {
  wt_writer_t measure = wt_writer_measure();
  wt_cursor_t c;
  wt_quic_error_t error = 0U;
  wt_status_t status;
  size_t written;

  WT_EXPECT_STATUS(label, WT_OK, wt_quic_frame_encode(&measure, frame));
  if (wt_writer_offset(&measure) > capacity) {
    WT_EXPECT_TRUE("  the measurement fits the test buffer", 0);
    return WT_ERR_LIMIT;
  }
  written = encode_ok("  the encode", frame, buffer, capacity);
  /* The SECOND pass's real length against the measurement: this used to compare
   * `wt_writer_offset(&measure)` with itself, so the two-pass property the helper exists for was
   * never checked, and the discard of `encode_ok`'s return hid it. */
  WT_EXPECT_U64("  the encode wrote what the measurement said",
                (uint64_t)wt_writer_offset(&measure), (uint64_t)written);
  c = wt_cursor_init(buffer, written);
  status = wt_quic_frame_decode(&c, out, &error);
  if (status == WT_OK) {
    WT_EXPECT_INT("  the frame consumed its whole encoding", 1, wt_cursor_at_end(&c));
  }
  return status;
}
static inline wt_status_t count_frames(void *context, const wt_quic_frame_t *frame) {
  uint64_t *counts = (uint64_t *)context;
  counts[(size_t)frame->kind]++;
  return WT_OK;
}
static inline wt_status_t stop_at_ping(void *context, const wt_quic_frame_t *frame) {
  uint64_t *seen = (uint64_t *)context;
  (*seen)++;
  if (frame->kind == WT_QUIC_FRAME_KIND_PING) return WT_ERR_CLOSED;
  return WT_OK;
}

#endif
