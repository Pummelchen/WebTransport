#include "test_http3_driver_internal.h"

void test_frame_boundaries_on_a_stream(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  frame_log_t log;
  uint8_t bytes[32];
  wt_writer_t w;
  wt_http3_frame_t frame;

  memset(&log, 0, sizeof(log));
  sink.on_frame_payload = record_frame;
  sink.context = &log;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* A DATA frame with three bytes: one frame, three payload bytes. */
  w = wt_writer_init(bytes, sizeof(bytes));
  frame = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);
  frame.payload = (const uint8_t *)"abc";
  frame.length = 3U;
  WT_EXPECT_OK("a DATA frame writes", wt_http3_frame_encode(&w, &frame));
  WT_EXPECT_OK("and arrives", wt_http3_driver_on_stream_bytes(
                                  &driver, 3U, bytes, wt_writer_offset(&w), 0, 64U, &sink, &error));
  WT_EXPECT_U64("as one frame", 1U, (uint64_t)log.frames);
  WT_EXPECT_U64("of type data", WT_HTTP3_FRAME_DATA, log.last_type);
  WT_EXPECT_U64("with its three bytes", 3U, (uint64_t)log.total_bytes);
  WT_EXPECT_U64("the first of which arrived", (uint64_t)'a', (uint64_t)log.first_byte);

  /* The same frame split byte by byte: the boundary is reassembled, and the sink sees the
   * payload in pieces with `last` only at the end. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("a frame that arrives one byte at a time",
               wt_http3_driver_on_stream_bytes(&driver, 3U, bytes, 1U, 0, 64U, &sink, &error));
  WT_EXPECT_U64("is not a frame yet", 0U, (uint64_t)log.frames);
  WT_EXPECT_OK("its second byte",
               wt_http3_driver_on_stream_bytes(&driver, 3U, bytes + 1U, 1U, 0, 64U, &sink, &error));
  WT_EXPECT_U64("still none", 0U, (uint64_t)log.frames);
  WT_EXPECT_OK("and the rest",
               wt_http3_driver_on_stream_bytes(&driver, 3U, bytes + 2U, wt_writer_offset(&w) - 2U,
                                               0, 64U, &sink, &error));
  WT_EXPECT_U64("now it is one frame", 1U, (uint64_t)log.frames);
  WT_EXPECT_U64("with every byte of it", 3U, (uint64_t)log.total_bytes);

  /* A frame whose declared length is over the bound is excessive load, refused BEFORE any
   * payload is handed over: the peer's number, not this endpoint's buffer. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_STATUS("an oversized frame is refused", WT_ERR_LIMIT,
                   wt_http3_driver_on_stream_bytes(&driver, 3U, bytes, wt_writer_offset(&w), 0, 2U,
                                                   &sink, &error));
  WT_EXPECT_U64("with the excessive-load code", WT_HTTP3_EXCESSIVE_LOAD, (uint64_t)error);
  WT_EXPECT_U64("and nothing delivered", 0U, (uint64_t)log.frames);

  /* A stream that ends in the middle of a frame is incomplete, and `fin` is what turns the
   * wait into a refusal. */
  WT_EXPECT_OK("a partial frame arrives",
               wt_http3_driver_on_stream_bytes(&driver, 3U, bytes, 1U, 0, 64U, &sink, &error));
  WT_EXPECT_STATUS("and the stream ends there", WT_ERR_TRUNCATED,
                   wt_http3_driver_on_stream_bytes(&driver, 3U, NULL, 0U, 1, 64U, &sink, &error));
  WT_EXPECT_U64("with the frame error code", WT_HTTP3_FRAME_ERROR, (uint64_t)error);
  WT_EXPECT_INT("and the half-read frame forgotten", 0, wt_http3_driver_forget_frame(&driver, 3U));

  /* An empty frame is still a frame: the sink is told once, with nothing in it. */
  memset(&log, 0, sizeof(log));
  {
    uint8_t empty[8];
    wt_writer_t ew = wt_writer_init(empty, sizeof(empty));
    wt_http3_frame_t empty_frame = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);
    empty_frame.payload = NULL;
    empty_frame.length = 0U;
    WT_EXPECT_OK("an empty frame writes", wt_http3_frame_encode(&ew, &empty_frame));
    WT_EXPECT_OK("and arrives",
                 wt_http3_driver_on_stream_bytes(&driver, 7U, empty, wt_writer_offset(&ew), 0, 64U,
                                                 &sink, &error));
    WT_EXPECT_U64("as one frame", 1U, (uint64_t)log.frames);
    WT_EXPECT_U64("with nothing in it", 0U, (uint64_t)log.total_bytes);
  }

  /* Two streams' frames do not run into each other: the boundary state is per stream. */
  {
    uint8_t one[8];
    wt_writer_t ow = wt_writer_init(one, sizeof(one));
    wt_http3_frame_t f1 = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);
    uint8_t two[8];
    wt_writer_t tw = wt_writer_init(two, sizeof(two));
    wt_http3_frame_t f2 = wt_http3_frame_make(WT_HTTP3_FRAME_HEADERS);
    f1.payload = (const uint8_t *)"x";
    f1.length = 1U;
    f2.payload = (const uint8_t *)"y";
    f2.length = 1U;
    WT_EXPECT_OK("one stream's frame writes", wt_http3_frame_encode(&ow, &f1));
    WT_EXPECT_OK("and another's", wt_http3_frame_encode(&tw, &f2));
    memset(&log, 0, sizeof(log));
    WT_EXPECT_OK("the first byte of each arrives",
                 wt_http3_driver_on_stream_bytes(&driver, 11U, one, 1U, 0, 64U, &sink, &error));
    WT_EXPECT_OK("and the other",
                 wt_http3_driver_on_stream_bytes(&driver, 15U, two, 1U, 0, 64U, &sink, &error));
    WT_EXPECT_U64("with no frame complete yet", 0U, (uint64_t)log.frames);
    WT_EXPECT_OK("the rest of the first",
                 wt_http3_driver_on_stream_bytes(&driver, 11U, one + 1U, wt_writer_offset(&ow) - 1U,
                                                 0, 64U, &sink, &error));
    WT_EXPECT_U64("completes it", 1U, (uint64_t)log.frames);
    WT_EXPECT_U64("as the data frame", WT_HTTP3_FRAME_DATA, log.last_type);
    WT_EXPECT_OK("and the rest of the second",
                 wt_http3_driver_on_stream_bytes(&driver, 15U, two + 1U, wt_writer_offset(&tw) - 1U,
                                                 0, 64U, &sink, &error));
    WT_EXPECT_U64("completes it too", 2U, (uint64_t)log.frames);
    WT_EXPECT_U64("as the headers frame", WT_HTTP3_FRAME_HEADERS, log.last_type);
  }
}

/* Settling a CONNECT stream's HEADERS frame releases that stream's frame-state slot, and the table is
 * unordered: the last entry -- possibly another stream's state, mid-frame -- is moved into the hole. A write
 * through the released slot's pointer after the settle would clear THAT stream's in-frame flag, so its
 * remaining payload would be parsed as a new frame header. This is the case the table's tail is a live stream
 * with its header already read and one payload byte delivered; the assertions after the settle are the
 * other stream's frame still completing as one frame. */
void test_settling_a_capsule_stream_leaves_the_other_streams_framing(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  frame_log_t log;
  uint8_t headers[8];
  wt_writer_t hw = wt_writer_init(headers, sizeof(headers));
  wt_http3_frame_t headers_frame = wt_http3_frame_make(WT_HTTP3_FRAME_HEADERS);
  uint8_t data[8];
  wt_writer_t dw = wt_writer_init(data, sizeof(data));
  wt_http3_frame_t data_frame = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);

  memset(&log, 0, sizeof(log));
  memset(&sink, 0, sizeof(sink));
  sink.on_frame_payload = record_frame;
  sink.context = &log;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  headers_frame.payload = (const uint8_t *)"y";
  headers_frame.length = 1U;
  WT_EXPECT_OK("the HEADERS frame writes", wt_http3_frame_encode(&hw, &headers_frame));
  WT_EXPECT_U64("with a two-byte header of its own", 2U,
                (uint64_t)wt_writer_offset(&hw) - headers_frame.length);

  data_frame.payload = (const uint8_t *)"abc";
  data_frame.length = 3U;
  WT_EXPECT_OK("and a DATA frame writes", wt_http3_frame_encode(&dw, &data_frame));

  /* The CONNECT stream is marked with its HEADERS frame still to come, so it takes the FIRST table slot and
   * holds it with the frame half-read. */
  WT_EXPECT_OK("the CONNECT stream is marked", wt_http3_driver_mark_capsule_stream(&driver, 5U, 1));
  WT_EXPECT_OK("its HEADERS header arrives alone",
               wt_http3_driver_on_stream_bytes(&driver, 5U, headers, 2U, 0, 64U, &sink, &error));

  /* A second stream takes the slot AFTER it and is left mid-frame: its header and first payload byte are in. */
  WT_EXPECT_OK("another stream's header and first payload byte arrive",
               wt_http3_driver_on_stream_bytes(&driver, 9U, data, 3U, 0, 64U, &sink, &error));
  WT_EXPECT_U64("with nothing complete yet", 0U, (uint64_t)log.frames);

  /* The HEADERS frame's last byte settles the CONNECT stream. Settling releases its slot and moves the other
   * stream's state into it, so a write through the old pointer after that would clear the other stream's flag. */
  WT_EXPECT_OK(
      "the HEADERS frame completes",
      wt_http3_driver_on_stream_bytes(&driver, 5U, headers + 2U, 1U, 0, 64U, &sink, &error));
  WT_EXPECT_U64("delivering the HEADERS frame", 1U, (uint64_t)log.frames);
  WT_EXPECT_TRUE("and the stream is now a capsule stream",
                 wt_http3_driver_is_capsule_stream(&driver, 5U) != 0);

  /* The rest of the other stream's payload is still that stream's payload: the flag that says so must have
   * survived the settle. */
  WT_EXPECT_OK("the rest of the other stream arrives",
               wt_http3_driver_on_stream_bytes(&driver, 9U, data + 3U, 2U, 0, 64U, &sink, &error));
  WT_EXPECT_U64("completing the other stream's frame", 2U, (uint64_t)log.frames);
  WT_EXPECT_U64("as a DATA frame", WT_HTTP3_FRAME_DATA, log.last_type);
  WT_EXPECT_U64("with its payload stitched across the boundary", 4U, (uint64_t)log.total_bytes);
}
