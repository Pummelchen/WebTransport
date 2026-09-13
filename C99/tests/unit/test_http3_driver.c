/* Driving an HTTP/3 endpoint from a connection (Phase 9).
 *
 * The driver exists for one reason: a stream's type prefix is a varint and a varint can be
 * split across frames. These tests are that fact and its consequences -- the prefix
 * reassembles across frames, the payload after it is a view into the frame that completed it,
 * a prefix that does not start at offset zero is the caller's accounting rather than the
 * peer's, an incomplete prefix is never classified, the pending table is a fixed bound, and a
 * stream that ends before its prefix is complete is dropped without ever becoming a stream of
 * any type. */

#include "wt_test.h"

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"

static void test_a_prefix_split_across_frames(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t prefix[8];
  size_t prefix_length;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* The draft's WebTransport stream type, 0x54, is one byte -- so the split is tested with a
   * type whose varint is longer. 0x1f * 0x21 + 0x21 is a reserved HTTP/2-era type this build
   * does not know: two bytes, and the first byte says so. */
  prefix_length = wt_quic_varint_encode((1U << 6) + 5U, prefix, sizeof(prefix));
  WT_EXPECT_U64("the test's type takes two bytes", 2U, (uint64_t)prefix_length);

  /* The first frame carries only the first byte: nothing is classified yet, and the driver
   * holds exactly that byte. */
  WT_EXPECT_OK("half a prefix is accepted",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, prefix, 1U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("with nothing classified", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
  WT_EXPECT_U64("no payload", 0U, (uint64_t)payload_length);
  WT_EXPECT_U64("and one byte held", 1U, (uint64_t)wt_http3_driver_pending_count(&driver));

  /* The second frame completes it and carries session data behind it. */
  {
    uint8_t frame[16];
    size_t i;
    frame[0] = prefix[1];
    for (i = 1U; i < sizeof(frame); i++) frame[i] = 0xa0U + (uint8_t)i;
    WT_EXPECT_OK("the rest of the prefix completes it",
                 wt_http3_driver_on_uni_stream_data(&driver, 3U, 1U, frame, sizeof(frame), &kind,
                                                    &payload, &payload_length, &consumed, &error));
    WT_EXPECT_INT("classifying the stream", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
    WT_EXPECT_U64("with one byte of this frame taken for it", 1U, (uint64_t)consumed);
    WT_EXPECT_U64("leaving the rest as payload", (uint64_t)(sizeof(frame) - 1U),
                  (uint64_t)payload_length);
    WT_EXPECT_TRUE("as a view into the frame", payload == frame + 1);
    WT_EXPECT_U64("starting with its first payload byte", (uint64_t)frame[1], (uint64_t)payload[0]);
  }
  WT_EXPECT_U64("and nothing left pending", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
}

static void test_a_complete_prefix_in_one_frame(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t frame[8];
  size_t frame_length = 0U;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* The draft's stream type spelled as a varint rather than assumed to be one byte: 0x54 has
   * its top bits set, so it is a TWO-byte varint, and a test that wrote it as one byte would
   * be testing the wrong stream type. */
  frame_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, frame, sizeof(frame));
  frame[frame_length] = 0x11U;
  frame[frame_length + 1U] = 0x22U;
  frame[frame_length + 2U] = 0x33U;
  frame_length += 3U;

  WT_EXPECT_OK("a whole prefix is classified at once",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, frame, frame_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the session layer's stream",
                (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("with the prefix's two bytes taken", 2U, (uint64_t)consumed);
  WT_EXPECT_U64("and three of payload", 3U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("viewed in place", payload == frame + 2U);

  /* A second WebTransport stream is allowed: the draft bounds them by the session's own
   * stream table, not by "one per connection". */
  WT_EXPECT_OK("a second one is classified too",
               wt_http3_driver_on_uni_stream_data(&driver, 7U, 0U, frame, frame_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the same kind", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);

  /* A prefix that does not start at offset zero is the caller's accounting: the first byte of
   * the varint is what says how long it is, and a caller that lost it cannot be helped by
   * guessing. */
  WT_EXPECT_STATUS("a prefix that starts late is the caller's error", WT_ERR_STATE,
                   wt_http3_driver_on_uni_stream_data(&driver, 11U, 1U, frame, frame_length, &kind,
                                                      &payload, &payload_length, &consumed, &error));

  /* Resuming a stream at the wrong offset is the same class of mistake. */
  {
    uint8_t two[2];
    two[0] = (uint8_t)((1U << 6) | 1U); /* a two-byte varint's first byte */
    two[1] = 0x00U;
    WT_EXPECT_OK("a stream may wait for its prefix",
                 wt_http3_driver_on_uni_stream_data(&driver, 15U, 0U, two, 1U, &kind, &payload,
                                                    &payload_length, &consumed, &error));
    WT_EXPECT_STATUS("but not resume out of order", WT_ERR_STATE,
                     wt_http3_driver_on_uni_stream_data(&driver, 15U, 2U, two, 1U, &kind, &payload,
                                                        &payload_length, &consumed, &error));
    WT_EXPECT_OK("and its end drops it", wt_http3_driver_on_uni_stream_end(&driver, 15U, &error));
    WT_EXPECT_U64("leaving nothing pending", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
  }

  /* An empty frame adds nothing and classifies nothing. */
  WT_EXPECT_OK("an empty frame is nothing",
               wt_http3_driver_on_uni_stream_data(&driver, 19U, 0U, NULL, 0U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_U64("with nothing pending", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
}

static void test_control_and_qpack_reach_the_endpoint(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t frame[2];

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);

  frame[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
  frame[1] = 0x00U;
  WT_EXPECT_OK("the peer's control stream is classified",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, frame, sizeof(frame), &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as control", (int)WT_HTTP3_ENDPOINT_STREAM_CONTROL, (int)kind);

  /* The endpoint's one-per-connection rule is applied through the driver: a second control
   * stream is a connection error, with the code the RFC names. */
  WT_EXPECT_STATUS("and a second one is refused", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_data(&driver, 7U, 0U, frame, sizeof(frame), &kind,
                                                      &payload, &payload_length, &consumed, &error));
  WT_EXPECT_U64("with the stream creation code", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  /* Ending the control stream is the error itself, and the driver passes that through. */
  WT_EXPECT_STATUS("closing it is an error", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_end(&driver, 3U, &error));
  WT_EXPECT_U64("with the closed-critical-stream code", WT_HTTP3_CLOSED_CRITICAL_STREAM,
                (uint64_t)error);

  /* A QPACK stream, and then a second of the same kind. */
  frame[0] = (uint8_t)WT_HTTP3_STREAM_QPACK_ENCODER;
  WT_EXPECT_OK("the QPACK encoder stream is classified",
               wt_http3_driver_on_uni_stream_data(&driver, 11U, 0U, frame, 1U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the encoder", (int)WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER, (int)kind);
  WT_EXPECT_STATUS("and only one is allowed", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_data(&driver, 15U, 0U, frame, 1U, &kind, &payload,
                                                      &payload_length, &consumed, &error));
  WT_EXPECT_OK("ending it is not an error", wt_http3_driver_on_uni_stream_end(&driver, 11U, &error));
}

static void test_the_pending_table_is_bounded(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t half = 0xc0U; /* a four-byte varint's first byte */
  size_t i;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  for (i = 0U; i < (size_t)WT_HTTP3_DRIVER_PENDING_MAX; i++) {
    WT_EXPECT_OK("a stream waits for its prefix",
                 wt_http3_driver_on_uni_stream_data(&driver, 4U + (uint64_t)i * 4U, 0U, &half, 1U,
                                                    &kind, &payload, &payload_length, &consumed,
                                                    &error));
  }
  WT_EXPECT_U64("the table is full", (uint64_t)WT_HTTP3_DRIVER_PENDING_MAX,
                (uint64_t)wt_http3_driver_pending_count(&driver));

  /* One more opening stream is THIS endpoint's bound: WT_ERR_LIMIT with no error code, because
   * a peer that opens streams is doing nothing wrong. */
  WT_EXPECT_STATUS("one more is limited", WT_ERR_LIMIT,
                   wt_http3_driver_on_uni_stream_data(&driver, 4096U, 0U, &half, 1U, &kind, &payload,
                                                      &payload_length, &consumed, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);

  /* Ending a waiting stream frees its slot, so the bound is about concurrency rather than a
   * lifetime total. */
  WT_EXPECT_OK("a waiting stream may end", wt_http3_driver_on_uni_stream_end(&driver, 4U, &error));
  WT_EXPECT_U64("freeing its slot", (uint64_t)(WT_HTTP3_DRIVER_PENDING_MAX - 1U),
                (uint64_t)wt_http3_driver_pending_count(&driver));
  WT_EXPECT_OK("so another may wait",
               wt_http3_driver_on_uni_stream_data(&driver, 4096U, 0U, &half, 1U, &kind, &payload,
                                                  &payload_length, &consumed, &error));
}

static void test_starting_our_own_streams(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_settings_t settings;
  uint8_t wire[256];
  uint8_t scratch[256];
  uint8_t read_scratch[256];
  size_t length;
  wt_writer_t w;
  wt_cursor_t cursor;
  wt_http3_frame_t frame;
  wt_http3_settings_t read_back;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t i;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);

  /* A SETTINGS frame with something in it, so the payload is not trivially empty. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a setting is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_OK("and another",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 4096U));

  /* The control stream is the type prefix and then the frame: the reader finds both, which
   * is what makes this a stream rather than a bag of bytes. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the control stream starts",
               wt_http3_driver_start_control(&driver, &settings, scratch, sizeof(scratch), &w));
  length = wt_writer_offset(&w);
  WT_EXPECT_TRUE("with bytes", length > 0U);
  WT_EXPECT_U64("the first byte being the control type", WT_HTTP3_STREAM_CONTROL, (uint64_t)wire[0]);

  cursor = wt_cursor_init(wire + 1U, length - 1U);
  WT_EXPECT_OK("and the rest decoding as a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("of type SETTINGS", WT_HTTP3_FRAME_SETTINGS, frame.type);
  WT_EXPECT_OK("whose payload parses",
               wt_http3_settings_parse(frame.payload, frame.length, &read_back, &error));
  WT_EXPECT_U64("with the first setting back", 1U,
                wt_http3_settings_get(&read_back, WT_HTTP3_SETTING_WT_ENABLED, NULL));
  WT_EXPECT_U64("and the second", 4096U,
                wt_http3_settings_get(&read_back, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, NULL));
  WT_EXPECT_U64("with nothing left over", 0U, (uint64_t)wt_cursor_remaining(&cursor));

  /* A second control stream is the endpoint's one-per-connection rule, and it is refused
   * before any bytes are written. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_STATUS("a second control stream is refused", WT_ERR_STATE,
                   wt_http3_driver_start_control(&driver, &settings, scratch, sizeof(scratch), &w));
  WT_EXPECT_U64("with nothing written", 0U, (uint64_t)wt_writer_offset(&w));

  /* The QPACK streams, each once. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the encoder stream starts", wt_http3_driver_start_qpack_stream(&driver, 1, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_ENCODER, (uint64_t)wire[0]);
  WT_EXPECT_STATUS("and not twice", WT_ERR_STATE,
                   wt_http3_driver_start_qpack_stream(&driver, 1, &w));
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("the decoder stream starts", wt_http3_driver_start_qpack_stream(&driver, 0, &w));
  WT_EXPECT_U64("as its type", WT_HTTP3_STREAM_QPACK_DECODER, (uint64_t)wire[0]);

  /* A payload that does not fit the caller's scratch is this endpoint's bound, and the
   * prefix is already out by then: the caller must know it. */
  {
    wt_http3_settings_t big;
    wt_http3_endpoint_t other;
    wt_http3_driver_t other_driver;
    wt_http3_endpoint_init(&other, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&other_driver, &other);
    wt_http3_settings_init(&big);
    for (i = 0U; i < 8U; i++) {
      (void)wt_http3_settings_set(&big, 0x21U + (uint64_t)i * 0x1fU, 1U);
    }
    w = wt_writer_init(wire, sizeof(wire));
    WT_EXPECT_STATUS("a settings payload that does not fit is limited", WT_ERR_LIMIT,
                     wt_http3_driver_start_control(&other_driver, &big, scratch, 2U, &w));
    WT_EXPECT_U64("after the prefix went out", 1U, (uint64_t)wt_writer_offset(&w));
  }
  (void)read_scratch;
}

/* A sink that records what it was handed, so the test can assert the frame boundary rather
 * than trusting it. */
typedef struct frame_log {
  unsigned frames;
  uint64_t last_type;
  size_t total_bytes;
  unsigned last_was_last;
  uint8_t first_byte;
} frame_log_t;

static wt_status_t record_frame(void *context, uint64_t stream_id, uint64_t type,
                                const uint8_t *payload, size_t length, int last) {
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

static void test_frame_boundaries_on_a_stream(void) {
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
  WT_EXPECT_OK("and arrives",
               wt_http3_driver_on_stream_bytes(&driver, 3U, bytes, wt_writer_offset(&w), 0, 64U,
                                               &sink, &error));
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
               wt_http3_driver_on_stream_bytes(&driver, 3U, bytes + 2U,
                                               wt_writer_offset(&w) - 2U, 0, 64U, &sink, &error));
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

/* A sink that records the session's own data, so the test can assert what the driver handed
 * over rather than what it happened to leave behind. */
typedef struct session_log {
  unsigned streams;
  size_t stream_bytes;
  unsigned datagrams;
  size_t datagram_bytes;
  uint64_t last_stream_id;
} session_log_t;

static wt_status_t record_stream_data(void *context, uint64_t stream_id, const uint8_t *data,
                                      size_t length, int fin) {
  session_log_t *log = context;
  (void)data;
  (void)fin;
  log->streams++;
  log->stream_bytes += length;
  log->last_stream_id = stream_id;
  return WT_OK;
}

static wt_status_t record_datagram(void *context, const uint8_t *data, size_t length) {
  session_log_t *log = context;
  (void)data;
  log->datagrams++;
  log->datagram_bytes += length;
  return WT_OK;
}

/* Both logs in one context, because one sink carries all three callbacks: a callback that
 * cast the context to the wrong log would write into the other one, which is exactly the kind
 * of mistake this test would then be unable to see. */
typedef struct route_log {
  frame_log_t frames;
  session_log_t session;
} route_log_t;

static wt_status_t route_frame(void *context, uint64_t stream_id, uint64_t type,
                               const uint8_t *payload, size_t length, int last) {
  return record_frame(&((route_log_t *)context)->frames, stream_id, type, payload, length, last);
}

static wt_status_t route_stream(void *context, uint64_t stream_id, const uint8_t *data,
                                size_t length, int fin) {
  return record_stream_data(&((route_log_t *)context)->session, stream_id, data, length, fin);
}

static wt_status_t route_datagram(void *context, const uint8_t *data, size_t length) {
  return record_datagram(&((route_log_t *)context)->session, data, length);
}

static void test_a_connection_frame_is_routed(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  route_log_t log;
  wt_quic_frame_t frame;
  uint8_t prefix[8];
  uint8_t body[16];
  size_t prefix_length;
  size_t i;

  memset(&log, 0, sizeof(log));
  sink.on_frame_payload = route_frame;
  sink.on_stream_data = route_stream;
  sink.on_datagram = route_datagram;
  sink.context = &log;

  /* A server: the peer is the client, so client-initiated stream IDs (low bit clear) are the
   * peer's. */
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);

  /* The draft's WebTransport stream: the prefix, then session bytes that are NOT HTTP/3
   * log.frames. They go to the session sink, and the frame sink must not see them. */
  prefix_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, prefix, sizeof(prefix));
  for (i = 0U; i < sizeof(body); i++) body[i] = (uint8_t)(0x10U + i);
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 2U; /* client-initiated unidirectional: low bit clear */
  frame.as.stream.offset = 0U;
  frame.as.stream.has_offset = 0;
  frame.as.stream.fin = 0;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = prefix;
  frame.as.stream.length = prefix_length;
  WT_EXPECT_OK("the prefix frame is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("delivering nothing to the session yet", 0U, (uint64_t)log.session.streams);
  WT_EXPECT_U64("and nothing to the frame sink", 0U, (uint64_t)log.frames.frames);

  frame.as.stream.offset = prefix_length;
  frame.as.stream.has_offset = 1;
  frame.as.stream.data = body;
  frame.as.stream.length = sizeof(body);
  WT_EXPECT_OK("the data frame is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("handing the session its bytes", 1U, (uint64_t)log.session.streams);
  WT_EXPECT_U64("all of them", (uint64_t)sizeof(body), (uint64_t)log.session.stream_bytes);
  WT_EXPECT_U64("for that stream", 2U, log.session.last_stream_id);

  /* The control stream's frames go to the FRAME sink instead: the same shape of frame, a
   * different destination, decided by the stream's type prefix rather than by the caller. */
  {
    uint8_t control[32];
    wt_writer_t cw;
    wt_http3_frame_t settings = wt_http3_frame_make(WT_HTTP3_FRAME_SETTINGS);

    control[0] = (uint8_t)WT_HTTP3_STREAM_CONTROL;
    cw = wt_writer_init(control + 1U, sizeof(control) - 1U);
    settings.payload = NULL;
    settings.length = 0U;
    WT_EXPECT_OK("a settings frame writes", wt_http3_frame_encode(&cw, &settings));

    frame.kind = WT_QUIC_FRAME_KIND_STREAM;
    frame.as.stream.id = 6U; /* client-initiated unidirectional */
    frame.as.stream.offset = 0U;
    frame.as.stream.has_offset = 0;
    frame.as.stream.fin = 0;
    frame.as.stream.has_length = 1;
    frame.as.stream.data = control;
    frame.as.stream.length = 1U + wt_writer_offset(&cw);
    WT_EXPECT_OK("the control stream's first frame is routed",
                 wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink,
                                               64U));
    WT_EXPECT_U64("to the frame sink", 1U, (uint64_t)log.frames.frames);
    WT_EXPECT_U64("as SETTINGS", WT_HTTP3_FRAME_SETTINGS, log.frames.last_type);
    WT_EXPECT_U64("and not to the session", 1U, (uint64_t)log.session.streams);
  }

  /* A datagram is the session's, uninterpreted. */
  frame.kind = WT_QUIC_FRAME_KIND_DATAGRAM;
  frame.as.datagram.data = body;
  frame.as.datagram.length = 4U;
  WT_EXPECT_OK("a datagram is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("as one datagram", 1U, (uint64_t)log.session.datagrams);
  WT_EXPECT_U64("of its four bytes", 4U, (uint64_t)log.session.datagram_bytes);

  /* A frame on a stream THIS endpoint opened is not routed at all: the peer's answer belongs
   * to the connection's own stream state. */
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 3U; /* server-initiated: ours, so not routed */
  WT_EXPECT_OK("our own stream's frame is ignored",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
  WT_EXPECT_U64("reaching neither sink", 1U, (uint64_t)log.session.streams);

  /* A frame kind this layer has no interest in is ignored rather than refused. */
  frame.kind = WT_QUIC_FRAME_KIND_PING;
  WT_EXPECT_OK("a ping is not ours to route",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 64U));
}

int main(void) {
  test_a_prefix_split_across_frames();
  test_a_complete_prefix_in_one_frame();
  test_control_and_qpack_reach_the_endpoint();
  test_starting_our_own_streams();
  test_frame_boundaries_on_a_stream();
  test_a_connection_frame_is_routed();
  test_the_pending_table_is_bounded();
  WT_TEST_MAIN_END("wt_http3_driver");
}
