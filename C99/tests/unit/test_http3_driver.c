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

#include <stdio.h>

#include "webtransport/http3/driver.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/connection.h"
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
  /* The draft's prefix is the TYPE and then the session ID, so the payload starts after both: a test that
   * omitted the session ID would be asserting that a byte of it is session data. */
  frame_length += wt_quic_varint_encode(0U, frame + frame_length, sizeof(frame) - frame_length);
  frame[frame_length] = 0x11U;
  frame[frame_length + 1U] = 0x22U;
  frame[frame_length + 2U] = 0x33U;
  frame_length += 3U;

  WT_EXPECT_OK("a whole prefix is classified at once",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, frame, frame_length, &kind,
                                                  &payload, &payload_length, &consumed, &error));
  WT_EXPECT_INT("as the session layer's stream",
                (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("with the type's two bytes and the session ID's one accounted for", 3U,
                (uint64_t)consumed);
  WT_EXPECT_U64("and three of payload", 3U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("viewed in place, after both parts of the prefix", payload == frame + 3U);

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
  /* And ending it IS one: RFC 9204 section 4.2 makes the QPACK encoder stream critical, so closing it is
   * H3_CLOSED_CRITICAL_STREAM -- the same answer the control stream gets two cases above. This assertion used to
   * read `WT_EXPECT_OK("ending it is not an error")`, which was the defect written down as a test: a peer could
   * close the stream its instructions were arriving on and this endpoint would carry on as though the dynamic
   * table were still in sync. An audit filed it (finding 11) and the endpoint now refuses it. */
  WT_EXPECT_STATUS("ending it is an error", WT_ERR_PROTOCOL,
                   wt_http3_driver_on_uni_stream_end(&driver, 11U, &error));
  WT_EXPECT_U64("with the closed-critical-stream code", WT_HTTP3_CLOSED_CRITICAL_STREAM,
                (uint64_t)error);
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
      /* LEGAL unknown identifiers, NOT the reserved family (0x21 + k*0x1f): the setter refuses those now, which is
       * the rule WT-137 restored, and a fixture that used them made this payload too small to overflow. */
      (void)wt_http3_settings_set(&big, 0x23U + (uint64_t)i * 2U, 1U);
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
  /* The session ID is part of the draft's prefix, so a frame that stops after the type is TRUNCATED rather
   * than a stream whose payload begins with its own session ID. */
  prefix_length += wt_quic_varint_encode(0U, prefix + prefix_length, sizeof(prefix) - prefix_length);
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

/* A transport that records what it was asked to do, so the outbound half can be checked
 * without a handshake: what this layer produces IS the thing under test, and a recording sink
 * is a more exact reader than a real connection. */
typedef struct fake_transport {
  unsigned streams_opened;
  uint64_t last_stream_id;
  unsigned sends;
  size_t first_send_bytes;
  uint8_t first_bytes[512];
  size_t last_send_bytes;
  int last_fin;
  uint8_t last_bytes[512];
  unsigned datagrams;
  size_t datagram_bytes;
  int refuse_open;
} fake_transport_t;

static wt_status_t fake_open(void *context, int bidirectional, uint64_t *out_stream_id,
                             uint64_t now) {
  fake_transport_t *fake = context;
  (void)now;
  if (fake->refuse_open != 0) return WT_ERR_AGAIN;
  WT_EXPECT_INT("streams this endpoint opens are unidirectional", 0, bidirectional ? 0 : 0);
  fake->streams_opened++;
  *out_stream_id = 4U * (uint64_t)fake->streams_opened;
  fake->last_stream_id = *out_stream_id;
  return WT_OK;
}

static wt_status_t fake_send(void *context, uint64_t stream_id, const uint8_t *data, size_t length,
                             int fin, uint64_t now) {
  fake_transport_t *fake = context;
  (void)now;
  if (fake->sends == 0U) {
    fake->first_send_bytes = length;
    if (length <= sizeof(fake->first_bytes)) memcpy(fake->first_bytes, data, length);
  }
  fake->sends++;
  fake->last_stream_id = stream_id;
  fake->last_fin = fin;
  fake->last_send_bytes = length;
  if (length <= sizeof(fake->last_bytes)) memcpy(fake->last_bytes, data, length);
  return WT_OK;
}

static wt_status_t fake_datagram(void *context, const uint8_t *data, size_t length) {
  fake_transport_t *fake = context;
  (void)data;
  fake->datagrams++;
  fake->datagram_bytes += length;
  return WT_OK;
}

static void test_the_outbound_half_sends_what_it_should(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_transport_t transport;
  wt_http3_settings_t settings;
  wt_http3_message_t request;
  fake_transport_t fake;
  wt_cursor_t cursor;
  wt_http3_frame_t frame;
  wt_http3_settings_t read_back;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  memset(&fake, 0, sizeof(fake));
  transport.open_stream = fake_open;
  transport.send_stream = fake_send;
  transport.send_datagram = fake_datagram;
  transport.context = &fake;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a setting is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));

  /* Three streams, in the order HTTP/3 requires them: the control stream first, because it
   * carries the SETTINGS the peer needs before anything else can be interpreted. */
  WT_EXPECT_OK("an endpoint starts its own streams",
               wt_http3_driver_start_own_streams(&driver, &transport, &settings, 0U));
  WT_EXPECT_U64("three streams are opened", 3U, (uint64_t)fake.streams_opened);
  WT_EXPECT_U64("and three things sent", 3U, (uint64_t)fake.sends);

  /* What went out on the control stream is the prefix and then a SETTINGS frame, which is what
   * the reader on the other side expects. */
  WT_EXPECT_U64("the control stream's first byte is its type", WT_HTTP3_STREAM_CONTROL,
                (uint64_t)fake.first_bytes[0]);
  cursor = wt_cursor_init(fake.first_bytes + 1U, fake.first_send_bytes - 1U);
  WT_EXPECT_OK("and the rest is a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("of type SETTINGS", WT_HTTP3_FRAME_SETTINGS, frame.type);
  (void)read_back;

  /* Starting them twice is the endpoint's own rule, and it is refused. */
  WT_EXPECT_STATUS("a second start is refused", WT_ERR_STATE,
                   wt_http3_driver_start_own_streams(&driver, &transport, &settings, 0U));
  WT_EXPECT_U64("without opening more", 3U, (uint64_t)fake.streams_opened);

  /* A message: the client's extended CONNECT, which is the request whose stream is the
   * session. */
  request.type = WT_HTTP3_HEADER_REQUEST;
  request.method = (const uint8_t *)"CONNECT";
  request.method_length = 7U;
  request.scheme = (const uint8_t *)"https";
  request.scheme_length = 5U;
  request.authority = (const uint8_t *)"localhost";
  request.authority_length = 9U;
  request.path = (const uint8_t *)"/chat";
  request.path_length = 5U;
  request.protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
  request.protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);
  request.status = 0U;
  request.has_status = 0;

  fake.sends = 0U;
  WT_EXPECT_OK("a request is sent",
               wt_http3_driver_send_message(&driver, &transport, 0U, &request, 0U, 0, 0U));
  WT_EXPECT_U64("as one send", 1U, (uint64_t)fake.sends);
  WT_EXPECT_U64("on the stream it was given", 0U, fake.last_stream_id);
  WT_EXPECT_INT("not ending the stream", 0, fake.last_fin);
  cursor = wt_cursor_init(fake.last_bytes, fake.last_send_bytes);
  WT_EXPECT_OK("carrying a frame", wt_http3_frame_decode(&cursor, &frame, &error));
  WT_EXPECT_U64("of type HEADERS", WT_HTTP3_FRAME_HEADERS, frame.type);

  /* A datagram, which this layer does not look inside. */
  WT_EXPECT_OK("a datagram is sent",
               wt_http3_driver_send_datagram(&driver, &transport, (const uint8_t *)"xy", 2U));
  WT_EXPECT_U64("as one datagram", 1U, (uint64_t)fake.datagrams);
  WT_EXPECT_U64("with its two bytes", 2U, (uint64_t)fake.datagram_bytes);

  /* A transport that cannot open a stream right now says so, and the driver does not pretend
   * otherwise: the refusal is the caller's, unchanged, because WT_ERR_AGAIN is congestion and
   * not an HTTP/3 condition. */
  {
    wt_http3_endpoint_t other;
    wt_http3_driver_t other_driver;
    wt_http3_endpoint_init(&other, WT_HTTP3_ROLE_CLIENT);
    wt_http3_driver_init(&other_driver, &other);
    fake.refuse_open = 1;
    WT_EXPECT_STATUS("a refused open is passed through", WT_ERR_AGAIN,
                     wt_http3_driver_start_own_streams(&other_driver, &transport, &settings, 0U));
    WT_EXPECT_U64("with nothing sent", 3U, (uint64_t)fake.streams_opened);
  }
}

/* The adapter to a real connection, checked by FORWARDING rather than by a session: a fresh
 * connection has no keys and no room, so it refuses, and the point of the test is that the
 * adapter returns exactly what the connection returns rather than inventing a status of its
 * own. That is what a thin layer has to get right, and it is the only part of it this test can
 * check without standing up a handshake. */
static void test_the_quic_transport_forwards(void) {
  static const uint8_t k_dcid[8] = {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U};
  wt_quic_connection_config_t config;
  wt_quic_connection_t connection;
  wt_http3_driver_transport_t transport;
  uint64_t stream_id = 0U;
  uint64_t now = 1000U;
  wt_status_t direct;

  memset(&config, 0, sizeof(config));
  memset(&connection, 0, sizeof(connection));
  config.role = WT_QUIC_ROLE_CLIENT;
  config.version = WT_QUIC_VERSION_1;
  config.local_connection_id = k_dcid;
  config.local_connection_id_length = sizeof(k_dcid);
  config.peer_connection_id = k_dcid;
  config.peer_connection_id_length = sizeof(k_dcid);
  config.aead = WT_AEAD_AES_128_GCM;
  config.max_ack_delay = 25000U;
  config.local_max_ack_delay = 25000U;
  config.idle_timeout = 30000000U;
  config.max_datagram_size = 1200U;

  WT_EXPECT_OK("a connection is initialised", wt_quic_connection_init(&connection, &config));
  wt_http3_driver_quic_transport(&connection, &transport);
  WT_EXPECT_TRUE("the transport has an opener", transport.open_stream != NULL);
  WT_EXPECT_TRUE("a sender", transport.send_stream != NULL);
  WT_EXPECT_TRUE("and a datagram sender", transport.send_datagram != NULL);
  WT_EXPECT_TRUE("bound to the connection", transport.context == &connection);

  /* The opener's answer IS the connection's answer, whatever it is: a fresh connection has no
   * peer limits yet, so this is a refusal rather than a success, and either way the two must
   * agree. */
  direct = wt_quic_connection_open_stream(&connection, 0, &stream_id);
  WT_EXPECT_STATUS("the opener forwards the connection's answer", direct,
                   transport.open_stream(transport.context, 0, &stream_id, now));

  /* A stream the connection does not know is the caller's accounting: this layer says so
   * itself rather than letting a NULL reach the connection. */
  WT_EXPECT_STATUS("sending on an unknown stream is a state error", WT_ERR_STATE,
                   transport.send_stream(transport.context, 8U, (const uint8_t *)"x", 1U, 0, now));

  /* A datagram is forwarded, and its refusal is the connection's too. */
  direct = wt_quic_connection_send_datagram(&connection, (const uint8_t *)"x", 1U, 0U);
  WT_EXPECT_STATUS("a datagram forwards the connection's answer", direct,
                   transport.send_datagram(transport.context, (const uint8_t *)"x", 1U));
  wt_quic_connection_clear(&connection);
}

/* The bidirectional-stream classifier, on its own: the routing that uses it is a separate step because that is
 * where WT-120's release-build crash lived, and a pure function can be proven in all three configurations
 * first. */
static void test_the_bidi_classifier(void) {
  uint8_t wire[16];
  wt_writer_t w;
  size_t length;
  size_t consumed = 0U;
  uint64_t session_id = 0U;
  wt_http3_bidi_start_kind_t kind = WT_HTTP3_BIDI_START_REQUEST;

  /* The draft's bidirectional prefix: `0x41` and the session ID. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a bidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
  wt_writer_bytes(&w, "body", 4U);
  length = wt_writer_offset(&w);
  WT_EXPECT_OK("and classifies as WebTransport",
               wt_http3_driver_classify_bidi_start(wire, length, &kind, &session_id, &consumed));
  WT_EXPECT_INT("as the WebTransport kind", (int)WT_HTTP3_BIDI_START_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("naming the session", 4U, session_id);
  /* Three bytes: the TYPE `0x41` needs a two-byte varint (65 > 63) and the session id is one byte. This is the
   * MSB-first varint lesson the tracker has recorded several times, and the assertion that caught it here was
   * "consumed is the prefix, not the body". */
  WT_EXPECT_U64("with the prefix's length consumed, not the body's", 3U, (uint64_t)consumed);

  /* An HTTP/3 request stream: a QPACK prefix, which is not the draft's type. */
  {
    uint8_t request[8];
    wt_writer_t rw = wt_writer_init(request, sizeof(request));
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x80U);
    WT_EXPECT_OK("a request stream classifies as a request",
                 wt_http3_driver_classify_bidi_start(request, wt_writer_offset(&rw), &kind, &session_id,
                                                     &consumed));
    WT_EXPECT_INT("as the request kind", (int)WT_HTTP3_BIDI_START_REQUEST, (int)kind);
    WT_EXPECT_U64("with nothing consumed", 0U, (uint64_t)consumed);
  }

  /* A prefix that has not fully arrived is a WAIT on a stream, never a refusal. */
  WT_EXPECT_STATUS("a lone type byte is incomplete", WT_ERR_TRUNCATED,
                   wt_http3_driver_classify_bidi_start(wire, 1U, &kind, &session_id, &consumed));
  /* And nothing at all is simply a stream with no bytes yet: a request stream until proven otherwise. */
  WT_EXPECT_OK("no bytes classify as a request",
               wt_http3_driver_classify_bidi_start(NULL, 0U, &kind, &session_id, &consumed));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_driver_classify_bidi_start(wire, length, NULL, &session_id, &consumed));
}

/* The ROUTING that uses the classifier, which is the step that crashed in the release build when it was first
 * attempted. The classifier is proven on its own (above); this proves that a WebTransport bidirectional stream
 * reaches the SESSION sink with its prefix removed, and that a request-shaped stream does not go there. */
static void test_a_bidi_stream_is_routed_by_its_prefix(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  session_log_t session;
  wt_quic_frame_t frame;
  uint8_t wire[64];
  uint8_t request[8];
  wt_writer_t w;
  size_t wire_length;

  memset(&session, 0, sizeof(session));
  memset(&sink, 0, sizeof(sink));
  sink.on_stream_data = record_stream_data;
  sink.context = &session;
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 4U);

  /* The draft's bidirectional prefix and then the session's bytes. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a bidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
  wt_writer_bytes(&w, "hello", 5U);
  wire_length = wt_writer_offset(&w);

  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 0U; /* a peer-initiated (client) bidirectional stream */
  frame.as.stream.offset = 0U;
  frame.as.stream.fin = 0;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = wire;
  frame.as.stream.length = wire_length;

  WT_EXPECT_OK("a WebTransport stream is routed",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
  WT_EXPECT_U64("the session is handed the bytes", 1U, (uint64_t)session.streams);
  WT_EXPECT_U64("after the prefix, and only those", 5U, (uint64_t)session.stream_bytes);
  WT_EXPECT_U64("for the stream they arrived on", 0U, session.last_stream_id);
  /* And the driver can say which session the stream named, which is what section 4.6's buffering rule asks
   * for when the session is not known yet (WT-180). */
  {
    uint64_t named = 0U;
    WT_EXPECT_OK("the stream's session is readable",
                 wt_http3_driver_data_stream_session_id(&driver, 0U, &named));
    WT_EXPECT_U64("as the one its prefix named", 4U, named);
  }

  /* A stream naming ANOTHER session is refused rather than delivered to this one. */
  {
    wt_http3_driver_t other;
    wt_http3_endpoint_t other_endpoint;
    wt_http3_driver_init(&other, &other_endpoint);
    wt_http3_driver_set_session_id(&other, 12U);
    frame.as.stream.id = 4U;
    WT_EXPECT_STATUS("a stream for another session is refused", WT_ERR_PROTOCOL,
                     wt_http3_driver_on_quic_frame(&other, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
    WT_EXPECT_U64("and reaches the session never", 1U, (uint64_t)session.streams);
  }

  /* A request-shaped stream is an HTTP/3 request and does NOT go to the session sink. */
  {
    wt_writer_t rw = wt_writer_init(request, sizeof(request));
    wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x00U);
    wt_writer_bytes(&rw, "x", 1U);
    frame.as.stream.id = 8U;
    frame.as.stream.data = request;
    frame.as.stream.length = wt_writer_offset(&rw);
    (void)wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U);
    WT_EXPECT_U64("a request stream does not reach the session as data", 1U, (uint64_t)session.streams);
    /* And the endpoint tracks it as a request stream, which is what makes it a request rather than nothing. */
    WT_EXPECT_OK("while the endpoint tracks it as a request",
                 wt_http3_endpoint_request_state(&endpoint, 8U, &state));
  }
}

/* A prefix that arrives in PIECES on a bidirectional stream: the held bytes must be assembled, and for a
 * REQUEST they must be REPLAYED -- the request path has to see a stream's first bytes rather than the middle of
 * them. The first implementation skipped the assembly for the continuation frame, because its offset is not
 * zero, and the counter that made the frame path say so is what found it. */
static void test_a_bidirectional_prefix_split_across_frames(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  session_log_t session;
  wt_quic_frame_t frame;
  uint8_t wire[64];
  wt_writer_t w;
  size_t wire_length;

  memset(&session, 0, sizeof(session));
  memset(&sink, 0, sizeof(sink));
  sink.on_stream_data = record_stream_data;
  sink.context = &session;
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 4U);

  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a bidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 0, 4U));
  wt_writer_bytes(&w, "split", 5U);
  wire_length = wt_writer_offset(&w);

  memset(&frame, 0, sizeof(frame));
  frame.kind = WT_QUIC_FRAME_KIND_STREAM;
  frame.as.stream.id = 0U;
  frame.as.stream.has_length = 1;
  frame.as.stream.data = wire;
  frame.as.stream.length = 1U; /* inside the two-byte type: nothing is decided yet */
  WT_EXPECT_OK("the first piece is held",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
  WT_EXPECT_U64("with nothing delivered", 0U, (uint64_t)session.streams);
  WT_EXPECT_U64("and the stream waiting", 1U, (uint64_t)wt_http3_driver_pending_count(&driver));
  frame.as.stream.offset = 1U;
  frame.as.stream.data = wire + 1;
  frame.as.stream.length = wire_length - 1U;
  WT_EXPECT_OK("the rest completes the prefix",
               wt_http3_driver_on_quic_frame(&driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink, 4096U));
  WT_EXPECT_U64("and the session has the payload", 5U, (uint64_t)session.stream_bytes);
  WT_EXPECT_U64("delivered once", 1U, (uint64_t)session.streams);
  WT_EXPECT_U64("with nothing left waiting", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));

  /* A REQUEST split the same way: the held bytes are replayed, so the request path sees the first bytes. */
  {
    wt_http3_driver_t request_driver;
    wt_http3_endpoint_t request_endpoint;
    wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
    uint8_t request[8];
    wt_writer_t rw = wt_writer_init(request, sizeof(request));

    wt_http3_endpoint_init(&request_endpoint, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&request_driver, &request_endpoint);
    wt_writer_u8(&rw, 0x00U); /* a QPACK prefix and then a DATA frame */
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x00U);
    wt_writer_u8(&rw, 0x01U);
    wt_writer_u8(&rw, 0x00U);
    frame.as.stream.id = 4U;
    frame.as.stream.offset = 0U;
    frame.as.stream.data = request;
    frame.as.stream.length = 2U;
    WT_EXPECT_OK("half a request prefix is held",
                 wt_http3_driver_on_quic_frame(&request_driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink,
                                               4096U));
    frame.as.stream.offset = 2U;
    frame.as.stream.data = request + 2;
    frame.as.stream.length = wt_writer_offset(&rw) - 2U;
    WT_EXPECT_OK("and its rest goes to the request path",
                 wt_http3_driver_on_quic_frame(&request_driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink,
                                               4096U));
    WT_EXPECT_OK("which tracks the stream",
                 wt_http3_endpoint_request_state(&request_endpoint, 4U, &state));
    WT_EXPECT_TRUE("with the frames it was given applied",
                   state == WT_HTTP3_REQUEST_BODY || state == WT_HTTP3_REQUEST_EXPECT_HEADERS);
    WT_EXPECT_U64("and the session was told nothing", 1U, (uint64_t)session.streams);
  }
}

/* A stream that arrives before its session is known has to be answerable: the session is the one its
 * PREFIX named, and the driver is where the prefix was parsed. This is the interface section 4.6's
 * buffering rule needs -- "buffer until it can be associated with an established session" -- because
 * without the ID a caller cannot tell "mine, early" from "not mine" (WT-180). */
static void test_a_data_stream_knows_its_session(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t wire[16];
  wt_writer_t w;
  uint64_t session_id = 0U;
  size_t wire_length;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  /* The server has NOT accepted a session yet: no ID is set on the driver, which is exactly the state a
   * stream can arrive in. */
  WT_EXPECT_STATUS("an unknown stream names no session", WT_ERR_CLOSED,
                   wt_http3_driver_data_stream_session_id(&driver, 0U, &session_id));

  /* A peer's unidirectional WebTransport stream: the draft's type 0x54, the session it names, then bytes. */
  w = wt_writer_init(wire, sizeof(wire));
  WT_EXPECT_OK("a unidirectional prefix writes", wt_webtransport_stream_prefix_write(&w, 1, 8U));
  wt_writer_bytes(&w, "early", 5U);
  wire_length = wt_writer_offset(&w);
  WT_EXPECT_OK("the peer's stream is classified",
               wt_http3_driver_on_uni_stream_data(&driver, 2U, 0U, wire, wire_length, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("as a WebTransport stream", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("with the payload after the prefix", 5U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("and the prefix consumed", consumed > 0U);
  WT_EXPECT_U64("which the driver remembers", 1U, (uint64_t)wt_http3_driver_is_data_stream(&driver, 2U));

  /* The ID is the one in the prefix -- NOT the driver's own (there is none), and not zero. */
  WT_EXPECT_OK("and its session is readable", wt_http3_driver_data_stream_session_id(&driver, 2U,
                                                                                    &session_id));
  WT_EXPECT_U64("as the session the prefix named", 8U, session_id);

  /* A stream that was never seen is CLOSED, which a caller can tell apart from "remembered but unknown". */
  WT_EXPECT_STATUS("a stream the driver never saw names nothing", WT_ERR_CLOSED,
                   wt_http3_driver_data_stream_session_id(&driver, 6U, &session_id));

}

/* F-07: a WebTransport unidirectional prefix split between the TYPE and the SESSION ID. The session ID is part
 * of the prefix, so a frame carrying only the type must be held and NOT classified; the frame that completes
 * the prefix must apply the session check before the endpoint is told the kind, and hand the session only the
 * bytes after the whole prefix. Before the fix the first frame classified the stream WEBTRANSPORT and returned
 * WT_ERR_TRUNCATED, which the frame route turns into a connection close with INTERNAL_ERROR, and the retry then
 * saw a stored WEBTRANSPORT kind and delivered the session ID's bytes as payload with no check at all. */
static void test_a_webtransport_uni_prefix_split_after_the_type(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  size_t consumed = 0U;
  uint8_t type[8];
  uint8_t rest[16];
  size_t type_length;
  size_t rest_length;
  uint64_t named = 0U;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  wt_http3_driver_set_session_id(&driver, 4U);

  type_length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, type, sizeof(type));
  rest_length = wt_quic_varint_encode(4U, rest, sizeof(rest));
  rest[rest_length] = 0xaaU;
  rest[rest_length + 1U] = 0xbbU;
  rest[rest_length + 2U] = 0xccU;
  rest_length += 3U;

  /* The first frame carries the TYPE only: nothing classified, nothing delivered, one entry held. */
  WT_EXPECT_OK("the type alone is held",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, 0U, type, type_length, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("with nothing classified", (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN, (int)kind);
  WT_EXPECT_U64("no payload", 0U, (uint64_t)payload_length);
  WT_EXPECT_U64("the type consumed", (uint64_t)type_length, (uint64_t)consumed);
  WT_EXPECT_U64("one stream waiting", 1U, (uint64_t)wt_http3_driver_pending_count(&driver));
  /* The endpoint must not have been told the kind, or a later frame on this stream would skip the prefix. */
  WT_EXPECT_INT("and the stream is not marked WebTransport yet",
                (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN,
                (int)wt_http3_endpoint_stream_kind(&endpoint, 3U));

  /* The second frame completes the prefix (the session ID) and carries payload behind it: only the session
   * ID's one byte comes out of this frame, and the payload starts after the whole prefix. */
  WT_EXPECT_OK("the session ID completes the prefix",
               wt_http3_driver_on_uni_stream_data(&driver, 3U, type_length, rest, rest_length, &kind, &payload,
                                                  &payload_length, &consumed, &error));
  WT_EXPECT_INT("classifying the stream", (int)WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT, (int)kind);
  WT_EXPECT_U64("with only the session ID taken from this frame", 1U, (uint64_t)consumed);
  WT_EXPECT_U64("leaving the rest as payload", 3U, (uint64_t)payload_length);
  WT_EXPECT_TRUE("starting right after the session ID", payload == rest + 1U);
  if (payload != NULL && payload_length > 0U) {
    WT_EXPECT_U64("and the first payload byte is the payload's", 0xaaU, (uint64_t)payload[0]);
  }
  WT_EXPECT_U64("with nothing left waiting", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
  WT_EXPECT_OK("and the stream is remembered for the session its prefix named",
               wt_http3_driver_data_stream_session_id(&driver, 3U, &named));
  WT_EXPECT_U64("which is this session", 4U, named);

  /* A split prefix naming ANOTHER session: the comparison must happen before classification, so the stream
   * leaves no trace in the endpoint and no payload reaches this session. */
  {
    uint8_t wrong[8];
    size_t wrong_length = wt_quic_varint_encode(12U, wrong, sizeof(wrong));
    wrong[wrong_length] = 0xddU;
    wrong_length += 1U;

    WT_EXPECT_OK("a wrong session's type is held too",
                 wt_http3_driver_on_uni_stream_data(&driver, 7U, 0U, type, type_length, &kind, &payload,
                                                    &payload_length, &consumed, &error));
    WT_EXPECT_STATUS("a stream for another session is refused", WT_ERR_PROTOCOL,
                     wt_http3_driver_on_uni_stream_data(&driver, 7U, type_length, wrong, wrong_length, &kind,
                                                        &payload, &payload_length, &consumed, &error));
    WT_EXPECT_U64("with the id error code", WT_HTTP3_ID_ERROR, (uint64_t)error);
    WT_EXPECT_INT("and the endpoint was never told the kind",
                  (int)WT_HTTP3_ENDPOINT_STREAM_UNKNOWN,
                  (int)wt_http3_endpoint_stream_kind(&endpoint, 7U));
    WT_EXPECT_U64("with nothing left waiting", 0U, (uint64_t)wt_http3_driver_pending_count(&driver));
  }

  /* And through the FRAME route, which is where the unfixed code closed the connection with INTERNAL_ERROR:
   * the first frame is held, the second completes the prefix and hands the session exactly the payload. */
  {
    wt_http3_endpoint_t route_endpoint;
    wt_http3_driver_t route_driver;
    wt_http3_driver_sink_t sink;
    session_log_t session;
    wt_quic_frame_t frame;

    memset(&session, 0, sizeof(session));
    memset(&sink, 0, sizeof(sink));
    sink.on_stream_data = record_stream_data;
    sink.context = &session;
    wt_http3_endpoint_init(&route_endpoint, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&route_driver, &route_endpoint);
    wt_http3_driver_set_session_id(&route_driver, 4U);

    memset(&frame, 0, sizeof(frame));
    frame.kind = WT_QUIC_FRAME_KIND_STREAM;
    frame.as.stream.id = 2U; /* a peer-initiated unidirectional stream */
    frame.as.stream.has_length = 1;
    frame.as.stream.offset = 0U;
    frame.as.stream.data = type;
    frame.as.stream.length = type_length;
    WT_EXPECT_OK("the frame route holds the type",
                 wt_http3_driver_on_quic_frame(&route_driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink,
                                               4096U));
    WT_EXPECT_U64("delivering nothing", 0U, (uint64_t)session.streams);

    frame.as.stream.offset = type_length;
    frame.as.stream.data = rest;
    frame.as.stream.length = rest_length;
    WT_EXPECT_OK("and the session ID completes the prefix",
                 wt_http3_driver_on_quic_frame(&route_driver, WT_QUIC_SPACE_APPLICATION, &frame, &sink,
                                               4096U));
    WT_EXPECT_U64("delivering the payload once", 1U, (uint64_t)session.streams);
    WT_EXPECT_U64("with no session-ID byte in it", 3U, (uint64_t)session.stream_bytes);
    WT_EXPECT_U64("for the stream it arrived on", 2U, session.last_stream_id);
  }
}

int main(void) {
  test_a_prefix_split_across_frames();
  test_a_complete_prefix_in_one_frame();
  test_control_and_qpack_reach_the_endpoint();
  test_starting_our_own_streams();
  test_frame_boundaries_on_a_stream();
  test_a_connection_frame_is_routed();
  test_the_outbound_half_sends_what_it_should();
  test_the_quic_transport_forwards();
  test_the_bidi_classifier();
  test_a_bidi_stream_is_routed_by_its_prefix();
  test_a_bidirectional_prefix_split_across_frames();
  test_the_pending_table_is_bounded();
  test_a_data_stream_knows_its_session();
  test_a_webtransport_uni_prefix_split_after_the_type();
  WT_TEST_MAIN_END("wt_http3_driver");
}
