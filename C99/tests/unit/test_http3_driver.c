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

int main(void) {
  test_a_prefix_split_across_frames();
  test_a_complete_prefix_in_one_frame();
  test_control_and_qpack_reach_the_endpoint();
  test_starting_our_own_streams();
  test_the_pending_table_is_bounded();
  WT_TEST_MAIN_END("wt_http3_driver");
}
