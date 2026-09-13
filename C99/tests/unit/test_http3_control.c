/* The peer's HTTP/3 control stream (RFC 9114 section 6.2.1).
 *
 * Four rules, four connection errors, and each is tested where it is easiest to
 * get wrong: the first frame must be SETTINGS (and a second one is unexpected),
 * only one control stream per peer exists, the stream may not close, and the
 * frames that describe requests have no meaning on it. The tests also pin the two
 * cases that are NOT errors, because those are the ones an over-eager
 * implementation breaks: GOAWAY, MAX_PUSH_ID, CANCEL_PUSH and unknown extension
 * frames are allowed there. */

#include "wt_test.h"

#include "webtransport/http3/control.h"

static void test_settings_first(void) {
  wt_http3_control_stream_t control;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_control_init(&control);
  WT_EXPECT_STATUS("a frame before the stream exists is a caller error", WT_ERR_STATE,
                   wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS, &error));
  /* WT_ERR_STATE is this endpoint's own ordering, not the peer's, so the code
   * says "no error" rather than naming one to send. */
  WT_EXPECT_U64("with no connection error named", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);

  WT_EXPECT_OK("the control stream opens", wt_http3_control_peer_opened(&control, &error));
  WT_EXPECT_INT("and is remembered as open", 1, control.opened);
  WT_EXPECT_OK("SETTINGS is the first frame", wt_http3_control_on_frame(&control,
                                                                       WT_HTTP3_FRAME_SETTINGS,
                                                                       &error));
  WT_EXPECT_INT("and is remembered", 1, control.settings_received);

  WT_EXPECT_STATUS("a second SETTINGS frame is unexpected", WT_ERR_PROTOCOL,
                   wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS, &error));
  WT_EXPECT_U64("as a frame unexpected error", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
}

static void test_first_frame_must_be_settings(void) {
  static const uint64_t frames[] = {WT_HTTP3_FRAME_DATA, WT_HTTP3_FRAME_HEADERS,
                                    WT_HTTP3_FRAME_GOAWAY, WT_HTTP3_FRAME_MAX_PUSH_ID,
                                    WT_HTTP3_FRAME_CANCEL_PUSH, WT_HTTP3_FRAME_PUSH_PROMISE};
  size_t i;

  for (i = 0U; i < sizeof(frames) / sizeof(frames[0]); i++) {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    wt_http3_control_init(&control);
    WT_EXPECT_OK("the stream opens", wt_http3_control_peer_opened(&control, &error));
    WT_EXPECT_STATUS("a first frame that is not SETTINGS is refused", WT_ERR_PROTOCOL,
                     wt_http3_control_on_frame(&control, frames[i], &error));
    WT_EXPECT_U64("with H3_MISSING_SETTINGS", WT_HTTP3_MISSING_SETTINGS, (uint64_t)error);
    WT_EXPECT_INT("and SETTINGS is still owed", 0, control.settings_received);
  }
}

static void test_frames_after_settings(void) {
  static const uint64_t allowed[] = {WT_HTTP3_FRAME_CANCEL_PUSH, WT_HTTP3_FRAME_GOAWAY,
                                     WT_HTTP3_FRAME_MAX_PUSH_ID, 0x2aU /* unknown extension */};
  static const uint64_t refused[] = {WT_HTTP3_FRAME_DATA, WT_HTTP3_FRAME_HEADERS,
                                     WT_HTTP3_FRAME_PUSH_PROMISE, 0x21U /* reserved for HTTP/2 */,
                                     0x40U /* also reserved: 0x1f * 1 + 0x21 */};
  size_t i;

  for (i = 0U; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    wt_http3_control_init(&control);
    WT_EXPECT_OK("the stream opens", wt_http3_control_peer_opened(&control, &error));
    WT_EXPECT_OK("SETTINGS arrives", wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS,
                                                               &error));
    WT_EXPECT_OK("and the frame is allowed", wt_http3_control_on_frame(&control, allowed[i], &error));
  }

  for (i = 0U; i < sizeof(refused) / sizeof(refused[0]); i++) {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;

    wt_http3_control_init(&control);
    WT_EXPECT_OK("the stream opens", wt_http3_control_peer_opened(&control, &error));
    WT_EXPECT_OK("SETTINGS arrives", wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS,
                                                               &error));
    WT_EXPECT_STATUS("a frame that does not belong there is refused", WT_ERR_PROTOCOL,
                     wt_http3_control_on_frame(&control, refused[i], &error));
    WT_EXPECT_U64("as unexpected", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  }
}

static void test_one_control_stream_and_closing(void) {
  wt_http3_control_stream_t control;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_control_init(&control);
  WT_EXPECT_OK("the first control stream opens", wt_http3_control_peer_opened(&control, &error));
  WT_EXPECT_STATUS("a second is refused", WT_ERR_PROTOCOL,
                   wt_http3_control_peer_opened(&control, &error));
  WT_EXPECT_U64("as a stream creation error", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  WT_EXPECT_OK("SETTINGS arrives", wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS,
                                                             &error));
  WT_EXPECT_STATUS("closing the control stream is refused", WT_ERR_PROTOCOL,
                   wt_http3_control_on_closed(&control, &error));
  WT_EXPECT_U64("as a closed critical stream", WT_HTTP3_CLOSED_CRITICAL_STREAM, (uint64_t)error);
  WT_EXPECT_INT("and the stream is marked closed", 1, control.closed);
  WT_EXPECT_STATUS("so no frame follows it", WT_ERR_STATE,
                   wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_GOAWAY, &error));
  WT_EXPECT_STATUS("and closing it twice is a caller error", WT_ERR_STATE,
                   wt_http3_control_on_closed(&control, &error));

  /* A stream that closes before SETTINGS is the same error: the closure is what
   * section 6.2.1 makes an error, not what the stream had carried. */
  wt_http3_control_init(&control);
  WT_EXPECT_OK("another connection's stream opens", wt_http3_control_peer_opened(&control, &error));
  WT_EXPECT_STATUS("closing it before SETTINGS is refused", WT_ERR_PROTOCOL,
                   wt_http3_control_on_closed(&control, &error));
  WT_EXPECT_U64("as a closed critical stream", WT_HTTP3_CLOSED_CRITICAL_STREAM, (uint64_t)error);

  /* And a stream that never opened cannot close. */
  wt_http3_control_init(&control);
  WT_EXPECT_STATUS("closing a stream that does not exist is a caller error", WT_ERR_STATE,
                   wt_http3_control_on_closed(&control, &error));
}

int main(void) {
  test_settings_first();
  test_first_frame_must_be_settings();
  test_frames_after_settings();
  test_one_control_stream_and_closing();
  WT_TEST_MAIN_END("wt_http3_control");
}
