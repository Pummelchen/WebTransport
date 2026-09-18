/* The connection close paths.
 *
 * THE TWO FORMS ARE CHECKED BECAUSE THEY ARE DIFFERENT MESSAGES: a transport close names the frame
 * that caused it and an application close cannot, and a connection that sent the wrong form would be
 * telling the peer something it cannot act on. The test checks which form comes out of each entry
 * point, and that the frame encoder accepts both.
 *
 * THE DRAINING PERIOD IS CHECKED AS ARITHMETIC: three probe timeouts from the moment of closing, with
 * no deadline at all when there is no probe timeout to multiply -- which is not the same as a deadline
 * that has already passed.
 *
 * AND THE RULE ABOUT WHICH FRAMES MAY STILL BE PROCESSED IS CHECKED AS A LIST, because it is one:
 * RFC 9000 section 10.2.1 allows CONNECTION_CLOSE, PADDING and the probes, and nothing else.
 */

#include "wt_test.h"

#include "webtransport/quic/close.h"

static void test_forms(void) {
  wt_quic_close_state_t state;
  wt_quic_frame_t frame;
  static const uint8_t reason[] = "too many streams";

  wt_quic_close_state_init(&state);
  WT_EXPECT_INT("a new connection is not closed", 0, wt_quic_close_is_closed(&state));
  WT_EXPECT_U64("and has no kind", (uint64_t)WT_QUIC_CLOSE_NONE,
                (uint64_t)wt_quic_close_kind(&state));
  WT_EXPECT_STATUS("and no frame to send", WT_ERR_STATE, wt_quic_close_frame(&state, &frame));
  WT_EXPECT_INT("nothing is expired", 0, wt_quic_close_draining_expired(&state, 1000000U));

  /* A transport close carries the frame type that caused it. */
  WT_EXPECT_OK("a transport close",
               wt_quic_close_transport(&state, 0x0aU, WT_QUIC_FRAME_STREAM_BASE, reason,
                                       sizeof(reason) - 1U, 1000U, 100U));
  WT_EXPECT_INT("which closes the connection", 1, wt_quic_close_is_closed(&state));
  WT_EXPECT_U64("with the transport kind", (uint64_t)WT_QUIC_CLOSE_TRANSPORT,
                (uint64_t)wt_quic_close_kind(&state));
  WT_EXPECT_U64("the error code", 0x0aU, (uint64_t)state.error_code);
  WT_EXPECT_U64("the frame that caused it", WT_QUIC_FRAME_STREAM_BASE, (uint64_t)state.frame_type);
  WT_EXPECT_OK("the frame it produces", wt_quic_close_frame(&state, &frame));
  WT_EXPECT_U64("is the transport form", (uint64_t)WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT,
                (uint64_t)frame.kind);
  WT_EXPECT_INT("which carries a frame type", 1, frame.as.connection_close.has_frame_type);
  WT_EXPECT_U64("the same frame type", WT_QUIC_FRAME_STREAM_BASE,
                frame.as.connection_close.frame_type);
  WT_EXPECT_U64("the error code", 0x0aU, frame.as.connection_close.error_code);
  WT_EXPECT_U64("and the reason's length", sizeof(reason) - 1U,
                (uint64_t)frame.as.connection_close.reason_length);
  /* The frame encoder accepts what this produced, which is the check that the two agree. */
  {
    uint8_t buffer[64];
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_OK("and the frame encodes", wt_quic_frame_encode(&w, &frame));
    WT_EXPECT_TRUE("with bytes", wt_writer_offset(&w) > 0U);
  }

  /* A second close is refused: two different reasons for one connection is not a message a peer can
   * act on. */
  WT_EXPECT_STATUS("a second close is refused", WT_ERR_STATE,
                   wt_quic_close_application(&state, 1U, NULL, 0U, 2000U, 100U));
  WT_EXPECT_U64("and the first one stands", 1000U, (uint64_t)state.closed_at);

  /* An application close has no frame type field at all. */
  {
    wt_quic_close_state_t app;
    wt_quic_close_state_init(&app);
    WT_EXPECT_OK("an application close",
                 wt_quic_close_application(&app, 42U, reason, sizeof(reason) - 1U, 500U, 50U));
    WT_EXPECT_U64("with the application kind", (uint64_t)WT_QUIC_CLOSE_APPLICATION,
                  (uint64_t)wt_quic_close_kind(&app));
    WT_EXPECT_OK("the frame", wt_quic_close_frame(&app, &frame));
    WT_EXPECT_U64("is the application form",
                  (uint64_t)WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION, (uint64_t)frame.kind);
    WT_EXPECT_INT("which has no frame type", 0, frame.as.connection_close.has_frame_type);
    WT_EXPECT_U64("and the application's error code", 42U,
                  (uint64_t)frame.as.connection_close.error_code);
    {
      uint8_t buffer[64];
      wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
      WT_EXPECT_OK("and it encodes", wt_quic_frame_encode(&w, &frame));
    }
  }

  /* A transport close with no frame to name: frame type zero is PADDING, which is why the flag
   * exists rather than the value. */
  {
    wt_quic_close_state_t plain;
    wt_quic_close_state_init(&plain);
    WT_EXPECT_OK("a transport close with no frame",
                 wt_quic_close_transport(&plain, 1U, 0U, NULL, 0U, 0U, 0U));
    WT_EXPECT_OK("produces its frame", wt_quic_close_frame(&plain, &frame));
    WT_EXPECT_INT("with the frame field present", 1, frame.as.connection_close.has_frame_type);
    WT_EXPECT_U64("and zero in it", 0U, (uint64_t)frame.as.connection_close.frame_type);
  }

  /* A reason with no bytes means an absent reason rather than a NULL dereference. */
  WT_EXPECT_STATUS("a NULL reason with a length is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_close_application(&state, 1U, NULL, 5U, 0U, 0U));
  WT_EXPECT_STATUS("a NULL state is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_close_transport(NULL, 1U, 0U, NULL, 0U, 0U, 0U));
  WT_EXPECT_STATUS("and a NULL frame is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_close_frame(&state, NULL));
}

static void test_draining(void) {
  wt_quic_close_state_t state;

  /* Three probe timeouts. A probe timeout of 100 microseconds gives a deadline of 300 after the
   * close. */
  wt_quic_close_state_init(&state);
  WT_EXPECT_OK("a close with a probe timeout",
               wt_quic_close_transport(&state, 0U, 0U, NULL, 0U, 1000U, 100U));
  WT_EXPECT_U64("the deadline is three timeouts later", 1000U + 3U * 100U,
                (uint64_t)state.draining_until);
  WT_EXPECT_INT("one microsecond before it, not expired", 0,
                wt_quic_close_draining_expired(&state, 1299U));
  WT_EXPECT_INT("at it, expired", 1, wt_quic_close_draining_expired(&state, 1300U));
  WT_EXPECT_INT("and after it", 1, wt_quic_close_draining_expired(&state, 5000U));

  /* With no probe timeout there is no deadline: a connection that has measured nothing cannot arm a
   * timer, and a deadline in the past would expire immediately. */
  {
    wt_quic_close_state_t none;
    wt_quic_close_state_init(&none);
    WT_EXPECT_OK("a close with no probe timeout",
                 wt_quic_close_application(&none, 0U, NULL, 0U, 1000U, 0U));
    WT_EXPECT_INT("has no deadline", 0, none.has_draining_deadline);
    WT_EXPECT_INT("so it never expires", 0, wt_quic_close_draining_expired(&none, 999999999U));
  }

  /* A connection that was never closed has nothing to expire. */
  {
    wt_quic_close_state_t open;
    wt_quic_close_state_init(&open);
    WT_EXPECT_INT("an open connection does not expire", 0,
                  wt_quic_close_draining_expired(&open, 999999999U));
  }
}

static void test_accepted_frames(void) {
  /* RFC 9000 section 10.2.1's list. */
  WT_EXPECT_INT("CONNECTION_CLOSE is processed", 1,
                wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT));
  WT_EXPECT_INT("the application form too", 1,
                wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION));
  WT_EXPECT_INT("PADDING is processed", 1, wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_PADDING));
  WT_EXPECT_INT("PING is processed", 1, wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_PING));
  WT_EXPECT_INT("a path challenge is processed", 1,
                wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_PATH_CHALLENGE));
  WT_EXPECT_INT("a path response is processed", 1,
                wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_PATH_RESPONSE));
  /* And the list is narrow: everything that would act on a dead connection is not. */
  WT_EXPECT_INT("STREAM is not", 0, wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_STREAM_BASE));
  WT_EXPECT_INT("CRYPTO is not", 0, wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_CRYPTO));
  WT_EXPECT_INT("ACK is not", 0, wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_ACK));
  WT_EXPECT_INT("MAX_DATA is not", 0, wt_quic_close_accepts_frame_type(WT_QUIC_FRAME_MAX_DATA));
  WT_EXPECT_INT("nor is an unknown frame type", 0, wt_quic_close_accepts_frame_type(0x3fU));
}

int main(void) {
  test_forms();
  test_draining();
  test_accepted_frames();

  WT_TEST_MAIN_END("wt_quic_close");
}
