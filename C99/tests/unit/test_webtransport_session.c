/* A WebTransport session's lifecycle (draft-ietf-webtrans-http3-16 sections 3 to 5).
 *
 * The state machine is small and every rule in it is about what a session may DO, so the
 * tests are transitions rather than bytes: a session that is establishing may not carry
 * streams, a drain in either direction stops new streams but allows the session to
 * finish, a close ends everything, and the FIRST close's code is the one the session
 * reports however many more arrive. The last rule is the one worth a test of its own,
 * because an implementation that let the latest close win would report an error code the
 * peer never ended the session with. */

#include "wt_test.h"

#include "webtransport/webtransport/session.h"

static void test_the_establishing_and_established_states(void) {
  wt_webtransport_session_t session;
  uint8_t bytes[32];
  wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));

  wt_webtransport_session_init(&session);
  WT_EXPECT_INT("a new session is establishing", (int)WT_WEBTRANSPORT_SESSION_ESTABLISHING,
                (int)session.state);
  WT_EXPECT_INT("and carries no new streams", 0, wt_webtransport_session_allows_new_streams(&session));
  WT_EXPECT_STATUS("and cannot be closed before it exists", WT_ERR_STATE,
                   wt_webtransport_session_write_close(&session, &w, 0U, NULL, 0U));

  WT_EXPECT_OK("the response establishes it", wt_webtransport_session_established(&session));
  WT_EXPECT_INT("which is its state", (int)WT_WEBTRANSPORT_SESSION_ESTABLISHED, (int)session.state);
  WT_EXPECT_INT("and now streams are allowed", 1,
                wt_webtransport_session_allows_new_streams(&session));
  WT_EXPECT_STATUS("and it cannot be established twice", WT_ERR_STATE,
                   wt_webtransport_session_established(&session));
}

static void test_draining(void) {
  wt_webtransport_session_t session;
  uint8_t bytes[32];
  wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));

  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("establish", wt_webtransport_session_established(&session));

  /* A drain RECEIVED: the peer is going away, and no new stream may be started. */
  WT_EXPECT_OK("a received drain is recorded", wt_webtransport_session_on_drain(&session, 0));
  WT_EXPECT_INT("moving to draining", (int)WT_WEBTRANSPORT_SESSION_DRAINING, (int)session.state);
  WT_EXPECT_INT("with no new streams", 0, wt_webtransport_session_allows_new_streams(&session));
  WT_EXPECT_INT("and the direction remembered", 1, session.drain_received);
  WT_EXPECT_INT("while the sent one is not", 0, session.drain_sent);
  /* Repeating it is idempotent: a peer may send a drain more than once. */
  WT_EXPECT_OK("a second drain is accepted", wt_webtransport_session_on_drain(&session, 0));

  /* The other direction: this endpoint draining. */
  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("establish again", wt_webtransport_session_established(&session));
  WT_EXPECT_OK("a drain writes", wt_webtransport_session_write_drain(&session, &w));
  WT_EXPECT_INT("marking it sent", 1, session.drain_sent);
  WT_EXPECT_INT("and stopping new streams", 0,
                wt_webtransport_session_allows_new_streams(&session));

  /* A drain after a close is a caller error: the session has no state for it. */
  WT_EXPECT_OK("a close ends it", wt_webtransport_session_on_close(&session, 1, 0U));
  WT_EXPECT_STATUS("so a later drain is refused", WT_ERR_STATE,
                   wt_webtransport_session_on_drain(&session, 0));
}

static void test_closing_and_the_first_code(void) {
  wt_webtransport_session_t session;
  uint8_t bytes[64];
  wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));

  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("establish", wt_webtransport_session_established(&session));

  WT_EXPECT_OK("a close writes", wt_webtransport_session_write_close(&session, &w, 0x1234U,
                                                                     (const uint8_t *)"bye", 3U));
  WT_EXPECT_INT("closing the session", (int)WT_WEBTRANSPORT_SESSION_CLOSED, (int)session.state);
  WT_EXPECT_INT("with the code set", 1, session.close_error_set);
  WT_EXPECT_U64("to what was sent", 0x1234U, (uint64_t)session.close_error_code);
  WT_EXPECT_INT("and the direction remembered", 1, session.close_sent);
  WT_EXPECT_INT("with no new streams", 0, wt_webtransport_session_allows_new_streams(&session));

  /* A close the PEER sends afterwards does not rewrite the code: the session ended at
   * the first one, and reporting the second would tell the caller about an error code
   * that did not end anything. */
  WT_EXPECT_OK("a second close is accepted", wt_webtransport_session_on_close(&session, 0, 0x99U));
  WT_EXPECT_U64("without changing the code", 0x1234U, (uint64_t)session.close_error_code);
  WT_EXPECT_INT("and the peer's direction is recorded", 1, session.close_received);

  /* A stream that just ends has no code to report, which is not the same as a close with
   * code zero. */
  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("establish once more", wt_webtransport_session_established(&session));
  WT_EXPECT_OK("and let the stream end", wt_webtransport_session_on_stream_end(&session));
  WT_EXPECT_INT("which closes the session", (int)WT_WEBTRANSPORT_SESSION_CLOSED,
                (int)session.state);
  WT_EXPECT_INT("with no application code", 0, session.close_error_set);
  WT_EXPECT_STATUS("and no second end", WT_ERR_STATE,
                   wt_webtransport_session_on_stream_end(&session));
}

int main(void) {
  test_the_establishing_and_established_states();
  test_draining();
  test_closing_and_the_first_code();
  WT_TEST_MAIN_END("wt_webtransport_session");
}
