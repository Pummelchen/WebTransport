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

#include <string.h>

#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/session.h"

/* The CONNECT stream's capsules, walked (WT-164).
 *
 * Draft-16 section 5 puts the session's control messages on the CONNECT stream as capsules, and a peer may put
 * several in one buffer and the connection may split one across many. The walker therefore has to do three things
 * that are each a rule of their own: apply what the session owns, hand over what only the caller can apply, and
 * leave a capsule that has not fully arrived exactly where it is -- because the caller owns the buffer and appends
 * to it.
 */
typedef struct capsule_observer {
  unsigned calls;
  uint64_t last_type;
  uint64_t maximum;
} capsule_observer_t;

static wt_status_t observe_flow(void *context, const wt_webtransport_capsule_t *capsule,
                                wt_http3_error_t *out_error) {
  capsule_observer_t *log = context;

  log->calls++;
  log->last_type = capsule->type;
  if (capsule->type == WT_CAPSULE_MAX_DATA) {
    uint64_t maximum = 0U;
    /* The observer owns this capsule's rules, including what a malformed one means: a value that is not exactly
     * one varint is H3_MESSAGE_ERROR, and the walker passes that code on rather than inventing its own. */
    if (wt_webtransport_max_data_parse(capsule, &maximum, out_error) != WT_OK) return WT_ERR_PROTOCOL;
    log->maximum = maximum;
  }
  return WT_OK;
}

static void test_the_connect_streams_capsules_are_walked(void) {
  uint8_t buffer[128];
  wt_webtransport_session_t session;
  wt_webtransport_flow_limits_t limits;
  capsule_observer_t log;
  wt_writer_t w;
  wt_cursor_t cursor;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  memset(&log, 0, sizeof(log));
  wt_webtransport_flow_limits_init(&limits);
  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("a session establishes", wt_webtransport_session_established(&session));

  /* A drain, a flow-control grant and a close in ONE buffer: three capsules, two of them the session's and one the
   * caller's. The session ends with the peer's close code, and the grant is applied by the observer -- whose
   * account is the one the caller enforces against. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_OK("the drain capsule encodes", wt_webtransport_drain_session_write(&w));
  WT_EXPECT_OK("the grant encodes", wt_webtransport_max_data_write(&w, 65536U));
  WT_EXPECT_OK("the close capsule encodes",
               wt_webtransport_close_session_write(&w, 0x1234U, (const uint8_t *)"bye", 3U));
  cursor = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_OK("the capsules are walked",
               wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow, &log,
                                                        &error));
  WT_EXPECT_INT("the drain stopped new streams", 0, wt_webtransport_session_allows_new_streams(&session));
  WT_EXPECT_INT("and came from the peer", 1, session.drain_received);
  WT_EXPECT_U64("the observer was given only what the session does not own", 1U, (uint64_t)log.calls);
  WT_EXPECT_U64("which is the flow-control grant", WT_CAPSULE_MAX_DATA, log.last_type);
  WT_EXPECT_U64("whose value reached the caller's account", 65536U, log.maximum);
  WT_EXPECT_INT("the close ended the session", (int)WT_WEBTRANSPORT_SESSION_CLOSED, (int)session.state);
  WT_EXPECT_INT("with the peer's code", 1, session.close_error_set);
  WT_EXPECT_U64("as the code the capsule carried", 0x1234U, (uint64_t)session.close_error_code);
  WT_EXPECT_INT("and the cursor walked all of it", 1, wt_cursor_at_end(&cursor));

  /* A capsule the connection split: one byte short is a WAIT, not a malformed capsule, and the cursor must not
   * move -- the caller appends the next bytes to the same buffer and walks again. */
  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("a session establishes once more", wt_webtransport_session_established(&session));
  log.calls = 0U;
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_OK("a grant encodes", wt_webtransport_max_data_write(&w, 4096U));
  {
    size_t complete = wt_writer_offset(&w);
    size_t partial = complete - 1U; /* the second byte of the value has not arrived */

    cursor = wt_cursor_init(buffer, partial);
    WT_EXPECT_STATUS("a capsule that has not fully arrived is a WAIT", WT_ERR_TRUNCATED,
                     wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow,
                                                              &log, &error));
    WT_EXPECT_U64("with nothing applied", 0U, (uint64_t)log.calls);
    WT_EXPECT_U64("and the cursor left on its first byte", (uint64_t)partial,
                  (uint64_t)wt_cursor_remaining(&cursor));

    cursor = wt_cursor_init(buffer, complete);
    WT_EXPECT_OK("and the completed bytes are walked",
                 wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow, &log,
                                                          &error));
    WT_EXPECT_U64("applying the grant now", 4096U, log.maximum);
    WT_EXPECT_INT("at the end of the buffer", 1, wt_cursor_at_end(&cursor));
  }

  /* A length beyond what the caller will buffer can never be assembled, so it is a LIMIT rather than a wait that
   * would never end. The bound is the CALLER's, which is why it is a parameter. */
  {
    uint8_t huge[8];
    size_t huge_length = wt_quic_varint_encode(WT_CAPSULE_MAX_DATA, huge, sizeof(huge));

    huge_length += wt_quic_varint_encode(63U, huge + huge_length, sizeof(huge) - huge_length);
    cursor = wt_cursor_init(huge, huge_length);
    WT_EXPECT_STATUS("a capsule past the caller's bound is refused", WT_ERR_LIMIT,
                     wt_webtransport_session_on_capsule_bytes(&session, &cursor, 8U, observe_flow, &log, &error));
    WT_EXPECT_U64("as excessive load", (uint64_t)WT_HTTP3_EXCESSIVE_LOAD, (uint64_t)error);
  }

  /* A malformed capsule is the OBSERVER's to refuse, and its code is what comes back: the session layer applies
   * only what it understands, and a value that is not exactly one varint is not a limit. */
  {
    static const uint8_t k_two_bytes[] = {0x01U, 0x02U};
    wt_webtransport_capsule_t malformed;

    memset(&malformed, 0, sizeof(malformed));
    malformed.type = WT_CAPSULE_MAX_DATA;
    malformed.value = k_two_bytes;
    malformed.value_length = sizeof(k_two_bytes);
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_OK("a malformed grant encodes", wt_webtransport_capsule_encode(&w, &malformed));
    cursor = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_STATUS("and is refused by the walker's observer", WT_ERR_PROTOCOL,
                     wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow,
                                                              &log, &error));
    WT_EXPECT_U64("naming the rule it broke", (uint64_t)WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  }

  /* A capsule nobody owns is dropped, which RFC 9297 section 2 makes legal for a receiver: this caller keeps no
   * flow account here, and a capsule it does not understand is not a reason to end a session. */
  {
    static const uint8_t k_value[] = {0x2aU};
    wt_webtransport_capsule_t unknown;

    memset(&unknown, 0, sizeof(unknown));
    unknown.type = 0x2b603742U; /* the WT_MAX_SESSIONS SETTINGS identifier, which is not a capsule type */
    unknown.value = k_value;
    unknown.value_length = sizeof(k_value);
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_OK("an unknown capsule encodes", wt_webtransport_capsule_encode(&w, &unknown));
    cursor = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_OK("and is walked without an owner", wt_webtransport_session_on_capsule_bytes(&session, &cursor,
                                                                                            sizeof(buffer), NULL,
                                                                                            NULL, &error));
    WT_EXPECT_INT("past it", 1, wt_cursor_at_end(&cursor));
  }
}

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

/* Section 5.4: WT_CLOSE_SESSION is the last thing on the CONNECT stream. The caller rebuilds a cursor once per
 * delivery (one per STREAM frame), so a peer can put the close in one frame and a flow-control grant in the
 * next; the walker must refuse the later frame's capsules rather than apply them. The tail check inside the
 * close branch cannot see that case -- it only sees what is left of the buffer the close arrived in -- so this
 * test delivers the close and the grant as two separate calls on the same session. */
static void test_a_capsule_after_the_close_is_refused(void) {
  uint8_t buffer[64];
  wt_webtransport_session_t session;
  capsule_observer_t log;
  wt_writer_t w;
  wt_cursor_t cursor;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t grant_length;

  memset(&log, 0, sizeof(log));
  wt_webtransport_session_init(&session);
  WT_EXPECT_OK("a session establishes", wt_webtransport_session_established(&session));

  /* The close arrives in one frame and ends the session. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_OK("the close capsule encodes", wt_webtransport_close_session_write(&w, 0x22U, NULL, 0U));
  cursor = wt_cursor_init(buffer, wt_writer_offset(&w));
  WT_EXPECT_OK("and closes the session",
               wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow, &log,
                                                        &error));
  WT_EXPECT_INT("which is now closed", (int)WT_WEBTRANSPORT_SESSION_CLOSED, (int)session.state);

  /* A LATER STREAM frame carries a flow-control grant. Nothing about it may be applied. */
  w = wt_writer_init(buffer, sizeof(buffer));
  WT_EXPECT_OK("a grant encodes into a later frame", wt_webtransport_max_data_write(&w, 65536U));
  grant_length = wt_writer_offset(&w);
  cursor = wt_cursor_init(buffer, grant_length);
  WT_EXPECT_STATUS("and the closed session refuses it", WT_ERR_PROTOCOL,
                   wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow, &log,
                                                            &error));
  WT_EXPECT_U64("naming a message error", (uint64_t)WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  WT_EXPECT_U64("with the observer never called", 0U, (uint64_t)log.calls);
  WT_EXPECT_U64("and the cursor left where it was", (uint64_t)grant_length,
                (uint64_t)wt_cursor_remaining(&cursor));

  /* An empty delivery is the ordinary FIN after the close, not a new capsule: it is not refused. */
  cursor = wt_cursor_init(buffer, 0U);
  WT_EXPECT_OK("an empty delivery after the close is still fine",
               wt_webtransport_session_on_capsule_bytes(&session, &cursor, sizeof(buffer), observe_flow, &log,
                                                        &error));
}

int main(void) {
  test_the_establishing_and_established_states();
  test_draining();
  test_closing_and_the_first_code();
  test_the_connect_streams_capsules_are_walked();
  test_a_capsule_after_the_close_is_refused();
  WT_TEST_MAIN_END("wt_webtransport_session");
}
