/* The session's send-side flow control (Phase 8).
 *
 * The tests are the draft's rules, checked at the surface a caller uses. Flow control is
 * off until both endpoints' SETTINGS say otherwise, and while it is off a capsule is
 * ignored rather than refused; a limit strictly increases; a limit above the draft's
 * stream-count ceiling is a flow-control error; and the allowances answer "may I send
 * this" before the refusal instead of after it, because that answer is what backpressure
 * means when there is no socket to block on. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/api/flow.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/writer.h"

static wt_session_t *make_session(void) {
  wt_session_config_t config = wt_session_config_default();
  wt_session_t *session = NULL;

  config.authority = "localhost";
  config.path = "/wt";
  config.session_id = 4U;
  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));
  WT_EXPECT_OK("and established", wt_session_established(session));
  return session;
}

static void test_advertised(void) {
  wt_http3_settings_t settings;

  wt_http3_settings_init(&settings);
  WT_EXPECT_INT("empty settings do not advertise flow control", 0,
                wt_session_flow_advertised(&settings));
  WT_EXPECT_INT("and neither does a NULL set", 0, wt_session_flow_advertised(NULL));

  WT_EXPECT_OK("a data limit is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 1024U));
  WT_EXPECT_INT("which advertises it", 1, wt_session_flow_advertised(&settings));

  /* The three settings are each enough on their own, and a ZERO value is not. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a zero data limit is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 0U));
  WT_EXPECT_INT("and zero is not an advertisement", 0, wt_session_flow_advertised(&settings));

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a stream count is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI, 4U));
  WT_EXPECT_INT("which advertises it", 1, wt_session_flow_advertised(&settings));

  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("the other direction is set too",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 4U));
  WT_EXPECT_INT("which advertises it", 1, wt_session_flow_advertised(&settings));
}

static void test_disabled_ignores_capsules(void) {
  wt_session_t *session = make_session();
  wt_session_flow_state_t state;
  uint8_t bytes[32];
  wt_writer_t w;

  /* With flow control off, every limit stays unenforced and a capsule is ignored. */
  state = wt_session_flow_snapshot(session);
  WT_EXPECT_INT("a fresh session has flow control off", 0, state.enabled);
  WT_EXPECT_INT("with no data limit", (int)WT_SESSION_LIMIT_DISABLED, (int)state.max_data_state);
  WT_EXPECT_U64("and a boundless allowance", (uint64_t)UINT64_MAX,
                (uint64_t)wt_session_flow_data_allowance(session));

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a MAX_DATA capsule writes", wt_webtransport_max_data_write(&w, 10U));
  WT_EXPECT_OK("and is accepted while flow control is off",
               wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  state = wt_session_flow_snapshot(session);
  WT_EXPECT_INT("without becoming a limit", (int)WT_SESSION_LIMIT_DISABLED,
                (int)state.max_data_state);
  WT_EXPECT_INT("and without an error", (int)WT_OK, (int)wt_session_last_error(session).status);

  /* Data and streams are not counted either: there is nothing to count against. */
  WT_EXPECT_OK("data may be recorded", wt_session_flow_record_data(session, 1000000U));
  WT_EXPECT_OK("and a stream started", wt_session_flow_register_stream(session, 0));
  state = wt_session_flow_snapshot(session);
  WT_EXPECT_U64("with no usage recorded", 0U, state.used_data);

  wt_session_destroy(session, NULL);
}

static void test_limits_and_allowances(void) {
  wt_session_t *session = make_session();
  wt_session_flow_state_t state;
  uint8_t bytes[32];
  wt_writer_t w;

  WT_EXPECT_OK("flow control is configured", wt_session_flow_configure(session, 1, 100U, 2U, 1U));
  state = wt_session_flow_snapshot(session);
  WT_EXPECT_INT("which is visible", 1, state.enabled);
  WT_EXPECT_INT("with a data limit", (int)WT_SESSION_LIMIT_LIMITED, (int)state.max_data_state);
  WT_EXPECT_U64("of the granted value", 100U, state.max_data);
  WT_EXPECT_U64("and 100 bytes of allowance", 100U, wt_session_flow_data_allowance(session));
  WT_EXPECT_U64("two bidirectional streams", 2U, wt_session_flow_stream_allowance(session, 0));
  WT_EXPECT_U64("and one unidirectional", 1U, wt_session_flow_stream_allowance(session, 1));

  /* Usage is counted, and the allowance follows it. */
  WT_EXPECT_OK("a byte is sent", wt_session_flow_record_data(session, 1U));
  WT_EXPECT_U64("leaving 99", 99U, wt_session_flow_data_allowance(session));
  WT_EXPECT_OK("the rest goes out", wt_session_flow_record_data(session, 99U));
  WT_EXPECT_U64("leaving nothing", 0U, wt_session_flow_data_allowance(session));

  /* One byte over the grant is refused, with the code the peer would be sent for it. */
  WT_EXPECT_STATUS("one byte more is refused", WT_ERR_LIMIT, wt_session_flow_record_data(session, 1U));
  WT_EXPECT_U64("with the draft's flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR,
                (uint64_t)wt_session_last_error(session).code);
  WT_EXPECT_U64("and the usage unchanged", 100U, wt_session_flow_snapshot(session).used_data);

  /* Streams: the count is per direction and refuses past the grant. */
  WT_EXPECT_OK("a bidirectional stream starts", wt_session_flow_register_stream(session, 0));
  WT_EXPECT_OK("and a second", wt_session_flow_register_stream(session, 0));
  WT_EXPECT_STATUS("but not a third", WT_ERR_LIMIT, wt_session_flow_register_stream(session, 0));
  WT_EXPECT_U64("while the other direction is untroubled", 1U,
                wt_session_flow_stream_allowance(session, 1));
  WT_EXPECT_OK("so its stream starts", wt_session_flow_register_stream(session, 1));
  WT_EXPECT_STATUS("and then it is full too", WT_ERR_LIMIT,
                   wt_session_flow_register_stream(session, 1));

  /* The peer raises both limits: the allowance grows and the counters stay. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a bigger MAX_DATA writes", wt_webtransport_max_data_write(&w, 200U));
  WT_EXPECT_OK("and is applied", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  WT_EXPECT_U64("giving 100 more bytes", 100U, wt_session_flow_data_allowance(session));
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a bigger stream count writes", wt_webtransport_max_streams_write(&w, 1, 3U));
  WT_EXPECT_OK("and is applied", wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  WT_EXPECT_U64("giving one more bidirectional stream", 1U,
                wt_session_flow_stream_allowance(session, 0));

  /* The draft's rule: strictly increasing, so a repeat and a decrease are both refused
   * with the flow-control code, and the limit stays where it was. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a repeated limit writes", wt_webtransport_max_data_write(&w, 200U));
  WT_EXPECT_STATUS("and is refused", WT_ERR_PROTOCOL,
                   wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  WT_EXPECT_U64("with the flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR,
                (uint64_t)wt_session_last_error(session).code);
  WT_EXPECT_U64("and the limit intact", 200U, wt_session_flow_snapshot(session).max_data);

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a count above the draft's ceiling writes",
               wt_webtransport_max_streams_write(&w, 1, WT_WEBTRANSPORT_MAX_STREAMS_VALUE + 1U));
  WT_EXPECT_STATUS("and is refused", WT_ERR_PROTOCOL,
                   wt_session_on_capsule(session, bytes, wt_writer_offset(&w)));
  WT_EXPECT_U64("as a flow-control error", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR,
                (uint64_t)wt_session_last_error(session).code);

  wt_session_destroy(session, NULL);
}

static void test_configuration_bounds(void) {
  wt_session_t *session = NULL;
  wt_session_config_t config = wt_session_config_default();
  uint64_t over = WT_WEBTRANSPORT_MAX_STREAMS_VALUE + 1U;

  config.authority = "localhost";
  config.path = "/wt";
  config.session_id = 4U;

  /* A SETTINGS value the draft forbids is refused where it is read, not at the first
   * capsule that happens to arrive later. */
  WT_EXPECT_OK("a session is created", wt_session_create(&config, NULL, &session));
  WT_EXPECT_STATUS("a stream count above the ceiling is refused at configure", WT_ERR_PROTOCOL,
                   wt_session_flow_configure(session, 1, 0U, over, 0U));
  WT_EXPECT_U64("with the flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR,
                (uint64_t)wt_session_last_error(session).code);

  /* An enabled session with a zero limit is a zero limit, not an absent one: that is what
   * an omitted SETTINGS value means on the wire. */
  WT_EXPECT_OK("a zero data limit configures", wt_session_flow_configure(session, 1, 0U, 0U, 0U));
  WT_EXPECT_INT("as a zero state", (int)WT_SESSION_LIMIT_ZERO,
                (int)wt_session_flow_snapshot(session).max_data_state);
  WT_EXPECT_U64("with no allowance at all", 0U, wt_session_flow_data_allowance(session));
  WT_EXPECT_STATUS("so sending is refused", WT_ERR_LIMIT, wt_session_flow_record_data(session, 1U));

  /* Zero for every stream also means no streams, in both directions. */
  WT_EXPECT_U64("and no bidirectional stream", 0U, wt_session_flow_stream_allowance(session, 0));
  WT_EXPECT_U64("nor a unidirectional one", 0U, wt_session_flow_stream_allowance(session, 1));
  WT_EXPECT_STATUS("so starting one is refused", WT_ERR_LIMIT,
                   wt_session_flow_register_stream(session, 1));

  wt_session_destroy(session, NULL);
}

int main(void) {
  test_advertised();
  test_disabled_ignores_capsules();
  test_limits_and_allowances();
  test_configuration_bounds();
  WT_TEST_MAIN_END("wt_api_flow");
}
