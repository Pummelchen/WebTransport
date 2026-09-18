/* The interop matrix scenarios (Phase 10). */

#include "scenario_matrix.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/api/flow.h"
#include "webtransport/api/session.h"
#include "webtransport/cursor.h"
#include "webtransport/http3/control.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/endpoint.h"
#include "webtransport/http3/goaway.h"
#include "webtransport/http3/role.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/writer.h"

#include "webtransport/http3/frame.h"

#include "webtransport/quic/datagram.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/webtransport/session_request.h"

#include "scenario_matrix_support.h"

void wt_scenario_malformed_flow_matrix(wt_cli_report_t *report) {
  matrix_row_t rows[WT_MATRIX_MAX_CASES];
  unsigned count = 0U;

  /* The malformed inputs a peer can send, each refused with a code rather than a shrug: a capsule that claims
   * more than this endpoint will buffer, and one that has not arrived at all -- which on a stream is a WAIT,
   * and is the only one of these that is. */
  {
    static const uint8_t value[20] = {0};
    uint8_t bytes[64];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    wt_webtransport_capsule_t capsule;
    wt_cursor_t c;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_capsule_encode(
                 &w, &(wt_webtransport_capsule_t){WT_CAPSULE_MAX_DATA, value, sizeof(value), 0U}) ==
             WT_OK;
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    memset(&capsule, 0, sizeof(capsule));
    ok = ok && wt_webtransport_capsule_decode(&c, 8U, &capsule, &error) == WT_ERR_LIMIT;
    rows[count].name = "a capsule over the caller's bound is WT_ERR_LIMIT";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_capsule_t capsule;
    wt_cursor_t c = wt_cursor_init(NULL, 0U);
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    memset(&capsule, 0, sizeof(capsule));
    int ok = wt_webtransport_capsule_decode(&c, 64U, &capsule, &error) == WT_ERR_TRUNCATED;
    rows[count].name = "a capsule that has not arrived is a wait";
    rows[count].held = ok;
    count++;
  }

  /* The control stream's three rules, which are the ones a peer breaks first. */
  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_http3_control_init(&control);
    int ok = wt_http3_control_peer_opened(&control, &error) == WT_OK;
    error = WT_HTTP3_NO_ERROR;
    ok = ok && wt_http3_control_peer_opened(&control, &error) != WT_OK &&
         error == WT_HTTP3_STREAM_CREATION_ERROR;
    rows[count].name = "a second control stream is H3_STREAM_CREATION_ERROR";
    rows[count].held = ok;
    count++;
  }
  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_http3_control_init(&control);
    (void)wt_http3_control_peer_opened(&control, &error);
    error = WT_HTTP3_NO_ERROR;
    (void)wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS, &error);
    error = WT_HTTP3_NO_ERROR;
    int ok = wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_HEADERS, &error) != WT_OK &&
             error == WT_HTTP3_FRAME_UNEXPECTED;
    rows[count].name = "a HEADERS frame on the control stream is H3_FRAME_UNEXPECTED";
    rows[count].held = ok;
    count++;
  }
  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_http3_control_init(&control);
    (void)wt_http3_control_peer_opened(&control, &error);
    error = WT_HTTP3_NO_ERROR;
    (void)wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS, &error);
    error = WT_HTTP3_NO_ERROR;
    /* DATA is the frame a stream carryies, so it is exactly as out of place here as HEADERS. */
    int ok = wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_DATA, &error) != WT_OK &&
             error == WT_HTTP3_FRAME_UNEXPECTED;
    rows[count].name = "a DATA frame on the control stream is H3_FRAME_UNEXPECTED";
    rows[count].held = ok;
    count++;
  }

  /* A field section that cannot be decoded: a dynamic-table reference with no table, refused rather than read
   * as empty. */
  {
    static const uint8_t section[] = {0x01U, 0x00U};
    uint8_t scratch[64];
    wt_http3_message_t message;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    memset(&message, 0, sizeof(message));
    int ok = wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, sizeof(section),
                                     NULL, 0U, 0U, scratch, sizeof(scratch), &error) != WT_OK;
    rows[count].name = "a field section needing a table that was never advertised is refused";
    rows[count].held = ok;
    count++;
  }

  /* The flow control the draft puts on the session itself: a limit of four bytes accepts four and refuses the
   * fifth, and the refusal is the draft's flow-control code rather than a shrug. */
  {
    wt_session_config_t config = wt_session_config_default();
    wt_session_t *session = NULL;
    int ok;
    config.authority = "example.com";
    config.path = "/flow";
    config.session_id = 0U;
    ok = wt_session_create(&config, NULL, &session) == WT_OK && session != NULL;
    ok = ok && wt_session_flow_configure(session, 1, 4U, 1U, 0U) == WT_OK;
    {
      wt_session_flow_state_t state = wt_session_flow_snapshot(session);
      ok = ok && state.enabled == 1 && state.max_data_state == WT_SESSION_LIMIT_LIMITED &&
           state.max_data == 4U && state.used_data == 0U;
    }
    ok = ok && wt_session_flow_record_data(session, 4U) == WT_OK;
    {
      wt_session_flow_state_t state = wt_session_flow_snapshot(session);
      ok = ok && state.used_data == 4U && wt_session_flow_data_allowance(session) == 0U;
    }
    ok = ok && wt_session_flow_record_data(session, 1U) != WT_OK;
    {
      wt_session_error_t error = wt_session_last_error(session);
      ok = ok && error.code == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
    }
    rows[count].name = "a session limit of four bytes accepts four and refuses the fifth";
    rows[count].held = ok;
    if (session != NULL) wt_session_destroy(session, NULL);
    count++;
  }

  /* The stream count is a limit of its own, in each direction. */
  {
    wt_session_config_t config = wt_session_config_default();
    wt_session_t *session = NULL;
    int ok;
    config.authority = "example.com";
    config.path = "/flow";
    config.session_id = 4U;
    ok = wt_session_create(&config, NULL, &session) == WT_OK && session != NULL;
    ok = ok && wt_session_flow_configure(session, 1, 100U, 1U, 0U) == WT_OK;
    ok = ok && wt_session_flow_register_stream(session, 0) == WT_OK &&
         wt_session_flow_register_stream(session, 0) != WT_OK;
    rows[count].name = "one bidirectional stream is allowed and a second is not";
    rows[count].held = ok;
    if (session != NULL) wt_session_destroy(session, NULL);
    count++;
  }

  /* And the case that keeps the limit from being read as a wall: a session that agreed NO flow control sends
   * without one. */
  {
    wt_session_config_t config = wt_session_config_default();
    wt_session_t *session = NULL;
    int ok;
    config.authority = "example.com";
    config.path = "/flow";
    config.session_id = 8U;
    ok = wt_session_create(&config, NULL, &session) == WT_OK && session != NULL;
    ok = ok && wt_session_flow_configure(session, 0, 0U, 0U, 0U) == WT_OK;
    ok = ok && wt_session_flow_record_data(session, 1000000U) == WT_OK &&
         wt_session_flow_data_allowance(session) == UINT64_MAX;
    {
      wt_session_flow_state_t state = wt_session_flow_snapshot(session);
      ok = ok && state.enabled == 0 && state.max_data_state == WT_SESSION_LIMIT_DISABLED;
    }
    rows[count].name = "a session with flow control disabled enforces no limit";
    rows[count].held = ok;
    if (session != NULL) wt_session_destroy(session, NULL);
    count++;
  }

  report_matrix(report, "interop-malformed-flow-matrix", "malformed and flow-control cases", rows,
                count);
}

void wt_scenario_flow_control_matrix(wt_cli_report_t *report) {
  matrix_row_t rows[WT_MATRIX_MAX_CASES];
  unsigned count = 0U;

  /* The connection-level limits a peer grants must STRICTLY increase. The first capsule establishes the limit
   * -- there is no default -- and a repeat is refused along with a decrease, because a repeat is what a peer
   * sends when it is confused about what it already granted. */
  {
    wt_webtransport_flow_limits_t limits;
    uint64_t error = 0U;
    int ok;
    wt_webtransport_flow_limits_init(&limits);
    ok = wt_webtransport_flow_on_max_data(&limits, 100U, &error) == WT_OK &&
         limits.max_data_set == 1 && limits.max_data == 100U;
    rows[count].name = "the first MAX_DATA capsule establishes the limit";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_flow_limits_t limits;
    uint64_t error = 0U;
    int ok;
    wt_webtransport_flow_limits_init(&limits);
    (void)wt_webtransport_flow_on_max_data(&limits, 100U, &error);
    error = 0U;
    ok = wt_webtransport_flow_on_max_data(&limits, 100U, &error) != WT_OK &&
         error == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR && limits.max_data == 100U;
    rows[count].name = "a repeated MAX_DATA is refused as WT_FLOW_CONTROL_ERROR";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_flow_limits_t limits;
    uint64_t error = 0U;
    int ok;
    wt_webtransport_flow_limits_init(&limits);
    (void)wt_webtransport_flow_on_max_data(&limits, 100U, &error);
    error = 0U;
    ok = wt_webtransport_flow_on_max_data(&limits, 40U, &error) != WT_OK &&
         error == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR && limits.max_data == 100U;
    rows[count].name = "a decreased MAX_DATA is refused and does not move the limit";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_flow_limits_t limits;
    uint64_t error = 0U;
    int ok;
    wt_webtransport_flow_limits_init(&limits);
    (void)wt_webtransport_flow_on_max_data(&limits, 100U, &error);
    error = 0U;
    ok =
        wt_webtransport_flow_on_max_data(&limits, 400U, &error) == WT_OK && limits.max_data == 400U;
    rows[count].name = "an increased MAX_DATA is accepted";
    rows[count].held = ok;
    count++;
  }

  /* The stream-count limits follow the same rule, and the two directions are counted separately: a limit on
   * bidirectional streams says nothing about unidirectional ones. */
  {
    wt_webtransport_flow_limits_t limits;
    uint64_t error = 0U;
    int ok;
    wt_webtransport_flow_limits_init(&limits);
    ok = wt_webtransport_flow_on_max_streams(&limits, 1, 2U, &error) == WT_OK &&
         limits.max_streams_bidi == 2U && limits.max_streams_bidi_set == 1;
    error = 0U;
    ok = ok && wt_webtransport_flow_on_max_streams(&limits, 1, 2U, &error) != WT_OK &&
         error == WT_WEBTRANSPORT_FLOW_CONTROL_ERROR;
    error = 0U;
    ok = ok && wt_webtransport_flow_on_max_streams(&limits, 1, 5U, &error) == WT_OK &&
         wt_webtransport_flow_on_max_streams(&limits, 0, 1U, &error) == WT_OK &&
         limits.max_streams_bidi == 5U && limits.max_streams_uni == 1U;
    rows[count].name = "stream limits strictly increase, and each direction is its own";
    rows[count].held = ok;
    count++;
  }

  /* An explicit zero is a LIMIT and not an absence: a peer that grants nothing means nothing, and a session
   * that read zero as "unlimited" would send data the peer never allowed. */
  {
    wt_session_config_t config = wt_session_config_default();
    wt_session_t *session = NULL;
    wt_session_flow_state_t state;
    int ok;
    config.authority = "example.com";
    config.path = "/zero";
    config.session_id = 12U;
    ok = wt_session_create(&config, NULL, &session) == WT_OK && session != NULL;
    ok = ok && wt_session_flow_configure(session, 1, 0U, 0U, 0U) == WT_OK;
    state = wt_session_flow_snapshot(session);
    ok = ok && state.enabled == 1 && state.max_data_state == WT_SESSION_LIMIT_ZERO &&
         wt_session_flow_data_allowance(session) == 0U &&
         wt_session_flow_record_data(session, 1U) != WT_OK;
    rows[count].name = "an explicit zero limit allows nothing rather than everything";
    rows[count].held = ok;
    if (session != NULL) wt_session_destroy(session, NULL);
    count++;
  }

  /* And the state is per session: one session's disabled flow control does not loosen another's limit. */
  {
    wt_session_config_t first_config = wt_session_config_default();
    wt_session_config_t second_config = wt_session_config_default();
    wt_session_t *first = NULL;
    wt_session_t *second = NULL;
    int ok;
    first_config.authority = "example.com";
    first_config.path = "/first";
    first_config.session_id = 0U;
    second_config.authority = "example.com";
    second_config.path = "/second";
    second_config.session_id = 4U;
    ok = wt_session_create(&first_config, NULL, &first) == WT_OK && first != NULL &&
         wt_session_create(&second_config, NULL, &second) == WT_OK && second != NULL;
    ok = ok && wt_session_flow_configure(first, 0, 0U, 0U, 0U) == WT_OK &&
         wt_session_flow_configure(second, 1, 2U, 0U, 0U) == WT_OK;
    /* A refused record does not spend anything: the allowance it was measured against is still there, which
     * is what makes the refusal a refusal rather than a partial send. */
    ok = ok && wt_session_flow_record_data(first, 1000U) == WT_OK &&
         wt_session_flow_record_data(second, 1000U) != WT_OK &&
         wt_session_flow_data_allowance(first) == UINT64_MAX &&
         wt_session_flow_data_allowance(second) == 2U &&
         wt_session_flow_record_data(second, 2U) == WT_OK &&
         wt_session_flow_data_allowance(second) == 0U;
    rows[count].name = "one session's flow state does not loosen another's";
    rows[count].held = ok;
    if (first != NULL) wt_session_destroy(first, NULL);
    if (second != NULL) wt_session_destroy(second, NULL);
    count++;
  }

  report_matrix(report, "flow-control-matrix", "flow-control cases", rows, count);
}
