/* The connection-control scenarios (Phase 10). */

#include "scenario_control.h"

#include <string.h>

#include "webtransport/http3/control.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/goaway.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/http3/role.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/writer.h"

static void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                          detail);
}

void wt_scenario_control_run(wt_cli_report_t *report) {
  /* RFC 9114 section 5.2: the graceful shutdown sends the maximum first and what was really processed second,
   * so a LOWER identifier is the ordinary case. An identifier that is greater than one already received is a
   * connection error, because a peer that raised it would be retrying requests it has already been told to
   * stop retrying. */
  {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int graceful;
    int raised;

    wt_http3_goaway_init(&goaway);
    error = WT_HTTP3_NO_ERROR;
    graceful = wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 8U, &error) == WT_OK &&
               error == WT_HTTP3_NO_ERROR &&
               wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 4U, &error) == WT_OK;

    wt_http3_goaway_init(&goaway);
    error = WT_HTTP3_NO_ERROR;
    (void)wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 8U, &error);
    error = WT_HTTP3_NO_ERROR;
    raised = wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 12U, &error) != WT_OK &&
             error == WT_HTTP3_ID_ERROR;

    add(report, "goaway-identifier-must-not-increase", graceful && raised,
        "8 then 4 is the graceful pair; 8 then 12 is H3_ID_ERROR (RFC 9114 section 5.2)");
  }

  /* RFC 9114 section 7.2.6: in the server-to-client direction the identifier is a client-initiated
   * bidirectional stream ID, and any other stream type is a connection error. The predicate is the stream
   * id's low bits, so this asserts the TYPE rather than a value. */
  {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int refused;

    wt_http3_goaway_init(&goaway);
    refused = wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 1U, &error) != WT_OK &&
              error == WT_HTTP3_ID_ERROR && wt_http3_goaway_allows_new_requests(&goaway) == 1;

    add(report, "goaway-identifier-must-be-a-client-stream", refused,
        "a server-initiated stream id is H3_ID_ERROR and leaves no GOAWAY in force");
  }

  /* Section 5.2: requests with the indicated identifier or greater are rejected by the sender of the GOAWAY.
   * The boundary is the part worth asserting: 8 itself is rejected, 4 is not. */
  {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int boundary;

    wt_http3_goaway_init(&goaway);
    (void)wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 8U, &error);
    boundary = wt_http3_goaway_rejects_stream(&goaway, 4U) == 0 &&
               wt_http3_goaway_rejects_stream(&goaway, 8U) == 1 &&
               wt_http3_goaway_rejects_stream(&goaway, 12U) == 1;

    add(report, "goaway-rejects-streams-at-or-above", boundary,
        "a GOAWAY for stream 8 rejects 8 and 12 and still allows 4");
    add(report, "goaway-stops-new-requests",
        wt_http3_goaway_allows_new_requests(&goaway) == 0 &&
            wt_http3_goaway_allows_new_requests(NULL) == 1,
        "once a GOAWAY has arrived no new request is started; an absent record allows one");
  }

  /* RFC 9114 section 6.2.1: exactly one control stream per connection, its first frame is SETTINGS, and a
   * request frame never belongs on it. */
  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int opened;
    int duplicate;

    wt_http3_control_init(&control);
    error = WT_HTTP3_NO_ERROR;
    opened = wt_http3_control_peer_opened(&control, &error) == WT_OK && error == WT_HTTP3_NO_ERROR;
    error = WT_HTTP3_NO_ERROR;
    duplicate = wt_http3_control_peer_opened(&control, &error) != WT_OK &&
                error == WT_HTTP3_STREAM_CREATION_ERROR;

    add(report, "control-stream-is-opened-once", opened && duplicate,
        "the first control stream is accepted and a second is H3_STREAM_CREATION_ERROR");
  }

  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int settings;
    int request;

    wt_http3_control_init(&control);
    (void)wt_http3_control_peer_opened(&control, &error);
    error = WT_HTTP3_NO_ERROR;
    settings = wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_SETTINGS, &error) == WT_OK;
    error = WT_HTTP3_NO_ERROR;
    request = wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_HEADERS, &error) != WT_OK &&
              error == WT_HTTP3_FRAME_UNEXPECTED;

    add(report, "control-stream-refuses-a-request-frame", settings && request,
        "SETTINGS is accepted on the control stream; a HEADERS frame there is H3_FRAME_UNEXPECTED");
  }

  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int late;

    wt_http3_control_init(&control);
    (void)wt_http3_control_peer_opened(&control, &error);
    error = WT_HTTP3_NO_ERROR;
    late = wt_http3_control_on_frame(&control, WT_HTTP3_FRAME_GOAWAY, &error) != WT_OK &&
           error == WT_HTTP3_MISSING_SETTINGS;

    add(report, "control-stream-settings-must-come-first", late,
        "a control stream whose first frame is not SETTINGS is H3_MISSING_SETTINGS");
  }

  {
    wt_http3_control_stream_t control;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int closed;

    wt_http3_control_init(&control);
    (void)wt_http3_control_peer_opened(&control, &error);
    error = WT_HTTP3_NO_ERROR;
    closed = wt_http3_control_on_closed(&control, &error) != WT_OK &&
             error == WT_HTTP3_CLOSED_CRITICAL_STREAM;

    add(report, "control-stream-closure-is-an-error", closed,
        "closing a critical stream is H3_CLOSED_CRITICAL_STREAM whether or not SETTINGS arrived");
  }

  /* The static table has 99 entries and the count is exact: entry 99 is past the end rather than a wrap into
   * the table, which is the same bound the refusals assert one layer up. */
  {
    wt_qpack_static_entry_t entry;
    size_t index;
    int in_range;
    int past_end;

    for (index = 0U; index < (size_t)WT_QPACK_STATIC_TABLE_SIZE; ++index) {
      if (wt_qpack_static_entry((uint64_t)index, &entry) != WT_OK) break;
    }
    in_range = index == (size_t)WT_QPACK_STATIC_TABLE_SIZE;
    past_end = wt_qpack_static_entry((uint64_t)WT_QPACK_STATIC_TABLE_SIZE, &entry) != WT_OK;

    add(report, "qpack-static-table-is-bounded", in_range && past_end,
        "every entry below 99 resolves and entry 99 is refused");
  }

  {
    int empty;
    int grows;

    empty = wt_qpack_max_entries(0U) == 0U;
    grows = wt_qpack_max_entries(4096U) >= wt_qpack_max_entries(64U);

    add(report, "qpack-dynamic-table-capacity-is-honoured", empty && grows,
        "a capacity of zero admits no entry and a larger capacity admits no fewer");
  }

  /* A WebTransport session lives on a client-initiated BIDIRECTIONAL stream -- the two low bits zero -- so the
   * predicate is a statement about stream type, not about a table this endpoint keeps. */
  {
    int session_streams;
    int other_streams;

    session_streams = wt_webtransport_is_session_stream_id(0U) == 1 &&
                      wt_webtransport_is_session_stream_id(4U) == 1;
    other_streams = wt_webtransport_is_session_stream_id(2U) == 0 &&
                    wt_webtransport_is_session_stream_id(3U) == 0;

    add(report, "session-stream-is-a-client-bidi-stream", session_streams && other_streams,
        "streams 0 and 4 carry sessions; 2 and 3 do not (RFC 9000 section 2.1)");
  }

  /* The datagram's first field is the QUARTER stream id, and the session id it names has to survive the round
   * trip: this is the mapping a receiver uses to find the session, so a wrong pairing here would route a
   * datagram to another session. */
  {
    uint8_t buffer[64];
    wt_writer_t w;
    uint64_t quarter = 0U;
    const uint8_t *payload = NULL;
    size_t length = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int wrote;
    int parsed;

    w = wt_writer_init(buffer, sizeof(buffer));
    wrote = wt_webtransport_datagram_write(&w, 6U, (const uint8_t *)"probe", 5U) == WT_OK;
    parsed = wrote && wt_webtransport_datagram_parse(buffer, wt_writer_offset(&w), &quarter,
                                                     &payload, &length, &error) == WT_OK;

    add(report, "datagram-carries-its-session-quarter-id",
        parsed && quarter == 6U && length == 5U && memcmp(payload, "probe", 5U) == 0,
        "the quarter stream id and the payload survive the encoding");
    add(report, "datagram-quarter-id-maps-to-a-session-id",
        wt_webtransport_session_id_from_quarter(6U) == 24U &&
            wt_webtransport_quarter_stream_id(24U) == 6U,
        "a quarter stream id and a session id are one number in two places");
  }
}
