/* A session's own capsules, on the wire (WT-164, WT-249).
 *
 * Draft-16 section 5 puts a WebTransport session's control messages on the CONNECT stream as capsules once that
 * stream's one HEADERS frame has passed: the flow-control grants, a drain, and a close. The tree had the codec and
 * no wiring -- the HTTP/3 driver parsed those bytes as HTTP/3 frames, and because a flow-control capsule's type is
 * an UNKNOWN frame type, its length was read as a frame length and the capsule was SKIPPED. The peer's credit was
 * dropped without a word and the session simply stalled at its initial limit.
 *
 * That wiring was half the answer. RFC 9297 section 3.1 makes the capsule protocol the CONTENTS of the request's
 * data stream, and RFC 9114 section 4.4 permits only DATA frames on the stream that carried CONNECT, so a capsule
 * belongs inside a DATA frame and a capsule's type written straight to the stream is not a capsule at all -- it is
 * the header of an unknown frame type, which section 9 requires the peer to ignore. Both halves of that were true
 * here and the exchange still "worked", which is the whole of WT-249: `capsules_send` below frames what it is
 * given, and `raw_capsules_are_not_capsules` pins what the unframed form actually does.
 *
 * This is that whole path exercised end to end over loopback: a real handshake, a real CONNECT and response, and
 * then capsules written by one endpoint and applied by the other -- a grant that moves the limit the receiver
 * enforces, a drain that stops new streams, and a close whose application code the peer ends up reporting.
 */

#include "scenario_capsules.h"

#include <string.h>

#include "scenario_pair.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/close.h"
#include "webtransport/quic/connection.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

#include "scenario_capsules_support.h"

static void capsules_run_refusals(wt_cli_report_t *report) {
  static const char *const k_bound = "draft16-a-capsule-past-the-bound-is-named";
  static const char *const k_flow = "draft16-a-decreasing-grant-closes-the-session";
  scenario_pair_t pair;
  char detail[WT_CLI_SCENARIO_DETAIL_MAX];
  char opened[WT_CLI_SCENARIO_DETAIL_MAX];
  uint8_t framed[64];
  wt_writer_t w;
  unsigned round;
  wt_cli_result_t result;

  opened[0] = '\0';
  result = scenario_pair_open(&pair, 0, opened, sizeof(opened));
  if (result != WT_CLI_RESULT_PASSED) {
    /* The precision bounds the composed text on purpose: the reason buffer is the same SIZE as this one, so a
     * bare conversion lets the compiler prove the result may be truncated, and the Windows cross-compile treats
     * that as an error (WT-134). The prefix plus 120 characters leaves room to spare. */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", opened);
    /* Zero, not `result == WT_CLI_RESULT_PASSED`: this branch is the one where it is NOT passed, so the
     * comparison read as if the outcome were still open (WT-177, found by cppcheck). */
    capsules_add(report, k_bound, 0, detail);
    capsules_add(report, k_flow, 0, detail);
    return;
  }
  if (capsules_open_session(&pair, 1, detail, sizeof(detail)) == 0) {
    capsules_add(report, k_bound, 0, detail);
    capsules_add(report, k_flow, 0, detail);
    scenario_pair_close(&pair);
    return;
  }

  /* A capsule declaration whose length is past the receiver's bound. Only the HEADER is sent: the receiver knows
   * its own bound from the length alone, and waiting for 2000 bytes to prove it would be a buffer it refuses to
   * allocate. The frame around it is complete -- it declares four bytes of capsule, which is all there is -- and the
   * capsule INSIDE it is what is incomplete, which is the case a bound is for. */
  {
    uint8_t capsule[WT_HTTP3_FRAME_DATA_HEADER_MAX + 8];
    wt_writer_t cw = wt_http3_frame_data_writer(capsule, sizeof(capsule));

    (void)wt_quic_writer_varint(&cw, WT_CAPSULE_MAX_DATA);
    (void)wt_quic_writer_varint(&cw, 2000U);
    if (capsules_send(&pair, 1, capsule, wt_writer_offset(&cw)) != WT_OK) {
      capsules_add(report, k_bound, 0, "the oversized capsule could not be sent");
      capsules_add(report, k_flow, 0, "the oversized capsule could not be sent");
      scenario_pair_close(&pair);
      return;
    }
    for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
      if (wt_quic_connection_is_closed(&pair.server.connection) != 0) break;
      scenario_pump_once(&pair);
    }
    for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
      if (pair.client.connection.peer_closed != 0) break;
      scenario_pump_once(&pair);
    }
    {
      const wt_quic_close_state_t *state = wt_quic_connection_close_state(&pair.server.connection);
      int passed = pair.server_side.capsules.refused > 0 &&
                   pair.server_side.capsule_error == (uint64_t)WT_HTTP3_EXCESSIVE_LOAD &&
                   state != NULL && state->kind == WT_QUIC_CLOSE_APPLICATION &&
                   state->error_code == (uint64_t)WT_HTTP3_EXCESSIVE_LOAD &&
                   pair.client.connection.peer_closed != 0 &&
                   pair.client.connection.peer_close_kind == WT_QUIC_CLOSE_APPLICATION &&
                   pair.client.connection.peer_error_code == (uint64_t)WT_HTTP3_EXCESSIVE_LOAD;
      (void)snprintf(
          detail, sizeof(detail),
          passed != 0
              ? "a capsule declaring 2000 bytes closed the connection as an application close "
                "with H3_EXCESSIVE_LOAD, and the peer read that code"
              : "the bound was not named (refused=%u, code=0x%llx, close=%d/0x%llx, peer=%d)",
          pair.server_side.capsules.refused, (unsigned long long)pair.server_side.capsule_error,
          state != NULL ? (int)state->kind : -1,
          state != NULL ? (unsigned long long)state->error_code : 0ULL,
          (int)pair.client.connection.peer_closed);
      capsules_add(report, k_bound, passed, detail);
    }
  }
  scenario_pair_close(&pair);

  /* The flow-control row, on a pair of its own: the grant is accepted and then repeated, and a repeat is what the
   * draft refuses as a limit that does not strictly increase. */
  opened[0] = '\0';
  result = scenario_pair_open(&pair, 0, opened, sizeof(opened));
  if (result != WT_CLI_RESULT_PASSED) {
    /* The precision bounds the composed text on purpose: the reason buffer is the same SIZE as this one, so a
     * bare conversion lets the compiler prove the result may be truncated, and the Windows cross-compile treats
     * that as an error (WT-134). The prefix plus 120 characters leaves room to spare. */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", opened);
    capsules_add(report, k_flow, result == WT_CLI_RESULT_PASSED, detail);
    return;
  }
  if (capsules_open_session(&pair, 1, detail, sizeof(detail)) == 0) {
    capsules_add(report, k_flow, 0, detail);
    scenario_pair_close(&pair);
    return;
  }
  {
    int sent = 1;
    unsigned grant;

    for (grant = 0U; grant < 2U; grant++) {
      w = wt_http3_frame_data_writer(framed, sizeof(framed));
      if (wt_webtransport_max_data_write(&w, grant == 0U ? 4096U : 4096U) != WT_OK ||
          capsules_send(&pair, 1, framed, wt_writer_offset(&w)) != WT_OK) {
        sent = 0;
      }
      for (round = 0U; round < 40U; round++)
        scenario_pump_once(&pair);
    }
    for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
      if (pair.client_side.capsules.session.close_received != 0) break;
      scenario_pump_once(&pair);
    }
    {
      int passed = sent != 0 && pair.client_side.capsules.session.close_received != 0 &&
                   pair.client_side.capsules.session.close_error_set != 0 &&
                   pair.client_side.capsules.session.close_error_code ==
                       (uint32_t)WT_WEBTRANSPORT_FLOW_CONTROL_ERROR &&
                   wt_quic_connection_is_closed(&pair.client.connection) == 0 &&
                   wt_quic_connection_is_closed(&pair.server.connection) == 0;
      (void)snprintf(
          detail, sizeof(detail),
          passed != 0
              ? "a repeated grant closed the SESSION with the draft's flow-control code "
                "(0x45d4487) and left both connections up"
              : "the session was not closed as the draft says (received=%d, codeSet=%d, code=0x%x, "
                "clientClosed=%d)",
          (int)pair.client_side.capsules.session.close_received,
          (int)pair.client_side.capsules.session.close_error_set,
          pair.client_side.capsules.session.close_error_code,
          (int)wt_quic_connection_is_closed(&pair.client.connection));
      capsules_add(report, k_flow, passed, detail);
    }
  }
  scenario_pair_close(&pair);
}

/* Section 5.1, second paragraph: "If the corresponding setting was not negotiated, an endpoint MUST ignore any
 * flow control capsules it receives." This is the tool-side gate for that rule, and it is the regression test
 * that did NOT hold before it: the pair's server advertises flow control, but the client's SETTINGS omit all
 * three limits, so the negotiation is one-sided and the MAX_DATA the client sends must leave the server's
 * account EMPTY rather than move it. Both connections stay up and nothing is refused -- the capsule is ignored,
 * not an error (WT-252). */
static void capsules_run_unnegotiated(wt_cli_report_t *report) {
  static const char *const k_ignored = "draft16-a-flow-capsule-with-no-negotiation-is-ignored";
  scenario_pair_t pair;
  char detail[WT_CLI_SCENARIO_DETAIL_MAX];
  char opened[WT_CLI_SCENARIO_DETAIL_MAX];
  uint8_t framed[64];
  wt_writer_t w;
  unsigned round;
  wt_cli_result_t result;

  opened[0] = '\0';
  result = scenario_pair_open(&pair, 0, opened, sizeof(opened));
  if (result != WT_CLI_RESULT_PASSED) {
    /* The precision bounds the composed text on purpose, as above: a bare conversion lets the compiler prove the
     * result may be truncated, and the Windows cross-compile treats that as an error (WT-134). */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", opened);
    capsules_add(report, k_ignored, 0, detail);
    return;
  }
  if (capsules_open_session(&pair, 0, detail, sizeof(detail)) == 0) {
    capsules_add(report, k_ignored, 0, detail);
    scenario_pair_close(&pair);
    return;
  }

  /* The same MAX_DATA grant the negotiated scenario asserts, sent by a client that advertised no
   * flow-control setting: section 5.1 says the server ignores it. */
  w = wt_http3_frame_data_writer(framed, sizeof(framed));
  if (wt_webtransport_max_data_write(&w, 65536U) != WT_OK ||
      capsules_send(&pair, 1, framed, wt_writer_offset(&w)) != WT_OK) {
    capsules_add(report, k_ignored, 0, "the unnegotiated grant could not be sent");
    scenario_pair_close(&pair);
    return;
  }
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.capsules.walked > 0U) break;
    scenario_pump_once(&pair);
  }
  {
    int passed = pair.server_side.capsules.walked > 0U &&
                 pair.server_side.capsules.peer_limits.max_data_set == 0 &&
                 pair.server_side.capsules.refused == 0U &&
                 pair.server_side.capsules.refused_session_code_set == 0 &&
                 pair.server_side.capsules.session.state != WT_WEBTRANSPORT_SESSION_CLOSED &&
                 wt_quic_connection_is_closed(&pair.server.connection) == 0 &&
                 wt_quic_connection_is_closed(&pair.client.connection) == 0;
    (void)snprintf(
        detail, sizeof(detail),
        passed != 0 ? "the MAX_DATA capsule was ignored because flow control was not negotiated on "
                      "both sides, and the peer's account stayed empty"
                    : "the unnegotiated grant was not ignored (walked=%u, set=%d, refused=%u, "
                      "closed=%d)",
        pair.server_side.capsules.walked, pair.server_side.capsules.peer_limits.max_data_set,
        pair.server_side.capsules.refused,
        (int)(pair.server_side.capsules.session.state == WT_WEBTRANSPORT_SESSION_CLOSED));
    capsules_add(report, k_ignored, passed, detail);
  }
  scenario_pair_close(&pair);
}

/* The largest capsule the draft allows, arriving in one delivery (WT-257).
 *
 * `WT_CAPSULE_STREAM_MAX` bounds how much of the capsule stream these tools hold, and its own contract is that it
 * bounds a CAPSULE: "a capsule longer than this is a bound this endpoint enforces rather than a buffer it grows".
 * The walker applied it to each DELIVERY instead, so the largest close the draft permits -- a 1024-byte reason,
 * which is 1032 bytes of capsule and comfortably inside one DATA frame -- was refused with H3_EXCESSIVE_LOAD and the
 * connection was closed over a message the peer was entitled to send. The same happened to any peer that put more
 * than 1024 bytes of capsules in one DATA frame, however small those capsules were. */
void wt_scenario_capsules_run(wt_cli_report_t *report) {
  static const char *const k_grant = "draft16-a-sessions-grant-moves-the-limit-the-peer-enforces";
  static const char *const k_ends = "draft16-a-drain-and-a-close-capsule-end-the-session";
  scenario_pair_t pair;
  char detail[WT_CLI_SCENARIO_DETAIL_MAX];
  char opened[WT_CLI_SCENARIO_DETAIL_MAX];
  uint8_t framed[64];
  wt_writer_t w;
  unsigned round;
  wt_cli_result_t result;

  opened[0] = '\0';
  result = scenario_pair_open(&pair, 0, opened, sizeof(opened));
  if (result != WT_CLI_RESULT_PASSED) {
    /* The precision bounds the composed text on purpose: the reason buffer is the same SIZE as this one, so a
     * bare conversion lets the compiler prove the result may be truncated, and the Windows cross-compile treats
     * that as an error (WT-134). The prefix plus 120 characters leaves room to spare. */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", opened);
    capsules_add(report, k_grant, result == WT_CLI_RESULT_PASSED, detail);
    capsules_add(report, k_ends, result == WT_CLI_RESULT_PASSED, detail);
    return;
  }
  if (capsules_open_session(&pair, 1, detail, sizeof(detail)) == 0) {
    capsules_add(report, k_grant, 0, detail);
    capsules_add(report, k_ends, 0, detail);
    scenario_pair_close(&pair);
    return;
  }

  /* The client grants the server credit: a MAX_DATA capsule, whose value only the session layer knows how to read.
   * Before WT-164 the server skipped it as an unknown HTTP/3 frame. */
  w = wt_http3_frame_data_writer(framed, sizeof(framed));
  if (wt_webtransport_max_data_write(&w, 65536U) != WT_OK ||
      capsules_send(&pair, 1, framed, wt_writer_offset(&w)) != WT_OK) {
    capsules_add(report, k_grant, 0, "the grant could not be sent");
    capsules_add(report, k_ends, 0, "the grant could not be sent");
    scenario_pair_close(&pair);
    return;
  }
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.capsules.peer_limits.max_data_set != 0) break;
    scenario_pump_once(&pair);
  }
  {
    int passed = pair.server_side.capsules.peer_limits.max_data_set != 0 &&
                 pair.server_side.capsules.peer_limits.max_data == 65536U &&
                 pair.server_side.capsules.walked > 0U;
    (void)snprintf(
        detail, sizeof(detail),
        passed != 0
            ? "the peer's MAX_DATA capsule reached the session and moved the limit it enforces "
              "to 65536"
            : "the grant did not reach the session (set=%d, value=%llu, capsules=%u)",
        pair.server_side.capsules.peer_limits.max_data_set,
        (unsigned long long)pair.server_side.capsules.peer_limits.max_data,
        pair.server_side.capsules.walked);
    capsules_add(report, k_grant, passed, detail);
  }

  /* A drain stops new streams without ending the session, and a close ends it with the peer's code -- and both are
   * the SESSION's, so the QUIC connection stays up: nothing about this is visible in a transport-level report. */
  w = wt_http3_frame_data_writer(framed, sizeof(framed));
  if (wt_webtransport_drain_session_write(&w) != WT_OK ||
      capsules_send(&pair, 0, framed, wt_writer_offset(&w)) != WT_OK) {
    capsules_add(report, k_ends, 0, "the drain could not be sent");
    scenario_pair_close(&pair);
    return;
  }
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.client_side.capsules.session.drain_received != 0) break;
    scenario_pump_once(&pair);
  }
  {
    int drained =
        pair.client_side.capsules.session.drain_received != 0 &&
        wt_webtransport_session_allows_new_streams(&pair.client_side.capsules.session) == 0;
    w = wt_http3_frame_data_writer(framed, sizeof(framed));
    if (!drained ||
        wt_webtransport_close_session_write(&w, 0x42U, (const uint8_t *)"bye", 3U) != WT_OK ||
        capsules_send(&pair, 0, framed, wt_writer_offset(&w)) != WT_OK) {
      capsules_add(report, k_ends, 0,
                   "the drain did not stop new streams, or the close could not be sent");
      scenario_pair_close(&pair);
      return;
    }
  }
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.client_side.capsules.session.close_received != 0) break;
    scenario_pump_once(&pair);
  }
  {
    int passed = pair.client_side.capsules.session.close_received != 0 &&
                 pair.client_side.capsules.session.close_error_set != 0 &&
                 pair.client_side.capsules.session.close_error_code == 0x42U &&
                 pair.client_side.capsules.session.state == WT_WEBTRANSPORT_SESSION_CLOSED;
    (void)snprintf(
        detail, sizeof(detail),
        passed != 0
            ? "the drain stopped new streams and the close ended the session with the peer's "
              "application code 0x42"
            : "the session did not end as the capsules said (received=%d, codeSet=%d, "
              "code=0x%x, state=%d)",
        pair.client_side.capsules.session.close_received,
        pair.client_side.capsules.session.close_error_set,
        pair.client_side.capsules.session.close_error_code,
        (int)pair.client_side.capsules.session.state);
    capsules_add(report, k_ends, passed, detail);
  }
  scenario_pair_close(&pair);

  capsules_run_refusals(report);
  /* And the other half of section 5.1: what happens when flow control was NOT negotiated (WT-252). */
  capsules_run_unnegotiated(report);
  /* The bound the tools hold capsules to is a bound on a CAPSULE, not on one delivery of them (WT-257). */
  capsules_run_the_largest_capsule(report);
  capsules_run_a_coalesced_delivery(report);
}
