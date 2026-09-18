/* The refusal that reaches the PEER, over a real connection (WT-159, WT-160).
 *
 * `scenario_refusals.c` asserts decisions: it calls a validator and checks the code a peer WOULD be sent. That is
 * a different claim from the code a peer IS sent, and the difference is three layers of library -- the frame
 * arrives through the QUIC connection, the HTTP/3 driver refuses it, and the runtime states that refusal to the
 * connection as an APPLICATION close. The library's own pair test drives all three (WT-159); this is the same
 * claim in the conformance tool, where both ENDS of it can be asserted, and the reason the shared pair harness
 * exists (WT-160).
 *
 * The refusal chosen is the one RFC 9114 section 7.1 makes unambiguous: a frame whose declared length is cut off
 * by the end of the stream is a connection error of type H3_FRAME_ERROR, not a stream error, so the peer is told
 * and this scenario can read the same code on both sides of the connection.
 */

#include "scenario_refusal_wire.h"

#include <stdio.h>

#include "scenario_pair.h"
#include "webtransport/http3/frame.h"
#include "webtransport/quic/close.h"
#include "webtransport/quic/connection.h"

static void refusal_wire_add(wt_cli_report_t *report, const char *name, wt_cli_result_t result,
                             const char *detail) {
  (void)wt_cli_report_add(report, name, result, detail);
}

void wt_scenario_refusal_wire_run(wt_cli_report_t *report) {
  static const char *const k_closed = "draft16-a-truncated-frame-is-an-application-close";
  static const char *const k_told = "draft16-the-refusal-reaches-the-peer-as-its-http3-code";
  /* The HEADERS frame type (RFC 9114 section 7.2.2) followed by a 64-byte length that never arrives: the stream
   * ends first, which is the truncated frame. */
  static const uint8_t k_truncated_headers[2] = {0x01U, 0x40U};
  scenario_pair_t pair;
  char detail[160];
  char refusal[160];
  uint64_t stream_id = 0U;
  unsigned round;
  wt_cli_result_t opened;

  refusal[0] = '\0';
  opened = scenario_pair_open(&pair, 0, refusal, sizeof(refusal));
  if (opened != WT_CLI_RESULT_PASSED) {
    /* An unsupported machine is a fact about the machine, not a failure of the code, and it is passed through
     * rather than flattened: `session-over-ipv6` reports the same way. */
    /* The precision bounds the composed text on purpose: the reason buffer is the same SIZE as this one, so a
     * bare conversion lets the compiler prove the result may be truncated, and the Windows cross-compile treats
     * that as an error (WT-134). The prefix plus 120 characters leaves room to spare. */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", refusal);
    refusal_wire_add(report, k_closed, opened, detail);
    refusal_wire_add(report, k_told, opened, detail);
    return;
  }

  /* A bidirectional stream this endpoint initiated, with no WebTransport prefix: the peer reads it as a request
   * stream, which is what makes the frame below its problem. */
  if (pair.client_transport.open_stream(pair.client_transport.context, 1, &stream_id, pair.now) !=
          WT_OK ||
      pair.client_transport.send_stream(pair.client_transport.context, stream_id,
                                        k_truncated_headers, sizeof(k_truncated_headers), 1,
                                        pair.now) != WT_OK) {
    refusal_wire_add(report, k_closed, WT_CLI_RESULT_FAILED,
                     "the truncated HEADERS frame could not be sent");
    refusal_wire_add(report, k_told, WT_CLI_RESULT_FAILED,
                     "the truncated HEADERS frame could not be sent");
    scenario_pair_close(&pair);
    return;
  }

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (wt_quic_connection_is_closed(&pair.server.connection) != 0) break;
    scenario_pump_once(&pair);
  }

  /* The endpoint that refused states an APPLICATION close carrying the HTTP/3 code. A transport close here would
   * mean the HTTP/3 layer's error was dropped on the way to the connection, and a silent close would mean the peer
   * was never told -- both are FAILURES, and the state is read rather than assumed. */
  {
    const wt_quic_close_state_t *state = wt_quic_connection_close_state(&pair.server.connection);
    int passed = state != NULL && state->kind == WT_QUIC_CLOSE_APPLICATION &&
                 state->error_code == (uint64_t)WT_HTTP3_FRAME_ERROR;
    if (state == NULL) {
      (void)snprintf(detail, sizeof(detail), "the refusing endpoint never closed");
    } else {
      (void)snprintf(
          detail, sizeof(detail),
          passed != 0 ? "a frame cut off by the end of the stream closed the connection as an "
                        "application close with H3_FRAME_ERROR (0x106)"
                      : "the refusal was kind %d with code 0x%llx, not an application close with "
                        "0x106",
          (int)state->kind, (unsigned long long)state->error_code);
    }
    refusal_wire_add(report, k_closed, passed != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                     detail);
  }

  /* And the OTHER end reads that code, which is the half a decision-only scenario cannot see. */
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.client.connection.peer_closed != 0) break;
    scenario_pump_once(&pair);
  }
  {
    int passed = pair.client.connection.peer_closed != 0 &&
                 pair.client.connection.peer_close_kind == WT_QUIC_CLOSE_APPLICATION &&
                 pair.client.connection.peer_error_code == (uint64_t)WT_HTTP3_FRAME_ERROR;
    if (pair.client.connection.peer_closed == 0) {
      (void)snprintf(detail, sizeof(detail), "the refusal never reached the peer");
    } else {
      (void)snprintf(
          detail, sizeof(detail),
          passed != 0
              ? "the peer read the refusal as an application close with H3_FRAME_ERROR (0x106)"
              : "the peer read kind %d with code 0x%llx",
          (int)pair.client.connection.peer_close_kind,
          (unsigned long long)pair.client.connection.peer_error_code);
    }
    refusal_wire_add(report, k_told, passed != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                     detail);
  }

  scenario_pair_close(&pair);
}
