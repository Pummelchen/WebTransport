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

void capsules_run_the_largest_capsule(wt_cli_report_t *report) {
  static const char *const k_largest = "draft16-the-largest-close-capsule-is-accepted";
  scenario_pair_t pair;
  char detail[WT_CLI_SCENARIO_DETAIL_MAX];
  char opened[WT_CLI_SCENARIO_DETAIL_MAX];
  /* The close capsule's bytes plus the reservation the DATA frame writes its header into. 1032 bytes of capsule:
   * the type and the value's length are two-byte varints and the value is the four-byte code plus the ceiling. */
  uint8_t framed[WT_HTTP3_FRAME_DATA_HEADER_MAX + 8U + WT_CAPSULE_CLOSE_MAX_REASON];
  static uint8_t reason[WT_CAPSULE_CLOSE_MAX_REASON];
  wt_writer_t w;
  unsigned round;
  wt_cli_result_t result;

  memset(reason, 'r', sizeof(reason));
  opened[0] = '\0';
  result = scenario_pair_open(&pair, 0, opened, sizeof(opened));
  if (result != WT_CLI_RESULT_PASSED) {
    /* The precision bounds the composed text on purpose, as above (WT-134). */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", opened);
    capsules_add(report, k_largest, 0, detail);
    return;
  }
  if (capsules_open_session(&pair, 1, detail, sizeof(detail)) == 0) {
    capsules_add(report, k_largest, 0, detail);
    scenario_pair_close(&pair);
    return;
  }

  w = wt_http3_frame_data_writer(framed, sizeof(framed));
  if (wt_webtransport_close_session_write(&w, 0x42U, reason, sizeof(reason)) != WT_OK ||
      capsules_send(&pair, 1, framed, wt_writer_offset(&w)) != WT_OK) {
    capsules_add(report, k_largest, 0, "the largest close capsule could not be sent");
    scenario_pair_close(&pair);
    return;
  }
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.capsules.session.close_received != 0) break;
    scenario_pump_once(&pair);
  }
  {
    int passed =
        pair.server_side.capsules.session.close_received != 0 &&
        pair.server_side.capsules.session.close_error_set != 0 &&
        pair.server_side.capsules.session.close_error_code == 0x42U &&
        pair.server_side.capsules.session.state == WT_WEBTRANSPORT_SESSION_CLOSED &&
        pair.server_side.capsules.refused == 0U &&
        pair.server_side.capsules.refused_session_code_set == 0 &&
        /* No refusal was recorded at all: zero is what the side starts with, and every refusal writes its
                  * code here (the capsule-refusal scenarios assert the value a refusal DOES leave). */
        pair.server_side.capsule_error == 0U &&
        wt_quic_connection_is_closed(&pair.server.connection) == 0 &&
        wt_quic_connection_is_closed(&pair.client.connection) == 0;
    (void)snprintf(
        detail, sizeof(detail),
        passed != 0
            ? "a close capsule carrying the draft's maximum 1024-byte reason was applied and "
              "ended the session, with both connections still up"
            : "the largest legal capsule was not accepted (received=%d, codeSet=%d, code=0x%x, "
              "refused=%u, refusalCode=0x%llx, serverClosed=%d, clientClosed=%d, state=%d)",
        (int)pair.server_side.capsules.session.close_received,
        (int)pair.server_side.capsules.session.close_error_set,
        pair.server_side.capsules.session.close_error_code, pair.server_side.capsules.refused,
        (unsigned long long)pair.server_side.capsule_error,
        (int)wt_quic_connection_is_closed(&pair.server.connection),
        (int)wt_quic_connection_is_closed(&pair.client.connection),
        (int)pair.server_side.capsules.session.state);
    capsules_add(report, k_largest, passed, detail);
  }
  scenario_pair_close(&pair);
}

/* The other half of the same bound (WT-257): the walker holds `WT_CAPSULE_STREAM_MAX` bytes, and a peer may put any
 * number of capsules into one DATA frame. A delivery larger than the buffer has to be taken in pieces with every
 * capsule applied, rather than the delivery refused for being large -- which is what the arithmetic bound used to do
 * to a peer whose capsules were all tiny. */
void capsules_run_a_coalesced_delivery(wt_cli_report_t *report) {
  static const char *const k_many = "draft16-many-capsules-in-one-delivery-are-all-applied";
  /* Enough grants, at eight bytes each, to be well past the walker's buffer in one delivery. */
  enum { k_grants = 160 };
  scenario_pair_t pair;
  char detail[WT_CLI_SCENARIO_DETAIL_MAX];
  char opened[WT_CLI_SCENARIO_DETAIL_MAX];
  uint8_t framed[WT_HTTP3_FRAME_DATA_HEADER_MAX + 4096U];
  wt_writer_t w;
  unsigned round;
  unsigned index;
  int sent = 1;
  wt_cli_result_t result;

  opened[0] = '\0';
  result = scenario_pair_open(&pair, 0, opened, sizeof(opened));
  if (result != WT_CLI_RESULT_PASSED) {
    /* The precision bounds the composed text on purpose, as above (WT-134). */
    (void)snprintf(detail, sizeof(detail), "the pair could not be opened: %.120s", opened);
    capsules_add(report, k_many, 0, detail);
    return;
  }
  /* Flow control negotiated on both sides, so each grant is APPLIED rather than ignored (section 5.1). */
  if (capsules_open_session(&pair, 1, detail, sizeof(detail)) == 0) {
    capsules_add(report, k_many, 0, detail);
    scenario_pair_close(&pair);
    return;
  }

  w = wt_http3_frame_data_writer(framed, sizeof(framed));
  for (index = 0U; index < (unsigned)k_grants; index++) {
    /* Strictly increasing, which is what section 5.1 requires of a MAX_DATA: a repeat would be a flow-control
     * error and the session would end before the interesting half of this ran. */
    if (wt_webtransport_max_data_write(&w, 1000U + (uint64_t)index) != WT_OK) {
      sent = 0;
      break;
    }
  }
  if (sent == 0 || capsules_send(&pair, 1, framed, wt_writer_offset(&w)) != WT_OK) {
    capsules_add(report, k_many, 0, "the coalesced grant run could not be sent");
    scenario_pair_close(&pair);
    return;
  }
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.capsules.peer_limits.max_data == 1000U + (uint64_t)(k_grants - 1)) break;
    scenario_pump_once(&pair);
  }
  {
    int passed =
        pair.server_side.capsules.peer_limits.max_data_set != 0 &&
        pair.server_side.capsules.peer_limits.max_data == 1000U + (uint64_t)(k_grants - 1) &&
        pair.server_side.capsules.refused == 0U &&
        pair.server_side.capsules.refused_session_code_set == 0 &&
        pair.server_side.capsules.session.state != WT_WEBTRANSPORT_SESSION_CLOSED &&
        wt_quic_connection_is_closed(&pair.server.connection) == 0 &&
        wt_quic_connection_is_closed(&pair.client.connection) == 0;
    (void)snprintf(
        detail, sizeof(detail),
        passed != 0
            ? "all 160 grants in one DATA frame were applied, past the walker's buffer, with "
              "nothing refused"
            : "the coalesced delivery was not walked (set=%d, limit=%llu, wanted=%llu, "
              "refused=%u, state=%d)",
        pair.server_side.capsules.peer_limits.max_data_set,
        (unsigned long long)pair.server_side.capsules.peer_limits.max_data,
        (unsigned long long)(1000U + (uint64_t)(k_grants - 1)), pair.server_side.capsules.refused,
        (int)pair.server_side.capsules.session.state);
    capsules_add(report, k_many, passed, detail);
  }
  scenario_pair_close(&pair);
}
