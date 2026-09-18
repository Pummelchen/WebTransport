/* Shared by the two capsule scenario modules.
 * The file-static helpers could not cross a translation unit, and the two moved scenarios
 * are called by the entry point that stayed behind, so they are declared here. */
#ifndef WT_CONFORMANCE_SCENARIO_CAPSULES_SUPPORT_H
#define WT_CONFORMANCE_SCENARIO_CAPSULES_SUPPORT_H

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

static inline void capsules_add(wt_cli_report_t *report, const char *name, int passed,
                                const char *detail) {
  (void)wt_cli_report_add(report, name, passed != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                          detail);
}

/* Bring a session up on the pair: CONNECT, decision, response, both sessions established, and both streams marked
 * for capsules. Anything that fails here is the exchange's problem rather than the capsules', and it is reported as
 * such rather than counted against them.
 *
 * `advertise_flow` says whether the CLIENT's SETTINGS carry section 5.1's three initial flow-control limits. The
 * server's own SETTINGS always do (see `scenario_pair_open`), so a caller that passes 0 leaves the negotiation
 * one-sided -- which is exactly the state section 5.1's "MUST ignore" rule is about (WT-252). */
static inline int capsules_open_session(scenario_pair_t *pair, int advertise_flow, char *detail,
                                        size_t detail_size) {
  wt_http3_settings_t settings;
  wt_http3_message_t decoded;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint8_t scratch[1024];
  uint64_t request_stream_id = 0U;
  unsigned round;

  wt_http3_settings_init(&settings);
  if (advertise_flow != 0) {
    /* The library's one answer for a WebTransport endpoint's settings, which now includes section 5.1's limits:
     * the real path a tool takes, rather than three hand-written settings here. */
    if (wt_webtransport_settings_apply(&settings, 0) != WT_OK) {
      scenario_detail_set(detail, detail_size, "the client's settings could not be assembled");
      return 0;
    }
  } else {
    /* Only the codepoint that makes this a WebTransport endpoint: no flow-control setting is negotiated. */
    (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  }
  /* The LOCAL half of the negotiation, recorded before the settings go out: the capsule gate reads it beside
   * the peer's half. */
  wt_capsule_stream_set_flow_advertised(&pair->client_side.capsules, &settings);
  if (wt_http3_driver_start_session(&pair->client_side.driver, &pair->client_transport, &settings,
                                    pair->authority, "/capsules", 0U, pair->now, &request_stream_id,
                                    &h3_error) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the CONNECT could not be started");
    return 0;
  }
  pair->client_side.request_stream_id = request_stream_id;
  pair->server_side.request_stream_id = request_stream_id;

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair->server_side.section_complete != 0) break;
    scenario_pump_once(pair);
  }
  if (pair->server_side.section_complete == 0) {
    scenario_detail_set(detail, detail_size, "the CONNECT did not arrive");
    return 0;
  }
  if (wt_http3_endpoint_on_request_headers(&pair->server_side.endpoint, request_stream_id,
                                           pair->server_side.section,
                                           pair->server_side.section_length, scratch,
                                           sizeof(scratch), &decoded, &h3_error) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the CONNECT did not decode");
    return 0;
  }
  policy.authority = pair->authority;
  policy.path = "/capsules";
  policy.wt_enabled = 1;
  if (wt_webtransport_session_request_validate(&decoded, &policy, &decision, &h3_error) != WT_OK ||
      decision.outcome != WT_WEBTRANSPORT_REQUEST_ACCEPT) {
    scenario_detail_set(detail, detail_size, "the draft-16 layer did not accept the CONNECT");
    return 0;
  }
  /* The server accepts: the request's HEADERS has been read, so its capsules begin here -- and the session is
   * established by the response that follows. */
  if (wt_http3_driver_mark_capsule_stream(&pair->server_side.driver, request_stream_id, 0) !=
      WT_OK) {
    scenario_detail_set(detail, detail_size, "the CONNECT stream could not be marked for capsules");
    return 0;
  }
  if (wt_http3_driver_send_response(&pair->server_side.driver, &pair->server_transport,
                                    request_stream_id, 200U, 0U, 0, pair->now) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the response could not be sent");
    return 0;
  }
  wt_capsule_stream_established(&pair->server_side.capsules);
  /* And the client's session is established by the response, which also settles the capsule mark `start_session`
   * made on its request stream. */
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair->client_side.section_complete != 0) break;
    scenario_pump_once(pair);
  }
  if (pair->client_side.section_complete == 0) {
    scenario_detail_set(detail, detail_size, "the response did not arrive");
    return 0;
  }
  wt_capsule_stream_established(&pair->client_side.capsules);
  return 1;
}

/* Send one capsule on this side's CONNECT stream, FRAMED: the session's own messages are capsules inside the HTTP/3
 * DATA frames RFC 9114 section 4.4 permits there, and `framed` is a buffer the caller filled through
 * `wt_http3_frame_data_writer`, so its `payload_length` bytes start behind the reservation this writes the header
 * into. One capsule per send, so a refusal is one frame on the wire. */
static inline wt_status_t capsules_send(scenario_pair_t *pair, int from_client, uint8_t *framed,
                                        size_t payload_length) {
  const wt_http3_driver_transport_t *transport =
      from_client ? &pair->client_transport : &pair->server_transport;
  uint64_t stream_id =
      from_client ? pair->client_side.request_stream_id : pair->server_side.request_stream_id;
  /* The capacity the caller's own writer had, which is what proves the payload is inside the buffer: the payload
   * was written at the reservation, so the reservation plus the payload is a bound the buffer meets by
   * construction. */
  size_t frame_length = 0U;

  if (wt_http3_frame_wrap_data_in_place(framed, WT_HTTP3_FRAME_DATA_HEADER_MAX + payload_length,
                                        payload_length, &frame_length) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  return transport->send_stream(transport->context, stream_id, framed, frame_length, 0, pair->now);
}

/* The two refusals a capsule can earn, each on its own pair because each ENDS something: a capsule whose declared
 * length is past what the receiver will buffer is an HTTP/3 error, so the CONNECTION closes naming it; a grant that
 * does not strictly increase is the draft's own flow-control error, so the SESSION closes with that code and the
 * connection stays up. The second is the case a flag would have got wrong -- returning the failure to the transport
 * would have closed the connection over the session's own error (WT-165). */

void capsules_run_the_largest_capsule(wt_cli_report_t *report);
void capsules_run_a_coalesced_delivery(wt_cli_report_t *report);

#endif
