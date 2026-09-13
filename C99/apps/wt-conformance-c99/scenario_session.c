/* The session scenarios: two endpoints in one process, over loopback (Phase 9).
 *
 * The plan's first completion criterion for the tools is that they "run local IPv4 and IPv6 packet sessions", and
 * this is that criterion as a scenario: a client and a server session inside one process, a real TLS 1.3 handshake
 * inside QUIC, an extended CONNECT, the response, a message on a stream and a message as a datagram. The PAIR
 * itself -- sockets, identity, parameters, both runtimes, the handshake -- is `scenario_pair.c`, which the refusal
 * scenarios share (WT-160); what is left here is the exchange.
 */

#include "scenario_session.h"

#include <stdio.h>
#include <string.h>

#include "scenario_pair.h"
#include "webtransport/http3/settings.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

wt_cli_result_t wt_scenario_session_run(int ipv6, char *detail, size_t detail_size) {
  scenario_pair_t pair;
  wt_http3_settings_t settings;
  wt_http3_message_t decoded;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
  uint8_t scratch[1024];
  uint64_t request_stream_id = 0U;
  unsigned round;

  {
    wt_cli_result_t opened = scenario_pair_open(&pair, ipv6, detail, detail_size);
    if (opened != WT_CLI_RESULT_PASSED) return opened;
  }

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  if (wt_http3_driver_start_session(&pair.client_side.driver, &pair.client_transport, &settings,
                                    pair.authority, "/conformance", 0U, pair.now, &request_stream_id,
                                    &h3_error) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the CONNECT could not be started");
    goto done_failed;
  }
  pair.client_side.request_stream_id = request_stream_id;
  pair.server_side.request_stream_id = request_stream_id;

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.section_complete != 0) break;
    scenario_pump_once(&pair);
  }
  if (pair.server_side.section_complete == 0) {
    scenario_detail_set(detail, detail_size, "the CONNECT did not arrive");
    goto done_failed;
  }
  if (wt_http3_endpoint_on_request_headers(&pair.server_side.endpoint, request_stream_id,
                                           pair.server_side.section, pair.server_side.section_length,
                                           scratch, sizeof(scratch), &decoded, &h3_error) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the CONNECT did not decode");
    goto done_failed;
  }
  policy.authority = pair.authority;
  policy.path = "/conformance";
  policy.wt_enabled = 1;
  if (wt_webtransport_session_request_validate(&decoded, &policy, &decision, &h3_error) != WT_OK ||
      decision.outcome != WT_WEBTRANSPORT_REQUEST_ACCEPT) {
    scenario_detail_set(detail, detail_size, "the draft-16 layer did not accept the CONNECT");
    goto done_failed;
  }

  /* The response, a message on a WebTransport stream, and a message as a datagram. */
  if (wt_http3_driver_send_response(&pair.server_side.driver, &pair.server_transport, request_stream_id,
                                    200U, 0U, 0, pair.now) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the response could not be sent");
    goto done_failed;
  }
  {
    uint8_t message[128];
    wt_writer_t w = wt_writer_init(message, sizeof(message));
    uint64_t stream_id = 0U;

    if (pair.client_transport.open_stream(pair.client_transport.context, 0, &stream_id, pair.now) != WT_OK ||
        wt_webtransport_stream_prefix_write(&w, 1, request_stream_id) != WT_OK) {
      scenario_detail_set(detail, detail_size, "a WebTransport stream could not be opened");
      goto done_failed;
    }
    wt_writer_bytes(&w, "conformance", 11U);
    if (pair.client_transport.send_stream(pair.client_transport.context, stream_id, message,
                                          wt_writer_offset(&w), 0, pair.now) != WT_OK) {
      scenario_detail_set(detail, detail_size, "the stream message could not be sent");
      goto done_failed;
    }
    w = wt_writer_init(message, sizeof(message));
    if (wt_webtransport_datagram_write(&w, request_stream_id / 4U, (const uint8_t *)"probe", 5U) != WT_OK ||
        pair.client_transport.send_datagram(pair.client_transport.context, message,
                                            wt_writer_offset(&w)) != WT_OK) {
      scenario_detail_set(detail, detail_size, "the datagram could not be sent");
      goto done_failed;
    }
  }

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.server_side.stream_bytes >= 11U && pair.server_side.datagrams > 0U &&
        pair.client_side.section_complete != 0) {
      break;
    }
    scenario_pump_once(&pair);
  }
  if (pair.server_side.stream_bytes != 11U ||
      memcmp(pair.server_side.stream_data, "conformance", 11U) != 0) {
    scenario_detail_set(detail, detail_size, "the stream message did not arrive as sent");
    goto done_failed;
  }
  if (pair.server_side.datagrams == 0U || pair.server_side.datagram_bytes == 0U) {
    scenario_detail_set(detail, detail_size, "the datagram did not arrive");
    goto done_failed;
  }
  {
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    wt_http3_error_t datagram_error = WT_HTTP3_NO_ERROR;
    if (wt_webtransport_datagram_parse(pair.server_side.datagram, pair.server_side.datagram_bytes, &quarter,
                                       &payload, &payload_length, &datagram_error) != WT_OK ||
        quarter != request_stream_id / 4U || payload_length != 5U ||
        memcmp(payload, "probe", 5U) != 0) {
      scenario_detail_set(detail, detail_size, "the datagram's framing did not match");
      goto done_failed;
    }
  }
  (void)snprintf(detail, detail_size,
                 "%s: handshake, CONNECT accepted, response, 11-byte stream message and a datagram",
                 ipv6 != 0 ? "ipv6" : "ipv4");
  scenario_pair_close(&pair);
  return WT_CLI_RESULT_PASSED;

done_failed:
  scenario_pair_close(&pair);
  return WT_CLI_RESULT_FAILED;
}
