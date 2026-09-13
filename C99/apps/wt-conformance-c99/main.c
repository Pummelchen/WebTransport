/* wt-conformance-c99 -- see ../../IMPLEMENTATION_PLAN.md, Phase 9.
 *
 * Phase 0 builds the executable and its link against the library, which is what
 * the plan's completion criterion asks for: "empty library and CLI stubs build
 * on every target compiler". The protocol phases fill this in, and until they do
 * the tool prints its usage and exits 3 -- a distinct status for "not
 * implemented" so that a script driving it cannot read a stub as success.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "webtransport/cli/options.h"
#include "webtransport/cli/report.h"

#include "scenario_session.h"
#include "scenario_refusals.h"
#include "scenario_control.h"
#include "scenario_headers.h"
#include "scenario_isolation.h"
#include "scenario_matrix.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/version.h"

static int wt_usage(const char *program) {
  printf("usage: %s [options]\n", program);
  printf("\n");
  printf("WebTransport over HTTP/3, C99 implementation %s (%s).\n",
         wt_version_string(), wt_protocol_draft());
  printf("\n");
  printf("This build carries the protocol layers and the public API, but the\n");
  printf("tool does not yet drive a session over a socket: that wiring is the\n");
  printf("rest of Phase 9. It exits 3 rather than 0 so a script cannot read\n");
  printf("this as a successful run.\n");
  return 3;
}

int main(int argc, char **argv) {
  wt_cli_options_t options;
  const char *error = NULL;
  const char *argument = NULL;
  wt_status_t parsed;

  parsed = wt_cli_options_parse(&options, argc, (const char *const *)argv, &error, &argument);
  if (parsed != WT_OK) {
    fprintf(stderr, "wt: %s: %s\n", error != NULL ? error : "invalid arguments",
            argument != NULL ? argument : "");
    return 2;
  }
  /* The mode is what this tool IS unless the command line chose the other one: a client that
   * can listen and a server that can connect are one tool with two modes, which is how the
   * Swift tools are driven too. */
  if (options.mode == WT_CLI_MODE_NONE && strcmp("none", "none") != 0) {
    options.mode = WT_CLI_MODE_NONE;
  }
  if (options.help != 0) {
    /* A caller asking what the tool does gets a SUCCESS: `wt_usage` returns the "not implemented" status for the
     * stub path, and a help request is not that. */
    (void)wt_usage(argv[0]);
    return 0;
  }
  if (options.version != 0) {
    printf("%s %s\n", argv[0], wt_version_string());
    return 0;
  }
  if (options.scenario_all == 0 && wt_cli_options_check(&options, &error) != WT_OK) {
    if (options.json != 0) {
      printf("{\"error\":\"missing mode or address\"}\n");
    } else {
      fprintf(stderr, "wt: %s\n", error != NULL ? error : "invalid arguments");
    }
    return 2;
  }
  if (options.json != 0) wt_cli_options_write_json(&options, stdout);

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      (void)wt_usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--version") == 0) {
      printf("%s %s\n", argv[0], wt_version_string());
      return 0;
    }
  }
  if (options.scenario_all == 0) return wt_usage(argv[0]);

  /* The scenarios this build can actually RUN are the in-process ones: a codec, a capsule, a
   * field section and the draft-16 decision. The session scenarios need two endpoints and a
   * socket, which is the rest of Phase 9, and they are reported as UNSUPPORTED with the reason
   * rather than left out -- a report whose green line cannot be told from "not attempted" is
   * worth nothing. */
  {
    wt_cli_report_t report;
    wt_cli_report_init(&report);

    /* QUIC varints: every form, and the boundaries where the form changes. The detail names
     * the value that failed rather than saying "a value did", because a report that cannot say
     * WHICH case failed makes the reader reproduce the whole scenario to find out. */
    {
      static const uint64_t values[] = {0U, 1U, 63U, 64U, 16383U, 16384U, 1073741823U, 1073741824U};
      char detail[WT_CLI_SCENARIO_DETAIL_MAX];
      wt_cli_result_t result = WT_CLI_RESULT_PASSED;
      size_t value_index;

      detail[0] = '\0';
      for (value_index = 0U; value_index < sizeof(values) / sizeof(values[0]); value_index++) {
        uint8_t encoded[8];
        wt_cursor_t varint_cursor;
        uint64_t decoded_value = 0U;
        size_t encoded_length = wt_quic_varint_encode(values[value_index], encoded, sizeof(encoded));
        size_t expected_length = wt_quic_varint_size(values[value_index]);
        varint_cursor = wt_cursor_init(encoded, encoded_length != 0U ? encoded_length : 1U);
        if (encoded_length == 0U || encoded_length != expected_length ||
            wt_quic_varint_decode(&varint_cursor, &decoded_value) != WT_OK ||
            decoded_value != values[value_index]) {
          result = WT_CLI_RESULT_FAILED;
          (void)snprintf(detail, sizeof(detail), "value %llu round-tripped wrongly",
                         (unsigned long long)values[value_index]);
          break;
        }
      }
      if (result == WT_CLI_RESULT_PASSED) {
        (void)snprintf(detail, sizeof(detail), "%llu values across every varint form",
                       (unsigned long long)(sizeof(values) / sizeof(values[0])));
      }
      (void)wt_cli_report_add(&report, "quic-varint-round-trip", result, detail);
    }

    /* A WebTransport capsule: the close capsule, with the peer's code and a reason. */
    {
      uint8_t bytes[64];
      wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
      wt_cursor_t cursor;
      wt_webtransport_capsule_t capsule;
      uint32_t code = 0U;
      wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
      int ok = 0;
      if (wt_webtransport_close_session_write(&w, 0x1234U, (const uint8_t *)"bye", 3U) == WT_OK) {
        cursor = wt_cursor_init(bytes, wt_writer_offset(&w));
        if (wt_webtransport_capsule_decode(&cursor, 64U, &capsule, &h3_error) == WT_OK &&
            wt_webtransport_close_session_parse(&capsule, &code, NULL, NULL, &h3_error) == WT_OK &&
            code == 0x1234U) {
          ok = 1;
        }
      }
      (void)wt_cli_report_add(&report, "webtransport-close-capsule",
                              ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                              ok != 0 ? "the peer's code survives the round trip"
                                      : "the close capsule did not round trip");
    }

    /* The draft-16 decision on a decoded request: the layer that says yes or no. */
    {
      wt_http3_message_t message;
      wt_webtransport_request_policy_t policy;
      wt_webtransport_session_request_t decision;
      wt_http3_error_t h3_error = WT_HTTP3_NO_ERROR;
      uint8_t value[16];
      wt_writer_t w = wt_writer_init(value, sizeof(value));
      int ok = 0;
      memset(&message, 0, sizeof(message));
      message.type = WT_HTTP3_HEADER_REQUEST;
      message.method = (const uint8_t *)"CONNECT";
      message.method_length = 7U;
      message.scheme = (const uint8_t *)"https";
      message.scheme_length = 5U;
      message.authority = (const uint8_t *)"localhost";
      message.authority_length = 9U;
      message.path = (const uint8_t *)"/chat";
      message.path_length = 5U;
      message.protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
      message.protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);
      policy.authority = "localhost";
      policy.path = "/chat";
      policy.wt_enabled = 1;
      if (wt_webtransport_session_request_validate(&message, &policy, &decision, &h3_error) == WT_OK &&
          decision.outcome == WT_WEBTRANSPORT_REQUEST_ACCEPT) {
        ok = 1;
      }
      (void)wt_cli_report_add(&report, "draft16-session-request",
                              ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                              ok != 0 ? "an extended CONNECT is accepted for its own path"
                                      : "the request decision differed");
      (void)w;
    }

    /* The refusal scenarios: what this endpoint refuses, and with which code. They need no sockets, because a
     * refusal is a decision rather than a session, and the code is the value the report can carry. */
    wt_scenario_refusals_run(&report);

    /* The connection-control scenarios: GOAWAY identifiers, the peer's control stream and the QPACK bounds.
     * They mirror the Swift suite's control and shutdown groups, and they too need no sockets: what is being
     * asserted is the code the peer would be sent. */
    wt_scenario_control_run(&report);

    /* The headers and QPACK scenarios: the positive field-section side, where a broken encoder would
     * otherwise only show up as a session that did not decode. */
    wt_scenario_headers_run(&report);

    /* Two sessions in one connection, and a datagram that belongs to neither: the isolation a
     * single-session scenario cannot see. */
    wt_scenario_isolation_run(&report);

    /* The stream interop matrix: one table, many cases, and the failing row named in the detail. */
    wt_scenario_matrix_run(&report);
    wt_scenario_datagram_matrix(&report);
    wt_scenario_goaway_close_drain_matrix(&report);
    wt_scenario_connect_matrix(&report);
    wt_scenario_malformed_flow_matrix(&report);

    /* The two session scenarios: two endpoints in ONE process over loopback, with a generated and pinned
     * identity, running the whole exchange -- handshake, CONNECT, response, a stream message and a datagram.
     * IPv6 reports `unsupported` with its reason on a machine that has no IPv6 loopback, because that is a
     * fact about the machine rather than a failure of the code. */
    {
      static char ipv4_detail[WT_CLI_SCENARIO_DETAIL_MAX];
      static char ipv6_detail[WT_CLI_SCENARIO_DETAIL_MAX];
      (void)wt_cli_report_add(&report, "session-over-ipv4",
                              wt_scenario_session_run(0, ipv4_detail, sizeof(ipv4_detail)), ipv4_detail);
      (void)wt_cli_report_add(&report, "session-over-ipv6",
                              wt_scenario_session_run(1, ipv6_detail, sizeof(ipv6_detail)), ipv6_detail);
    }

    if (options.json != 0) {
      wt_cli_report_write_json(&report, stdout);
    } else {
      wt_cli_report_write_text(&report, stdout);
    }
    return wt_cli_report_exit_status(&report);
  }
}
