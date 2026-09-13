/* The sub-protocol negotiation scenario (Phase 10). */

#include "scenario_protocol.h"

#include <string.h>

#include "webtransport/http3/message.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/webtransport/protocol.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

static void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED, detail);
}

/* Walk a field section for one field by name, which is what a client does with a response: the pseudo-headers
 * are the message decoder's business and everything else is the caller's, so the search is here rather than
 * assumed to be done. */
static int find_field(const uint8_t *section, size_t length, const char *name, const uint8_t **out_value,
                      size_t *out_value_length) {
  wt_qpack_field_section_decoder_t decoder;
  wt_qpack_resolved_field_t field;
  uint8_t scratch[256];
  wt_qpack_error_t error = WT_QPACK_ERROR_NONE;
  size_t name_length = strlen(name);

  if (wt_qpack_field_section_begin(&decoder, NULL, 0U, section, length, 0U, &error) != WT_OK) return 0;
  for (;;) {
    memset(&field, 0, sizeof(field));
    if (wt_qpack_field_section_decoder_next(&decoder, scratch, sizeof(scratch), &field, &error) != WT_OK) {
      return 0;
    }
    if (field.name_length == name_length && memcmp(field.name, name, name_length) == 0) {
      if (out_value != NULL) *out_value = field.value;
      if (out_value_length != NULL) *out_value_length = field.value_length;
      return 1;
    }
  }
}

void wt_scenario_protocol_run(wt_cli_report_t *report) {
  static const char *const offered_strings[] = {"chat.v1", "chat.v2"};
  static const char *const supported_strings[] = {"chat.v3", "chat.v2"};
  static const char *const disjoint_strings[] = {"other.v1"};
  wt_webtransport_protocol_list_t offered;
  wt_webtransport_protocol_list_t supported;
  wt_webtransport_protocol_list_t disjoint;
  wt_webtransport_session_request_t decision;
  uint8_t section[256];
  uint8_t scratch[256];
  wt_writer_t w;
  wt_http3_message_t response;
  wt_http3_message_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_webtransport_protocol_token_t selected;
  int ok;

  ok = wt_webtransport_protocol_list_from_strings(&offered, offered_strings, 2U) == WT_OK &&
       wt_webtransport_protocol_list_from_strings(&supported, supported_strings, 2U) == WT_OK &&
       wt_webtransport_protocol_list_from_strings(&disjoint, disjoint_strings, 1U) == WT_OK;

  /* The request carries the list, and the server decides from it. The CLIENT's order decides: the client
   * offered chat.v1 first, but the server does not support it, so chat.v2 is the answer -- and a server that
   * scanned its own list would still say chat.v2 here, which is why the next case exists. */
  memset(&request, 0, sizeof(request));
  request.type = WT_HTTP3_HEADER_REQUEST;
  request.method = (const uint8_t *)"CONNECT";
  request.method_length = 7U;
  request.scheme = (const uint8_t *)"https";
  request.scheme_length = 5U;
  request.authority = (const uint8_t *)"example.com";
  request.authority_length = 11U;
  request.path = (const uint8_t *)"/chat";
  request.path_length = 5U;
  request.protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
  request.protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);

  memset(&decision, 0, sizeof(decision));
  error = WT_HTTP3_NO_ERROR;
  ok = ok && wt_webtransport_session_request_validate(&request, &(wt_webtransport_request_policy_t){
                                                                  "example.com", "/chat", 1},
                                                      &decision, &error) == WT_OK &&
       decision.outcome == WT_WEBTRANSPORT_REQUEST_ACCEPT;
  ok = ok && wt_webtransport_session_request_negotiate(&decision, &offered, &supported, 1) == WT_OK &&
       decision.outcome == WT_WEBTRANSPORT_REQUEST_ACCEPT &&
       decision.selected_protocol_length == 7U &&
       memcmp(decision.selected_protocol, "chat.v2", 7U) == 0;

  /* The response carries the selection, in the field section, next to the status: the message encoder writes
   * the pseudo-headers and the caller appends the field, which is the order a QPACK section needs. */
  memset(&response, 0, sizeof(response));
  response.type = WT_HTTP3_HEADER_RESPONSE;
  response.status = 200U;
  response.has_status = 1;
  w = wt_writer_init(section, sizeof(section));
  selected.bytes = decision.selected_protocol;
  selected.length = decision.selected_protocol_length;
  ok = ok && wt_http3_message_encode(&w, &response, 0U, &error) == WT_OK &&
       wt_webtransport_protocol_write_field(&w, &selected) == WT_OK;

  /* And the client reads it back out of the section: the value is a Structured Fields string, and it has to
   * name a token the client offered. */
  {
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    wt_webtransport_protocol_token_t received;
    memset(&received, 0, sizeof(received));
    ok = ok && find_field(section, wt_writer_offset(&w), WT_WEBTRANSPORT_PROTOCOL_HEADER, &value,
                          &value_length);
    ok = ok && wt_webtransport_session_response_selected_protocol(value, value_length, &offered, &received) ==
                   WT_OK &&
         received.length == 7U && memcmp(received.bytes, "chat.v2", 7U) == 0;
  }

  add(report, "protocol-negotiation", ok,
      "the client's list is offered, the server selects the first token it supports, and the client accepts "
      "the answer only because it offered it");

  /* The refusal: a client that REQUIRES a sub-protocol and offers nothing this server supports is answered
   * with the draft's requirements-not-met status rather than a session that quietly speaks nothing. */
  {
    wt_webtransport_session_request_t refused;
    memset(&refused, 0, sizeof(refused));
    refused.outcome = WT_WEBTRANSPORT_REQUEST_ACCEPT;
    (void)wt_webtransport_session_request_negotiate(&refused, &offered, &disjoint, 1);
    add(report, "protocol-negotiation-required-refusal",
        refused.outcome == WT_WEBTRANSPORT_REQUEST_REJECT &&
            refused.status == WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED &&
            refused.selected_protocol == NULL,
        "a required sub-protocol that cannot be selected is a 400, not a session speaking nothing");

    /* And the other half of the same rule: a server that names a token the client never offered is refused by
     * the client, whatever the server believes it negotiated. */
    {
      uint8_t value[32];
      wt_writer_t value_writer = wt_writer_init(value, sizeof(value));
      wt_webtransport_protocol_token_t unoffered;
      wt_webtransport_protocol_token_t received;
      wt_status_t answered;
      unoffered.bytes = (const uint8_t *)"other.v1";
      unoffered.length = 8U;
      (void)wt_webtransport_protocol_encode_item(&value_writer, &unoffered);
      answered = wt_webtransport_session_response_selected_protocol(value, wt_writer_offset(&value_writer),
                                                                    &offered, &received);
      add(report, "protocol-negotiation-unoffered-selection", answered == WT_ERR_PROTOCOL,
          "a response naming a sub-protocol the client never offered is refused rather than spoken");
    }
  }
  (void)scratch;
}
