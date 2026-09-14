/* The refusal scenarios (Phase 10). */

#include "scenario_refusals.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/http3/driver.h"
#include "webtransport/http3/endpoint.h"
#include "webtransport/http3/settings.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

/* A decoded request with the pseudo-headers a WebTransport CONNECT carries, so a scenario can vary ONE field. */
static void make_request(wt_http3_message_t *message) {
  memset(message, 0, sizeof(*message));
  message->type = WT_HTTP3_HEADER_REQUEST;
  message->method = (const uint8_t *)"CONNECT";
  message->method_length = 7U;
  message->scheme = (const uint8_t *)"https";
  message->scheme_length = 5U;
  message->authority = (const uint8_t *)"example.com";
  message->authority_length = 11U;
  message->path = (const uint8_t *)"/chat";
  message->path_length = 5U;
  message->protocol = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN;
  message->protocol_length = strlen(WT_WEBTRANSPORT_PROTOCOL_TOKEN);
}

static void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED, detail);
}

void wt_scenario_refusals_run(wt_cli_report_t *report) {
  wt_webtransport_request_policy_t policy;
  wt_http3_message_t message;
  wt_webtransport_session_request_t decision;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  policy.authority = "example.com";
  policy.path = "/chat";
  policy.wt_enabled = 1;

  /* The wrong path is a 404 for THIS server rather than a session: the comparison is exact, because a prefix
   * match would let one host's request be served as another's. */
  {
    make_request(&message);
    message.path = (const uint8_t *)"/other";
    message.path_length = 6U;
    (void)wt_webtransport_session_request_validate(&message, &policy, &decision, &error);
    add(report, "draft16-request-wrong-path",
        decision.outcome == WT_WEBTRANSPORT_REQUEST_REJECT && decision.status == 404U,
        "a path this server does not serve is refused with 404");
  }

  /* A CONNECT for another protocol is not a WebTransport request at all, and the caller answers it as it would
   * answer any other request. */
  {
    make_request(&message);
    message.protocol = (const uint8_t *)"websocket";
    message.protocol_length = 9U;
    (void)wt_webtransport_session_request_validate(&message, &policy, &decision, &error);
    add(report, "draft16-request-other-protocol",
        decision.outcome == WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT,
        "an extended CONNECT for another protocol is not a WebTransport request");
  }

  /* A server that never advertised WebTransport refuses a session it could not have been expected to serve. */
  {
    wt_webtransport_request_policy_t disabled = policy;
    disabled.wt_enabled = 0;
    make_request(&message);
    (void)wt_webtransport_session_request_validate(&message, &disabled, &decision, &error);
    add(report, "draft16-server-without-wt-enabled",
        decision.outcome == WT_WEBTRANSPORT_REQUEST_REJECT,
        "a server that did not advertise WT_ENABLED refuses the session");
  }

  /* The peer's SETTINGS must obey the draft's rules before anything else can be interpreted: a repeated
   * identifier is a SETTINGS error, and so is one the RFC reserves. */
  {
    /* WT_ENABLED twice: RFC 9114 section 7.2.4 forbids a repeated identifier. */
    /* WT_ENABLED as a FOUR-byte varint (its top bits are `10`), twice: the first byte carries the two high bits
     * of the identifier, so `0xac 0x7c 0xf0 0x00` is 0x2c7cf000 and not the two-byte form a first draft of this
     * scenario used -- the same MSB-first lesson the tracker keeps recording. */
    static const uint8_t repeated[] = {0xacU, 0x7cU, 0xf0U, 0x00U, 0x00U,
                                       0xacU, 0x7cU, 0xf0U, 0x00U, 0x01U};
    wt_http3_settings_t settings;
    wt_http3_error_t settings_error = WT_HTTP3_NO_ERROR;
    wt_status_t status = wt_http3_settings_parse(repeated, sizeof(repeated), &settings, &settings_error);
    add(report, "settings-repeated-identifier",
        status == WT_ERR_PROTOCOL && settings_error == WT_HTTP3_SETTINGS_ERROR,
        "a repeated SETTINGS identifier is H3_SETTINGS_ERROR");
  }
  {
    /* The EXERCISE identifiers of RFC 9114 section 7.2.4.1 -- `0x1f * N + 0x21` -- are IGNORED: "Endpoints
     * SHOULD include at least one such setting in their SETTINGS frame. Endpoints MUST NOT consider such settings
     * to have any meaning upon receipt." This scenario asserted the OPPOSITE for a round (that one is
     * H3_SETTINGS_ERROR), which is the rule for the other reserved family and made this tool refuse a conforming
     * peer's padding. Both outcomes are now asserted, because the section states them one sentence apart. */
    static const uint8_t exerciser[] = {0x21U, 0x01U};
    static const uint8_t http2_reserved[] = {0x02U, 0x01U};
    wt_http3_settings_t settings;
    wt_http3_error_t settings_error = WT_HTTP3_NO_ERROR;
    wt_status_t status = wt_http3_settings_parse(exerciser, sizeof(exerciser), &settings,
                                                 &settings_error);
    int present = 1;
    add(report, "settings-exerciser-identifier-ignored",
        status == WT_OK && settings_error == WT_HTTP3_NO_ERROR &&
            wt_http3_settings_get(&settings, 0x21U, &present) == 0U && present == 0,
        "a SETTINGS exercise identifier (0x1f*N+0x21) is IGNORED, not stored and not an error");

    settings_error = WT_HTTP3_NO_ERROR;
    status = wt_http3_settings_parse(http2_reserved, sizeof(http2_reserved), &settings,
                                     &settings_error);
    add(report, "settings-http2-identifier-refused",
        status == WT_ERR_PROTOCOL && settings_error == WT_HTTP3_SETTINGS_ERROR,
        "a SETTINGS identifier reserved from HTTP/2 (0x02..0x05) is H3_SETTINGS_ERROR");
  }

  /* A field section that references a dynamic entry when NO dynamic table was advertised must be refused rather
   * than read against indices that do not exist -- the configuration the malformed corpus exercises at random and
   * this asserts by hand. */
  {
    uint8_t section[8];
    uint8_t scratch[64];
    wt_http3_message_t decoded;
    wt_http3_error_t qpack_error = WT_HTTP3_NO_ERROR;
    wt_status_t status;

    /* The prefix says a required insert count of one (0x01) and a base of zero (0x00), then a dynamic
     * name-reference line: `0x80` is "literal with a dynamic name reference, index 0". */
    section[0] = 0x01U;
    section[1] = 0x00U;
    section[2] = 0x80U;
    section[3] = 0x00U;
    status = wt_http3_message_decode(&decoded, WT_HTTP3_HEADER_REQUEST, section, 4U, NULL, 0U, 0U, scratch,
                                     sizeof(scratch), &qpack_error);
    add(report, "qpack-dynamic-reference-without-a-table",
        status == WT_ERR_PROTOCOL && qpack_error != WT_HTTP3_NO_ERROR,
        "a section that needs a dynamic table this endpoint never advertised is refused, with a code");
  }

  /* The session's own state machine: a drain stops new streams, and the FIRST close code is the one the session
   * ends with (draft-16 section 5.4). */
  {
    wt_webtransport_session_t session;

    wt_webtransport_session_init(&session);
    wt_webtransport_session_on_close(&session, 0, 0x1234U);
    wt_webtransport_session_on_close(&session, 1, 0x5678U);
    add(report, "session-keeps-the-first-close-code",
        session.state == WT_WEBTRANSPORT_SESSION_CLOSED && session.close_error_code == 0x1234U,
        "the first close's code is the session's, and a later one does not replace it");
  }
  {
    wt_webtransport_session_t session;

    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    (void)wt_webtransport_session_on_drain(&session, 0);
    add(report, "session-drain-stops-new-streams",
        wt_webtransport_session_allows_new_streams(&session) == 0 &&
            session.state == WT_WEBTRANSPORT_SESSION_DRAINING,
        "a session the peer is draining starts no new streams while existing ones may finish");
  }

  /* A capsule whose value is over the bound is refused with the excessive-load code rather than buffered. */
  {
    uint8_t bytes[16];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    wt_cursor_t cursor;
    wt_webtransport_capsule_t capsule;
    wt_http3_error_t capsule_error = WT_HTTP3_NO_ERROR;
    int ok = 0;
    bytes[0] = 0x01U; /* MAX_DATA */
    bytes[1] = 0x40U; /* a two-byte varint length: 64 */
    bytes[2] = 0x3fU;
    {
      size_t i;
      for (i = 3U; i < sizeof(bytes); i++) bytes[i] = 0U;
    }
    cursor = wt_cursor_init(bytes, sizeof(bytes));
    if (wt_webtransport_capsule_decode(&cursor, 32U, &capsule, &capsule_error) == WT_ERR_LIMIT &&
        capsule_error == WT_HTTP3_EXCESSIVE_LOAD) {
      ok = 1;
    }
    (void)w;
    add(report, "capsule-over-bound", ok,
        ok != 0 ? "a capsule value over the bound is refused as excessive load"
                : "a capsule over the bound was not refused with the load code");
  }

  /* A peer stream past the endpoint's bound is refused with NO error code: the bound is this endpoint's. */
  {
    wt_http3_endpoint_t endpoint;
    wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
    wt_http3_error_t stream_error = WT_HTTP3_NO_ERROR;
    uint8_t bytes[8];
    size_t length;
    uint64_t index;
    wt_status_t status = WT_OK;

    wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
    length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, bytes, sizeof(bytes));
    length += wt_quic_varint_encode(0U, bytes + length, sizeof(bytes) - length);
    for (index = 0U; index < (uint64_t)WT_HTTP3_ENDPOINT_STREAMS_MAX && status == WT_OK; index++) {
      status = wt_http3_endpoint_on_uni_stream(&endpoint, 4U + index * 4U, bytes, length, NULL, &kind,
                                               &stream_error);
    }
    status = wt_http3_endpoint_on_uni_stream(&endpoint, 4096U, bytes, length, NULL, &kind, &stream_error);
    add(report, "peer-stream-over-bound",
        status == WT_ERR_LIMIT && stream_error == WT_HTTP3_NO_ERROR,
        "one peer stream past the bound is WT_ERR_LIMIT with no error code, because the bound is ours");
  }

  /* A datagram that does not hold its quarter stream ID is malformed rather than short: a datagram IS the unit. */
  {
    uint64_t quarter = 0U;
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    wt_http3_error_t datagram_error = WT_HTTP3_NO_ERROR;
    wt_status_t status = wt_webtransport_datagram_parse(NULL, 0U, &quarter, &payload, &payload_length,
                                                        &datagram_error);
    add(report, "datagram-without-quarter-id",
        status == WT_ERR_PROTOCOL && datagram_error == WT_HTTP3_DATAGRAM_ERROR,
        "an empty datagram is malformed rather than incomplete, with H3_DATAGRAM_ERROR (0x33)");
  }

  /* And the positive edge this project earned the hard way: a prefix split across frames is assembled, and a
   * switch to the WebTransport kind is not decided from half a varint. */
  {
    wt_http3_endpoint_t endpoint;
    wt_http3_driver_t driver;
    wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
    wt_http3_error_t stream_error = WT_HTTP3_NO_ERROR;
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    size_t consumed = 0U;
    uint8_t bytes[8];
    size_t length;

    wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
    wt_http3_driver_init(&driver, &endpoint);
    length = wt_quic_varint_encode(WT_WEBTRANSPORT_STREAM_UNI, bytes, sizeof(bytes));
    length += wt_quic_varint_encode(0U, bytes + length, sizeof(bytes) - length);
    payload_length = 99U;
    (void)wt_http3_driver_on_uni_stream_data(&driver, 4U, 0U, bytes, 1U, &kind, &payload, &payload_length,
                                             &consumed, &stream_error);
    (void)wt_http3_driver_on_uni_stream_data(&driver, 4U, 1U, bytes + 1, length - 1U, &kind, &payload,
                                             &payload_length, &consumed, &stream_error);
    add(report, "prefix-split-across-frames",
        kind == WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT && payload_length == 0U,
        "half a prefix decides nothing, and the whole one classifies the stream");
  }
}
