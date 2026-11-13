/* The WebTransport session request (draft-ietf-webtrans-http3-17 section 3.1).
 *
 * A request that is not WebTransport must be REPORTED rather than refused -- an
 * ordinary GET, a plain CONNECT and an extended CONNECT for another protocol are all
 * legal requests that belong to someone else -- and everything that is WebTransport
 * must be decided precisely, because the answer to a rejection is a status the client
 * reads. The tests are one case per rule, including the two that are easy to get
 * backwards: the CONNECT exception does NOT excuse a WebTransport request from carrying
 * :scheme and :path, and a server that never advertised itself cannot accept. */

#include "wt_test.h"

#include "webtransport/webtransport/session_request.h"

static void make_request(wt_http3_message_t *message, const char *method, const char *protocol,
                         const char *scheme, const char *authority, const char *path) {
  memset(message, 0, sizeof(*message));
  message->type = WT_HTTP3_HEADER_REQUEST;
  message->method = (const uint8_t *)method;
  message->method_length = method == NULL ? 0U : strlen(method);
  message->protocol = (const uint8_t *)protocol;
  message->protocol_length = protocol == NULL ? 0U : strlen(protocol);
  message->scheme = (const uint8_t *)scheme;
  message->scheme_length = scheme == NULL ? 0U : strlen(scheme);
  message->authority = (const uint8_t *)authority;
  message->authority_length = authority == NULL ? 0U : strlen(authority);
  message->path = (const uint8_t *)path;
  message->path_length = path == NULL ? 0U : strlen(path);
}

static void test_accepted_and_not_ours(void) {
  wt_http3_message_t message;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  policy.authority = "localhost";
  policy.path = "/wt";
  policy.wt_enabled = 1;

  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "localhost", "/wt");
  WT_EXPECT_OK("a WebTransport CONNECT is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);
  WT_EXPECT_BYTES("carrying the authority", (const uint8_t *)"localhost", request.authority, 9U);
  WT_EXPECT_BYTES("and the path", (const uint8_t *)"/wt", request.path, 3U);

  /* RFC 3986 section 3.1 makes a URI scheme case-insensitive, so the same field upper-cased is
   * still `https` and still names a session (section 3.2 requires the https scheme). */
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "HTTPS", "localhost", "/wt");
  WT_EXPECT_OK("an upper-cased scheme is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* An ordinary request: not ours, and not an error. */
  make_request(&message, "GET", NULL, "https", "localhost", "/wt");
  WT_EXPECT_OK("a GET is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as not WebTransport", (int)WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT,
                (int)request.outcome);

  /* A plain CONNECT: RFC 9114's tunnel, which is not a session. */
  make_request(&message, "CONNECT", NULL, NULL, "localhost", NULL);
  WT_EXPECT_OK("a plain CONNECT is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as not WebTransport too", (int)WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT,
                (int)request.outcome);

  /* An extended CONNECT for another protocol: someone else's. */
  make_request(&message, "CONNECT", "websocket", "https", "localhost", "/ws");
  WT_EXPECT_OK("another protocol is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as not WebTransport", (int)WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT,
                (int)request.outcome);
}

static void test_rejections(void) {
  wt_http3_message_t message;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  policy.authority = "localhost";
  policy.path = "/wt";
  policy.wt_enabled = 1;

  /* A WebTransport request without a scheme or a path. The CONNECT exception in RFC
   * 9114 does not apply to an EXTENDED CONNECT, and a layer that inherited it would
   * accept a request it cannot route. */
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, NULL, "localhost", "/wt");
  WT_EXPECT_OK("a request with no scheme is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);
  WT_EXPECT_U64("with 404", (uint64_t)WT_WEBTRANSPORT_REJECT_NOT_FOUND, (uint64_t)request.status);

  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "localhost", NULL);
  WT_EXPECT_OK("and one with no path",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection as well", (int)WT_WEBTRANSPORT_REQUEST_REJECT,
                (int)request.outcome);

  /* Section 3.2: "The :scheme field MUST be https." A WebTransport CONNECT over http is a refusal, not a
   * session: the scheme is part of what identifies the target resource, so it takes the same rejection as a
   * missing one rather than being reported as someone else's request. */
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "http", "localhost", "/wt");
  WT_EXPECT_OK("a request over http is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);
  WT_EXPECT_U64("with 404", (uint64_t)WT_WEBTRANSPORT_REJECT_NOT_FOUND, (uint64_t)request.status);

  /* Authority and path are compared exactly: a different host is not this server's
   * session, and neither is a path that merely starts the same way. */
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "elsewhere", "/wt");
  WT_EXPECT_OK("another authority is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);

  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "localhost",
               "/wt/deeper");
  WT_EXPECT_OK("and a longer path",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);

  /* A server that never advertised WT_ENABLED refuses with 501 rather than serving a
   * session the client could not have known about. */
  policy.wt_enabled = 0;
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "localhost", "/wt");
  WT_EXPECT_OK("a server that did not advertise decides",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);
  WT_EXPECT_U64("with 501", (uint64_t)WT_WEBTRANSPORT_REJECT_NOT_IMPLEMENTED,
                (uint64_t)request.status);
}

/* A helper for the test below: is `identifier` present with exactly `value`? */
static int has_setting(const wt_http3_settings_t *settings, uint64_t identifier, uint64_t value) {
  int present = 0;
  uint64_t read = wt_http3_settings_get(settings, identifier, &present);
  return present != 0 && read == value;
}

/* What a WebTransport endpoint MUST advertise (draft-17 section 3.1, with section 7.1's draft codepoints),
 * asserted as a set because a missing member is what the third-party peer refused: this tree's client sent only
 * SETTINGS_WT_ENABLED, so `web-transport`'s `supports_webtransport()` -- datagram support AND a WebTransport
 * setting -- saw no WebTransport endpoint and never answered the CONNECT (WT-145). The DUAL profile -- the
 * default -- sends the section 9.2 codepoint AND the draft-16 one, one per version supported; the FINAL profile
 * is the section 9.2 codepoint alone for a server, and NO version codepoint at all for a client, which is what
 * section 3.1's client list carries. */
static void test_the_settings_a_webtransport_endpoint_advertises(void) {
  wt_http3_settings_t settings;

  /* A DUAL client: the datagram setting and BOTH version codepoints, and NOT the CONNECT-protocol setting,
   * which is the server's to advertise (RFC 9220 section 3: a client may only send `:protocol` once the server
   * has). */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a client's settings apply", wt_webtransport_settings_apply(&settings, 0));
  WT_EXPECT_INT("with H3_DATAGRAM", 1, has_setting(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_INT("with the section 9.2 WT_ENABLED codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_INT("with the draft-16 codepoint beside it", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U));
  WT_EXPECT_INT("with the earlier drafts' session codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U));
  WT_EXPECT_INT("and with the codepoint it replaced", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U));
  WT_EXPECT_INT("but not ENABLE_CONNECT_PROTOCOL, which a server sends", 0,
                has_setting(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U));
  /* And section 5.1's three initial flow-control limits, which are what opens the session's own flow control:
   * they must be the values the runtime enforces, `wt_runtime_session_advertise(100000, 4096, 8, 8)` (WT-252). */
  WT_EXPECT_INT("with the initial data limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_INT("with the bidirectional stream limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 8U));
  WT_EXPECT_INT("and with the unidirectional stream limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI, 8U));

  /* A DUAL server: everything the client sends, plus the extended-CONNECT advertisement and the limit half of
   * the older pair. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a server's settings apply", wt_webtransport_settings_apply(&settings, 1));
  WT_EXPECT_INT("with H3_DATAGRAM", 1, has_setting(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_INT("with the section 9.2 WT_ENABLED codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_INT("with the draft-16 codepoint beside it", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U));
  WT_EXPECT_INT("with ENABLE_CONNECT_PROTOCOL", 1,
                has_setting(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U));
  WT_EXPECT_INT("with the earlier drafts' session codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U));
  WT_EXPECT_INT("and with its limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS_DEPRECATED, 1U));
  /* The same section 5.1 limits, because flow control is a property of the connection rather than of a role. */
  WT_EXPECT_INT("with the initial data limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA, 100000U));
  WT_EXPECT_INT("with the bidirectional stream limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI, 8U));
  WT_EXPECT_INT("and with the unidirectional stream limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI, 8U));

  /* The two codepoints are DISTINCT, which is the fact that makes "one per version" a rule with content: the
   * section 9.2 registration and the draft-16 codepoint are different numbers a peer can tell apart. */
  WT_EXPECT_TRUE("the section 9.2 codepoint is not the draft-16 one",
                 WT_HTTP3_SETTING_WT_ENABLED != WT_HTTP3_SETTING_WT_ENABLED_DRAFT16);
  WT_EXPECT_TRUE("and the draft-16 codepoint is the value the earlier draft registered",
                 WT_HTTP3_SETTING_WT_ENABLED_DRAFT16 == (uint64_t)0x2c7cf000U);
  WT_EXPECT_TRUE("while the section 9.2 one is the final registration",
                 WT_HTTP3_SETTING_WT_ENABLED == (uint64_t)0x20b8933bU);

  /* A FINAL client sends NO version codepoint at all: section 3.1's client list carries none, and
   * section 7.1 is explicit that a client supporting only the final version does not send the setting. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a FINAL client's settings apply",
               wt_webtransport_settings_apply_profile(&settings, 0, WT_WEBTRANSPORT_PROFILE_FINAL));
  WT_EXPECT_INT("with H3_DATAGRAM still", 1,
                has_setting(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_INT("but with NO section 9.2 codepoint", 0,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_INT("and NO draft-16 codepoint", 0,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U));

  /* A FINAL server advertises the section 9.2 codepoint alone: a draft-16 peer finds none of its
   * codepoints and never attempts a session, which is the point of the strict posture. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a FINAL server's settings apply",
               wt_webtransport_settings_apply_profile(&settings, 1, WT_WEBTRANSPORT_PROFILE_FINAL));
  WT_EXPECT_INT("with H3_DATAGRAM", 1, has_setting(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_INT("with the section 9.2 codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_INT("but with NO draft-16 codepoint", 0,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U));
  WT_EXPECT_INT("and still with ENABLE_CONNECT_PROTOCOL", 1,
                has_setting(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U));

  WT_EXPECT_STATUS("a NULL settings is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_settings_apply(NULL, 0));
}

/* Section 7.1's selection matrix, as a table: which codepoints the CLIENT sent, and the version the server
 * selects. One test per row, because the matrix is the normative answer and each row names a different rule. */
static void test_the_section_7_1_selection_matrix(void) {
  wt_http3_settings_t settings;
  wt_webtransport_version_t version;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A client that sent the section 9.2 codepoint selected the final version. Its VALUE is ignored:
   * section 3.1 makes SETTINGS_WT_ENABLED meaningless from a client, so even a value a client of the
   * server's SETTINGS would refuse is not this server's business. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U);
  WT_EXPECT_OK("a client that sent the section 9.2 codepoint selects",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the final version", (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 7U);
  WT_EXPECT_OK("and so does one whose section 9.2 value is not 1",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("still the final version", (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  /* A client that sent ONLY the draft-16 codepoint, with the value 1 a draft client sends, is a draft-16
   * client, and the draft-16 version is selected. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
  WT_EXPECT_OK("a draft-16-only client selects",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the draft-16 version", (int)WT_WEBTRANSPORT_VERSION_DRAFT16, (int)version);

  /* A draft-16 codepoint with any other value is not a selection: it is the connection error section 3.1
   * gives the setting. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 2U);
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS("a draft-16 codepoint that is not 1 is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("with H3_SETTINGS_ERROR", (int)WT_HTTP3_SETTINGS_ERROR, (int)error);

  /* A client that sent NO version codepoint is a FINAL client -- section 3.1's client list carries none --
   * so silence selects the final version rather than refusing the connection. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a client that sent nothing selects",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the final version too", (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  /* A client that sent ONLY the earlier drafts' advertisement is a LEGACY client, and the legacy
   * session is what its era agreed to: the wt2 server-direction peers (pywebtransport, quic-go)
   * advertise exactly this, measured against the deployed peers on 13 November 2026. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  WT_EXPECT_OK("a legacy-enabled client selects",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the legacy version", (int)WT_WEBTRANSPORT_VERSION_LEGACY, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U);
  WT_EXPECT_OK("and so does one that advertised only the max-sessions setting",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the legacy version again", (int)WT_WEBTRANSPORT_VERSION_LEGACY, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
  WT_EXPECT_OK("a legacy client that also sent the draft-16 codepoint selects",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the draft-16 version over the legacy one", (int)WT_WEBTRANSPORT_VERSION_DRAFT16,
                (int)version);

  /* Both codepoints together: the section 9.2 one wins, which is the highest version both support. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
  WT_EXPECT_OK("a client that sent both selects",
               wt_webtransport_version_select(&settings, &version, &error));
  WT_EXPECT_INT("the final version over the draft", (int)WT_WEBTRANSPORT_VERSION_FINAL,
                (int)version);

  WT_EXPECT_STATUS("a NULL settings is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_version_select(NULL, &version, &error));
}

/* The client's half of the same matrix: what the SERVER's SETTINGS enable, per profile. */
static void test_the_client_version_matrix(void) {
  wt_http3_settings_t settings;
  wt_webtransport_version_t version;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* The section 9.2 codepoint with the value 1 enables the final version, preferred over any draft
   * codepoint beside it. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
  WT_EXPECT_OK(
      "a server that sent both codepoints enables",
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));
  WT_EXPECT_INT("the final version", (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  /* A value greater than 1 is the connection error section 3.1 names, whatever else the set carried. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 2U);
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS(
      "a section 9.2 value greater than 1 is refused", WT_ERR_PROTOCOL,
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));
  WT_EXPECT_INT("with H3_SETTINGS_ERROR", (int)WT_HTTP3_SETTINGS_ERROR, (int)error);

  /* Only the draft-16 codepoint, with the value 1: a DUAL client accepts it, and the draft-16 version
   * is what the two ends speak. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
  WT_EXPECT_OK(
      "a draft-16-only server enables a DUAL client",
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));
  WT_EXPECT_INT("at the draft-16 version", (int)WT_WEBTRANSPORT_VERSION_DRAFT16, (int)version);

  /* The same advertisement leaves a FINAL client without WebTransport: a server that sent none of the
   * codepoints its profile requires does not serve WebTransport for it, and no session may be
   * attempted on the connection. */
  WT_EXPECT_STATUS(
      "it does not enable a FINAL client", WT_ERR_STATE,
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_FINAL, &version, &error));

  /* A server that sent neither codepoint does not serve WebTransport for any profile: the setting's
   * default value is 0, which means the server does not support it. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_STATUS(
      "a server that advertised nothing enables nothing", WT_ERR_STATE,
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));

  /* A draft-16 codepoint with a value other than 1 is not an advertisement either: the value is how
   * the era's setting said "supported". */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 5U);
  WT_EXPECT_STATUS(
      "a draft-16 codepoint that is not 1 enables nothing", WT_ERR_STATE,
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));

  /* The earlier drafts' advertisement, and nothing newer: a pre-draft-16 server. Every third-party
   * peer this tree interoperates with advertises exactly this -- measured against the five deployed
   * VPS peers on 13 November 2026, all five carrying 0x2b603742=1 and two of them 0xc671706a=1 -- so
   * the DUAL profile serves it as the LEGACY session it is. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  WT_EXPECT_OK(
      "a legacy-enabled server enables a DUAL client",
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));
  WT_EXPECT_INT("at the legacy version", (int)WT_WEBTRANSPORT_VERSION_LEGACY, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U);
  WT_EXPECT_OK(
      "and so does one that advertised only the max-sessions setting",
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));
  WT_EXPECT_INT("at the legacy version again", (int)WT_WEBTRANSPORT_VERSION_LEGACY, (int)version);

  /* A FINAL profile keeps its word: the strict posture serves the version the section 9.2 codepoint
   * names, and the earlier drafts' advertisement does not enable WebTransport for it. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  WT_EXPECT_STATUS(
      "a legacy-only server does not enable a FINAL client", WT_ERR_STATE,
      wt_webtransport_client_version(&settings, WT_WEBTRANSPORT_PROFILE_FINAL, &version, &error));

  WT_EXPECT_STATUS(
      "a NULL settings is refused", WT_ERR_INVALID_ARGUMENT,
      wt_webtransport_client_version(NULL, WT_WEBTRANSPORT_PROFILE_DUAL, &version, &error));
}

/* What version a peer's SETTINGS advertise, without a profile -- the one question the flow-control
 * baseline needs answered about the same parsed SETTINGS before either endpoint knows its role. */
static void test_the_peer_advertised_version_matrix(void) {
  wt_http3_settings_t settings;
  wt_webtransport_version_t version;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  WT_EXPECT_OK("the section 9.2 codepoint advertises",
               wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("the final version", (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 7U);
  WT_EXPECT_OK("a section 9.2 value a client would refuse still advertises",
               wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("the final version, its value being the server's business",
                (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 1U);
  WT_EXPECT_OK("the draft-16 codepoint advertises",
               wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("the draft-16 version", (int)WT_WEBTRANSPORT_VERSION_DRAFT16, (int)version);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U);
  WT_EXPECT_OK("the earlier drafts' settings advertise",
               wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("the legacy version", (int)WT_WEBTRANSPORT_VERSION_LEGACY, (int)version);

  wt_http3_settings_init(&settings);
  WT_EXPECT_STATUS("an empty SETTINGS advertises nothing", WT_ERR_STATE,
                   wt_webtransport_peer_advertised_version(&settings, &version, &error));

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 2U);
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS("a draft-16 codepoint that is not 1 is the connection error", WT_ERR_PROTOCOL,
                   wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("with H3_SETTINGS_ERROR", (int)WT_HTTP3_SETTINGS_ERROR, (int)error);

  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 2U);
  WT_EXPECT_OK("a section 9.2 value greater than 1 still classifies as final",
               wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("its value being the 2xx gate's rule, not the rule selector's",
                (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  /* But a final advertisement beside a broken draft one is still final: the higher version is what
   * section 7.1 selects, and the final codepoint is checked before the draft's value. */
  wt_http3_settings_init(&settings);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  (void)wt_http3_settings_set(&settings, WT_HTTP3_SETTING_WT_ENABLED_DRAFT16, 2U);
  WT_EXPECT_OK("a final codepoint beside a broken draft one advertises",
               wt_webtransport_peer_advertised_version(&settings, &version, &error));
  WT_EXPECT_INT("the final version", (int)WT_WEBTRANSPORT_VERSION_FINAL, (int)version);

  WT_EXPECT_STATUS("a NULL settings is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_peer_advertised_version(NULL, &version, &error));
}

/* An authority a real client sends carries the port, and a policy names a HOST: RFC 9114 section 4.3.1 makes
 * `:authority` the target URI's authority, and a URI on a non-default port has `localhost:8443` there. Comparing
 * the whole string refused every third-party client -- pywebtransport connected to `https://127.0.0.1:54070/` and
 * this server answered "not this authority" -- while this tree's own two tools never noticed, because both sent
 * the bare host (WT-153). A bracketed IPv6 literal is the case that makes the port rule interesting: it is full of
 * colons that are not separators. */
static void test_an_authority_may_name_the_port_it_is_talking_to(void) {
  wt_http3_message_t message;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  memset(&policy, 0, sizeof(policy));
  policy.authority = "localhost";
  policy.path = "/wt";
  policy.wt_enabled = 1;

  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "localhost:54070",
               "/wt");
  WT_EXPECT_OK("a port on the authority is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance for the host the policy names",
                (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* The port is not part of the comparison, so a DIFFERENT host is still refused with one. */
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "elsewhere:54070",
               "/wt");
  WT_EXPECT_OK("another host with a port is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);

  /* An IPv6 literal keeps its colons and drops only the port after the bracket. */
  policy.authority = "[::1]";
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "[::1]:54070", "/wt");
  WT_EXPECT_OK("a bracketed IPv6 literal with a port is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* And the bare literal, with no port at all, is the same host. */
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "[::1]", "/wt");
  WT_EXPECT_OK("as is the same literal alone",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("which is accepted too", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* A policy that names no authority serves any, which is the honest default for a listener: the transport has
   * already proved the client reached this port. The path, when one is named, is still compared exactly. */
  memset(&policy, 0, sizeof(policy));
  policy.path = NULL;
  policy.wt_enabled = 1;
  make_request(&message, "CONNECT", WT_WEBTRANSPORT_PROTOCOL_TOKEN, "https", "anything:1234",
               "/anything");
  WT_EXPECT_OK("a policy with no authority and no path accepts any",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);
}

/* Draft-ietf-webtrans-http3-17 sections 3.2 and 9.1 name the `:protocol` value `webtransport-h3`; the drafts
 * before it used `webtransport`, which section 2.1.2 defines as the WebTransport-over-HTTP/2 token. They are
 * DIFFERENT strings, and this server accepts BOTH: the draft-16 token because that is what a conforming peer
 * sends, the pre-draft one deliberately, because four of the five interop peers send it (see the constant's
 * comment). Two constants that were the same string could not state that: the client could not send the
 * draft-16 token at all, no peer could be told the two apart, and the acceptance check `x || x` accepted only
 * one value while claiming to accept two. */
static void test_both_protocol_tokens_are_accepted_and_distinct(void) {
  wt_http3_message_t message;
  wt_webtransport_request_policy_t policy;
  wt_webtransport_session_request_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* The names are two tokens, which is what makes accepting both a decision rather than a tautology. */
  WT_EXPECT_TRUE("the draft-16 token is not the pre-draft token",
                 strcmp(WT_WEBTRANSPORT_PROTOCOL_TOKEN, WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY) !=
                     0);
  WT_EXPECT_BYTES("and the draft-16 token is the one the draft registers",
                  (const uint8_t *)"webtransport-h3",
                  (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN, strlen("webtransport-h3"));
  WT_EXPECT_BYTES("while the pre-draft token is the HTTP/2 one", (const uint8_t *)"webtransport",
                  (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY, strlen("webtransport"));

  /* And the SELECTION maps to those two strings, with the draft-16 token as its zero so that a zeroed driver
   * sends the current token (F-02b). Before this selection existed the client could only ever send one of them. */
  WT_EXPECT_INT("the draft-16 selection is the default zero", 0,
                (int)WT_WEBTRANSPORT_UPGRADE_TOKEN_DRAFT16);
  WT_EXPECT_STR("and names the draft-16 token", "webtransport-h3",
                wt_webtransport_upgrade_token_value(WT_WEBTRANSPORT_UPGRADE_TOKEN_DRAFT16));
  WT_EXPECT_STR("the legacy selection names the pre-draft token", "webtransport",
                wt_webtransport_upgrade_token_value(WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY));
  WT_EXPECT_TRUE(
      "so the two selections put different strings on the wire",
      strcmp(wt_webtransport_upgrade_token_value(WT_WEBTRANSPORT_UPGRADE_TOKEN_DRAFT16),
             wt_webtransport_upgrade_token_value(WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY)) != 0);

  memset(&policy, 0, sizeof(policy));
  policy.authority = "localhost";
  policy.path = "/wt";
  policy.wt_enabled = 1;

  /* The draft-16 token is the one a conforming client sends, and it is accepted. */
  make_request(&message, "CONNECT", "webtransport-h3", "https", "localhost", "/wt");
  WT_EXPECT_OK("a draft-16 request is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* The pre-draft token is accepted too, deliberately and separately. */
  make_request(&message, "CONNECT", "webtransport", "https", "localhost", "/wt");
  WT_EXPECT_OK("a pre-draft request is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance as well", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                (int)request.outcome);

  /* A third token is somebody else's extended CONNECT. `webtransport-h2` is the near miss that matters: it is
   * the same LENGTH as the draft-16 token, so a match that compared only a prefix or a length would accept it. */
  make_request(&message, "CONNECT", "webtransport-h2", "https", "localhost", "/wt");
  WT_EXPECT_OK("an unrelated protocol is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as not WebTransport", (int)WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT,
                (int)request.outcome);
}

int main(void) {
  test_accepted_and_not_ours();
  test_rejections();
  test_the_settings_a_webtransport_endpoint_advertises();
  test_the_section_7_1_selection_matrix();
  test_the_client_version_matrix();
  test_the_peer_advertised_version_matrix();
  test_an_authority_may_name_the_port_it_is_talking_to();
  test_both_protocol_tokens_are_accepted_and_distinct();
  WT_TEST_MAIN_END("wt_webtransport_session_request");
}
