/* The WebTransport session request (draft-ietf-webtrans-http3-16 section 3.1).
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

  make_request(&message, "CONNECT", "webtransport", "https", "localhost", "/wt");
  WT_EXPECT_OK("a WebTransport CONNECT is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);
  WT_EXPECT_BYTES("carrying the authority", (const uint8_t *)"localhost", request.authority, 9U);
  WT_EXPECT_BYTES("and the path", (const uint8_t *)"/wt", request.path, 3U);

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
  make_request(&message, "CONNECT", "webtransport", NULL, "localhost", "/wt");
  WT_EXPECT_OK("a request with no scheme is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);
  WT_EXPECT_U64("with 404", (uint64_t)WT_WEBTRANSPORT_REJECT_NOT_FOUND, (uint64_t)request.status);

  make_request(&message, "CONNECT", "webtransport", "https", "localhost", NULL);
  WT_EXPECT_OK("and one with no path",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection as well", (int)WT_WEBTRANSPORT_REQUEST_REJECT,
                (int)request.outcome);

  /* Authority and path are compared exactly: a different host is not this server's
   * session, and neither is a path that merely starts the same way. */
  make_request(&message, "CONNECT", "webtransport", "https", "elsewhere", "/wt");
  WT_EXPECT_OK("another authority is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);

  make_request(&message, "CONNECT", "webtransport", "https", "localhost", "/wt/deeper");
  WT_EXPECT_OK("and a longer path",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);

  /* A server that never advertised WT_ENABLED refuses with 501 rather than serving a
   * session the client could not have known about. */
  policy.wt_enabled = 0;
  make_request(&message, "CONNECT", "webtransport", "https", "localhost", "/wt");
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

/* What a WebTransport endpoint MUST advertise (draft-16 section 3.1), asserted as a set because a missing member
 * is what the third-party peer refused: this tree's client sent only SETTINGS_WT_ENABLED, so `web-transport`'s
 * `supports_webtransport()` -- datagram support AND a WebTransport setting -- saw no WebTransport endpoint and
 * never answered the CONNECT (WT-145). The earlier drafts' enabling codepoints are asserted too, because section
 * 7.1 negotiates a version with one codepoint per version and a peer that predates the rename recognises none of
 * the others. */
static void test_the_settings_a_webtransport_endpoint_advertises(void) {
  wt_http3_settings_t settings;

  /* A client: the datagram setting and the version codepoints, and NOT the CONNECT-protocol setting, which is
   * the server's to advertise (RFC 9220 section 3: a client may only send `:protocol` once the server has). */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a client's settings apply", wt_webtransport_settings_apply(&settings, 0));
  WT_EXPECT_INT("with H3_DATAGRAM", 1, has_setting(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_INT("with the draft-specific WT_ENABLED codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_INT("with the earlier drafts' session codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U));
  WT_EXPECT_INT("and with the codepoint it replaced", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U));
  WT_EXPECT_INT("but not ENABLE_CONNECT_PROTOCOL, which a server sends", 0,
                has_setting(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U));

  /* A server: everything the client sends, plus the extended-CONNECT advertisement and the limit half of the
   * older pair. */
  wt_http3_settings_init(&settings);
  WT_EXPECT_OK("a server's settings apply", wt_webtransport_settings_apply(&settings, 1));
  WT_EXPECT_INT("with H3_DATAGRAM", 1, has_setting(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_INT("with the draft-specific WT_ENABLED codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_ENABLED, 1U));
  WT_EXPECT_INT("with ENABLE_CONNECT_PROTOCOL", 1,
                has_setting(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U));
  WT_EXPECT_INT("with the earlier drafts' session codepoint", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U));
  WT_EXPECT_INT("and with its limit", 1,
                has_setting(&settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS_DEPRECATED, 1U));

  WT_EXPECT_STATUS("a NULL settings is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_settings_apply(NULL, 0));
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

  make_request(&message, "CONNECT", "webtransport", "https", "localhost:54070", "/wt");
  WT_EXPECT_OK("a port on the authority is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance for the host the policy names", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT,
                (int)request.outcome);

  /* The port is not part of the comparison, so a DIFFERENT host is still refused with one. */
  make_request(&message, "CONNECT", "webtransport", "https", "elsewhere:54070", "/wt");
  WT_EXPECT_OK("another host with a port is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as a rejection", (int)WT_WEBTRANSPORT_REQUEST_REJECT, (int)request.outcome);

  /* An IPv6 literal keeps its colons and drops only the port after the bracket. */
  policy.authority = "[::1]";
  make_request(&message, "CONNECT", "webtransport", "https", "[::1]:54070", "/wt");
  WT_EXPECT_OK("a bracketed IPv6 literal with a port is decided",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* And the bare literal, with no port at all, is the same host. */
  make_request(&message, "CONNECT", "webtransport", "https", "[::1]", "/wt");
  WT_EXPECT_OK("as is the same literal alone",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("which is accepted too", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);

  /* A policy that names no authority serves any, which is the honest default for a listener: the transport has
   * already proved the client reached this port. The path, when one is named, is still compared exactly. */
  memset(&policy, 0, sizeof(policy));
  policy.path = NULL;
  policy.wt_enabled = 1;
  make_request(&message, "CONNECT", "webtransport", "https", "anything:1234", "/anything");
  WT_EXPECT_OK("a policy with no authority and no path accepts any",
               wt_webtransport_session_request_validate(&message, &policy, &request, &error));
  WT_EXPECT_INT("as an acceptance", (int)WT_WEBTRANSPORT_REQUEST_ACCEPT, (int)request.outcome);
}

int main(void) {
  test_accepted_and_not_ours();
  test_rejections();
  test_the_settings_a_webtransport_endpoint_advertises();
  test_an_authority_may_name_the_port_it_is_talking_to();
  WT_TEST_MAIN_END("wt_webtransport_session_request");
}
