/* The endpoint configuration (Phase 8).
 *
 * The point of this surface is that a misconfiguration is a RETURN VALUE here rather than
 * a handshake failure twenty seconds later, so the tests are the rules: a role must be
 * chosen, a client must name a port and a trust mode, a server must not carry one, and the
 * development bypass is tied to a loopback name -- checked through the TRUST LAYER's own
 * function, so the two layers cannot drift apart. The last test is the one that matters
 * most: the session configuration the endpoint produces actually creates a session. */

#include "wt_test.h"

#include <string.h>

#include "webtransport/api/endpoint.h"
#include "webtransport/api/events.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/writer.h"

static void test_roles_and_names(void) {
  WT_EXPECT_STR("a client is named", "client", wt_endpoint_role_name(WT_ENDPOINT_ROLE_CLIENT));
  WT_EXPECT_STR("a server is named", "server", wt_endpoint_role_name(WT_ENDPOINT_ROLE_SERVER));
  WT_EXPECT_STR("and nothing else is", "unknown", wt_endpoint_role_name((wt_endpoint_role_t)0));
}

static void test_a_client_needs_everything(void) {
  wt_endpoint_config_t config = wt_endpoint_config_default();
  wt_tls_trust_policy_t trust;
  unsigned char fingerprint[WT_SHA256_LEN];

  memset(&trust, 0, sizeof(trust));

  /* The default has no role, and that is refused: the two sides need different things. */
  config.host = "example.com";
  config.port = 443U;
  WT_EXPECT_STATUS("a default configuration has no role", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));

  /* A client with no trust policy has nothing to judge the peer with. */
  config.role = WT_ENDPOINT_ROLE_CLIENT;
  WT_EXPECT_STATUS("and a client with no trust policy is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));

  /* SYSTEM without a name is allowed by the trust layer (documented as skipping the name
   * check), so it is allowed here too. */
  trust.mode = WT_TLS_TRUST_SYSTEM;
  config.trust = trust;
  WT_EXPECT_OK("a system-trust client is accepted", wt_endpoint_config_check(&config));

  /* A client must name a port. */
  config.port = 0U;
  WT_EXPECT_STATUS("but not without a port", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));
  config.port = 443U;

  /* A pinning policy needs pins. */
  memset(&trust, 0, sizeof(trust));
  trust.mode = WT_TLS_TRUST_PINNED_CERTIFICATE;
  config.trust = trust;
  WT_EXPECT_STATUS("a pinned client with no pin is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));
  trust.fingerprints[0][0] = 0x01U;
  trust.fingerprint_count = 1U;
  config.trust = trust;
  WT_EXPECT_OK("and one with a pin is accepted", wt_endpoint_config_check(&config));
  trust.fingerprint_count = WT_TLS_PINNED_MAX + 1U;
  config.trust = trust;
  WT_EXPECT_STATUS("while more pins than a policy holds are refused", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));

  (void)fingerprint;
}

static void test_the_development_bypass_is_tied_to_loopback(void) {
  wt_endpoint_config_t config = wt_endpoint_config_default();

  config.role = WT_ENDPOINT_ROLE_CLIENT;
  config.port = 4433U;
  config.host = "localhost";
  config.trust.mode = WT_TLS_TRUST_LOCAL_DEVELOPMENT;
  WT_EXPECT_OK("the bypass is accepted for localhost", wt_endpoint_config_check(&config));

  config.host = "127.0.0.1";
  WT_EXPECT_OK("and for a loopback address", wt_endpoint_config_check(&config));

  /* The point of the rule: a real endpoint cannot be reached with the bypass. */
  config.host = "example.com";
  WT_EXPECT_STATUS("but not for a real endpoint", WT_ERR_TRUST, wt_endpoint_config_check(&config));

  /* A name that merely CONTAINS a loopback name is not one of them. */
  config.host = "localhost.example.com";
  WT_EXPECT_STATUS("nor for a name that looks like one", WT_ERR_TRUST,
                   wt_endpoint_config_check(&config));

  /* The trust policy's own host name wins when it names one, because that is the name the
   * certificate is validated against. */
  config.host = "localhost";
  config.trust.host_name = "example.com";
  WT_EXPECT_STATUS("and the policy's name is what is checked", WT_ERR_TRUST,
                   wt_endpoint_config_check(&config));

  /* The two layers share one implementation of the rule, which is the reason it is
   * exported at all. */
  WT_EXPECT_INT("the trust layer agrees about localhost", 1,
                wt_tls_trust_host_is_loopback("localhost"));
  WT_EXPECT_INT("about ::1", 1, wt_tls_trust_host_is_loopback("::1"));
  WT_EXPECT_INT("and about a real name", 0, wt_tls_trust_host_is_loopback("example.com"));
  WT_EXPECT_INT("including NULL", 0, wt_tls_trust_host_is_loopback(NULL));
}

static void test_a_server_has_no_trust_policy(void) {
  wt_endpoint_config_t config = wt_endpoint_config_default();

  config.role = WT_ENDPOINT_ROLE_SERVER;
  config.host = "localhost";
  config.port = 4433U;
  WT_EXPECT_OK("a server with no policy is accepted", wt_endpoint_config_check(&config));

  /* Port 0 is the system's choice, which is what a test binding an ephemeral port wants. */
  config.port = 0U;
  WT_EXPECT_OK("and may leave the port to the system", wt_endpoint_config_check(&config));
  config.port = 4433U;

  /* A server has no peer certificate to judge in this draft, so a policy here would be a
   * promise the library cannot keep. */
  config.trust.mode = WT_TLS_TRUST_SYSTEM;
  WT_EXPECT_STATUS("but not a trust policy", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));

  config.trust.mode = (wt_tls_trust_mode_t)0;
  config.host = NULL;
  WT_EXPECT_STATUS("and not an empty host", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));
}

static void test_paths_and_bounds(void) {
  wt_endpoint_config_t config = wt_endpoint_config_default();
  char too_long[WT_SESSION_AUTHORITY_MAX + 1U];

  config.role = WT_ENDPOINT_ROLE_CLIENT;
  config.host = "example.com";
  config.port = 443U;
  config.trust.mode = WT_TLS_TRUST_SYSTEM;
  WT_EXPECT_OK("a default path is an absolute one", wt_endpoint_config_check(&config));

  config.path = "chat";
  WT_EXPECT_STATUS("a relative path is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_config_check(&config));
  config.path = "/chat";
  WT_EXPECT_OK("and an absolute one is accepted", wt_endpoint_config_check(&config));

  memset(too_long, 'a', sizeof(too_long) - 1U);
  too_long[0] = '/';
  too_long[sizeof(too_long) - 1U] = '\0';
  config.path = too_long;
  WT_EXPECT_STATUS("a path longer than the handle copies is refused", WT_ERR_LIMIT,
                   wt_endpoint_config_check(&config));

  config.path = "/chat";
  config.authority = too_long;
  WT_EXPECT_STATUS("and so is an authority", WT_ERR_LIMIT, wt_endpoint_config_check(&config));
}

static void test_a_session_is_built_from_it(void) {
  wt_endpoint_config_t config = wt_endpoint_config_default();
  wt_session_config_t session_config;
  wt_session_t *session = NULL;
  uint8_t bytes[32];
  wt_writer_t w;

  config.role = WT_ENDPOINT_ROLE_CLIENT;
  config.host = "example.com";
  config.port = 443U;
  config.path = "/chat";
  config.trust.mode = WT_TLS_TRUST_SYSTEM;

  WT_EXPECT_OK("an endpoint produces a session configuration",
               wt_endpoint_session_config(&config, 4U, &session_config));
  /* No authority of its own: the host is what the CONNECT request carries. */
  WT_EXPECT_STR("with the host as the authority", "example.com", session_config.authority);
  WT_EXPECT_STR("and the endpoint's path", "/chat", session_config.path);
  WT_EXPECT_U64("on the CONNECT stream it was given", 4U, session_config.session_id);

  /* The produced configuration is a real one: it creates a session that works. */
  WT_EXPECT_OK("which creates a session", wt_session_create(&session_config, NULL, &session));
  WT_EXPECT_U64("for that session ID", 4U, wt_session_id(session));
  WT_EXPECT_OK("established", wt_session_established(session));

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a datagram writes", wt_webtransport_datagram_write(&w, 1U, (const uint8_t *)"x", 1U));
  WT_EXPECT_OK("and is delivered on it", wt_session_on_datagram(session, bytes, wt_writer_offset(&w)));
  wt_session_destroy(session, NULL);

  /* An endpoint that does not pass its own check produces no configuration at all. */
  config.role = (wt_endpoint_role_t)0;
  memset(&session_config, 0, sizeof(session_config));
  WT_EXPECT_STATUS("a misconfigured endpoint produces nothing", WT_ERR_INVALID_ARGUMENT,
                   wt_endpoint_session_config(&config, 4U, &session_config));
  WT_EXPECT_STR("whose fields are untouched", "", session_config.path != NULL ? session_config.path : "");
}

int main(void) {
  test_roles_and_names();
  test_a_client_needs_everything();
  test_the_development_bypass_is_tied_to_loopback();
  test_a_server_has_no_trust_policy();
  test_paths_and_bounds();
  test_a_session_is_built_from_it();
  WT_TEST_MAIN_END("wt_api_endpoint");
}
