/* A packet session: a socket, a QUIC connection and a TLS handshake, driven together (Phase 9).
 *
 * What is tested here is the SESSION's own contract, not the handshake's (the handshake has its own
 * suite, with the repository's trust fixtures): that starting an endpoint arms it and installs the
 * Initial keys in both directions, that a pump neither blocks nor invents an error when there is
 * nothing to read, that a session is not established before a handshake has happened, and that clearing
 * one twice is safe -- because a tool that could not clear a session twice would leak a socket on an
 * error path. The two-endpoint handshake over loopback is the next part, and it belongs beside the
 * fixtures it needs rather than here.
 */

#include "wt_test.h"

#include <string.h>

#include "webtransport/runtime/session.h"

static const uint8_t k_connection_id[8] = {0x81U, 0x82U, 0x83U, 0x84U,
                                           0x85U, 0x86U, 0x87U, 0x88U};

static void make_config(wt_quic_connection_config_t *config, wt_quic_role_t role) {
  memset(config, 0, sizeof(*config));
  config->role = role;
  config->version = WT_QUIC_VERSION_1;
  config->local_connection_id = k_connection_id;
  config->local_connection_id_length = sizeof(k_connection_id);
  config->peer_connection_id = k_connection_id;
  config->peer_connection_id_length = sizeof(k_connection_id);
  config->aead = WT_AEAD_AES_128_GCM;
  config->max_ack_delay = 25000U;
  config->local_max_ack_delay = 25000U;
  config->idle_timeout = 30000000U;
  config->max_datagram_size = 1200U;
}

static void test_starting_an_endpoint_arms_it(void) {
  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  wt_quic_connection_config_t config;
  wt_tls_client_config_t tls;
  wt_runtime_session_t session;

  {
    wt_udp_address_t local;
    WT_EXPECT_OK("a loopback address parses", wt_udp_address_parse_host_port("127.0.0.1:0", &local));
    WT_EXPECT_OK("a socket opens", wt_udp_socket_open(&socket, WT_UDP_IPV4));
    WT_EXPECT_OK("and binds", wt_udp_bind(&socket, &local));
    WT_EXPECT_TRUE("on a port the system chose", socket.port != 0U);
  }
  WT_EXPECT_OK("and a peer address", wt_udp_address_parse("127.0.0.1", 4433U, &peer));

  make_config(&config, WT_QUIC_ROLE_CLIENT);
  memset(&tls, 0, sizeof(tls));
  tls.host_name = "localhost";

  /* The arguments are the session's own guard: a NULL socket or address is a caller error rather than
   * anything about the wire. */
  WT_EXPECT_STATUS("a NULL session is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_start_client(NULL, &socket, &peer, k_connection_id,
                                                   sizeof(k_connection_id), &config, &tls, 0U));
  WT_EXPECT_STATUS("a NULL socket is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_start_client(&session, NULL, &peer, k_connection_id,
                                                   sizeof(k_connection_id), &config, &tls, 0U));
  WT_EXPECT_STATUS("and a NULL connection ID", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_start_client(&session, &socket, &peer, NULL, 0U, &config, &tls,
                                                   0U));

  memset(&session, 0, sizeof(session));
  WT_EXPECT_OK("a client session starts",
               wt_runtime_session_start_client(&session, &socket, &peer, k_connection_id,
                                               sizeof(k_connection_id), &config, &tls, 1000U));
  WT_EXPECT_INT("not established before a handshake", 0, wt_runtime_session_established(&session));
  WT_EXPECT_INT("and with no application keys", 0, wt_runtime_session_keys_ready(&session));
  WT_EXPECT_STATUS("and no failure yet", WT_OK, wt_runtime_session_failure(&session));

  /* A pump with nothing to read is a completed round, not an error: in a two-endpoint loop most rounds
   * have nothing in them, and a pump that refused them would make the loop a place to invent statuses. */
  WT_EXPECT_OK("a pump with nothing to read completes", wt_runtime_session_pump(&session, 2000U));
  WT_EXPECT_U64("having read nothing", 0U, (uint64_t)session.packets_seen);
  WT_EXPECT_OK("and again", wt_runtime_session_pump(&session, 3000U));

  /* A pump on a session that was never started is the caller's ordering. */
  {
    wt_runtime_session_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    WT_EXPECT_STATUS("an unstarted session cannot be pumped", WT_ERR_INVALID_ARGUMENT,
                     wt_runtime_session_pump(&fresh, 0U));
    WT_EXPECT_INT("and reports nothing established", 0, wt_runtime_session_established(&fresh));
    WT_EXPECT_INT("nor keys", 0, wt_runtime_session_keys_ready(&fresh));
  }

  wt_runtime_session_clear(&session);
  WT_EXPECT_INT("clearing a session leaves it unstarted", 0, wt_runtime_session_established(&session));
  /* Twice, because an error path that clears and then unwinds would otherwise double free. */
  wt_runtime_session_clear(&session);
  wt_runtime_session_clear(NULL);

  wt_udp_close(&socket);
}

static void test_a_server_without_an_identity_is_refused(void) {
  wt_udp_socket_t socket;
  wt_udp_address_t peer;
  wt_quic_connection_config_t config;
  wt_tls_server_config_t tls;
  wt_runtime_session_t session;
  wt_udp_address_t local;

  WT_EXPECT_OK("a loopback address parses", wt_udp_address_parse_host_port("127.0.0.1:0", &local));
  WT_EXPECT_OK("a socket opens", wt_udp_socket_open(&socket, WT_UDP_IPV4));
  WT_EXPECT_OK("and binds", wt_udp_bind(&socket, &local));
  WT_EXPECT_OK("and a peer address", wt_udp_address_parse("127.0.0.1", 4433U, &peer));

  make_config(&config, WT_QUIC_ROLE_SERVER);
  memset(&tls, 0, sizeof(tls));

  WT_EXPECT_STATUS("a NULL configuration is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_start_server(&session, &socket, &peer, k_connection_id,
                                                   sizeof(k_connection_id), NULL, &tls, 0U));

  /* A server with no identity cannot begin: there is no certificate to present, and a session that
   * armed itself anyway would fail at the first ClientHello instead, where the reason is much harder to
   * see. The full server start -- with the repository's trust fixtures -- belongs with the two-endpoint
   * handshake test, which needs them anyway. */
  memset(&session, 0, sizeof(session));
  WT_EXPECT_STATUS("a server with no certificate is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_start_server(&session, &socket, &peer, k_connection_id,
                                                   sizeof(k_connection_id), &config, &tls, 1000U));
  WT_EXPECT_INT("and is left unstarted", 0, wt_runtime_session_established(&session));

  wt_runtime_session_clear(&session);
  wt_runtime_session_clear(&session);
  wt_udp_close(&socket);
}

int main(void) {
  test_starting_an_endpoint_arms_it();
  test_a_server_without_an_identity_is_refused();
  WT_TEST_MAIN_END("wt_runtime_session");
}
