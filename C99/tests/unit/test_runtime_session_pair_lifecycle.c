/* Shutdown, cancellation and a peer that closes (WT-178, WT-147). */

#include "test_runtime_session_pair_internal.h"

/* SHUTDOWN AND CANCELLATION (WT-178). The Swift suite tests its server's shutdown path from the operator's point
 * of view -- refuse at once, return promptly with nothing served, and survive being run twice -- and those
 * assertions are about a server object this tree does not have. What they are about BEHAVIOURALLY is the release
 * path every layer has, and that is `wt_runtime_session_clear`: it must be safe twice, safe before anything
 * began, safe in the middle of a handshake, and it must leave the struct ready to start again. Each of those is
 * a property an ASan run checks for free and a reader cannot check at all.
 */

/* A zeroed session, which is what a caller that never started one has. */
void test_clearing_a_session_that_never_started_is_safe(void) {
  wt_runtime_session_t session;

  memset(&session, 0, sizeof(session));
  wt_runtime_session_clear(&session);
  wt_runtime_session_clear(&session);
  /* The accessors are part of the contract too: a report written after a shutdown must not read a released
   * pointer. `failure` and `keys_ready` both look at state a cleared session has none of. */
  WT_EXPECT_STATUS("a cleared session has no failure", WT_OK, wt_runtime_session_failure(&session));
  WT_EXPECT_INT("and is not established", 0, wt_runtime_session_established(&session));
  WT_EXPECT_INT("and holds no application keys", 0, wt_runtime_session_keys_ready(&session));
  WT_EXPECT_STATUS("and a null session is a no-op", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_session_failure(NULL));
  wt_runtime_session_clear(NULL);
}

void test_a_session_survives_being_cleared_twice_and_can_start_again(void) {
  pair_t pair;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  WT_EXPECT_INT("with application keys on the client", 1,
                wt_runtime_session_keys_ready(&pair.client));

  /* Twice, on a live session: the second call is the one a signal handler and a deployment script both reach. */
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_runtime_session_clear(&pair.server);
  WT_EXPECT_INT("a cleared session holds no application keys", 0,
                wt_runtime_session_keys_ready(&pair.client));
  WT_EXPECT_INT("and is not established", 0, wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("nor is the peer's", 0, wt_runtime_session_established(&pair.server));

  /* And the SAME struct starts again: every start zeroes it first, so a caller reusing one does not have to
   * clear it between tries -- which is what makes a retry loop possible at all. The sockets are the caller's and
   * are reused here, which is also why the client drains them: a datagram left by the abandoned attempt is the
   * next session's problem otherwise, and the contract says so. */
  {
    uint8_t stale[WT_UDP_MAX_DATAGRAM];
    size_t stale_length = 0U;
    while (wt_udp_receive(&pair.client_socket, stale, sizeof(stale), &stale_length, NULL) ==
           WT_OK) {
      /* discarded */
    }
    while (wt_udp_receive(&pair.server_socket, stale, sizeof(stale), &stale_length, NULL) ==
           WT_OK) {
      /* discarded */
    }
  }
  memset(&pair.client, 0, sizeof(pair.client));
  memset(&pair.server, 0, sizeof(pair.server));
  pair.now += 1000U;
  WT_EXPECT_OK("the client starts again on the same struct",
               wt_runtime_session_start_client(
                   &pair.client, &pair.client_socket, &pair.server_address, k_connection_id,
                   sizeof(k_connection_id), &pair.client_connection, &pair.client_tls, pair.now));
  WT_EXPECT_OK("and so does the server",
               wt_runtime_session_start_server(
                   &pair.server, &pair.server_socket, &pair.client_address, k_connection_id,
                   sizeof(k_connection_id), &pair.server_connection, &pair.server_tls, pair.now));
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("and a second handshake completes on them", rounds < 400U);
  WT_EXPECT_INT("with keys again", 1, wt_runtime_session_keys_ready(&pair.client));

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* Cancelling in the MIDDLE of a handshake, which is the case a caller reaches by giving up on a slow peer: the
 * session is cleared while the TLS machine is between flights, and nothing may be left dangling. */
void test_cancelling_a_handshake_is_safe(void) {
  pair_t pair;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  (void)pump_pair(&pair, 3U, both_established); /* a few rounds: mid-handshake, not established */
  WT_EXPECT_INT("the handshake did not finish in three rounds", 0,
                wt_runtime_session_established(&pair.client));
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  WT_EXPECT_INT("the cancelled client is not established", 0,
                wt_runtime_session_established(&pair.client));
  WT_EXPECT_INT("and holds no keys", 0, wt_runtime_session_keys_ready(&pair.client));
  /* The protocol contract: clearing releases the SESSION, it does not close the connection or tell the peer.
   * A caller that wants the peer told closes first -- and this assertion is what keeps the difference honest. */
  WT_EXPECT_INT("while the connection itself is not closed", 0,
                wt_quic_connection_is_closed(&pair.client.connection));
  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* And the other direction of cancellation: the PEER closes while this endpoint is waiting for it. The wait used
 * to run to its deadline and report a timeout (WT-147 found that); what this asserts is the pair of facts a
 * caller acts on -- the close is SEEN (the peer's code is readable) and it is seen WITHOUT waiting out the clock.
 */
void test_a_peer_that_closes_is_noticed_without_waiting_the_clock(void) {
  pair_t pair;
  unsigned rounds;
  uint64_t deadline;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  WT_EXPECT_OK("the server closes the connection",
               wt_quic_connection_close(&pair.server.connection, WT_QUIC_NO_ERROR, 0U,
                                        (const uint8_t *)"done", 4U, pair.now));
  WT_EXPECT_OK("and sends it", wt_runtime_session_pump(&pair.server, pair.now));

  /* The client's next rounds must SEE it. Ten rounds is a millisecond of pact time and far short of the five
   * second timeout the header documents, so a client that waited for its deadline would fail this. */
  deadline = pair.now + 10000U;
  for (rounds = 0U; rounds < 50U && pair.client.connection.peer_closed == 0; rounds++) {
    (void)wt_udp_wait(&pair.client_socket, 2000U);
    (void)wt_runtime_session_pump(&pair.client, pair.now);
    pair.now += 1000U;
  }
  WT_EXPECT_INT("the client sees the peer's close", 1, pair.client.connection.peer_closed);
  WT_EXPECT_TRUE("without waiting out its clock", pair.now < deadline);
  WT_EXPECT_U64("and the code the peer sent is readable", 0U,
                (uint64_t)pair.client.connection.peer_error_code);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}
