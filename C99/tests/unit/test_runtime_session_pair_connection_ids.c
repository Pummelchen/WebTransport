/* Connection ID retirement: the replacement and the rate limit on a retire flood (WT-171, WT-173). */

#include "test_runtime_session_pair_internal.h"

/* WT-171: a connection ID the peer RETIRES is REPLACED rather than only given up.
 *
 * RFC 9000 section 5.1.2 makes a RETIRE_CONNECTION_ID a REQUEST -- "requests that the peer replace it with a new
 * connection ID" -- and section 5.1.1 sizes the spare: the peer's `active_connection_id_limit` counts the
 * connection ID the handshake used, so the default of two allows exactly one. Before this round nothing in the
 * tree ever issued a spare, so a peer that retired one was talking to an endpoint that would run out; the seam it
 * had to go through was the frame handler, which is where the retire arrives.
 *
 * The pair is asymmetric on purpose: only the SERVER keeps a spare, so the one ID the client stores below can
 * only have come from the server's new policy. */
static int peer_has_a_spare(const pair_t *pair) {
  return pair->client.connection.peer_id_count > 0U;
}

static int peer_has_a_replacement(const pair_t *pair) {
  size_t i;

  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (pair->client.connection.peer_ids[i].in_use &&
        pair->client.connection.peer_ids[i].sequence > 1U) {
      return 1;
    }
  }
  return 0;
}

void test_a_retired_connection_id_is_replaced(void) {
  pair_t pair;
  uint64_t spare_sequence = 0U;
  size_t i;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  WT_EXPECT_OK("the server keeps a spare connection ID",
               wt_runtime_session_keep_spare_connection_id(&pair.server));
  WT_EXPECT_U64("and has issued none yet", 0U, (uint64_t)pair.server.spare_ids_issued);

  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);

  /* The spare goes out once the handshake has given this endpoint 1-RTT keys and the peer's limit is known --
   * `active_connection_id_limit` is 2 in the parameters this pair advertises, so exactly one spare is allowed. */
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("the spare reaches the client", rounds < 100U);
  WT_EXPECT_U64("the server counted it once", 1U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("and refused nothing", 0U, (uint64_t)pair.server.spare_id_refusals);
  WT_EXPECT_U64("the client holds one connection ID from the peer", 1U,
                (uint64_t)pair.client.connection.peer_id_count);
  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (pair.client.connection.peer_ids[i].in_use) {
      spare_sequence = pair.client.connection.peer_ids[i].sequence;
    }
  }
  WT_EXPECT_U64("which is the sequence the server issued", 1U, spare_sequence);

  /* The client retires it, which is the request the replacement answers. Through the CONNECTION's own call, not
   * a hand-built frame: the frame and the forgetting are one act, and a caller that sent the frame alone would
   * leave this layer's table holding an ID the peer counts as gone -- which the first version of this test did,
   * and the peer's replacement was then refused with CONNECTION_ID_LIMIT_ERROR (WT-171's second finding). */
  WT_EXPECT_OK("the client retires the spare",
               wt_quic_connection_retire_peer_connection_id(&pair.client.connection, spare_sequence,
                                                            pair.now));
  WT_EXPECT_STATUS("and cannot retire an ID it does not have", WT_ERR_STATE,
                   wt_quic_connection_retire_peer_connection_id(&pair.client.connection,
                                                                spare_sequence, pair.now));

  rounds = pump_pair(&pair, 100U, peer_has_a_replacement);
  WT_EXPECT_TRUE("a replacement arrives", rounds < 100U);
  WT_EXPECT_U64("so the server has issued twice", 2U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("and still holds exactly one spare", 1U,
                (uint64_t)pair.server.connection.issued_count);
  WT_EXPECT_U64("with the sequence it has not used yet", 3U,
                pair.server.connection.next_issued_sequence);
  WT_EXPECT_U64("the client holds one ID again", 1U,
                (uint64_t)pair.client.connection.peer_id_count);
  WT_EXPECT_U64("and it retired the one it gave up", 1U,
                wt_quic_connection_peer_ids_retired(&pair.client.connection));
  /* Both CLOSED assertions, not just the handshake's status: `wt_runtime_session_failure` reports the TLS
   * handshake alone, so it says WT_OK for a connection the transport has closed -- which is how the first version
   * of this test passed its "did not close" line while the client was in fact closing with
   * CONNECTION_ID_LIMIT_ERROR (WT-171's second finding, and the reason the peer's code is checked below). */
  WT_EXPECT_STATUS("the server did not fail its handshake", WT_OK,
                   wt_runtime_session_failure(&pair.server));
  WT_EXPECT_INT("and is still open", 0, wt_quic_connection_is_closed(&pair.server.connection));
  WT_EXPECT_INT("so is the client", 0, wt_quic_connection_is_closed(&pair.client.connection));
  WT_EXPECT_INT("with no close received on either side", 0,
                pair.client.connection.peer_closed + pair.server.connection.peer_closed);
  WT_EXPECT_U64("and neither refused a packet", 0U,
                (uint64_t)(pair.client.receive_errors + pair.server.receive_errors));

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}

/* WT-173: a peer that retires every connection ID it is given must not be able to make this endpoint issue one
 * per round trip for the life of the connection. Each NEW_CONNECTION_ID is a frame the peer pays nothing for, and
 * RFC 9000 section 5.1.2 makes a retire a REQUEST for another -- so an endpoint that always answers is an
 * amplifier with the peer holding the trigger.
 *
 * The policy is a rate limit with the FIRST replacement free, because a peer that retires a spare once is doing
 * exactly what the section recommends: a bound that refused that would break the flow the policy exists to serve.
 * What is asserted here is both halves -- the first replacement arrives at once, the second is refused and COUNTED,
 * and after the interval the endpoint answers again, so a peer that retires slowly is never cut off. */
void test_a_retire_flood_is_rate_limited(void) {
  pair_t pair;
  uint64_t now;
  unsigned rounds;

  memset(&pair, 0, sizeof(pair));
  arm_pair(&pair);
  WT_EXPECT_OK("the server keeps a spare connection ID",
               wt_runtime_session_keep_spare_connection_id(&pair.server));
  rounds = pump_pair(&pair, 400U, both_established);
  WT_EXPECT_TRUE("the handshake completes", rounds < 400U);
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("and the first spare arrives", rounds < 100U);
  WT_EXPECT_U64("which is not a replacement", 0U, (uint64_t)pair.server.spare_ids_replaced);

  /* The first replacement, at once, because section 5.1.2 asks for it. */
  WT_EXPECT_OK("the client retires it",
               wt_quic_connection_retire_peer_connection_id(&pair.client.connection, 1U, pair.now));
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("and the replacement arrives", rounds < 100U);
  WT_EXPECT_U64("as the first replacement", 1U, (uint64_t)pair.server.spare_ids_replaced);
  WT_EXPECT_U64("with nothing rate limited yet", 0U, (uint64_t)pair.server.spare_ids_rate_limited);

  /* The second, immediately after: refused by the bound. The client is left with NO spare, which is the price of
   * the bound -- and it is the peer's own doing, not something this endpoint owes it. */
  now = pair.now;
  WT_EXPECT_OK("the client retires the replacement",
               wt_quic_connection_retire_peer_connection_id(&pair.client.connection, 2U, now));
  (void)pump_pair(&pair, 30U, peer_has_a_spare);
  WT_EXPECT_U64("no second replacement is issued", 2U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("because the rate limit refused it", 1U,
                (uint64_t)pair.server.spare_ids_rate_limited);
  WT_EXPECT_U64("leaving the client with none", 0U, (uint64_t)pair.client.connection.peer_id_count);

  /* And past the interval the endpoint answers again: a peer that retires slowly is never cut off. */
  pair.now += WT_RUNTIME_SPARE_ID_INTERVAL + 1000U;
  rounds = pump_pair(&pair, 100U, peer_has_a_spare);
  WT_EXPECT_TRUE("a later retire is answered again", rounds < 100U);
  WT_EXPECT_U64("with a third ID issued", 3U, (uint64_t)pair.server.spare_ids_issued);
  WT_EXPECT_U64("a second replacement", 2U, (uint64_t)pair.server.spare_ids_replaced);
  WT_EXPECT_U64("and still exactly one rate-limited refusal", 1U,
                (uint64_t)pair.server.spare_ids_rate_limited);
  WT_EXPECT_STATUS("with neither side closed", WT_OK, wt_runtime_session_failure(&pair.client));
  WT_EXPECT_INT("nor by the transport", 0, wt_quic_connection_is_closed(&pair.server.connection));

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
}
