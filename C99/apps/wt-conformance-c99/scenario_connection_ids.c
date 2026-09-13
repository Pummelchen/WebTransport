/* WT-171 over a real connection: a connection ID the peer retires is replaced (see the header). */

#include "scenario_connection_ids.h"

#include <stdio.h>
#include <string.h>

#include "scenario_pair.h"

/* The lowest sequence the side holds that is above `floor`, or 0 when it holds none. The connection's IDs are the
 * only state this scenario reads, and it reads them through the public struct because that is where the library
 * keeps them: a second accessor for a test's convenience would be a second thing to keep in step. */
static uint64_t held_sequence_above(const wt_quic_connection_t *connection, uint64_t floor) {
  uint64_t best = 0U;
  size_t i;

  for (i = 0U; i < WT_QUIC_PEER_CONNECTION_IDS_MAX; i++) {
    if (!connection->peer_ids[i].in_use) continue;
    if (connection->peer_ids[i].sequence <= floor) continue;
    if (best == 0U || connection->peer_ids[i].sequence < best) best = connection->peer_ids[i].sequence;
  }
  return best;
}

static uint64_t held_sequence(const wt_quic_connection_t *connection) {
  return held_sequence_above(connection, 0U);
}

wt_cli_result_t wt_scenario_connection_ids_run(int ipv6, char *detail, size_t detail_size) {
  scenario_pair_t pair;
  uint64_t retired = 0U;
  uint64_t replacement = 0U;
  unsigned round;

  {
    wt_cli_result_t opened = scenario_pair_open(&pair, ipv6, detail, detail_size);
    if (opened != WT_CLI_RESULT_PASSED) return opened;
  }

  /* What the tools do: both endpoints keep one spare connection ID issued. The peer's
   * `active_connection_id_limit` is two in this pair's parameters, and it COUNTS the handshake's ID, so exactly
   * one spare is allowed per side. */
  if (wt_runtime_session_keep_spare_connection_id(&pair.server) != WT_OK ||
      wt_runtime_session_keep_spare_connection_id(&pair.client) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the spare-connection-id policy could not be armed");
    scenario_pair_close(&pair);
    return WT_CLI_RESULT_FAILED;
  }

  /* The spares cross. The pair is already handshaken, so this needs only the rounds in which the sessions have
   * 1-RTT keys and can put a NEW_CONNECTION_ID on the wire. */
  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    if (pair.client.connection.peer_id_count > 0U && pair.server.connection.peer_id_count > 0U) break;
    scenario_pump_once(&pair);
  }
  if (pair.client.connection.peer_id_count == 0U || pair.server.connection.peer_id_count == 0U) {
    scenario_detail_set(detail, detail_size, "a spare connection ID did not reach its peer");
    scenario_pair_close(&pair);
    return WT_CLI_RESULT_FAILED;
  }
  retired = held_sequence(&pair.client.connection);
  if (retired == 0U || pair.server.spare_ids_issued != 1U) {
    scenario_detail_set(detail, detail_size, "the server did not issue exactly one spare");
    scenario_pair_close(&pair);
    return WT_CLI_RESULT_FAILED;
  }

  /* The retire: the client gives up the ID the server issued, which RFC 9000 section 5.1.2 makes a REQUEST for
   * another one. Through the connection's own call, because the frame and the forgetting are one act. */
  if (wt_quic_connection_retire_peer_connection_id(&pair.client.connection, retired, pair.now) != WT_OK) {
    scenario_detail_set(detail, detail_size, "the client could not retire the spare");
    scenario_pair_close(&pair);
    return WT_CLI_RESULT_FAILED;
  }

  for (round = 0U; round < WT_SCENARIO_TIMEOUT_ROUNDS; round++) {
    replacement = held_sequence_above(&pair.client.connection, retired);
    if (replacement != 0U) break;
    scenario_pump_once(&pair);
  }
  replacement = held_sequence_above(&pair.client.connection, retired);

  if (replacement == 0U || pair.server.spare_ids_issued != 2U) {
    scenario_detail_set(detail, detail_size, "the retired connection ID was not replaced");
    scenario_pair_close(&pair);
    return WT_CLI_RESULT_FAILED;
  }
  if (wt_quic_connection_is_closed(&pair.client.connection) != 0 ||
      wt_quic_connection_is_closed(&pair.server.connection) != 0 ||
      pair.client.connection.peer_closed != 0 || pair.server.connection.peer_closed != 0) {
    scenario_detail_set(detail, detail_size, "a connection closed over the retire and its replacement");
    scenario_pair_close(&pair);
    return WT_CLI_RESULT_FAILED;
  }

  (void)snprintf(detail, detail_size,
                 "the client retired sequence %llu, the server replaced it with %llu, and both sides stayed up",
                 (unsigned long long)retired, (unsigned long long)replacement);
  scenario_pair_close(&pair);
  return WT_CLI_RESULT_PASSED;
}
