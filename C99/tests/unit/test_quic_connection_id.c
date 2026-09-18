/* QUIC connection ID storage and retirement (RFC 9000 sections 5.1 and 10.2).
 *
 * The three rules that matter, each tested at its boundary:
 *
 *   - an endpoint may not provide more connection IDs than the peer's
 *     active_connection_id_limit allows (section 5.1.1);
 *   - receiving more than this endpoint advertised is a
 *     CONNECTION_ID_LIMIT_ERROR, which is the code the peer is told;
 *   - retiring a sequence the endpoint never issued is a PROTOCOL_VIOLATION
 *     (section 19.16).
 *
 * The sequence number is the identity and not the bytes, so a test that matched
 * by bytes would pass while the store attributed packets to the wrong
 * connection. The byte lookup is checked separately for the receive path, and
 * it is checked to distinguish a retired ID from one that never existed -- the
 * two need different answers, because a packet on a retired ID belongs to the
 * connection and must be refused rather than dropped as unknown.
 */

#include "wt_test.h"

#include "webtransport/quic/connection_id.h"

static void fill(uint8_t *out, size_t length, uint8_t seed) {
  size_t i;
  for (i = 0U; i < length; i++)
    out[i] = (uint8_t)(seed + i);
}

int main(void) {
  wt_quic_connection_id_store_t store;
  wt_quic_error_t error = 0U;
  uint8_t id[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  uint64_t sequence = 0U;
  size_t index = 0U;
  int retired = 0;
  size_t i;

  /* A store with the peer allowing four and this endpoint advertising eight. */
  WT_EXPECT_STATUS("the store initialises", WT_OK,
                   wt_quic_connection_ids_init(&store, 4U, WT_QUIC_CONNECTION_ID_LIMIT));
  WT_EXPECT_U64("with the peer's limit", 4U, store.peer_limit);
  WT_EXPECT_U64("and this endpoint's", WT_QUIC_CONNECTION_ID_LIMIT, store.local_limit);
  WT_EXPECT_U64("nothing is active", 0U, (uint64_t)wt_quic_connection_ids_active(&store));
  WT_EXPECT_U64("and four are issueable", 4U, wt_quic_connection_ids_issueable(&store));

  /* A limit below two is raised to two rather than accepted: RFC 9000 section
   * 18.2 requires at least two, and an endpoint that allowed itself one could
   * not migrate. */
  {
    wt_quic_connection_id_store_t small;
    WT_EXPECT_STATUS("a limit below two initialises", WT_OK,
                     wt_quic_connection_ids_init(&small, 1U, 1U));
    WT_EXPECT_U64("with the peer's limit raised", 2U, small.peer_limit);
    WT_EXPECT_U64("and this endpoint's", 2U, small.local_limit);
  }

  /* Issue IDs until the peer's limit stops it. */
  fill(id, 8U, 1U);
  for (i = 0U; i < 4U; i++) {
    fill(id, 8U, (uint8_t)(1U + i));
    WT_EXPECT_STATUS("an issued ID is added", WT_OK,
                     wt_quic_connection_ids_add_issued(&store, id, 8U, &sequence));
    WT_EXPECT_U64("with the next sequence", (uint64_t)i, sequence);
  }
  WT_EXPECT_U64("four are active", 4U, (uint64_t)wt_quic_connection_ids_active(&store));
  WT_EXPECT_U64("and none are issueable", 0U, wt_quic_connection_ids_issueable(&store));
  fill(id, 8U, 9U);
  WT_EXPECT_STATUS("a fifth is refused by the peer's limit", WT_ERR_LIMIT,
                   wt_quic_connection_ids_add_issued(&store, id, 8U, &sequence));
  WT_EXPECT_U64("and the count did not move", 4U, (uint64_t)wt_quic_connection_ids_active(&store));

  /* Retiring one frees a slot in the peer's limit, because section 5.1.1 counts
   * what the endpoint is currently providing. */
  WT_EXPECT_STATUS("retiring sequence 0", WT_OK, wt_quic_connection_ids_retire(&store, 0U, &error));
  WT_EXPECT_U64("leaves three active", 3U, (uint64_t)wt_quic_connection_ids_active(&store));
  WT_EXPECT_U64("and one issueable", 1U, wt_quic_connection_ids_issueable(&store));
  fill(id, 8U, 9U);
  WT_EXPECT_STATUS("so a new ID can be issued", WT_OK,
                   wt_quic_connection_ids_add_issued(&store, id, 8U, &sequence));
  WT_EXPECT_U64("with the next sequence", 4U, sequence);

  /* Retiring a sequence at or above the next one is a PROTOCOL_VIOLATION: the
   * endpoint never issued it. */
  error = 0U;
  WT_EXPECT_STATUS("retiring an unissued sequence is refused", WT_ERR_PROTOCOL,
                   wt_quic_connection_ids_retire(&store, 5U, &error));
  WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);
  error = 0U;
  WT_EXPECT_STATUS("retiring the next sequence is refused", WT_ERR_PROTOCOL,
                   wt_quic_connection_ids_retire(&store, 5U, &error));

  /* The receive path: a packet's connection ID is matched against what was
   * issued, and a retired ID is reported as retired rather than as unknown. */
  {
    uint8_t issued[8];
    fill(issued, 8U, 2U); /* the ID with sequence 1 */
    WT_EXPECT_STATUS("an issued ID is found", WT_OK,
                     wt_quic_connection_ids_find(&store, issued, 8U, &index, &retired));
    WT_EXPECT_U64("at its index", 1U, (uint64_t)index);
    WT_EXPECT_INT("and it is not retired", 0, retired);

    fill(issued, 8U, 1U); /* sequence 0, retired above */
    WT_EXPECT_STATUS("a retired ID is still found", WT_OK,
                     wt_quic_connection_ids_find(&store, issued, 8U, &index, &retired));
    WT_EXPECT_INT("and is reported as retired", 1, retired);

    fill(issued, 8U, 0xEEU);
    WT_EXPECT_STATUS("an unknown ID is not found", WT_ERR_CLOSED,
                     wt_quic_connection_ids_find(&store, issued, 8U, &index, &retired));
    /* A zero-length ID is a legitimate connection ID, and it must not match
     * every zero-length query by accident. */
    WT_EXPECT_STATUS("a zero-length ID is not found here", WT_ERR_CLOSED,
                     wt_quic_connection_ids_find(&store, NULL, 0U, &index, &retired));
  }

  /* A peer's NEW_CONNECTION_ID, including retire_prior_to. */
  {
    wt_quic_connection_id_store_t peer;
    wt_quic_connection_id_store_t limit;
    WT_EXPECT_STATUS("a peer store initialises", WT_OK, wt_quic_connection_ids_init(&peer, 8U, 4U));

    fill(id, 6U, 0x10U);
    WT_EXPECT_STATUS("a peer ID is added", WT_OK,
                     wt_quic_connection_ids_add_peer(&peer, 3U, 0U, id, 6U, &error));
    WT_EXPECT_U64("it is active", 1U, (uint64_t)wt_quic_connection_ids_active(&peer));
    /* The same sequence again is not a duplicate error: a peer may repeat a
     * frame, and the store already has it. */
    WT_EXPECT_STATUS("the same sequence again is accepted", WT_OK,
                     wt_quic_connection_ids_add_peer(&peer, 3U, 0U, id, 6U, &error));
    WT_EXPECT_U64("and does not add a second entry", 1U,
                  (uint64_t)wt_quic_connection_ids_active(&peer));

    /* retire_prior_to of 3 retires everything below it, including nothing here;
     * a later one for sequence 5 with retire_prior_to 4 retires the entry at 3. */
    fill(id, 6U, 0x20U);
    WT_EXPECT_STATUS("a peer ID with retire_prior_to", WT_OK,
                     wt_quic_connection_ids_add_peer(&peer, 5U, 4U, id, 6U, &error));
    WT_EXPECT_U64("retires what is below it", 1U, (uint64_t)wt_quic_connection_ids_active(&peer));

    /* More than this endpoint advertised is a CONNECTION_ID_LIMIT_ERROR: the
     * store advertised four. */
    for (i = 0U; i < 8U; i++) {
      fill(id, 6U, (uint8_t)(0x30U + i));
      (void)wt_quic_connection_ids_add_peer(&peer, 10U + i, 0U, id, 6U, &error);
    }
    WT_EXPECT_TRUE("the store never holds more than it advertised",
                   wt_quic_connection_ids_active(&peer) <= 4U);
    error = 0U;
    fill(id, 6U, 0x40U);
    (void)wt_quic_connection_ids_add_peer(&peer, 100U, 0U, id, 6U, &error);
    WT_EXPECT_U64("and reports the connection ID limit error", WT_QUIC_CONNECTION_ID_LIMIT_ERROR,
                  error);

    /* A retire_prior_to above the sequence is a frame encoding error, refused
     * here as well as by the frame parser. */
    error = 0U;
    WT_EXPECT_STATUS("retire_prior_to above the sequence is refused", WT_ERR_PROTOCOL,
                     wt_quic_connection_ids_add_peer(&peer, 1U, 2U, id, 6U, &error));
    WT_EXPECT_U64("  as a frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);

    /* A connection ID above twenty bytes. */
    {
      uint8_t long_id[21];
      fill(long_id, sizeof(long_id), 1U);
      error = 0U;
      WT_EXPECT_STATUS(
          "a 21-byte connection ID is refused", WT_ERR_PROTOCOL,
          wt_quic_connection_ids_add_peer(&limit, 0U, 0U, long_id, sizeof(long_id), &error));
      WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);
    }

    /* A store whose local limit is larger than the array still stops at the
     * array: the bound is this implementation's, not the peer's. */
    {
      wt_quic_connection_id_store_t big;
      size_t added = 0U;
      (void)wt_quic_connection_ids_init(&big, 1000U, 1000U);
      for (i = 0U; i < 64U; i++) {
        fill(id, 4U, (uint8_t)i);
        if (wt_quic_connection_ids_add_peer(&big, i, 0U, id, 4U, &error) != WT_OK) {
          break;
        }
        added++;
      }
      WT_EXPECT_U64("the array bound stops it", WT_QUIC_CONNECTION_ID_LIMIT, (uint64_t)added);
    }
  }

  /* Refusals on the store's own arguments. */
  WT_EXPECT_STATUS("a NULL store is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_ids_init(NULL, 2U, 2U));
  WT_EXPECT_STATUS("adding an over-long issued ID is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_ids_add_issued(&store, id, 21U, &sequence));
  WT_EXPECT_STATUS("adding NULL bytes is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_ids_add_issued(&store, NULL, 4U, &sequence));
  WT_EXPECT_STATUS("retiring on a NULL store is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_ids_retire(NULL, 0U, &error));
  WT_EXPECT_STATUS("finding on a NULL store is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_ids_find(NULL, id, 4U, &index, &retired));
  WT_EXPECT_STATUS("finding with a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_connection_ids_find(&store, id, 4U, NULL, &retired));
  WT_EXPECT_U64("an empty store has nothing active", 0U,
                (uint64_t)wt_quic_connection_ids_active(NULL));
  WT_EXPECT_U64("and nothing issueable", 0U, wt_quic_connection_ids_issueable(NULL));

  /* A zero-length connection ID is a legitimate configuration: RFC 9000 section
   * 5.1 says an endpoint may use one, and it must be storable and findable. */
  {
    wt_quic_connection_id_store_t zero;
    WT_EXPECT_STATUS("a store with a zero-length ID initialises", WT_OK,
                     wt_quic_connection_ids_init(&zero, 2U, 2U));
    WT_EXPECT_STATUS("a zero-length issued ID is added", WT_OK,
                     wt_quic_connection_ids_add_issued(&zero, NULL, 0U, &sequence));
    WT_EXPECT_STATUS("and is found by its empty bytes", WT_OK,
                     wt_quic_connection_ids_find(&zero, NULL, 0U, &index, &retired));
    WT_EXPECT_U64("at index 0", 0U, (uint64_t)index);
    WT_EXPECT_INT("and not retired", 0, retired);
  }

  WT_TEST_MAIN_END("wt_quic_connection_id");
}
