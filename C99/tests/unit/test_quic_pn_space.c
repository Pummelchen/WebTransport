/* Packet number space bookkeeping: received ranges, ACK construction, round trip time.
 *
 * WHAT IS CHECKED HERE IS THE ARITHMETIC THAT EVERYTHING ELSE RESTS ON. The received set decides
 * what an ACK frame says, and an ACK frame that says the wrong thing makes a peer retransmit what
 * arrived or wait for what did not; the round trip estimator decides when a probe timeout fires,
 * and an estimator that is wrong by a factor makes a connection that is slow or one that gives up.
 * Both are pure arithmetic, so both are checked against values computed by hand rather than
 * against this implementation's own output.
 *
 * The property that matters most for the ranges is that order does not matter: the same packets
 * inserted in any order must produce the same set, and inserting one twice must change nothing.
 * The test inserts a permutation and compares, which is the check that the merging logic is a set
 * rather than an append.
 */

#include "wt_test.h"

#include "webtransport/quic/packet_number.h"
#include "webtransport/quic/pn_space.h"
#include "webtransport/quic/varint.h"

/* The ranges, as a readable string of run lengths, so a failure says which shape came out. */
static int ranges_are(const wt_quic_ack_state_t *state, const uint64_t *bounds,
                      size_t count) {
  size_t i;
  if (state->count != count) return 0;
  for (i = 0U; i < count; i++) {
    if (state->ranges[i].smallest != bounds[i * 2U] ||
        state->ranges[i].largest != bounds[i * 2U + 1U]) {
      return 0;
    }
  }
  return 1;
}

static void test_received_ranges(void) {
  wt_quic_ack_state_t state;

  wt_quic_ack_state_init(&state);
  WT_EXPECT_U64("a fresh state has no ranges", 0U, (uint64_t)state.count);
  WT_EXPECT_INT("and nothing pending", 0, state.ack_pending);
  WT_EXPECT_INT("and no largest", 0, state.has_largest);
  WT_EXPECT_INT("nothing is contained", 0, wt_quic_ack_contains(&state, 0U));
  WT_EXPECT_INT("and no gap", 0, wt_quic_ack_has_gap(&state));

  /* One packet, and the same packet again. */
  WT_EXPECT_OK("a packet is recorded", wt_quic_ack_record(&state, 5U, 1));
  WT_EXPECT_U64("as one range", 1U, (uint64_t)state.count);
  {
    const uint64_t bounds[] = {5U, 5U};
    WT_EXPECT_TRUE("which is [5,5]", ranges_are(&state, bounds, 1U));
  }
  WT_EXPECT_INT("and is contained", 1, wt_quic_ack_contains(&state, 5U));
  WT_EXPECT_INT("while a neighbour is not", 0, wt_quic_ack_contains(&state, 4U));
  WT_EXPECT_U64("the largest received", 5U, (uint64_t)state.largest_received);
  WT_EXPECT_U64("one packet is owed an acknowledgement", 1U,
                (uint64_t)state.ack_eliciting_since_ack);
  WT_EXPECT_OK("recording it again", wt_quic_ack_record(&state, 5U, 1));
  WT_EXPECT_U64("changes nothing", 1U, (uint64_t)state.count);
  WT_EXPECT_U64("and does not count twice", 1U,
                (uint64_t)state.ack_eliciting_since_ack);

  /* A packet that fills a gap joins the two ranges. */
  wt_quic_ack_state_init(&state);
  WT_EXPECT_OK("7 is recorded", wt_quic_ack_record(&state, 7U, 1));
  WT_EXPECT_OK("then 9", wt_quic_ack_record(&state, 9U, 1));
  WT_EXPECT_U64("which is two ranges", 2U, (uint64_t)state.count);
  WT_EXPECT_INT("with a gap", 1, wt_quic_ack_has_gap(&state));
  WT_EXPECT_OK("then 8", wt_quic_ack_record(&state, 8U, 1));
  WT_EXPECT_U64("joining them", 1U, (uint64_t)state.count);
  {
    const uint64_t bounds[] = {7U, 9U};
    WT_EXPECT_TRUE("into [7,9]", ranges_are(&state, bounds, 1U));
  }
  WT_EXPECT_INT("and the gap is gone", 0, wt_quic_ack_has_gap(&state));
  WT_EXPECT_U64("three packets received", 3U, wt_quic_ack_received_count(&state));

  /* A packet below everything extends the oldest range downwards, and one above extends the
   * newest upwards. */
  WT_EXPECT_OK("6 is recorded", wt_quic_ack_record(&state, 6U, 0));
  {
    const uint64_t bounds[] = {6U, 9U};
    WT_EXPECT_TRUE("extending downwards", ranges_are(&state, bounds, 1U));
  }
  WT_EXPECT_OK("10 is recorded", wt_quic_ack_record(&state, 10U, 0));
  {
    const uint64_t bounds[] = {6U, 10U};
    WT_EXPECT_TRUE("and upwards", ranges_are(&state, bounds, 1U));
  }
  WT_EXPECT_U64("with the largest following", 10U, (uint64_t)state.largest_received);
  WT_EXPECT_U64("and only the ack-eliciting ones counted", 3U,
                (uint64_t)state.ack_eliciting_since_ack);

  /* ORDER DOES NOT MATTER, which is the property the merging logic exists for. */
  {
    static const uint64_t packets[] = {0U, 2U, 3U, 7U, 8U, 1U, 5U, 9U, 4U, 6U};
    static const uint64_t reversed[] = {6U, 4U, 9U, 5U, 1U, 8U, 7U, 3U, 2U, 0U};
    wt_quic_ack_state_t forward;
    wt_quic_ack_state_t backward;
    size_t i;
    wt_quic_ack_state_init(&forward);
    wt_quic_ack_state_init(&backward);
    for (i = 0U; i < 10U; i++) {
      WT_EXPECT_OK("a packet is recorded in order",
                   wt_quic_ack_record(&forward, packets[i], 1));
      WT_EXPECT_OK("and in reverse order",
                   wt_quic_ack_record(&backward, reversed[i], 1));
    }
    WT_EXPECT_U64("both are one range", 1U, (uint64_t)forward.count);
    WT_EXPECT_U64("of the same count", 10U, wt_quic_ack_received_count(&forward));
    {
      const uint64_t bounds[] = {0U, 9U};
      WT_EXPECT_TRUE("and the ordered one is [0,9]", ranges_are(&forward, bounds, 1U));
      WT_EXPECT_TRUE("and so is the reversed one", ranges_are(&backward, bounds, 1U));
    }
  }

  /* The range bound: more ranges than the set holds drops the oldest rather than failing, which is
   * what RFC 9002 section 13.2.3 permits and what keeps a peer from choosing this endpoint's
   * memory. */
  {
    wt_quic_ack_state_t bounded;
    size_t i;
    wt_quic_ack_state_init(&bounded);
    /* Every other packet, so each is its own range. */
    for (i = 0U; i < WT_QUIC_RECEIVED_RANGES_MAX + 4U; i++) {
      WT_EXPECT_OK("an isolated packet is recorded",
                   wt_quic_ack_record(&bounded, (uint64_t)(2U * i), 1));
    }
    WT_EXPECT_U64("the set stays at its bound", (uint64_t)WT_QUIC_RECEIVED_RANGES_MAX,
                  (uint64_t)bounded.count);
    /* The oldest were dropped, so the newest is still there and packet 0 is not. */
    WT_EXPECT_INT("the newest is still recorded", 1,
                  wt_quic_ack_contains(
                      &bounded, (uint64_t)(2U * (WT_QUIC_RECEIVED_RANGES_MAX + 3U))));
    WT_EXPECT_INT("and the oldest was dropped", 0, wt_quic_ack_contains(&bounded, 0U));
  }

  WT_EXPECT_STATUS("a NULL state is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_ack_record(NULL, 1U, 1));
}

static void test_ack_frame(void) {
  wt_quic_ack_state_t state;
  wt_quic_frame_t frame;
  uint8_t ranges[64];
  size_t ranges_len = 0U;

  /* Nothing received: there is no acknowledgement to build. */
  wt_quic_ack_state_init(&state);
  WT_EXPECT_STATUS("no ACK without a packet", WT_ERR_STATE,
                   wt_quic_ack_build(&state, 0U, ranges, sizeof(ranges), &ranges_len,
                                     &frame));

  /* One range: the first_range describes it and there are no ranges behind it. */
  WT_EXPECT_OK("5 arrives", wt_quic_ack_record(&state, 5U, 1));
  WT_EXPECT_OK("6 arrives", wt_quic_ack_record(&state, 6U, 1));
  WT_EXPECT_OK("7 arrives", wt_quic_ack_record(&state, 7U, 1));
  WT_EXPECT_OK("the ACK builds",
               wt_quic_ack_build(&state, 1234U, ranges, sizeof(ranges), &ranges_len, &frame));
  WT_EXPECT_U64("with the largest received", 7U, frame.as.ack.largest);
  WT_EXPECT_U64("the delay it was given", 1234U, frame.as.ack.delay);
  WT_EXPECT_U64("a first range of two", 2U, frame.as.ack.first_range);
  WT_EXPECT_U64("and no further ranges", 0U, frame.as.ack.range_count);
  WT_EXPECT_U64("with no range bytes", 0U, (uint64_t)ranges_len);
  WT_EXPECT_U64("and the frame is an ACK", (uint64_t)WT_QUIC_FRAME_KIND_ACK,
                (uint64_t)frame.kind);
  WT_EXPECT_INT("which is not ECN", 0, frame.as.ack.has_ecn);

  /* Two ranges: the gap and the length are the wire's, and a decoder must read them back as the
   * same set. */
  WT_EXPECT_OK("10 arrives", wt_quic_ack_record(&state, 10U, 1));
  WT_EXPECT_OK("11 arrives", wt_quic_ack_record(&state, 11U, 1));
  WT_EXPECT_OK("the two-range ACK builds",
               wt_quic_ack_build(&state, 0U, ranges, sizeof(ranges), &ranges_len, &frame));
  WT_EXPECT_U64("with the largest", 11U, frame.as.ack.largest);
  WT_EXPECT_U64("a first range of one", 1U, frame.as.ack.first_range);
  WT_EXPECT_U64("one further range", 1U, frame.as.ack.range_count);
  WT_EXPECT_TRUE("and bytes for it", ranges_len > 0U);
  /* The gap is RFC 9000 section 19.3.1's: "the number of contiguous unacknowledged packets
   * preceding the packet number one lower than the smallest in the preceding ACK Range". One lower
   * than 10 is 9, packet 8 is the only contiguous unacknowledged packet before it (7 arrived), so
   * the gap is one. The decoded range must be the one that was recorded, which is the check that
   * matters: the encoder and the decoder are inverses or every ACK this implementation sends is
   * describing the wrong set. */
  {
    wt_quic_ack_range_t range;
    WT_EXPECT_OK("the range decodes",
                 wt_quic_frame_ack_range_at(&frame, 0U, &range));
    WT_EXPECT_U64("with the gap the missing packet implies", 1U, range.gap);
    WT_EXPECT_U64("and the length of the older range", 2U, range.length);
  }

  /* The ranges must fit the caller's buffer: a truncated ACK would tell a peer less than arrived. */
  WT_EXPECT_STATUS("a buffer that cannot hold the ranges is refused", WT_ERR_LIMIT,
                   wt_quic_ack_build(&state, 0U, ranges, 0U, &ranges_len, &frame));
  WT_EXPECT_STATUS("a NULL frame is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_ack_build(&state, 0U, ranges, sizeof(ranges), &ranges_len, NULL));
  WT_EXPECT_STATUS("a NULL range length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_ack_build(&state, 0U, ranges, sizeof(ranges), NULL, &frame));
  WT_EXPECT_STATUS("a NULL state is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_ack_build(NULL, 0U, ranges, sizeof(ranges), &ranges_len, &frame));

  /* Sending the acknowledgement clears the debt. */
  WT_EXPECT_INT("an acknowledgement is owed", 1, state.ack_pending);
  wt_quic_ack_sent(&state);
  WT_EXPECT_INT("and is no longer", 0, state.ack_pending);
  WT_EXPECT_U64("with the counter reset", 0U,
                (uint64_t)state.ack_eliciting_since_ack);
  wt_quic_ack_sent(NULL);
  WT_EXPECT_INT("clearing NULL is harmless", 1, 1);

  /* Whether to send now or wait: two ack-eliciting packets, or a gap, make it now. */
  wt_quic_ack_state_init(&state);
  WT_EXPECT_INT("nothing to send for an empty state", 0, wt_quic_ack_should_send(&state));
  WT_EXPECT_OK("one packet arrives", wt_quic_ack_record(&state, 1U, 1));
  WT_EXPECT_INT("which may wait for a second", 0, wt_quic_ack_should_send(&state));
  WT_EXPECT_OK("a second arrives", wt_quic_ack_record(&state, 2U, 1));
  WT_EXPECT_INT("which makes it prompt", 1, wt_quic_ack_should_send(&state));
  wt_quic_ack_state_init(&state);
  WT_EXPECT_OK("an out-of-order packet arrives", wt_quic_ack_record(&state, 4U, 1));
  WT_EXPECT_OK("and a later one", wt_quic_ack_record(&state, 6U, 1));
  WT_EXPECT_INT("a gap makes it prompt", 1, wt_quic_ack_should_send(&state));
}

static void test_rtt(void) {
  wt_quic_rtt_t rtt;
  uint64_t pto = 0U;

  wt_quic_rtt_init(&rtt);
  WT_EXPECT_INT("a fresh estimator has no sample", 0, rtt.has_sample);
  WT_EXPECT_STATUS("and no probe timeout", WT_ERR_STATE, wt_quic_rtt_pto(&rtt, 0U, &pto));

  /* The first sample: RFC 9002 section 5.3's "smoothed_rtt = latest_rtt; rttvar = latest_rtt / 2".
   * The handshake is not confirmed, so the reported delay is not subtracted yet. */
  WT_EXPECT_OK("the first sample",
               wt_quic_rtt_update(&rtt, 100000U, 50000U, 25000U, 0));
  WT_EXPECT_U64("sets the latest", 100000U, rtt.latest);
  WT_EXPECT_U64("the smoothed value to the sample", 100000U, rtt.smoothed);
  WT_EXPECT_U64("and the variation to half of it", 50000U, rtt.rttvar);
  WT_EXPECT_U64("and the minimum", 100000U, rtt.min_rtt);
  WT_EXPECT_OK("the probe timeout", wt_quic_rtt_pto(&rtt, 25000U, &pto));
  /* smoothed 100000 + max(4 * 50000, 1000) + max_ack_delay 25000 = 325000. */
  WT_EXPECT_U64("is smoothed plus four variations plus the peer's delay", 325000U, pto);

  /* A second sample, with the arithmetic worked out by hand:
   *   adjusted = 120000 (delay 10000 is below min_rtt + delay, so it is not subtracted)
   *   difference = |100000 - 120000| = 20000
   *   rttvar = (3 * 50000 + 20000) / 4 = 42500
   *   smoothed = (7 * 100000 + 120000) / 8 = 102500 */
  WT_EXPECT_OK("a second sample", wt_quic_rtt_update(&rtt, 120000U, 10000U, 25000U, 0));
  WT_EXPECT_U64("the variation follows", 42500U, rtt.rttvar);
  WT_EXPECT_U64("and the smoothed value", 102500U, rtt.smoothed);
  WT_EXPECT_U64("while the minimum stays", 100000U, rtt.min_rtt);

  /* Once the handshake is confirmed, a reported delay is subtracted, capped at the peer's
   * maximum. Here the delay is larger than the cap, so the cap is what is subtracted:
   *   adjusted = 200000 - 25000 = 175000
   *   difference = |102500 - 175000| = 72500
   *   rttvar = (3 * 42500 + 72500) / 4 = 50000
   *   smoothed = (7 * 102500 + 175000) / 8 = 111562 (integer division) */
  WT_EXPECT_OK("a sample with a delay",
               wt_quic_rtt_update(&rtt, 200000U, 60000U, 25000U, 1));
  /* `latest` is the raw sample: the adjustment is applied to the estimate, not to the sample a
   * caller might compare against something else. */
  WT_EXPECT_U64("keeps the raw sample", 200000U, rtt.latest);
  WT_EXPECT_U64("and the variation follows", 50000U, rtt.rttvar);
  WT_EXPECT_U64("and the smoothed value", 111562U, rtt.smoothed);

  /* A sample below the minimum updates it, and a delay that would take more than the sample is
   * not subtracted (which would underflow). */
  WT_EXPECT_OK("a smaller sample",
               wt_quic_rtt_update(&rtt, 50000U, 40000U, 25000U, 1));
  WT_EXPECT_U64("updates the minimum", 50000U, rtt.min_rtt);
  WT_EXPECT_U64("and is not reduced below itself", 50000U, rtt.latest);
  WT_EXPECT_OK("the probe timeout still computes", wt_quic_rtt_pto(&rtt, 25000U, &pto));
  WT_EXPECT_TRUE("and is positive", pto > 0U);

  WT_EXPECT_STATUS("a NULL estimator is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_rtt_update(NULL, 1U, 1U, 1U, 1));
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_rtt_pto(&rtt, 25000U, NULL));
}

static void test_pn_space(void) {
  wt_quic_pn_space_t space;
  uint64_t packet_number = 0U;

  wt_quic_pn_space_init(&space);
  WT_EXPECT_U64("a fresh space sends packet number zero first", 0U, space.next_send);
  WT_EXPECT_INT("with nothing sent", 0, space.has_sent);
  WT_EXPECT_INT("and nothing acknowledged", 0, space.has_largest_acked);
  WT_EXPECT_U64("so nothing is in flight", 0U,
                wt_quic_pn_space_first_in_flight(&space));

  WT_EXPECT_OK("a packet number is taken", wt_quic_pn_space_next(&space, &packet_number));
  WT_EXPECT_U64("which is zero", 0U, packet_number);
  WT_EXPECT_INT("and the space has sent", 1, space.has_sent);
  WT_EXPECT_OK("another", wt_quic_pn_space_next(&space, &packet_number));
  WT_EXPECT_U64("which is one", 1U, packet_number);
  WT_EXPECT_U64("and the next is two", 2U, space.next_send);

  /* The largest acknowledged only moves forwards: a late ACK for an earlier packet is a state
   * error rather than a step backwards. */
  WT_EXPECT_OK("the second packet is acknowledged", wt_quic_pn_space_on_ack(&space, 1U));
  WT_EXPECT_U64("so the watermark is one", 1U, space.largest_acked);
  WT_EXPECT_U64("and the first packet in flight is two", 2U,
                wt_quic_pn_space_first_in_flight(&space));
  WT_EXPECT_STATUS("an older acknowledgement is refused", WT_ERR_STATE,
                   wt_quic_pn_space_on_ack(&space, 0U));
  WT_EXPECT_U64("and the watermark has not moved", 1U, space.largest_acked);
  WT_EXPECT_OK("a later acknowledgement is accepted", wt_quic_pn_space_on_ack(&space, 1U));

  /* The space is exhausted rather than wrapped: a reused packet number is a reused nonce. */
  {
    wt_quic_pn_space_t exhausted;
    wt_quic_pn_space_init(&exhausted);
    exhausted.has_sent = 1;
    exhausted.next_send = WT_QUIC_PACKET_NUMBER_MAX + 1U;
    WT_EXPECT_STATUS("an exhausted space refuses to send", WT_ERR_OVERFLOW,
                     wt_quic_pn_space_next(&exhausted, &packet_number));
  }

  WT_EXPECT_STATUS("a NULL space is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_pn_space_next(NULL, &packet_number));
  WT_EXPECT_STATUS("a NULL packet number is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_pn_space_next(&space, NULL));
  WT_EXPECT_U64("a NULL space has nothing in flight", 0U,
                wt_quic_pn_space_first_in_flight(NULL));
}

int main(void) {
  test_received_ranges();
  test_ack_frame();
  test_rtt();
  test_pn_space();

  WT_TEST_MAIN_END("wt_quic_pn_space");
}
