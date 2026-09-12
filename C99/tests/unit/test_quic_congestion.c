/* Congestion control: the initial window, slow start, congestion avoidance, and the recovery epoch.
 *
 * THE EPOCH IS WHAT THESE TESTS ARE MOSTLY ABOUT. One congested queue produces a burst of losses, and
 * a controller that halves the window for each of them ends up with a window that cannot send a
 * packet -- which looks like a dead path rather than a congestion response. So the sequence a burst
 * produces is checked exactly: the first loss halves the window and begins a recovery period, and
 * every later packet from the same burst changes nothing, in either direction. The other direction
 * is checked too: a packet sent after the period began does move the window, or the connection would
 * never recover.
 *
 * The arithmetic is checked against RFC 9002 section 7's formulas with the values worked out by hand,
 * including the two that are easy to misread: the initial window's max() with 14720 (which is what a
 * datagram larger than 1472 bytes runs into), and the congestion avoidance increment's integer
 * division (which is why a small acknowledgement adds nothing at all).
 */

#include "wt_test.h"

#include "webtransport/quic/congestion.h"

#define WT_MDS 1200U

static void test_windows(void) {
  /* min(10 * mds, max(2 * mds, 14720)). For 1200-byte datagrams that is 12000; for 1500-byte
   * datagrams the 14720 bound wins and the window is 14720, not 15000; for tiny datagrams the
   * 2 * mds floor wins. */
  WT_EXPECT_U64("the initial window for 1200-byte datagrams", 12000U,
                wt_quic_congestion_initial_window(1200U));
  WT_EXPECT_U64("the initial window for 1500-byte datagrams", 14720U,
                wt_quic_congestion_initial_window(1500U));
  WT_EXPECT_U64("the initial window for 200-byte datagrams", 2000U,
                wt_quic_congestion_initial_window(200U));
  WT_EXPECT_U64("the minimum window", 2400U, wt_quic_congestion_minimum_window(1200U));
  WT_EXPECT_U64("and for another datagram size", 3000U,
                wt_quic_congestion_minimum_window(1500U));

  /* A connection starts in slow start, with a threshold of infinity. */
  {
    wt_quic_congestion_t congestion;
    wt_quic_congestion_init(&congestion, WT_MDS);
    WT_EXPECT_U64("a fresh window is the initial one", 12000U,
                  wt_quic_congestion_window(&congestion));
    WT_EXPECT_INT("and the connection is in slow start", 1,
                  wt_quic_congestion_in_slow_start(&congestion));
    WT_EXPECT_INT("and not in recovery", 0, wt_quic_congestion_in_recovery(&congestion));
    WT_EXPECT_INT("a packet may be sent", 1,
                  wt_quic_congestion_can_send(&congestion, 0U));
    WT_EXPECT_INT("but not once the window is full", 0,
                  wt_quic_congestion_can_send(&congestion, 12000U));
    WT_EXPECT_INT("while one byte less fits", 1,
                  wt_quic_congestion_can_send(&congestion, 11999U));
  }

  /* A datagram size of zero is a caller error rather than a window of zero. */
  {
    wt_quic_congestion_t congestion;
    wt_quic_congestion_init(&congestion, 0U);
    WT_EXPECT_U64("a zero datagram size falls back", 12000U,
                  wt_quic_congestion_window(&congestion));
  }
  WT_EXPECT_U64("a NULL window is zero", 0U, wt_quic_congestion_window(NULL));
  WT_EXPECT_INT("a NULL connection cannot send", 0,
                wt_quic_congestion_can_send(NULL, 0U));
}

static void test_slow_start_and_avoidance(void) {
  wt_quic_congestion_t congestion;

  /* Slow start: the window grows by what was acknowledged, which doubles it each round trip. */
  wt_quic_congestion_init(&congestion, WT_MDS);
  WT_EXPECT_OK("one datagram is acknowledged",
               wt_quic_congestion_on_ack(&congestion, 1200U, 100U));
  WT_EXPECT_U64("and the window grows by it", 13200U,
                wt_quic_congestion_window(&congestion));
  WT_EXPECT_OK("three more", wt_quic_congestion_on_ack(&congestion, 3600U, 200U));
  WT_EXPECT_U64("and again", 16800U, wt_quic_congestion_window(&congestion));
  WT_EXPECT_INT("still in slow start", 1,
                wt_quic_congestion_in_slow_start(&congestion));

  /* A loss takes it out of slow start: the threshold becomes half the window and the window
   * follows it. 16800 / 2 = 8400. */
  WT_EXPECT_OK("a packet sent at 100 is lost",
               wt_quic_congestion_on_loss(&congestion, 100U, 1000U));
  WT_EXPECT_U64("the threshold is half the window", 8400U,
                wt_quic_congestion_ssthresh(&congestion));
  WT_EXPECT_U64("and so is the window", 8400U, wt_quic_congestion_window(&congestion));
  WT_EXPECT_INT("now in recovery", 1, wt_quic_congestion_in_recovery(&congestion));
  WT_EXPECT_INT("and out of slow start", 0,
                wt_quic_congestion_in_slow_start(&congestion));

  /* Congestion avoidance: one datagram per round trip at most, as mds * acked / cwnd.
   * With cwnd 8400 and 1200 acknowledged: 1200 * 1200 / 8400 = 171. */
  WT_EXPECT_OK("a packet sent after the recovery period is acknowledged",
               wt_quic_congestion_on_ack(&congestion, 1200U, 2000U));
  WT_EXPECT_U64("which grows the window by about a seventh of a datagram", 8571U,
                wt_quic_congestion_window(&congestion));

  /* The increment is never more than what was acknowledged, and it can be zero: with a large window
   * and a small acknowledgement, mds * acked < cwnd and integer division gives nothing at all. */
  {
    wt_quic_congestion_t large;
    wt_quic_congestion_init(&large, WT_MDS);
    large.cwnd = 120000U;
    large.ssthresh = 60000U; /* out of slow start */
    /* 1200 * 50 / 120000 is zero: an acknowledgement this small adds nothing at all, which is the
     * formula and not a rounding choice. */
    WT_EXPECT_OK("a small acknowledgement against a large window",
                 wt_quic_congestion_on_ack(&large, 50U, 100U));
    WT_EXPECT_U64("adds nothing", 120000U, wt_quic_congestion_window(&large));
    /* 1200 * 100 / 120000 is one byte: the increment is a fraction of a datagram, and the fractions
     * are what add up to about a datagram per round trip. */
    WT_EXPECT_OK("a slightly larger one", wt_quic_congestion_on_ack(&large, 100U, 150U));
    WT_EXPECT_U64("adds one byte", 120001U, wt_quic_congestion_window(&large));
    /* 1200 * 24000 / 120001 is 239 bytes, and never the 24000 that were acknowledged. */
    WT_EXPECT_OK("a large acknowledgement", wt_quic_congestion_on_ack(&large, 24000U, 200U));
    WT_EXPECT_U64("adds a fraction of a datagram, not the acknowledged bytes", 120240U,
                  wt_quic_congestion_window(&large));
  }
}

static void test_recovery_epoch(void) {
  wt_quic_congestion_t congestion;

  wt_quic_congestion_init(&congestion, WT_MDS);
  /* A burst of ten packets sent at times 1000..1009, of which the first is lost at time 5000. */
  WT_EXPECT_OK("the first loss", wt_quic_congestion_on_loss(&congestion, 1000U, 5000U));
  WT_EXPECT_U64("halves the window", 6000U, wt_quic_congestion_window(&congestion));
  WT_EXPECT_U64("and the recovery period begins at the loss", 5000U,
                congestion.recovery_start_time);

  /* The rest of the burst: every packet was sent before the period began, so none of them reduces
   * the window again. This is the check that a burst costs one halving rather than ten. */
  {
    uint64_t i;
    for (i = 1001U; i <= 1009U; i++) {
      WT_EXPECT_OK("another loss from the same burst",
                   wt_quic_congestion_on_loss(&congestion, i, 5000U + i));
    }
    WT_EXPECT_U64("leaves the window where the first loss put it", 6000U,
                  wt_quic_congestion_window(&congestion));
  }

  /* Acknowledgements from before the period do not grow it either: those packets were sent into the
   * congestion that caused the loss. */
  WT_EXPECT_OK("an acknowledgement of an old packet",
               wt_quic_congestion_on_ack(&congestion, 1200U, 1005U));
  WT_EXPECT_U64("changes nothing", 6000U, wt_quic_congestion_window(&congestion));
  WT_EXPECT_INT("and the packet is known to be in the period", 1,
                wt_quic_congestion_in_recovery_at(&congestion, 1005U));
  WT_EXPECT_INT("while a later one is not", 0,
                wt_quic_congestion_in_recovery_at(&congestion, 5001U));

  /* A packet sent after the period began is a new event: its loss halves the window again. */
  WT_EXPECT_OK("a later packet is lost",
               wt_quic_congestion_on_loss(&congestion, 6000U, 7000U));
  WT_EXPECT_U64("which halves the window again", 3000U,
                wt_quic_congestion_window(&congestion));
  WT_EXPECT_U64("and begins a new period", 7000U, congestion.recovery_start_time);

  /* The window never goes below two datagrams, however many times it is halved. */
  {
    wt_quic_congestion_t small;
    uint64_t i;
    wt_quic_congestion_init(&small, WT_MDS);
    /* Each loss is a NEW event: the packet is sent after the previous recovery period began, so it
     * belongs to the next congestion event rather than to the same burst. A loss from the same burst
     * would change nothing at all, which the previous test checks. */
    for (i = 0U; i < 20U; i++) {
      uint64_t sent = 1000000U + i * 10U;
      WT_EXPECT_OK("a loss in its own period",
                   wt_quic_congestion_on_loss(&small, sent, sent + 5U));
    }
    WT_EXPECT_U64("the window stops at the minimum", 2400U,
                  wt_quic_congestion_window(&small));
    WT_EXPECT_INT("which is still able to send", 1,
                  wt_quic_congestion_can_send(&small, 0U));
    WT_EXPECT_INT("but not when a datagram is in flight", 0,
                  wt_quic_congestion_can_send(&small, 2400U));
  }

  /* A loss on a fresh connection where the window is already at the minimum does not raise it. */
  {
    wt_quic_congestion_t fresh;
    wt_quic_congestion_init(&fresh, WT_MDS);
    fresh.cwnd = 2400U;
    WT_EXPECT_OK("a loss at the minimum", wt_quic_congestion_on_loss(&fresh, 1U, 2U));
    WT_EXPECT_U64("leaves it there", 2400U, wt_quic_congestion_window(&fresh));
  }
}

static void test_persistent_congestion(void) {
  wt_quic_congestion_t congestion;

  wt_quic_congestion_init(&congestion, WT_MDS);
  WT_EXPECT_OK("the window grows first", wt_quic_congestion_on_ack(&congestion, 12000U, 100U));
  WT_EXPECT_U64("to twice the initial window", 24000U,
                wt_quic_congestion_window(&congestion));

  /* Persistent congestion collapses the window to the minimum and makes the connection earn it
   * back: RFC 9002 section 7.6. */
  WT_EXPECT_OK("persistent congestion is declared",
               wt_quic_congestion_on_persistent_congestion(&congestion, 9000U));
  WT_EXPECT_U64("which collapses the window", 2400U,
                wt_quic_congestion_window(&congestion));
  WT_EXPECT_U64("and the threshold with it", 2400U,
                wt_quic_congestion_ssthresh(&congestion));
  WT_EXPECT_INT("in a new recovery period", 1,
                wt_quic_congestion_in_recovery(&congestion));
  WT_EXPECT_U64("which began now", 9000U, congestion.recovery_start_time);
  WT_EXPECT_INT("and the connection is not in slow start", 0,
                wt_quic_congestion_in_slow_start(&congestion));

  WT_EXPECT_STATUS("a NULL connection is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_congestion_on_persistent_congestion(NULL, 1U));
  WT_EXPECT_STATUS("and so is a NULL acknowledgement", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_congestion_on_ack(NULL, 1U, 1U));
  WT_EXPECT_STATUS("and a NULL loss", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_congestion_on_loss(NULL, 1U, 1U));
}

int main(void) {
  test_windows();
  test_slow_start_and_avoidance();
  test_recovery_epoch();
  test_persistent_congestion();

  WT_TEST_MAIN_END("wt_quic_congestion");
}
