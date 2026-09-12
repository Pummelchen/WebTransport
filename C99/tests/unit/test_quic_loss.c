/* Loss detection and probe timeouts.
 *
 * WHAT IS BEING CHECKED IS WHEN A PACKET IS DECLARED LOST, because both of the answers are wrong
 * in a way that is expensive and quiet. Declaring a packet lost too early retransmits what arrived
 * and halves the congestion window for a loss that did not happen; declaring it too late leaves a
 * hole that only a probe timeout can fill, and a connection that fills it slowly looks like a slow
 * network rather than a bug. So the tests are the rules and then the boundaries of the rules: three
 * numbers higher is the packet threshold, two is not; 9/8 of the round trip time is the time
 * threshold, and a packet sent just inside it is not yet lost.
 *
 * The probe timeout is checked for the two things that are easy to get wrong: it only exists while
 * something ack-eliciting is in flight, and its backoff doubles on each expiry and is reset by an
 * acknowledgement of an ack-eliciting packet rather than by any acknowledgement at all.
 */

#include "wt_test.h"

#include "webtransport/quic/loss.h"

/* A clock the tests advance by hand, in microseconds. */
static const uint64_t WT_RTT_SAMPLE = 100000U; /* 100 ms */

static wt_quic_sent_packet_t packet_at(uint64_t number, uint64_t time_sent,
                                       int ack_eliciting) {
  wt_quic_sent_packet_t packet;
  memset(&packet, 0, sizeof(packet));
  packet.packet_number = number;
  packet.time_sent = time_sent;
  packet.size = 1200U;
  packet.tag = number * 10U;
  packet.ack_eliciting = ack_eliciting;
  packet.in_flight = 1;
  return packet;
}

static void seed_rtt(wt_quic_rtt_t *rtt) {
  wt_quic_rtt_init(rtt);
  /* One sample, so the estimator is usable and the time threshold has a value. */
  WT_EXPECT_OK("the estimator takes a sample",
               wt_quic_rtt_update(rtt, WT_RTT_SAMPLE, 0U, 0U, 0));
  WT_EXPECT_U64("with a smoothed value of the sample", WT_RTT_SAMPLE, rtt->smoothed);
}

/* What the visitor collected, so a test can say which packets were declared lost and in what
 * order. */
typedef struct wt_loss_log {
  uint64_t packet_numbers[16];
  uint64_t tags[16];
  size_t count;
} wt_loss_log_t;

static void log_lost(void *context, const wt_quic_sent_packet_t *packet) {
  wt_loss_log_t *log = (wt_loss_log_t *)context;
  if (log->count < 16U) {
    log->packet_numbers[log->count] = packet->packet_number;
    log->tags[log->count] = packet->tag;
    log->count++;
  }
}

static void test_sent_list(void) {
  wt_quic_loss_t loss;
  wt_quic_sent_packet_t packet;

  wt_quic_loss_init(&loss);
  WT_EXPECT_U64("a fresh list is empty", 0U, (uint64_t)wt_quic_loss_count(&loss));
  WT_EXPECT_U64("with nothing in flight", 0U, wt_quic_loss_bytes_in_flight(&loss));

  packet = packet_at(0U, 1000U, 1);
  WT_EXPECT_OK("a packet is recorded", wt_quic_loss_on_sent(&loss, &packet));
  packet = packet_at(1U, 2000U, 1);
  WT_EXPECT_OK("and another", wt_quic_loss_on_sent(&loss, &packet));
  WT_EXPECT_U64("two packets", 2U, (uint64_t)wt_quic_loss_count(&loss));
  WT_EXPECT_U64("2400 bytes in flight", 2400U, wt_quic_loss_bytes_in_flight(&loss));
  WT_EXPECT_U64("both ack-eliciting", 2U, wt_quic_loss_ack_eliciting_in_flight(&loss));

  /* The same packet number twice is a caller that has lost track: recording it again would
   * count its bytes twice and make it two packets for loss detection. */
  packet = packet_at(1U, 3000U, 1);
  WT_EXPECT_STATUS("a packet number is not reused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_loss_on_sent(&loss, &packet));
  WT_EXPECT_U64("and the list is unchanged", 2U, (uint64_t)wt_quic_loss_count(&loss));

  /* A packet that is not in flight counts towards nothing. */
  packet = packet_at(2U, 3000U, 0);
  packet.in_flight = 0;
  WT_EXPECT_OK("a packet that is not in flight is recorded",
               wt_quic_loss_on_sent(&loss, &packet));
  WT_EXPECT_U64("without adding bytes", 2400U, wt_quic_loss_bytes_in_flight(&loss));
  WT_EXPECT_U64("or an ack-eliciting packet", 2U,
                wt_quic_loss_ack_eliciting_in_flight(&loss));

  /* The list has a bound, and being at it is an error rather than a silent drop. */
  {
    wt_quic_loss_t full;
    size_t i;
    wt_quic_loss_init(&full);
    for (i = 0U; i < WT_QUIC_SENT_PACKETS_MAX; i++) {
      packet = packet_at((uint64_t)i, 1000U + (uint64_t)i, 1);
      WT_EXPECT_OK("a packet is recorded until the bound",
                   wt_quic_loss_on_sent(&full, &packet));
    }
    packet = packet_at((uint64_t)WT_QUIC_SENT_PACKETS_MAX, 9000U, 1);
    WT_EXPECT_STATUS("and the next is refused rather than dropped", WT_ERR_LIMIT,
                     wt_quic_loss_on_sent(&full, &packet));
    WT_EXPECT_U64("so nothing was forgotten", (uint64_t)WT_QUIC_SENT_PACKETS_MAX,
                  (uint64_t)wt_quic_loss_count(&full));
  }

  WT_EXPECT_STATUS("a NULL list is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_loss_on_sent(NULL, &packet));
  WT_EXPECT_STATUS("a NULL packet is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_loss_on_sent(&loss, NULL));
}

static void test_packet_threshold(void) {
  wt_quic_loss_t loss;
  wt_quic_rtt_t rtt;
  wt_quic_sent_packet_t packet;
  wt_loss_log_t log;
  uint64_t i;

  seed_rtt(&rtt);
  wt_quic_loss_init(&loss);
  /* Packets 0 to 9, one microsecond apart, so the time threshold cannot be the reason any of them
   * is declared lost: the clock is held near the send times and 9/8 of the round trip time is
   * 112500 microseconds. */
  for (i = 0U; i < 10U; i++) {
    packet = packet_at(i, 1000U + i, 1);
    WT_EXPECT_OK("a packet is sent", wt_quic_loss_on_sent(&loss, &packet));
  }

  /* Acknowledging 0 declares nothing: 0 >= 0 + 3 is false, and the time threshold has not passed.
   * An endpoint does not declare its own packets lost before a later one is acknowledged. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("packet 0 is acknowledged",
               wt_quic_loss_detect(&loss, &rtt, 1000U, 0U, log_lost, &log));
  WT_EXPECT_U64("declaring nothing lost", 0U, (uint64_t)log.count);

  /* Acknowledging 2 still declares nothing: 2 >= 0 + 3 and 2 >= 1 + 3 are both false. Two numbers
   * higher than a packet is inside the threshold. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("packet 2 is acknowledged",
               wt_quic_loss_detect(&loss, &rtt, 1000U, 2U, log_lost, &log));
  WT_EXPECT_U64("still declaring nothing lost", 0U, (uint64_t)log.count);

  /* Acknowledging 3 declares packet 0 and only packet 0: 3 >= 0 + 3 is true (three numbers higher
   * has arrived) and 3 >= 1 + 3 is false. This is the boundary the threshold is about. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("packet 3 is acknowledged",
               wt_quic_loss_detect(&loss, &rtt, 1000U, 3U, log_lost, &log));
  WT_EXPECT_U64("one packet is declared lost", 1U, (uint64_t)log.count);
  WT_EXPECT_U64("which is packet 0", 0U, log.packet_numbers[0]);
  WT_EXPECT_U64("with the caller's tag", 0U, log.tags[0]);

  /* Acknowledging 6 declares 1, 2 and 3: each is at least three below six. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("packet 6 is acknowledged",
               wt_quic_loss_detect(&loss, &rtt, 1000U, 6U, log_lost, &log));
  WT_EXPECT_U64("three packets are declared lost", 3U, (uint64_t)log.count);
  WT_EXPECT_U64("the first is packet 1", 1U, log.packet_numbers[0]);
  WT_EXPECT_U64("the second is packet 2", 2U, log.packet_numbers[1]);
  WT_EXPECT_U64("the third is packet 3", 3U, log.packet_numbers[2]);
  WT_EXPECT_U64("and the tags come back with them", 10U, log.tags[0]);
  WT_EXPECT_INT("in the order they were sent", 1,
                log.packet_numbers[0] < log.packet_numbers[1] &&
                        log.packet_numbers[1] < log.packet_numbers[2]);
  WT_EXPECT_U64("leaving six packets in flight", 6U, (uint64_t)wt_quic_loss_count(&loss));
  WT_EXPECT_U64("and the bytes of the lost ones gone from flight", 6U * 1200U,
                wt_quic_loss_bytes_in_flight(&loss));

  /* Detection is idempotent: a second call with the same watermark declares nothing, because the
   * packets it declared are no longer in the list. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("detecting again", wt_quic_loss_detect(&loss, &rtt, 1000U, 6U, log_lost, &log));
  WT_EXPECT_U64("declares nothing the second time", 0U, (uint64_t)log.count);
}

static void test_time_threshold(void) {
  wt_quic_loss_t loss;
  wt_quic_rtt_t rtt;
  wt_quic_sent_packet_t packet;
  wt_loss_log_t log;

  seed_rtt(&rtt);
  wt_quic_loss_init(&loss);
  /* 9/8 of 100 ms is 112500 microseconds. Packet 0 is sent at one second and packet 1 a
   * microsecond later; packet 1 is acknowledged, so packet 0 is below the watermark by one -- which
   * is not enough for the packet threshold, and leaves the time threshold as the only rule that can
   * declare it lost. */
  packet = packet_at(0U, 1000000U, 1);
  WT_EXPECT_OK("the first packet is sent", wt_quic_loss_on_sent(&loss, &packet));
  packet = packet_at(1U, 1000001U, 1);
  WT_EXPECT_OK("the second packet is sent", wt_quic_loss_on_sent(&loss, &packet));
  {
    int newly_acked = 0;
    WT_EXPECT_OK("the second is acknowledged",
                 wt_quic_loss_on_ack(&loss, 1U, &rtt, 1000002U, 0U, &newly_acked));
    WT_EXPECT_INT("which is new", 1, newly_acked);
  }

  /* One microsecond inside the threshold the packet is not yet lost: it was sent 112499
   * microseconds ago and the delay is 112500. */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("detection one microsecond inside",
               wt_quic_loss_detect(&loss, &rtt, 1000000U + 112499U, 1U, log_lost, &log));
  WT_EXPECT_U64("declares nothing lost", 0U, (uint64_t)log.count);
  WT_EXPECT_U64("and packet 0 is still in flight", 1U,
                (uint64_t)wt_quic_loss_count(&loss));

  /* The time at which it will be lost, which is what a connection arms its loss timer with. */
  WT_EXPECT_U64("the loss time is the send time plus the delay", 1000000U + 112500U,
                wt_quic_loss_time(&loss, &rtt, 1U));

  /* At the threshold it is lost: RFC 9002 section 6.1's comparison is "sent at or before
   * now minus the delay". */
  memset(&log, 0, sizeof(log));
  WT_EXPECT_OK("detection at the threshold",
               wt_quic_loss_detect(&loss, &rtt, 1000000U + 112500U, 1U, log_lost, &log));
  WT_EXPECT_U64("declares packet 0 lost", 1U, (uint64_t)log.count);
  WT_EXPECT_U64("which is the packet sent first", 0U, log.packet_numbers[0]);
  WT_EXPECT_U64("leaving nothing in flight", 0U, (uint64_t)wt_quic_loss_count(&loss));
  WT_EXPECT_U64("and no loss time, because nothing is below the watermark", 0U,
                wt_quic_loss_time(&loss, &rtt, 1U));

  /* A packet that has met the packet threshold is not given a loss time: it is lost on the next
   * detection rather than by a timer, so arming one for it would be a timer that fires for nothing. */
  {
    wt_quic_loss_t space;
    wt_quic_loss_init(&space);
    packet = packet_at(0U, 5000U, 1);
    WT_EXPECT_OK("a packet is sent", wt_quic_loss_on_sent(&space, &packet));
    packet = packet_at(1U, 5000U, 1);
    WT_EXPECT_OK("and another", wt_quic_loss_on_sent(&space, &packet));
    packet = packet_at(2U, 5000U, 1);
    WT_EXPECT_OK("and a third", wt_quic_loss_on_sent(&space, &packet));
    packet = packet_at(3U, 5000U, 1);
    WT_EXPECT_OK("and a fourth", wt_quic_loss_on_sent(&space, &packet));
    /* With 3 acknowledged, packet 0 has met the packet threshold and is skipped, while packet 1
     * has not and is the one the timer is for. */
    WT_EXPECT_U64("the loss time comes from the packet that has not met the threshold",
                  5000U + 112500U, wt_quic_loss_time(&space, &rtt, 3U));
    /* With everything below the watermark having met it, there is no loss time at all: those
     * packets are declared lost by number rather than by a timer. */
    WT_EXPECT_U64("and none when every packet has met it", 0U,
                  wt_quic_loss_time(&space, &rtt, 7U));
  }
}

static void test_acknowledgement(void) {
  wt_quic_loss_t loss;
  wt_quic_rtt_t rtt;
  wt_quic_sent_packet_t packet;
  int newly_acked = 0;

  seed_rtt(&rtt);
  wt_quic_loss_init(&loss);
  packet = packet_at(0U, 1000U, 1);
  WT_EXPECT_OK("an ack-eliciting packet is sent", wt_quic_loss_on_sent(&loss, &packet));
  WT_EXPECT_OK("it is acknowledged",
               wt_quic_loss_on_ack(&loss, 0U, &rtt, 2000U, 0U, &newly_acked));
  WT_EXPECT_INT("which is a new acknowledgement", 1, newly_acked);
  WT_EXPECT_U64("and it is no longer in flight", 0U, (uint64_t)wt_quic_loss_count(&loss));
  WT_EXPECT_U64("with no bytes in flight", 0U, wt_quic_loss_bytes_in_flight(&loss));

  /* Acknowledging it again is not an error: a peer may repeat an acknowledgement, and the packet
   * may already have been declared lost and retransmitted. */
  WT_EXPECT_OK("acknowledging it again",
               wt_quic_loss_on_ack(&loss, 0U, &rtt, 3000U, 0U, &newly_acked));
  WT_EXPECT_INT("is not a new acknowledgement", 0, newly_acked);

  /* The probe timeout's backoff is reset by acknowledging an ack-eliciting packet. */
  packet = packet_at(1U, 5000U, 1);
  WT_EXPECT_OK("a packet is in flight", wt_quic_loss_on_sent(&loss, &packet));
  wt_quic_loss_on_pto(&loss);
  wt_quic_loss_on_pto(&loss);
  WT_EXPECT_U64("two expiries have backed it off", 2U, loss.pto_count);
  WT_EXPECT_OK("the packet is acknowledged",
               wt_quic_loss_on_ack(&loss, 1U, &rtt, 6000U, 0U, &newly_acked));
  WT_EXPECT_U64("which resets the backoff", 0U, loss.pto_count);

  /* A packet that was not ack-eliciting does not reset it: acknowledging a packet the peer did not
   * have to answer says nothing about whether it is still there. */
  packet = packet_at(2U, 7000U, 0);
  WT_EXPECT_OK("a packet that needs no answer is sent",
               wt_quic_loss_on_sent(&loss, &packet));
  wt_quic_loss_on_pto(&loss);
  WT_EXPECT_U64("the backoff is one", 1U, loss.pto_count);
  WT_EXPECT_OK("and it is acknowledged",
               wt_quic_loss_on_ack(&loss, 2U, &rtt, 8000U, 0U, &newly_acked));
  WT_EXPECT_U64("which does not reset the backoff", 1U, loss.pto_count);
}

static void test_probe_timeout(void) {
  wt_quic_loss_t loss;
  wt_quic_rtt_t rtt;
  wt_quic_sent_packet_t packet;
  uint64_t pto = 0U;
  uint64_t first = 0U;

  seed_rtt(&rtt);
  wt_quic_loss_init(&loss);
  /* Nothing ack-eliciting in flight: there is nothing to probe for. */
  WT_EXPECT_STATUS("no probe timeout with nothing outstanding", WT_ERR_STATE,
                   wt_quic_loss_pto(&loss, &rtt, 0U, &pto));

  /* A packet that needs no answer does not arm it either. */
  packet = packet_at(0U, 1000U, 0);
  WT_EXPECT_OK("a packet that needs no answer is sent",
               wt_quic_loss_on_sent(&loss, &packet));
  WT_EXPECT_STATUS("which does not arm the probe timeout", WT_ERR_STATE,
                   wt_quic_loss_pto(&loss, &rtt, 0U, &pto));

  /* An ack-eliciting one does: sent at 2000, plus smoothed 100000 + 4 * 50000 (the variation) =
   * 300000, so 302000. */
  packet = packet_at(1U, 2000U, 1);
  WT_EXPECT_OK("an ack-eliciting packet is sent", wt_quic_loss_on_sent(&loss, &packet));
  WT_EXPECT_OK("the probe timeout is armed", wt_quic_loss_pto(&loss, &rtt, 0U, &pto));
  WT_EXPECT_U64("at the send time plus the timeout", 2000U + 100000U + 4U * 50000U, pto);
  first = pto;

  /* Each expiry doubles it from the same send time. */
  wt_quic_loss_on_pto(&loss);
  WT_EXPECT_OK("after one expiry", wt_quic_loss_pto(&loss, &rtt, 0U, &pto));
  WT_EXPECT_U64("the timeout is doubled", 2000U + 2U * (first - 2000U), pto);
  wt_quic_loss_on_pto(&loss);
  WT_EXPECT_OK("after two", wt_quic_loss_pto(&loss, &rtt, 0U, &pto));
  WT_EXPECT_U64("it is doubled again", 2000U + 4U * (first - 2000U), pto);

  /* The peer's maximum acknowledgement delay belongs to the Application space, and a caller that
   * passes it gets it added. */
  {
    wt_quic_loss_t space;
    wt_quic_loss_init(&space);
    packet = packet_at(0U, 0U, 1);
    WT_EXPECT_OK("a packet in the application space",
                 wt_quic_loss_on_sent(&space, &packet));
    WT_EXPECT_OK("the probe timeout with a delay",
                 wt_quic_loss_pto(&space, &rtt, 25000U, &pto));
    WT_EXPECT_U64("includes the delay", 300000U + 25000U, pto);
  }

  /* The backoff is bounded, so a connection whose peer has gone away cannot push its timer past
   * the point where the arithmetic stops making sense. */
  {
    size_t i;
    for (i = 0U; i < 64U; i++) wt_quic_loss_on_pto(&loss);
    WT_EXPECT_TRUE("the backoff is bounded", loss.pto_count <= 16U);
    WT_EXPECT_OK("and the timeout still computes", wt_quic_loss_pto(&loss, &rtt, 0U, &pto));
    WT_EXPECT_TRUE("in the future", pto > first);
  }

  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_loss_pto(&loss, &rtt, 0U, NULL));
  WT_EXPECT_STATUS("a NULL estimator is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_loss_pto(&loss, NULL, 0U, &pto));
}

int main(void) {
  test_sent_list();
  test_packet_threshold();
  test_time_threshold();
  test_acknowledgement();
  test_probe_timeout();

  WT_TEST_MAIN_END("wt_quic_loss");
}
