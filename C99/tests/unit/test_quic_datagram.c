/* QUIC DATAGRAM: the size rule in both directions, and the queue's bound and policy.
 *
 * THE SIZE RULE HAS TWO BOUNDS AND THE INTERESTING CASES ARE WHERE THEY DISAGREE. A datagram that
 * fits the peer's `max_datagram_frame_size` but not the path's packet size would be fragmented or
 * dropped by the path; one that fits the packet but not the frame limit would be refused by the peer.
 * `wt_quic_datagram_max_payload` answers with the smaller of the two, and the tests check the
 * boundaries on each side -- including the frame's own length field, whose width depends on the value
 * it describes.
 *
 * THE QUEUE'S POLICY IS CHECKED BECAUSE IT IS A POLICY. When it is full the NEWEST datagram is the one
 * discarded: the application has already been told about everything in the queue, and for the traffic
 * this carries the freshest message is the one that matters least. A queue that dropped the oldest
 * instead would be a different design, and the test says which one this is.
 */

#include "wt_test.h"

#include "webtransport/quic/datagram.h"

static void test_max_payload(void) {
  /* A peer that does not accept datagrams at all (RFC 9221 section 3: the parameter's absence, and a
   * zero value, both mean "no"). */
  WT_EXPECT_U64("no datagrams without the parameter", 0U,
                wt_quic_datagram_max_payload(0U, 1200U, 20U));
  /* A packet with no room for a payload. */
  WT_EXPECT_U64("no payload when the packet is all overhead", 0U,
                wt_quic_datagram_max_payload(1000U, 20U, 20U));
  WT_EXPECT_U64("nor when it is smaller", 0U,
                wt_quic_datagram_max_payload(1000U, 19U, 20U));

  /* The packet's bound binds when the frame limit is generous: 1200 - 30 is the payload, and the
   * frame's overhead is inside it. */
  WT_EXPECT_U64("the packet's bound", 1200U - 30U,
                wt_quic_datagram_max_payload(65535U, 1200U, 30U));

  /* The frame's bound binds when it is small, and it includes the type byte and a length field whose
   * width follows the value. For a limit of 1300 with plenty of packet: a 1297-byte payload needs
   * 1 + 2 + 1297 = 1300 exactly. */
  WT_EXPECT_U64("the frame's bound, exactly", 1297U,
                wt_quic_datagram_max_payload(1300U, 65535U, 30U));
  /* One byte less of limit cannot carry the same payload, and the length field there is still two
   * bytes wide. */
  WT_EXPECT_U64("one byte less of limit", 1296U,
                wt_quic_datagram_max_payload(1299U, 65535U, 30U));
  /* A limit small enough that the length field is one byte wide: 1 + 1 + 62 = 64. */
  WT_EXPECT_U64("a one-byte length field", 62U,
                wt_quic_datagram_max_payload(64U, 65535U, 30U));
  /* A limit that cannot hold even an empty datagram. */
  WT_EXPECT_U64("nothing fits under a tiny limit", 0U,
                wt_quic_datagram_max_payload(1U, 65535U, 30U));
  /* A limit of two bytes: 1 + 1 + 0 = 2, so an empty payload fits. */
  WT_EXPECT_U64("an empty payload under a two-byte limit", 0U,
                wt_quic_datagram_max_payload(2U, 65535U, 30U));
}

static void test_queue(void) {
  wt_quic_datagram_queue_t queue;
  uint8_t out[WT_QUIC_DATAGRAM_MAX];
  size_t out_length = 0U;
  uint64_t received_at = 0U;
  int discarded = 0;
  uint8_t message[4];

  wt_quic_datagram_queue_init(&queue);
  WT_EXPECT_U64("a fresh queue is empty", 0U,
                (uint64_t)wt_quic_datagram_queue_count(&queue));
  WT_EXPECT_STATUS("and popping one says so", WT_ERR_AGAIN,
                   wt_quic_datagram_queue_pop(&queue, out, sizeof(out), &out_length,
                                              &received_at));
  WT_EXPECT_U64("nothing received", 0U, wt_quic_datagram_queue_received(&queue));
  WT_EXPECT_U64("nothing discarded", 0U, wt_quic_datagram_queue_discarded(&queue));

  /* Three datagrams in, three out, oldest first. */
  {
    static const uint8_t first[] = {1U, 2U, 3U};
    static const uint8_t second[] = {4U, 5U};
    static const uint8_t third[] = {6U};
    WT_EXPECT_OK("the first arrives",
                 wt_quic_datagram_queue_push(&queue, first, sizeof(first), 100U,
                                             &discarded));
    WT_EXPECT_INT("and is not discarded", 0, discarded);
    WT_EXPECT_OK("the second arrives",
                 wt_quic_datagram_queue_push(&queue, second, sizeof(second), 200U,
                                             &discarded));
    WT_EXPECT_OK("the third arrives",
                 wt_quic_datagram_queue_push(&queue, third, sizeof(third), 300U,
                                             &discarded));
    WT_EXPECT_U64("three are queued", 3U, (uint64_t)wt_quic_datagram_queue_count(&queue));
    WT_EXPECT_OK("the first comes out", wt_quic_datagram_queue_pop(&queue, out,
                                                                   sizeof(out), &out_length,
                                                                   &received_at));
    WT_EXPECT_U64("with its length", 3U, (uint64_t)out_length);
    WT_EXPECT_BYTES("its bytes", first, out, 3U);
    WT_EXPECT_U64("and its arrival time", 100U, received_at);
    WT_EXPECT_OK("then the second", wt_quic_datagram_queue_pop(&queue, out, sizeof(out),
                                                                &out_length, &received_at));
    WT_EXPECT_BYTES("which is the second", second, out, 2U);
    WT_EXPECT_U64("two arrived", 3U, wt_quic_datagram_queue_received(&queue));
    WT_EXPECT_OK("and the third", wt_quic_datagram_queue_pop(&queue, out, sizeof(out),
                                                              &out_length, &received_at));
    WT_EXPECT_BYTES("which is the third", third, out, 1U);
    WT_EXPECT_U64("leaving the queue empty", 0U,
                  (uint64_t)wt_quic_datagram_queue_count(&queue));
  }

  /* The ring wraps: pushing and popping more than the queue's depth keeps working, and the order is
   * the order they arrived. */
  {
    size_t i;
    int all_in_order = 1;
    /* Two in, two out, ten times: the head and the count walk the whole ring without the queue ever
     * being full, and the order has to stay the order they arrived. */
    wt_quic_datagram_queue_init(&queue);
    for (i = 0U; i < 10U; i++) {
      uint8_t first = (uint8_t)(2U * i);
      uint8_t second = (uint8_t)(2U * i + 1U);
      WT_EXPECT_OK("a datagram arrives",
                   wt_quic_datagram_queue_push(&queue, &first, 1U, i, &discarded));
      WT_EXPECT_OK("and another",
                   wt_quic_datagram_queue_push(&queue, &second, 1U, i, &discarded));
      WT_EXPECT_OK("the first is taken", wt_quic_datagram_queue_pop(&queue, out, sizeof(out),
                                                                    &out_length,
                                                                    &received_at));
      if (out_length != 1U || out[0] != first) all_in_order = 0;
      WT_EXPECT_OK("then the second", wt_quic_datagram_queue_pop(&queue, out, sizeof(out),
                                                                 &out_length, &received_at));
      if (out_length != 1U || out[0] != second) all_in_order = 0;
    }
    WT_EXPECT_INT("the ring returns them in order", 1, all_in_order);
  }

  /* The bound: once full, the NEWEST is discarded and counted, and what is queued is unchanged. */
  {
    wt_quic_datagram_queue_t full;
    size_t i;
    int discarded_here = 0;
    wt_quic_datagram_queue_init(&full);
    for (i = 0U; i < WT_QUIC_DATAGRAM_QUEUE_MAX; i++) {
      uint8_t value = (uint8_t)(i + 1U);
      WT_EXPECT_OK("a datagram fills the queue",
                   wt_quic_datagram_queue_push(&full, &value, 1U, i, &discarded_here));
    }
    WT_EXPECT_U64("which is now full", (uint64_t)WT_QUIC_DATAGRAM_QUEUE_MAX,
                  (uint64_t)wt_quic_datagram_queue_count(&full));
    message[0] = 99U;
    WT_EXPECT_OK("one more arrives", wt_quic_datagram_queue_push(&full, message, 1U, 50U,
                                                                 &discarded_here));
    WT_EXPECT_INT("and is discarded rather than queued", 1, discarded_here);
    WT_EXPECT_U64("so the queue is still full", (uint64_t)WT_QUIC_DATAGRAM_QUEUE_MAX,
                  (uint64_t)wt_quic_datagram_queue_count(&full));
    WT_EXPECT_U64("with one discarded", 1U, wt_quic_datagram_queue_discarded(&full));
    WT_EXPECT_U64("and all of them received", (uint64_t)WT_QUIC_DATAGRAM_QUEUE_MAX + 1U,
                  wt_quic_datagram_queue_received(&full));
    /* The oldest is still the first one, and the discarded one is not in the queue. */
    WT_EXPECT_OK("the oldest comes out", wt_quic_datagram_queue_pop(&full, out, sizeof(out),
                                                                    &out_length,
                                                                    &received_at));
    WT_EXPECT_U64("which is the first", 1U, (uint64_t)out[0]);
    {
      size_t remaining = wt_quic_datagram_queue_count(&full);
      int found_discarded = 0;
      while (remaining > 0U) {
        WT_EXPECT_OK("the next comes out", wt_quic_datagram_queue_pop(&full, out,
                                                                      sizeof(out), &out_length,
                                                                      &received_at));
        if (out_length == 1U && out[0] == 99U) found_discarded = 1;
        remaining--;
      }
      WT_EXPECT_INT("and the discarded one was never queued", 0, found_discarded);
    }
  }

  /* A datagram larger than this implementation holds is a caller error, and an empty one is legal.
   * The queue is drained first, because the ring test above left entries in it. */
  {
    uint8_t large[WT_QUIC_DATAGRAM_MAX + 1U];
    wt_quic_datagram_queue_init(&queue);
    memset(large, 0x5a, sizeof(large));
    WT_EXPECT_STATUS("an oversized datagram is refused", WT_ERR_LIMIT,
                     wt_quic_datagram_queue_push(&queue, large, sizeof(large), 0U,
                                                 &discarded));
    WT_EXPECT_OK("an empty one is accepted",
                 wt_quic_datagram_queue_push(&queue, NULL, 0U, 0U, &discarded));
    WT_EXPECT_OK("and popped", wt_quic_datagram_queue_pop(&queue, out, sizeof(out),
                                                          &out_length, &received_at));
    WT_EXPECT_U64("with no bytes", 0U, (uint64_t)out_length);
    WT_EXPECT_STATUS("a NULL queue is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_datagram_queue_push(NULL, message, 1U, 0U, &discarded));
  }

  /* A caller whose buffer is too small does not lose the datagram: it stays queued. */
  {
    uint8_t small[2];
    wt_quic_datagram_queue_init(&queue);
    size_t small_length = 0U;
    message[0] = 7U;
    message[1] = 8U;
    message[2] = 9U;
    WT_EXPECT_OK("a three-byte datagram is queued",
                 wt_quic_datagram_queue_push(&queue, message, 3U, 0U, &discarded));
    WT_EXPECT_STATUS("popping it into two bytes is refused", WT_ERR_LIMIT,
                     wt_quic_datagram_queue_pop(&queue, small, sizeof(small), &small_length,
                                                &received_at));
    WT_EXPECT_U64("and it is still queued", 1U,
                  (uint64_t)wt_quic_datagram_queue_count(&queue));
    WT_EXPECT_OK("so a larger buffer takes it", wt_quic_datagram_queue_pop(&queue, out,
                                                                           sizeof(out),
                                                                           &out_length,
                                                                           &received_at));
    WT_EXPECT_U64("with its bytes", 3U, (uint64_t)out_length);
  }
}

int main(void) {
  test_max_payload();
  test_queue();

  WT_TEST_MAIN_END("wt_quic_datagram");
}
