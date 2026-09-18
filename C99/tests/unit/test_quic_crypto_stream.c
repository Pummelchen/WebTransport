/* The CRYPTO stream: handshake bytes arriving by offset.
 *
 * WHAT THIS TEST IS REALLY ABOUT IS A PEER'S CONTROL OVER MEMORY. A CRYPTO frame names its own offset
 * and its own length, so the two ways a receiver can be made to misbehave are a frame that claims to
 * start far beyond what has arrived -- which must not make the buffer grow -- and a handshake split so
 * that a message's second half arrives first. Both are checked here with the offsets a peer would send,
 * because the module's whole job is to answer them with a bound and with order.
 *
 * THE SLIDING WINDOW IS CHECKED AS THE PROPERTY THAT MAKES THE BOUND WORKABLE: after the consumer takes
 * bytes, a peer may send more at the offset the consumer has reached. A window that did not slide would
 * be a buffer that fills up once and then refuses a perfectly ordinary handshake.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/crypto_stream.h"

static const uint8_t k_message[] = "hello world";
/* One byte as a uint8_t array rather than a string literal: a string literal is char, and this tree
 * treats that as the different type it is. */
static const uint8_t k_bang[1] = {'!'};

static void test_in_order(void) {
  wt_quic_crypto_recv_t recv;
  const uint8_t *data = NULL;
  size_t available;

  wt_quic_crypto_recv_init(&recv);
  WT_EXPECT_U64("a fresh stream has delivered nothing", 0U, (uint64_t)recv.length);
  WT_EXPECT_U64("from offset zero", 0U, wt_quic_crypto_recv_read_offset(&recv));
  WT_EXPECT_U64("and has nothing available", 0U,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_TRUE("with no pointer to nothing", data == NULL);
  WT_EXPECT_INT("and no gap", 0, wt_quic_crypto_recv_has_gap(&recv));

  WT_EXPECT_OK("the message arrives at offset zero",
               wt_quic_crypto_recv_insert(&recv, 0U, k_message, sizeof(k_message) - 1U));
  available = wt_quic_crypto_recv_available(&recv, &data);
  WT_EXPECT_U64("all of it is available", (uint64_t)sizeof(k_message) - 1U, (uint64_t)available);
  WT_EXPECT_BYTES("and it is the message", k_message, data, sizeof(k_message) - 1U);
  WT_EXPECT_INT("with no gap", 0, wt_quic_crypto_recv_has_gap(&recv));

  /* Consuming part of it leaves the rest available, because the window slides. */
  WT_EXPECT_OK("two bytes are consumed", wt_quic_crypto_recv_consume(&recv, 2U));
  WT_EXPECT_U64("which moves the read offset", 2U, wt_quic_crypto_recv_read_offset(&recv));
  available = wt_quic_crypto_recv_available(&recv, &data);
  WT_EXPECT_U64("with the rest available", (uint64_t)sizeof(k_message) - 3U, (uint64_t)available);
  WT_EXPECT_BYTES("from where the consumer is", k_message + 2, data, sizeof(k_message) - 3U);

  /* More data at the offset just past what is held -- the read offset plus the length, which is where
   * the sender's next byte goes because it has no idea the consumer has taken two bytes. */
  WT_EXPECT_OK("more arrives at the end of what is held",
               wt_quic_crypto_recv_insert(&recv, 2U + (sizeof(k_message) - 3U), k_bang, 1U));
  available = wt_quic_crypto_recv_available(&recv, &data);
  WT_EXPECT_U64("and is available too", (uint64_t)sizeof(k_message) - 2U, (uint64_t)available);
  WT_EXPECT_U64("as one span", (uint64_t)sizeof(k_message) - 2U, (uint64_t)recv.length);

  WT_EXPECT_OK("everything is consumed",
               wt_quic_crypto_recv_consume(&recv, sizeof(k_message) - 2U));
  WT_EXPECT_U64("leaving the offset at the end", (uint64_t)sizeof(k_message),
                wt_quic_crypto_recv_read_offset(&recv));
  WT_EXPECT_U64("and nothing held", 0U, (uint64_t)recv.length);
  WT_EXPECT_U64("or available", 0U, (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
}

/* A message split across two packets: the second half arrives first, and nothing is delivered until
 * the first half fills the hole. */
static void test_out_of_order(void) {
  wt_quic_crypto_recv_t recv;
  const uint8_t *data = NULL;

  wt_quic_crypto_recv_init(&recv);
  WT_EXPECT_OK("the second half arrives first",
               wt_quic_crypto_recv_insert(&recv, 6U, k_message + 6, 5U));
  WT_EXPECT_U64("delivering nothing", 0U, (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_INT("and reporting a gap", 1, wt_quic_crypto_recv_has_gap(&recv));
  WT_EXPECT_U64("while holding what arrived", 11U, (uint64_t)recv.length);
  WT_EXPECT_U64("with the consumer still at the start", 0U, wt_quic_crypto_recv_read_offset(&recv));

  WT_EXPECT_OK("the first half fills the hole",
               wt_quic_crypto_recv_insert(&recv, 0U, k_message, 6U));
  WT_EXPECT_U64("and everything is delivered now", 11U,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_BYTES("in the order the message has", k_message, data, 11U);
  WT_EXPECT_INT("with the gap closed", 0, wt_quic_crypto_recv_has_gap(&recv));

  /* A duplicate changes nothing, and neither does an overlapping retransmission. */
  WT_EXPECT_OK("a duplicate is accepted", wt_quic_crypto_recv_insert(&recv, 6U, k_message + 6, 5U));
  WT_EXPECT_U64("and changes nothing", 11U, (uint64_t)recv.length);
  WT_EXPECT_OK("an overlapping range is accepted",
               wt_quic_crypto_recv_insert(&recv, 3U, k_message + 3, 6U));
  WT_EXPECT_U64("and changes nothing either", 11U, (uint64_t)recv.length);
  WT_EXPECT_U64("with the same bytes delivered", 11U,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_BYTES("unchanged", k_message, data, 11U);

  /* Everything already delivered: a peer repeating itself is ordinary. */
  WT_EXPECT_OK("all of it is consumed", wt_quic_crypto_recv_consume(&recv, 11U));
  WT_EXPECT_OK("and the peer sends it again",
               wt_quic_crypto_recv_insert(&recv, 0U, k_message, 11U));
  WT_EXPECT_U64("which delivers nothing", 0U,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_U64("and holds nothing", 0U, (uint64_t)recv.length);
}

/* The bound. A peer names the offsets, so a frame that would need memory beyond the buffer is refused
 * whole and the caller closes the connection with the error code the RFC gives it. */
static void test_the_bound(void) {
  wt_quic_crypto_recv_t recv;
  const uint8_t *data = NULL;
  uint8_t block[WT_QUIC_CRYPTO_BUFFER_MAX];

  memset(block, 0xa5, sizeof(block));
  wt_quic_crypto_recv_init(&recv);

  /* A frame whose start is beyond the window. */
  WT_EXPECT_STATUS(
      "a frame past the window is a limit", WT_ERR_LIMIT,
      wt_quic_crypto_recv_insert(&recv, (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX, block, 1U));
  WT_EXPECT_U64("and nothing is held", 0U, (uint64_t)recv.length);
  WT_EXPECT_U64("nor delivered", 0U, (uint64_t)wt_quic_crypto_recv_available(&recv, &data));

  /* A frame that starts inside the window and runs past its end. */
  WT_EXPECT_STATUS(
      "a frame that runs past the window is a limit", WT_ERR_LIMIT,
      wt_quic_crypto_recv_insert(&recv, (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX - 16U, block, 32U));
  WT_EXPECT_U64("and still nothing is held", 0U, (uint64_t)recv.length);

  /* A frame that ends exactly at the end fits. */
  WT_EXPECT_OK("a frame that fills the window fits",
               wt_quic_crypto_recv_insert(&recv, 0U, block, sizeof(block)));
  WT_EXPECT_U64("and is all held", (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX, (uint64_t)recv.length);
  WT_EXPECT_U64("and all delivered", (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));

  /* The window slides, which is what makes the bound workable: after the consumer takes the bytes, the
   * peer may send more at the offset it reached. */
  WT_EXPECT_OK("all of it is consumed", wt_quic_crypto_recv_consume(&recv, sizeof(block)));
  WT_EXPECT_OK(
      "and the peer sends the next block",
      wt_quic_crypto_recv_insert(&recv, (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX, block, sizeof(block)));
  WT_EXPECT_U64("which is delivered", (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_U64("from the offset the consumer reached", (uint64_t)WT_QUIC_CRYPTO_BUFFER_MAX,
                wt_quic_crypto_recv_read_offset(&recv));

  /* The offset itself is bounded by the protocol: RFC 9000 section 19.6 makes a CRYPTO offset plus its
   * length no more than 2^62-1. */
  wt_quic_crypto_recv_init(&recv);
  WT_EXPECT_STATUS("an offset past the protocol's bound is an overflow", WT_ERR_OVERFLOW,
                   wt_quic_crypto_recv_insert(&recv, (UINT64_C(1) << 62) - 1U, block, 2U));
  WT_EXPECT_STATUS("and a null payload with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_recv_insert(&recv, 0U, NULL, 4U));
  WT_EXPECT_OK("while a zero-length frame is accepted",
               wt_quic_crypto_recv_insert(&recv, 0U, NULL, 0U));
  WT_EXPECT_STATUS("and a null stream is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_recv_insert(NULL, 0U, block, 1U));
}

/* Consuming more than was delivered would move the read offset past data the module still holds, so it
 * is refused and the state is left alone. */
static void test_consume_errors(void) {
  wt_quic_crypto_recv_t recv;
  const uint8_t *data = NULL;

  wt_quic_crypto_recv_init(&recv);
  WT_EXPECT_STATUS("consuming from an empty stream is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_recv_consume(&recv, 1U));
  WT_EXPECT_OK("four bytes arrive", wt_quic_crypto_recv_insert(&recv, 0U, k_message, 4U));
  WT_EXPECT_STATUS("consuming more than arrived is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_recv_consume(&recv, 5U));
  WT_EXPECT_U64("with the offset unmoved", 0U, wt_quic_crypto_recv_read_offset(&recv));
  WT_EXPECT_U64("and the bytes still held", 4U,
                (uint64_t)wt_quic_crypto_recv_available(&recv, &data));
  WT_EXPECT_OK("consuming nothing is fine", wt_quic_crypto_recv_consume(&recv, 0U));
  WT_EXPECT_STATUS("and a null stream is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_recv_consume(NULL, 1U));
  WT_EXPECT_U64("with quiet queries on a null stream", 0U, wt_quic_crypto_recv_read_offset(NULL));
  WT_EXPECT_INT("that report no gap", 0, wt_quic_crypto_recv_has_gap(NULL));
}

/* The send half: what the handshake produced, handed out in ranges and kept for a retransmission. */
static void test_send(void) {
  wt_quic_crypto_send_t send;
  const uint8_t *data = NULL;
  uint64_t offset = 0U;
  size_t length = 0U;
  uint8_t big[WT_QUIC_CRYPTO_BUFFER_MAX];

  memset(big, 0x5a, sizeof(big));
  wt_quic_crypto_send_init(&send);
  WT_EXPECT_INT("a fresh sender has nothing pending", 0, wt_quic_crypto_send_pending(&send));
  WT_EXPECT_STATUS("and no range to hand out", WT_ERR_STATE,
                   wt_quic_crypto_send_next(&send, 100U, &offset, &data, &length));

  WT_EXPECT_OK("a message is appended",
               wt_quic_crypto_send_append(&send, k_message, sizeof(k_message) - 1U));
  WT_EXPECT_INT("which is pending", 1, wt_quic_crypto_send_pending(&send));

  /* Capped by the caller's packet budget. */
  WT_EXPECT_OK("the first range is handed out",
               wt_quic_crypto_send_next(&send, 4U, &offset, &data, &length));
  WT_EXPECT_U64("from offset zero", 0U, offset);
  WT_EXPECT_U64("capped at what the caller asked for", 4U, (uint64_t)length);
  WT_EXPECT_BYTES("with the first bytes", k_message, data, 4U);
  WT_EXPECT_OK("and recorded as sent", wt_quic_crypto_send_advance(&send, 4U));

  WT_EXPECT_OK("the next range continues",
               wt_quic_crypto_send_next(&send, 100U, &offset, &data, &length));
  WT_EXPECT_U64("from where the last stopped", 4U, offset);
  WT_EXPECT_U64("to the end of what is held", (uint64_t)sizeof(k_message) - 5U, (uint64_t)length);
  WT_EXPECT_BYTES("with the rest of the message", k_message + 4, data, length);
  WT_EXPECT_OK("which is sent too", wt_quic_crypto_send_advance(&send, length));
  WT_EXPECT_INT("so nothing is pending", 0, wt_quic_crypto_send_pending(&send));
  WT_EXPECT_STATUS("and there is no next range", WT_ERR_STATE,
                   wt_quic_crypto_send_next(&send, 100U, &offset, &data, &length));

  /* A loss of the first packet: its bytes are still held, which is the point of keeping them. */
  WT_EXPECT_OK("the first range is handed out again",
               wt_quic_crypto_send_retransmit(&send, 0U, 4U, &data));
  WT_EXPECT_BYTES("with the bytes it carried", k_message, data, 4U);
  WT_EXPECT_OK("and so is the second", wt_quic_crypto_send_retransmit(&send, 4U, 7U, &data));
  WT_EXPECT_BYTES("with its bytes", k_message + 4, data, 7U);
  WT_EXPECT_STATUS("a range that was never sent is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_send_retransmit(&send, 11U, 1U, &data));
  WT_EXPECT_STATUS("and one the buffer does not hold is a state error", WT_ERR_STATE,
                   wt_quic_crypto_send_retransmit(&send, 8U, 8U, &data));

  /* Appending after sending continues the stream at the right offset. */
  WT_EXPECT_OK("another message is appended", wt_quic_crypto_send_append(&send, k_bang, 1U));
  WT_EXPECT_OK("and handed out at the offset after the last",
               wt_quic_crypto_send_next(&send, 100U, &offset, &data, &length));
  WT_EXPECT_U64("which is the end of what was sent before", 11U, offset);
  WT_EXPECT_BYTES("with the new byte", k_bang, data, 1U);

  /* The bound, and the arguments. */
  wt_quic_crypto_send_init(&send);
  WT_EXPECT_OK("a full buffer is accepted", wt_quic_crypto_send_append(&send, big, sizeof(big)));
  WT_EXPECT_STATUS("and one more byte is refused", WT_ERR_LIMIT,
                   wt_quic_crypto_send_append(&send, k_bang, 1U));
  WT_EXPECT_STATUS("a null payload with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_send_append(&send, NULL, 1U));
  WT_EXPECT_STATUS("a null sender is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_send_append(NULL, big, 1U));
  WT_EXPECT_STATUS("advancing past what was sent is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_send_advance(&send, (size_t)WT_QUIC_CRYPTO_BUFFER_MAX + 1U));
  WT_EXPECT_STATUS("and a null output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_send_next(&send, 1U, NULL, &data, &length));
  WT_EXPECT_INT("with quiet queries on a null sender", 0, wt_quic_crypto_send_pending(NULL));
}

int main(void) {
  test_in_order();
  test_out_of_order();
  test_the_bound();
  test_consume_errors();
  test_send();

  WT_TEST_MAIN_END("wt_quic_crypto_stream");
}
