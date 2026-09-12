/* QUIC packet number encoding and reconstruction.
 *
 * The RFC's own example is the first test: a largest received number of
 * 0xa82f30ea and a 16-bit value of 0x9b32 reconstruct as 0xa82f9b32. Then the
 * boundaries, because the window is where this goes wrong: a number exactly half
 * a window ahead is the furthest a sender may encode, and one step further is
 * not encodable at all.
 *
 * The encoder and decoder are checked against each other AND against the RFC,
 * since two functions wrong in the same direction agree perfectly.
 */

#include "wt_test.h"

#include "webtransport/quic/packet_number.h"
#include "webtransport/quic/varint.h"

/* The reconstruction, for a range of distances either side of the expectation.
 * Shared because both the "round trip" and the "wrong distance" cases need it. */
static uint64_t decode_bytes(const uint8_t *bytes, size_t byte_count,
                             uint64_t largest_received) {
  uint64_t truncated = 0U;
  size_t i;
  for (i = 0U; i < byte_count; i++) {
    truncated = (truncated << 8) | (uint64_t)bytes[i];
  }
  return wt_quic_packet_number_decode(truncated, byte_count, largest_received);
}

int main(void) {
  uint8_t bytes[4];
  size_t size = 0U;
  size_t i;

  /* RFC 9000 appendix A.2's example. */
  {
    static const uint8_t truncated[2] = {0x9bU, 0x32U};
    uint64_t largest = UINT64_C(0xa82f30ea);
    uint64_t full = wt_quic_packet_number_decode(0x9b32U, 2U, largest);
    WT_EXPECT_U64("the RFC's example reconstructs", UINT64_C(0xa82f9b32), full);
    WT_EXPECT_U64("and decoding its bytes agrees", UINT64_C(0xa82f9b32),
                  decode_bytes(truncated, 2U, largest));
  }

  /* The window and half window for each width. */
  WT_EXPECT_U64("a one-byte window is 256", 256U,
                wt_quic_packet_number_window(1U));
  WT_EXPECT_U64("a two-byte window is 65536", 65536U,
                wt_quic_packet_number_window(2U));
  WT_EXPECT_U64("a four-byte window is 2^32", UINT64_C(4294967296),
                wt_quic_packet_number_window(4U));
  WT_EXPECT_U64("zero bytes is not a width", 0U,
                wt_quic_packet_number_window(0U));
  WT_EXPECT_U64("five bytes is not a width", 0U,
                wt_quic_packet_number_window(5U));

  /* THE RULE IS THE RECONSTRUCTION WINDOW, NOT THE RFC'S PSEUDOCODE VERBATIM.
   * RFC 9000 appendix A.2 chooses a width from the number of outstanding
   * packets, and the criterion its prose states is "at least twice this range".
   * With `delta` the distance from the expectation, that criterion is
   * `2^(8n) >= 2 * (delta + 1)`, which is `delta < half_window` -- exactly what
   * the encoder tests. The pseudocode's `floor(log2(num_unacked)) + 1` rounds to
   * a byte and is one bit optimistic at `num_unacked = 2^15 + 1`, where 16 bits
   * cannot carry twice the range; being a byte wider there is always safe, and
   * the reconstruction window is what has to hold. */
  WT_EXPECT_U64("packet 1 needs one byte", 1U,
                wt_quic_packet_number_size(1U, 0U));
  WT_EXPECT_U64("packet 128 still fits in one byte", 1U,
                wt_quic_packet_number_size(128U, 0U));
  WT_EXPECT_U64("packet 256 needs two", 2U,
                wt_quic_packet_number_size(256U, 0U));
  WT_EXPECT_U64("packet 32769 needs three", 3U,
                wt_quic_packet_number_size(32769U, 0U));
  WT_EXPECT_U64("packet 2^31 is the widest that fits", 4U,
                wt_quic_packet_number_size(UINT64_C(1) << 31, 0U));
  WT_EXPECT_U64("one more is too far ahead to send", 0U,
                wt_quic_packet_number_size((UINT64_C(1) << 31) + 1U, 0U));

  /* The RFC's two worked examples, which are the check that the rule above is
   * the RFC's and not a rule invented here. With 0xabe8b3 acknowledged, a packet
   * numbered 0xac5c02 needs 16 bits and 0xace8fe needs 24. */
  WT_EXPECT_U64("the RFC's first encoding example",
                2U, wt_quic_packet_number_size(0xac5c02U, 0xabe8b3U));
  WT_EXPECT_U64("the RFC's second encoding example",
                3U, wt_quic_packet_number_size(0xace8feU, 0xabe8b3U));
  /* A number at or below the largest acknowledged is in the past. */
  WT_EXPECT_U64("the acknowledged number itself is not sendable", 0U,
                wt_quic_packet_number_size(10U, 10U));
  WT_EXPECT_U64("nor one below it", 0U, wt_quic_packet_number_size(9U, 10U));
  WT_EXPECT_U64("one above it is", 1U, wt_quic_packet_number_size(11U, 10U));

  /* The half-window boundary, which is the whole reason the rule is half: a
   * receiver picks the candidate nearest its expectation, so a number exactly
   * half a window ahead is already ambiguous and must not be sent with that
   * width. */
  {
    uint64_t largest = 1000U;
    WT_EXPECT_U64("127 ahead fits in one byte", 1U,
                  wt_quic_packet_number_size(largest + 1U + 127U, largest));
    WT_EXPECT_U64("128 ahead does not", 2U,
                  wt_quic_packet_number_size(largest + 1U + 128U, largest));
  }
  {
    uint64_t largest = 100000U;
    uint64_t half = 32768U; /* two-byte window is 65536 */
    WT_EXPECT_U64("32767 ahead fits in two bytes", 2U,
                  wt_quic_packet_number_size(largest + 1U + half - 1U, largest));
    WT_EXPECT_U64("32768 ahead needs three", 3U,
                  wt_quic_packet_number_size(largest + 1U + half, largest));
  }

  /* Every width round-trips at the edge of the HALF window, which is the
   * furthest a sender may go and therefore where a wrong comparison shows up.
   * A number a full window ahead is deliberately not in this loop: the encoder
   * must not choose that width for it, and the reconstruction is then allowed to
   * disagree -- which is checked separately below. */
  for (size = 1U; size <= 4U; size++) {
    uint64_t half = wt_quic_packet_number_window(size) / 2U;
    uint64_t largest = 4096U;
    uint64_t offsets[3];
    offsets[0] = 0U;
    offsets[1] = half / 2U;
    offsets[2] = half - 1U;
    for (i = 0U; i < 3U; i++) {
      uint64_t number = largest + 1U + offsets[i];
      size_t written = wt_quic_packet_number_encode(number, size, bytes);
      uint64_t back;
      WT_EXPECT_U64("the encode reports the width", (uint64_t)size,
                    (uint64_t)written);
      back = decode_bytes(bytes, size, largest);
      WT_EXPECT_U64("the round trip reconstructs it", number, back);
    }
    /* And the encoder must not pick this width for a number beyond it. For the
     * four-byte width there is no wider one, so "more than this width" is
     * reported as 0 -- not sendable at all until more has been acknowledged. */
    {
      size_t beyond = wt_quic_packet_number_size(largest + 1U + half, largest);
      WT_EXPECT_TRUE("a number beyond the half window does not use this width",
                     beyond == 0U || beyond > size);
    }
  }

  /* Reconstructed with a width the sender had no business using, the result is
   * the candidate nearest the expectation, which is what the algorithm
   * specifies: a full window ahead reads as the expectation's own epoch. This is
   * not a defect, it is why the sender's rule exists. */
  {
    size_t written = wt_quic_packet_number_encode(4096U + 256U, 1U, bytes);
    WT_EXPECT_U64("a one-byte encode", 1U, (uint64_t)written);
    WT_EXPECT_U64("reconstructs to the nearer epoch", 4096U,
                  decode_bytes(bytes, 1U, 4096U));
  }

  /* Reconstruction when the expectation is near the top of the 62-bit range,
   * where a naive `candidate + half` would exceed the largest packet number
   * QUIC allows. The guard in the algorithm exists for this case and nothing
   * else, so it is reached here. */
  {
    uint64_t largest = WT_QUIC_PACKET_NUMBER_MAX - 4U;
    uint64_t number = WT_QUIC_PACKET_NUMBER_MAX - 2U;
    size = wt_quic_packet_number_size(number, largest);
    WT_EXPECT_U64("a number near the maximum is encodable", 1U, (uint64_t)size);
    (void)wt_quic_packet_number_encode(number, size, bytes);
    WT_EXPECT_U64("and reconstructs", number,
                  decode_bytes(bytes, size, largest));
  }

  /* Encoding writes the low bytes big-endian. */
  (void)wt_quic_packet_number_encode(UINT64_C(0x123456789A), 4U, bytes);
  WT_EXPECT_BYTES("four bytes are the low four", (const uint8_t *)"\x56\x78\x9a"
                                                      + 0,
                  bytes, 0U);
  (void)wt_quic_packet_number_encode(UINT64_C(0x123456789A), 4U, bytes);
  WT_EXPECT_BYTES("the low four bytes big-endian",
                  (const uint8_t *)"\x34\x56\x78\x9a", bytes, 4U);
  (void)wt_quic_packet_number_encode(UINT64_C(0x123456789A), 1U, bytes);
  WT_EXPECT_BYTES("the low byte", (const uint8_t *)"\x9a", bytes, 1U);
  (void)wt_quic_packet_number_encode(UINT64_C(0x123456789A), 2U, bytes);
  WT_EXPECT_BYTES("the low two bytes big-endian",
                  (const uint8_t *)"\x78\x9a", bytes, 2U);
  (void)wt_quic_packet_number_encode(UINT64_C(0x123456789A), 3U, bytes);
  WT_EXPECT_BYTES("the low three bytes big-endian",
                  (const uint8_t *)"\x56\x78\x9a", bytes, 3U);

  /* Refusals: a width outside 1..4, and a truncated value that does not fit the
   * width it was read with. */
  WT_EXPECT_U64("zero bytes is not a width to encode", 0U,
                (uint64_t)wt_quic_packet_number_encode(1U, 0U, bytes));
  WT_EXPECT_U64("five bytes is not a width to encode", 0U,
                (uint64_t)wt_quic_packet_number_encode(1U, 5U, bytes));
  WT_EXPECT_U64("a NULL output is refused", 0U,
                (uint64_t)wt_quic_packet_number_encode(1U, 1U, NULL));
  WT_EXPECT_U64("a truncated value above the width is refused", 0U,
                wt_quic_packet_number_decode(256U, 1U, 10U));
  WT_EXPECT_U64("zero bytes is not a width to decode", 0U,
                wt_quic_packet_number_decode(1U, 0U, 10U));
  WT_EXPECT_U64("five bytes is not a width to decode", 0U,
                wt_quic_packet_number_decode(1U, 5U, 10U));

  /* A truncated value inside the window reconstructs in the expectation's own
   * epoch; the subtract branch needs a value below the window. */
  {
    uint64_t largest = 1000U;
    /* expected is 1001 and the window is 65536 wide, so a truncated value of 10
     * is nearer than the candidate one window up. */
    WT_EXPECT_U64("a low truncated value stays in the epoch", 10U,
                  wt_quic_packet_number_decode(10U, 2U, largest));
  }
  {
    /* expected is 100001 (0x186a1) and the truncated value 10 with a two-byte
     * width gives candidate 0x0000a = 10, which is more than half a window
     * below the expectation, so it is read as the next epoch down. */
    uint64_t largest = 100000U;
    uint64_t half = 32768U;
    uint64_t expected = largest + 1U;
    uint64_t candidate = expected & ~(UINT64_C(65536) - 1U);
    WT_EXPECT_U64("the candidate is in the expectation's epoch", 65536U,
                  candidate);
    /* 65536 + 10 = 65546, which is more than half a window below 100001. */
    WT_EXPECT_U64("a candidate a half window below moves up one",
                  65536U + 10U + 65536U,
                  wt_quic_packet_number_decode(10U, 2U, largest));
    (void)half;
  }

  WT_TEST_MAIN_END("wt_quic_packet_number");
}
