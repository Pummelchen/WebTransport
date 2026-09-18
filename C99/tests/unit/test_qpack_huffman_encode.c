/* QPACK's Huffman encoder (RFC 7541 appendix B, adopted by RFC 9204 section 4.1.2).
 *
 * The encoder and the decoder read the same table, so a round trip alone would
 * pass against a table that is wrong for both. The test that matters is the RFC's
 * own worked example: appendix C.4.1's `:authority` value must encode to exactly
 * the twelve bytes the RFC prints, which is a check neither side of this
 * implementation can satisfy by being self-consistent. The exhaustive pass over
 * all 256 symbols then says the table's short entries and its long ones both
 * survive the bit packing. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

#include "rfc7541_huffman_vectors.h"

static void test_the_rfc_example(void) {
  uint8_t encoded[64];
  size_t length = 0U;
  size_t size = 0U;

  WT_EXPECT_OK("the example's size is known",
               wt_qpack_huffman_encoded_size(WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT,
                                             WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT_LENGTH, &size));
  WT_EXPECT_U64("and is what the RFC prints", WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH, (uint64_t)size);

  WT_EXPECT_OK("the example encodes",
               wt_qpack_huffman_encode(WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT,
                                       WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT_LENGTH, encoded,
                                       sizeof(encoded), &length));
  WT_EXPECT_U64("to the RFC's own bytes", WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH, (uint64_t)length);
  WT_EXPECT_BYTES("byte for byte", WT_RFC7541_HUFFMAN_EXAMPLE, encoded, length);
}

static void test_every_symbol_round_trips(void) {
  unsigned symbol;

  for (symbol = 0U; symbol < 256U; symbol++) {
    uint8_t plain = (uint8_t)symbol;
    uint8_t encoded[4];
    uint8_t decoded[4];
    size_t encoded_length = 0U;
    size_t decoded_length = 0U;

    WT_EXPECT_OK("a symbol encodes",
                 wt_qpack_huffman_encode(&plain, 1U, encoded, sizeof(encoded), &encoded_length));
    WT_EXPECT_OK("and decodes", wt_qpack_huffman_decode(encoded, encoded_length, decoded,
                                                        sizeof(decoded), &decoded_length));
    WT_EXPECT_U64("to one byte", 1U, (uint64_t)decoded_length);
    WT_EXPECT_U64("with the same value", (uint64_t)symbol, (uint64_t)decoded[0]);
  }
}

static void test_packing_and_limits(void) {
  static const uint8_t word[4] = {'t', 'e', 's', 't'};
  uint8_t encoded[8];
  uint8_t decoded[8];
  size_t length = 0U;
  size_t size = 0U;
  size_t decoded_length = 0U;

  WT_EXPECT_OK("a word encodes",
               wt_qpack_huffman_encode(word, sizeof(word), encoded, sizeof(encoded), &length));
  WT_EXPECT_OK("and decodes",
               wt_qpack_huffman_decode(encoded, length, decoded, sizeof(decoded), &decoded_length));
  WT_EXPECT_U64("to the same length", (uint64_t)sizeof(word), (uint64_t)decoded_length);
  WT_EXPECT_BYTES("and the same bytes", word, decoded, decoded_length);

  WT_EXPECT_OK("its encoded size is known",
               wt_qpack_huffman_encoded_size(word, sizeof(word), &size));
  WT_EXPECT_U64("and matches", (uint64_t)length, (uint64_t)size);

  /* A buffer one byte short is a limit, not a partial string: a half-written
   * representation is one the peer would decode into something else. */
  WT_EXPECT_STATUS("a short buffer is refused", WT_ERR_LIMIT,
                   wt_qpack_huffman_encode(word, sizeof(word), encoded, length - 1U, &length));
  WT_EXPECT_U64("and nothing is reported written", 0U, (uint64_t)length);

  /* An empty string is no bytes, and its size is zero. */
  WT_EXPECT_OK("an empty string encodes",
               wt_qpack_huffman_encode(NULL, 0U, encoded, sizeof(encoded), &length));
  WT_EXPECT_U64("to nothing", 0U, (uint64_t)length);
  WT_EXPECT_OK("with a size of zero", wt_qpack_huffman_encoded_size(NULL, 0U, &size));
  WT_EXPECT_U64("as promised", 0U, (uint64_t)size);

  WT_EXPECT_STATUS("a null output length is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_qpack_huffman_encode(word, sizeof(word), encoded, sizeof(encoded), NULL));
}

int main(void) {
  test_the_rfc_example();
  test_every_symbol_round_trips();
  test_packing_and_limits();
  WT_TEST_MAIN_END("wt_qpack_huffman_encode");
}
