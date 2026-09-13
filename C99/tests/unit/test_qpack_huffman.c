/* QPACK's Huffman decoder (RFC 7541 appendix B, adopted by RFC 9204 section 4.1.2).
 *
 * The table and the worked example are extracted from RFC 7541 by
 * `tests/vectors/extract_rfc7541_huffman.py`, so the one vector here is the RFC's
 * own: the Huffman-coded `:authority` value from appendix C.4.1, which must decode
 * to the plaintext the RFC prints beside it. The rest are the refusals section 5.2
 * requires -- EOS in the string, wrong padding, a padding longer than seven bits,
 * and an output the caller did not leave room for. */

#include "wt_test.h"

#include "webtransport/http3/qpack.h"

#include "rfc7541_huffman_vectors.h"

static void test_the_rfc_example(void) {
  uint8_t decoded[64];
  size_t length = 0U;

  WT_EXPECT_OK("the RFC's example decodes",
               wt_qpack_huffman_decode(WT_RFC7541_HUFFMAN_EXAMPLE,
                                       WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH, decoded, sizeof(decoded),
                                       &length));
  WT_EXPECT_U64("to its plaintext length", WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT_LENGTH,
                (uint64_t)length);
  WT_EXPECT_BYTES("and its plaintext", WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT, decoded, length);

  /* The output buffer is the caller's bound, and the decoded size is the peer's to
   * choose: one byte short is a limit, not a partial decode. */
  WT_EXPECT_STATUS("a buffer one byte short is refused", WT_ERR_LIMIT,
                   wt_qpack_huffman_decode(WT_RFC7541_HUFFMAN_EXAMPLE,
                                           WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH, decoded,
                                           WT_RFC7541_HUFFMAN_EXAMPLE_PLAINTEXT_LENGTH - 1U,
                                           &length));
  WT_EXPECT_U64("and nothing is reported decoded", 0U, (uint64_t)length);
}

static void test_decoding_errors(void) {
  uint8_t decoded[64];
  size_t length = 0U;

  /* An empty string decodes to nothing, which is what a zero-length field value
   * is: no bits, no padding, no error. */
  WT_EXPECT_OK("an empty string decodes",
               wt_qpack_huffman_decode(NULL, 0U, decoded, sizeof(decoded), &length));
  WT_EXPECT_U64("to nothing", 0U, (uint64_t)length);

  /* Four 0xff bytes are thirty-two one-bits, and the first thirty of them are the
   * EOS code itself. Section 5.2 makes that a decoding error. */
  {
    static const uint8_t eos[4] = {0xffU, 0xffU, 0xffU, 0xffU};
    WT_EXPECT_STATUS("the EOS symbol is refused", WT_ERR_PROTOCOL,
                     wt_qpack_huffman_decode(eos, sizeof(eos), decoded, sizeof(decoded), &length));
  }

  /* Padding must be all ones. 0x00 is five zero bits -- the code for '0' -- and
   * then three zero bits of padding, which is not the EOS prefix. */
  {
    static const uint8_t bad_padding[1] = {0x00U};
    WT_EXPECT_STATUS("padding that is not all ones is refused", WT_ERR_PROTOCOL,
                     wt_qpack_huffman_decode(bad_padding, sizeof(bad_padding), decoded,
                                             sizeof(decoded), &length));
  }

  /* A null output length is the caller's own mistake, not the peer's. */
  WT_EXPECT_STATUS("a null output length is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_qpack_huffman_decode(WT_RFC7541_HUFFMAN_EXAMPLE,
                                           WT_RFC7541_HUFFMAN_EXAMPLE_LENGTH, decoded,
                                           sizeof(decoded), NULL));
}

int main(void) {
  test_the_rfc_example();
  test_decoding_errors();
  WT_TEST_MAIN_END("wt_qpack_huffman");
}
