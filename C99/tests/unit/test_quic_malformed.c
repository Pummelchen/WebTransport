/* Malformed and truncated QUIC wire input.
 *
 * Phase 1's second completion criterion is that "malformed wire input fails
 * deterministically without undefined behavior". The per-module tests check the
 * specific refusals each field rule implies; this file is the other half, and it
 * is deliberately blunt: a deterministic pseudo-random byte stream is fed to
 * every parser, and the requirements are that nothing crashes, that no parser
 * consumes more than it was given, and that the same input produces the same
 * answer twice.
 *
 * UNDER THE SANITIZERS THIS IS THE TEST THAT MATTERS. A random buffer is a far
 * better generator of the case nobody thought of than a list of cases somebody
 * did, and AddressSanitizer turns an out-of-bounds read into a failure rather
 * than into a value that looks plausible. The stream is seeded and reproducible,
 * so a failure here can be re-run exactly.
 */

#include "wt_test.h"

#include "webtransport/quic/frame.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/packet_number.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/quic/varint.h"

/* A small deterministic generator: xorshift64*, which is one multiply and two
 * shifts and has no state beyond the word. It is not a cryptographic generator
 * and does not need to be -- it is generating inputs, not secrets. */
typedef struct wt_rng {
  uint64_t state;
} wt_rng_t;

static uint64_t wt_rng_next(wt_rng_t *rng) {
  uint64_t x = rng->state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  rng->state = x;
  return x * UINT64_C(2685821657736338717);
}

/* A buffer biased towards structures that parse further: QUIC's first bytes are
 * mostly small values, so a uniform byte stream is almost entirely rejected at
 * the first field and never reaches the interesting paths. Half the bytes here
 * are drawn from a small set of plausible values. */
static void wt_rng_fill_structured(wt_rng_t *rng, uint8_t *out, size_t length) {
  static const uint8_t plausible[12] = {0x00U, 0x01U, 0x02U, 0x06U, 0x08U, 0x0fU,
                                        0x10U, 0x18U, 0x1cU, 0x30U, 0x31U,
                                        0x40U};
  size_t i;
  for (i = 0U; i < length; i++) {
    uint64_t draw = wt_rng_next(rng);
    if ((draw & 0x03U) != 0U) {
      out[i] = plausible[(size_t)((draw >> 8) % 12U)];
    } else {
      out[i] = (uint8_t)(draw & 0xFFU);
    }
  }
}

static void fuzz_varint(wt_rng_t *rng) {
  uint8_t buffer[64];
  size_t iteration;
  for (iteration = 0U; iteration < 4000U; iteration++) {
    size_t length = (size_t)(wt_rng_next(rng) % sizeof(buffer));
    wt_cursor_t c;
    uint64_t value = 0U;
    size_t size = 0U;
    wt_rng_fill_structured(rng, buffer, length);
    c = wt_cursor_init(buffer, length);
    if (wt_quic_varint_decode_sized(&c, &value, &size) == WT_OK) {
      /* A varint that parsed must have consumed exactly as many bytes as it
       * said, and must not have consumed more than the buffer held. */
      WT_EXPECT_TRUE("a parsed varint's size fits the buffer", size <= length);
      WT_EXPECT_TRUE("and the cursor agrees", c.offset == size);
      WT_EXPECT_TRUE("and the value is in range", value <= WT_QUIC_VARINT_MAX);
    } else {
      /* `c.offset <= length` was vacuous -- the cursor's own invariant makes it true of every cursor,
       * failed or not. The contract is exact: a failed decode on an empty buffer leaves the cursor
       * alone, and otherwise it has consumed ONLY the length byte it read before it could know the
       * rest was missing, and left the cursor failed so a later read sees nothing (varint.c). */
      if (length == 0U) {
        WT_EXPECT_U64("a failed varint on an empty buffer consumed nothing", 0U, (uint64_t)c.offset);
      } else {
        WT_EXPECT_U64("a failed varint consumed only its length byte", 1U, (uint64_t)c.offset);
        WT_EXPECT_TRUE("and left the cursor failed", wt_cursor_failed(&c) != 0);
      }
    }
  }
}

static void fuzz_frame(wt_rng_t *rng) {
  uint8_t buffer[256];
  size_t iteration;
  for (iteration = 0U; iteration < 4000U; iteration++) {
    size_t length = (size_t)(wt_rng_next(rng) % sizeof(buffer));
    wt_cursor_t c;
    wt_quic_frame_t frame;
    wt_quic_error_t error = 0U;
    wt_status_t first;
    wt_status_t second;
    wt_rng_fill_structured(rng, buffer, length);
    c = wt_cursor_init(buffer, length);
    first = wt_quic_frame_decode(&c, &frame, &error);
    /* Deterministic: the same bytes give the same answer. A parser that read
     * uninitialised memory would not. */
    {
      wt_cursor_t again = wt_cursor_init(buffer, length);
      wt_quic_frame_t frame2;
      wt_quic_error_t error2 = 0U;
      second = wt_quic_frame_decode(&again, &frame2, &error2);
      WT_EXPECT_INT("the same frame bytes give the same status", (long)first,
                    (long)second);
      if (first == WT_OK) {
        WT_EXPECT_INT("and the same kind", (long)frame.kind, (long)frame2.kind);
        WT_EXPECT_INT("and the same position", (long)c.offset, (long)again.offset);
      }
    }
    if (first == WT_OK) {
      WT_EXPECT_TRUE("a parsed frame consumed within the buffer",
                     c.offset <= length);
      /* And every frame that parsed can be encoded again and parsed back, which
       * is the round trip the completion criterion asks for. */
      {
        uint8_t encoded[512];
        wt_writer_t w = wt_writer_init(encoded, sizeof(encoded));
        if (wt_quic_frame_encode(&w, &frame) == WT_OK) {
          wt_cursor_t reparse = wt_cursor_init(encoded, wt_writer_offset(&w));
          wt_quic_frame_t back;
          wt_quic_error_t reparse_error = 0U;
          WT_EXPECT_STATUS("a parsed frame re-encodes and re-parses", WT_OK,
                           wt_quic_frame_decode(&reparse, &back,
                                                &reparse_error));
          WT_EXPECT_INT("to the same kind", (long)frame.kind, (long)back.kind);
        }
      }
    }
  }
}

static void fuzz_packet(wt_rng_t *rng) {
  uint8_t buffer[512];
  size_t iteration;
  for (iteration = 0U; iteration < 4000U; iteration++) {
    size_t length = (size_t)(wt_rng_next(rng) % sizeof(buffer));
    size_t cut;
    wt_quic_packet_kind_t kind = WT_QUIC_PACKET_KIND_SHORT;
    wt_rng_fill_structured(rng, buffer, length);
    (void)wt_quic_packet_kind(buffer, length, &kind);

    /* Every prefix must be safe to decode, which is the property a receive path
     * depends on when a datagram is truncated by the network. */
    for (cut = 0U; cut <= length; cut += (length / 8U) + 1U) {
      wt_cursor_t c = wt_cursor_init(buffer, cut);
      wt_quic_long_header_t long_header;
      wt_quic_short_header_t short_header;
      wt_quic_error_t error = 0U;
      if (wt_quic_long_header_decode(&c, &long_header, &error) == WT_OK) {
        WT_EXPECT_TRUE("a parsed long header fits its buffer",
                       long_header.total_len <= cut);
        WT_EXPECT_TRUE("and its header is inside it",
                       long_header.header_len <= long_header.total_len);
      }
      c = wt_cursor_init(buffer, cut);
      if (wt_quic_short_header_decode(&c, 8U, &short_header, &error) == WT_OK) {
        WT_EXPECT_TRUE("a parsed short header fits its buffer",
                       short_header.total_len <= cut);
      }
      /* A Retry is decoded from its own buffer. The assertion is gated on the decode having
       * SUCCEEDED, as the long- and short-header blocks above are: `retry.total_len <= cut` held
       * trivially on failure because the decoder zeroes `retry`, so the only Retry check in the
       * corpus could not fail. */
      {
        wt_quic_retry_packet_t retry;
        wt_quic_error_t retry_error = 0U;
        if (wt_quic_retry_packet_decode(buffer, cut, &retry, &retry_error) == WT_OK) {
          WT_EXPECT_TRUE("a parsed Retry fits its buffer",
                         retry.total_len <= cut);
        }
      }
    }
  }
}

static void fuzz_transport_parameters(wt_rng_t *rng) {
  uint8_t buffer[256];
  size_t iteration;
  for (iteration = 0U; iteration < 4000U; iteration++) {
    size_t length = (size_t)(wt_rng_next(rng) % sizeof(buffer));
    wt_quic_transport_parameters_t params;
    wt_quic_error_t error = 0U;
    wt_status_t status;
    wt_rng_fill_structured(rng, buffer, length);
    status = wt_quic_transport_parameters_decode(buffer, length, &params,
                                                 &error);
    if (status == WT_OK) {
      WT_EXPECT_TRUE("a parsed parameter list fits the bound",
                     params.count <= WT_QUIC_MAX_TRANSPORT_PARAMETERS);
      /* Every entry's value must lie inside the buffer it came from. */
      {
        size_t i;
        for (i = 0U; i < params.count; i++) {
          WT_EXPECT_TRUE("a parameter's value lies inside the buffer",
                         params.entries[i].value >= buffer &&
                             params.entries[i].value <= buffer + length);
          WT_EXPECT_TRUE("and its length fits",
                         params.entries[i].length <= length);
        }
      }
      /* The check either accepts it or names an offender that is in the list. */
      {
        uint64_t offender = 0U;
        if (wt_quic_transport_parameters_check(&params, 0, &error, &offender) !=
            WT_OK) {
          size_t i;
          int found = 0;
          for (i = 0U; i < params.count; i++) {
            if (params.entries[i].id == offender) found = 1;
          }
          WT_EXPECT_INT("a refused parameter is one the peer sent", 1, found);
        }
      }
    }
  }
}

static void fuzz_packet_number(wt_rng_t *rng) {
  size_t iteration;
  for (iteration = 0U; iteration < 4000U; iteration++) {
    uint64_t truncated = wt_rng_next(rng);
    size_t byte_count = (size_t)(wt_rng_next(rng) % 6U);
    uint64_t largest = wt_rng_next(rng) % WT_QUIC_PACKET_NUMBER_MAX;
    uint64_t mask = wt_quic_packet_number_window(byte_count);
    uint64_t value = wt_quic_packet_number_decode(truncated, byte_count, largest);
    if (byte_count == 0U || byte_count > 4U) {
      WT_EXPECT_U64("an invalid width decodes to zero", 0U, value);
      continue;
    }
    truncated &= (mask - 1U);
    value = wt_quic_packet_number_decode(truncated, byte_count, largest);
    /* The reconstruction is never below the window's floor: it stays in the
     * epoch of the expectation or the one below it, and never jumps further. */
    WT_EXPECT_TRUE("a reconstruction stays near the expectation",
                   value <= largest + mask);
    /* And the low bits are the truncated value, which is what makes the
     * reconstruction a reconstruction. */
    WT_EXPECT_U64("the low bits are the truncated value", truncated,
                  value & (mask - 1U));
  }
}

int main(void) {
  /* A fixed seed: a failure here is reproducible, and the corpus is the same
   * every run so a new failure is a change in the code. */
  wt_rng_t rng;
  rng.state = UINT64_C(0x9E3779B97F4A7C15);

  fuzz_varint(&rng);
  fuzz_frame(&rng);
  fuzz_packet(&rng);
  fuzz_transport_parameters(&rng);
  fuzz_packet_number(&rng);

  WT_TEST_MAIN_END("wt_quic_malformed");
}
