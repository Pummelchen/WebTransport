/* The WebTransport error-code mapping (draft-ietf-webtrans-http3-16 section 4.4) and the draft's registered codes
 * (section 9.5).
 *
 * The property that matters is an ALGEBRAIC one, so the test carries the section's own pseudocode as an
 * independent implementation and compares against it: a mapping written from the same reading twice could be
 * wrong twice, but a mapping compared with `first + n + floor(n / 0x1e)` computed a second way is being checked.
 * The two ends of the range are asserted as LITERALS from the section -- 0x00000000 maps to 0x52e4a40fa8db and
 * 0xffffffff to 0x52e5ac983162 -- because those are the numbers a peer was told.
 *
 * The reserved codepoints are the subtle half: RFC 9114 section 8.1 reserves the codepoints of the form
 * `0x1f * N + 0x21`, section 4.4 says they "have to be skipped when mapping", and both directions are checked
 * here -- the forward map never produces one, and the reverse map refuses one rather than turning a protocol code
 * into an application code.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/error.h"

/* The section's pseudocode, written the way the section writes it. */
static uint64_t oracle_to_http3(uint32_t application_error) {
  uint64_t n = (uint64_t)application_error;
  return UINT64_C(0x52e4a40fa8db) + n + (n / UINT64_C(0x1e));
}

static int is_reserved(uint64_t codepoint) {
  return (codepoint - UINT64_C(0x21)) % UINT64_C(0x1f) == 0U;
}

int main(void) {
  uint32_t round_trip = 0U;
  size_t i;

  /* The two ends, as the section states them. */
  WT_EXPECT_U64("zero maps to the first codepoint of the range", UINT64_C(0x52e4a40fa8db),
                wt_webtransport_error_to_http3(0U));
  WT_EXPECT_U64("and 0xffffffff to the last", UINT64_C(0x52e5ac983162),
                wt_webtransport_error_to_http3(UINT32_C(0xffffffff)));
  WT_EXPECT_U64("which is the range's own last codepoint", WT_WEBTRANSPORT_APPLICATION_ERROR_LAST,
                wt_webtransport_error_to_http3(UINT32_C(0xffffffff)));
  WT_EXPECT_U64("and the range's first is what zero maps to", WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST,
                wt_webtransport_error_to_http3(0U));

  /* The oracle, over the boundaries of the gap pattern and a stride across the space: 0x1e codes are followed by
   * one reserved codepoint, so 0x1e, 0x1f, 0x3c and their neighbours are where an off-by-one would live. */
  {
    static const uint32_t k_samples[] = {0U,          1U,          0x1dU,       0x1eU,       0x1fU,
                                         0x3cU,       0x3dU,       0x3eU,       0x1000U,     0x12345678U,
                                         0xfffffffeU, 0xffffffffU};
    for (i = 0U; i < sizeof(k_samples) / sizeof(k_samples[0]); i++) {
      WT_EXPECT_U64("the mapping matches the section's pseudocode", oracle_to_http3(k_samples[i]),
                    wt_webtransport_error_to_http3(k_samples[i]));
    }
  }
  for (i = 0U; i < 512U; i++) {
    uint32_t sample = (uint32_t)(UINT32_C(0xffffffff) / 511U * (uint32_t)i);
    WT_EXPECT_U64("and across a stride of the whole space", oracle_to_http3(sample),
                  wt_webtransport_error_to_http3(sample));
  }

  /* No application error maps to a reserved codepoint, which is what "skipped when mapping" means. */
  for (i = 0U; i < 4096U; i++) {
    uint64_t codepoint = wt_webtransport_error_to_http3((uint32_t)(i * UINT32_C(0x10001)));
    WT_EXPECT_INT("no mapped codepoint is a reserved one", 0, is_reserved(codepoint));
    WT_EXPECT_INT("and every one is in the registered range", 1,
                  wt_webtransport_error_is_application_range(codepoint));
  }

  /* And back again. */
  WT_EXPECT_OK("the first codepoint carries application error zero",
               wt_webtransport_error_from_http3(WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST, &round_trip));
  WT_EXPECT_U64("which is zero", 0U, (uint64_t)round_trip);
  WT_EXPECT_OK("the last carries 0xffffffff",
               wt_webtransport_error_from_http3(WT_WEBTRANSPORT_APPLICATION_ERROR_LAST, &round_trip));
  WT_EXPECT_U64("which is 0xffffffff", (uint64_t)UINT32_C(0xffffffff), (uint64_t)round_trip);
  {
    static const uint32_t k_samples[] = {0U, 1U, 0x1dU, 0x1eU, 0x1fU, 0x3cU, 0x12345678U, 0xffffffffU};
    for (i = 0U; i < sizeof(k_samples) / sizeof(k_samples[0]); i++) {
      WT_EXPECT_OK("a mapped code comes back",
                   wt_webtransport_error_from_http3(wt_webtransport_error_to_http3(k_samples[i]),
                                                    &round_trip));
      WT_EXPECT_U64("as the value it was", (uint64_t)k_samples[i], (uint64_t)round_trip);
    }
  }

  /* The refusals: below the range, above it, and a RESERVED codepoint inside it. The reserved one is built the
   * way the reservation is written -- `0x1f * N + 0x21` for the first N that lands in the range -- rather than
   * transcribed, so the test cannot agree with a wrong constant. */
  WT_EXPECT_STATUS("a codepoint below the range is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_error_from_http3(WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST - 1U,
                                                    &round_trip));
  WT_EXPECT_STATUS("and one above it", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_error_from_http3(WT_WEBTRANSPORT_APPLICATION_ERROR_LAST + 1U,
                                                    &round_trip));
  {
    uint64_t reserved = UINT64_C(0x1f) * ((WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST - UINT64_C(0x21)) /
                                          UINT64_C(0x1f)) + UINT64_C(0x21);
    while (reserved < WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST) reserved += UINT64_C(0x1f);
    WT_EXPECT_INT("the reserved codepoint this test built is one", 1, is_reserved(reserved));
    WT_EXPECT_INT("and it is inside the range", 1,
                  reserved >= WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST &&
                      reserved <= WT_WEBTRANSPORT_APPLICATION_ERROR_LAST);
    WT_EXPECT_STATUS("a reserved codepoint is refused rather than mapped", WT_ERR_INVALID_ARGUMENT,
                     wt_webtransport_error_from_http3(reserved, &round_trip));
    WT_EXPECT_INT("and the same test says it is not an application code", 0,
                  wt_webtransport_error_is_application_range(reserved));
  }
  WT_EXPECT_STATUS("a null output is a caller error", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_error_from_http3(WT_WEBTRANSPORT_APPLICATION_ERROR_FIRST, NULL));

  /* The five codes section 9.5 registers, as LITERALS: these are the numbers on the wire, they are HTTP/3 error
   * codes rather than application ones, and a mapping that swallowed them would name something else entirely. */
  WT_EXPECT_U64("WT_BUFFERED_STREAM_REJECTED is 0x3994bd84", UINT64_C(0x3994bd84),
                WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED);
  WT_EXPECT_U64("WT_SESSION_GONE is 0x170d7b68", UINT64_C(0x170d7b68),
                WT_WEBTRANSPORT_ERROR_SESSION_GONE);
  WT_EXPECT_U64("WT_FLOW_CONTROL_ERROR is 0x045d4487", UINT64_C(0x045d4487),
                WT_WEBTRANSPORT_ERROR_FLOW_CONTROL);
  WT_EXPECT_U64("and the name this tree used before still means it", WT_WEBTRANSPORT_ERROR_FLOW_CONTROL,
                WT_WEBTRANSPORT_FLOW_CONTROL_ERROR);
  WT_EXPECT_U64("WT_ALPN_ERROR is 0x0817b3dd", UINT64_C(0x0817b3dd), WT_WEBTRANSPORT_ERROR_ALPN);
  WT_EXPECT_U64("WT_REQUIREMENTS_NOT_MET is 0x212c0d48", UINT64_C(0x212c0d48),
                WT_WEBTRANSPORT_ERROR_REQUIREMENTS_NOT_MET);
  /* The protocol codes are NOT in the application range, which is why they must not be mapped through it: none of
   * the five is one an application error could have produced. */
  {
    static const uint64_t k_protocol_codes[] = {
        UINT64_C(0x3994bd84), UINT64_C(0x170d7b68), UINT64_C(0x045d4487), UINT64_C(0x0817b3dd),
        UINT64_C(0x212c0d48)};
    for (i = 0U; i < sizeof(k_protocol_codes) / sizeof(k_protocol_codes[0]); i++) {
      WT_EXPECT_INT("a registered protocol code is outside the application range", 0,
                    wt_webtransport_error_is_application_range(k_protocol_codes[i]));
    }
  }

  WT_TEST_MAIN_END("wt_webtransport_error");
}
