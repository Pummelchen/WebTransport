/* A malformed-input corpus for HTTP/3, QPACK and the WebTransport session layer (Phase 10).
 *
 * The plan's test port asks for malformed input and resource exhaustion, and this is how this project does
 * both: a deterministic pseudo-random byte stream fed to every parser in the layer, with the assertion that a
 * refusal is a STATUS and never a crash. Under AddressSanitizer and UndefinedBehaviorSanitizer a read past the
 * end of a buffer is a failure rather than a plausible value, so a corpus is a better generator of the case
 * nobody thought of than a list of cases somebody did -- which is the argument already written beside the QUIC
 * corpus, and the reason the same treatment is owed to the layers above it.
 *
 * The corpus also asserts that it REFUSES things. A fuzz test whose inputs all happen to be accepted proves
 * only that the parser does not crash on valid input, and a generator change that made every input valid would
 * silently turn this suite into a no-op.
 */

#include "wt_test.h"

#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/http3/settings.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

#define WT_CORPUS_ITERATIONS 4000U
#define WT_CORPUS_MAX_BYTES 128U

/* The same deterministic generator the QUIC corpus uses: xorshift64*, one multiply and two shifts. It
 * generates inputs, not secrets. */
typedef struct corpus_rng {
  uint64_t state;
} corpus_rng_t;

static uint64_t corpus_next(corpus_rng_t *rng) {
  uint64_t x = rng->state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  rng->state = x;
  return x * UINT64_C(2685821657736338717);
}

/* Biased towards structures that parse further: an HTTP/3 length is usually short, a frame type is usually one
 * of the small ones, and QPACK's prefix bytes are mostly small. A uniform stream is rejected at the first
 * field and never reaches the paths worth testing. */
static void corpus_fill(corpus_rng_t *rng, uint8_t *out, size_t length) {
  static const uint8_t plausible[16] = {0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
                                        0x08U, 0x0dU, 0x10U, 0x21U, 0x40U, 0x41U, 0x54U, 0x7fU};
  size_t i;
  for (i = 0U; i < length; i++) {
    uint64_t draw = corpus_next(rng);
    if ((draw & 0x03U) != 0U) {
      out[i] = plausible[(size_t)((draw >> 8) % 16U)];
    } else {
      out[i] = (uint8_t)(draw & 0xFFU);
    }
  }
}

static void test_the_frame_and_settings_parsers(void) {
  corpus_rng_t rng;
  uint8_t bytes[WT_CORPUS_MAX_BYTES];
  unsigned refused = 0U;
  unsigned accepted = 0U;
  unsigned iteration;

  rng.state = UINT64_C(0x5eed1234);
  for (iteration = 0U; iteration < WT_CORPUS_ITERATIONS; iteration++) {
    wt_cursor_t cursor;
    wt_http3_frame_t frame;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    size_t length = (size_t)(corpus_next(&rng) % WT_CORPUS_MAX_BYTES) + 1U;

    corpus_fill(&rng, bytes, length);
    cursor = wt_cursor_init(bytes, length);
    if (wt_http3_frame_decode(&cursor, &frame, &error) == WT_OK) {
      accepted++;
    } else {
      refused++;
    }

    /* The SETTINGS payload is a sequence of identifier/value pairs, and a malformed one is the parser's
     * refusal rather than an identifier nobody recognises. */
    {
      wt_http3_settings_t settings;
      wt_http3_error_t settings_error = WT_HTTP3_NO_ERROR;
      if (wt_http3_settings_parse(bytes, length, &settings, &settings_error) == WT_OK) {
        accepted++;
      } else {
        refused++;
      }
    }
  }
  /* The corpus must refuse most of what it generates, or it is not testing a parser's boundaries at all. */
  WT_EXPECT_TRUE("the corpus refused plenty", refused > accepted);
  WT_EXPECT_TRUE("and accepted some, so the acceptance path is exercised too", accepted > 0U);
}

static void test_the_capsule_and_WebTransport_parsers(void) {
  corpus_rng_t rng;
  uint8_t bytes[WT_CORPUS_MAX_BYTES];
  unsigned refused = 0U;
  unsigned accepted = 0U;
  unsigned iteration;

  rng.state = UINT64_C(0xcafe5678);
  for (iteration = 0U; iteration < WT_CORPUS_ITERATIONS; iteration++) {
    size_t length = (size_t)(corpus_next(&rng) % WT_CORPUS_MAX_BYTES) + 1U;
    corpus_fill(&rng, bytes, length);

    {
      wt_cursor_t cursor = wt_cursor_init(bytes, length);
      wt_webtransport_capsule_t capsule;
      wt_http3_error_t error = WT_HTTP3_NO_ERROR;
      if (wt_webtransport_capsule_decode(&cursor, 1024U, &capsule, &error) == WT_OK) {
        accepted++;
        /* A capsule that decoded is a capsule whose VALUE must also be handled: the close capsule's code and
         * reason, and the flow-control capsules' numbers. This is where a decoder that trusted its own length
         * would be caught. */
        if (capsule.type == WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION) {
          uint32_t code = 0U;
          (void)wt_webtransport_close_session_parse(&capsule, &code, NULL, NULL, &error);
        } else if (capsule.type == WT_CAPSULE_MAX_DATA) {
          uint64_t maximum = 0U;
          (void)wt_webtransport_max_data_parse(&capsule, &maximum, &error);
        } else if (capsule.type == WT_CAPSULE_MAX_STREAM_DATA) {
          uint64_t stream_id = 0U;
          uint64_t maximum = 0U;
          (void)wt_webtransport_max_stream_data_parse(&capsule, &stream_id, &maximum, &error);
        }
      } else {
        refused++;
      }
    }

    /* A datagram is a unit, so its parser has to be told the whole thing at once and must refuse a quarter
     * stream ID it cannot read rather than reading past it. */
    {
      uint64_t quarter = 0U;
      const uint8_t *payload = NULL;
      size_t payload_length = 0U;
      wt_http3_error_t error = WT_HTTP3_NO_ERROR;
      if (wt_webtransport_datagram_parse(bytes, length, &quarter, &payload, &payload_length,
                                         &error) == WT_OK) {
        accepted++;
      } else {
        refused++;
      }
    }
  }
  /* A capsule decoder ACCEPTS most of this corpus, and that is the right answer rather than a weak corpus: an
   * unknown capsule type with a length that fits is a valid capsule (RFC 9297 tells a receiver to ignore what
   * it does not understand), so refusal is the minority case here. What matters is that BOTH happened --
   * otherwise the corpus would be testing one path. */
  WT_EXPECT_TRUE("the capsule corpus refused some", refused > 0U);
  WT_EXPECT_TRUE("and accepted the rest", accepted > 0U);
  /* Two calls per iteration -- the capsule decoder and the datagram parser -- and every one of them has to
   * come back with a status rather than crash. */
  WT_EXPECT_U64("with every input answered by a status", 2U * (uint64_t)WT_CORPUS_ITERATIONS,
                (uint64_t)accepted + (uint64_t)refused);
}

static void test_a_whole_request_off_the_wire(void) {
  corpus_rng_t rng;
  uint8_t bytes[WT_CORPUS_MAX_BYTES];
  uint8_t scratch[256];
  unsigned refused = 0U;
  unsigned accepted = 0U;
  unsigned iteration;

  rng.state = UINT64_C(0x13579bdf);
  for (iteration = 0U; iteration < WT_CORPUS_ITERATIONS; iteration++) {
    wt_http3_message_t message;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    size_t length = (size_t)(corpus_next(&rng) % WT_CORPUS_MAX_BYTES) + 1U;

    corpus_fill(&rng, bytes, length);
    /* A field section with NO dynamic table: the strictest configuration, where a section that references one
     * is refused rather than read against indices that do not exist. */
    if (wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, bytes, length, NULL, 0U, 0U,
                                scratch, sizeof(scratch), &error) == WT_OK) {
      wt_webtransport_request_policy_t policy;
      wt_webtransport_session_request_t decision;
      accepted++;
      /* And the draft-16 decision on whatever decoded: a message that reached this far must not be able to
       * make the validator read outside itself either. */
      policy.authority = "localhost";
      policy.path = "/";
      policy.wt_enabled = 1;
      (void)wt_webtransport_session_request_validate(&message, &policy, &decision, &error);
    } else {
      refused++;
    }
  }
  /* With NO dynamic table, a random field section is essentially never valid -- the QPACK prefix alone has to
   * survive -- so this corpus is a refusal corpus by construction, and the assertion says so rather than
   * pretending otherwise. Every input still has to come back with a status. */
  WT_EXPECT_TRUE("the field-section corpus refused things", refused > 0U);
  WT_EXPECT_U64("and every input was answered", (uint64_t)WT_CORPUS_ITERATIONS,
                (uint64_t)accepted + (uint64_t)refused);
}

static void test_the_driver_under_random_streams(void) {
  corpus_rng_t rng;
  uint8_t bytes[WT_CORPUS_MAX_BYTES];
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  unsigned refused = 0U;
  unsigned accepted = 0U;
  unsigned iteration;

  rng.state = UINT64_C(0x2468ace0);
  sink.on_frame_payload = NULL;
  sink.on_stream_data = NULL;
  sink.on_datagram = NULL;
  sink.context = NULL;
  for (iteration = 0U; iteration < WT_CORPUS_ITERATIONS; iteration++) {
    wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    size_t consumed = 0U;
    size_t length = (size_t)(corpus_next(&rng) % WT_CORPUS_MAX_BYTES) + 1U;

    /* A fresh driver per iteration: the corpus is about the parsers, and a driver that accumulated state would
     * be testing the table's bounds instead (which the bounded-table tests already do). */
    wt_http3_endpoint_init(&endpoint,
                           (iteration & 1U) != 0U ? WT_HTTP3_ROLE_SERVER : WT_HTTP3_ROLE_CLIENT);
    wt_http3_driver_init(&driver, &endpoint);
    corpus_fill(&rng, bytes, length);
    if (wt_http3_driver_on_uni_stream_data(&driver, 4U, 0U, bytes, length, &kind, &payload,
                                           &payload_length, &consumed, &error) == WT_OK) {
      accepted++;
    } else {
      refused++;
    }

    /* The frame-boundary reassembler is fed random bytes too: a frame header is two varints, and a corpus is
     * exactly how the "payload or header cut off by FIN" case gets covered. */
    {
      wt_http3_driver_t second;
      wt_http3_endpoint_t second_endpoint;
      /* The driver reads the endpoint's role and walks its request table, so this is initialised rather than
       * left to whatever the stack held. */
      wt_http3_endpoint_init(&second_endpoint, WT_HTTP3_ROLE_SERVER);
      wt_http3_driver_init(&second, &second_endpoint);
      (void)wt_http3_driver_on_stream_bytes(&second, 0U, bytes, length, 1, 1024U, &sink, &error);
    }

    /* And the endpoint's own decode of a request section, on a stream it tracks. */
    {
      wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
      wt_http3_message_t message;
      (void)wt_http3_endpoint_open_request(&endpoint, 0U, &error);
      (void)wt_http3_endpoint_on_request_headers(&endpoint, 0U, bytes, length, bytes, sizeof(bytes),
                                                 &message, &error);
      (void)wt_http3_endpoint_request_state(&endpoint, 0U, &state);
    }
  }
  /* The classifier ACCEPTS an unknown stream type -- section 6.2.1 says to ignore the stream rather than fail
   * it -- so acceptance dominates here too, and a refusal is the truncated prefix. Both must appear. */
  WT_EXPECT_TRUE("the driver corpus refused some", refused > 0U);
  WT_EXPECT_TRUE("and classified some", accepted > 0U);
}

int main(void) {
  test_the_frame_and_settings_parsers();
  test_the_capsule_and_WebTransport_parsers();
  test_a_whole_request_off_the_wire();
  test_the_driver_under_random_streams();
  WT_TEST_MAIN_END("wt_http3_malformed");
}
