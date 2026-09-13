/* WebTransport's session flow control (draft-ietf-webtrans-http3-16 section 5.1).
 *
 * Each capsule carries one or two varints, so the tests are about the two ways that goes
 * wrong: a value that is not exactly a number (a trailing byte is not a bigger number)
 * and a connection-level limit that SHRINKS. The second is the rule worth the part: a
 * limit below one already granted would invalidate data sent against the old one, so it
 * is WT_FLOW_CONTROL_ERROR rather than a new limit, and an implementation that simply
 * stored it would accept a peer rewriting its own promise. */

#include "wt_test.h"

#include "webtransport/webtransport/capsule.h"

static wt_webtransport_capsule_t decode(uint8_t *bytes, size_t length) {
  wt_cursor_t c = wt_cursor_init(bytes, length);
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_OK("the capsule decodes", wt_webtransport_capsule_decode(&c, 1024U, &capsule, &error));
  return capsule;
}

static void test_round_trips(void) {
  uint8_t bytes[32];
  wt_writer_t w;
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint64_t first = 0U;
  uint64_t second = 0U;

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("MAX_DATA writes", wt_webtransport_max_data_write(&w, 100000U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_U64("as its type", WT_CAPSULE_MAX_DATA, capsule.type);
  WT_EXPECT_OK("whose value parses", wt_webtransport_max_data_parse(&capsule, &first, &error));
  WT_EXPECT_U64("to the limit", 100000U, first);

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("MAX_STREAM_DATA writes",
               wt_webtransport_max_stream_data_write(&w, 4U, 2048U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_U64("as its type", WT_CAPSULE_MAX_STREAM_DATA, capsule.type);
  WT_EXPECT_OK("whose value parses",
               wt_webtransport_max_stream_data_parse(&capsule, &first, &second, &error));
  WT_EXPECT_U64("to the stream first", 4U, first);
  WT_EXPECT_U64("and the limit second", 2048U, second);

  /* The direction decides the type for the stream-count capsules. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a bidirectional MAX_STREAMS writes",
               wt_webtransport_max_streams_write(&w, 1, 8U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_U64("as the bidirectional one", WT_CAPSULE_MAX_STREAMS_BIDI, capsule.type);
  WT_EXPECT_OK("parsing to its count", wt_webtransport_max_streams_parse(&capsule, &first, &error));
  WT_EXPECT_U64("which is what was written", 8U, first);

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a unidirectional one writes", wt_webtransport_max_streams_write(&w, 0, 3U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_U64("as the unidirectional type", WT_CAPSULE_MAX_STREAMS_UNI, capsule.type);

  /* The blocked capsules: one varint, and two for the per-stream one. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("DATA_BLOCKED writes", wt_webtransport_data_blocked_write(&w, 4096U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("parsing to its limit", wt_webtransport_data_blocked_parse(&capsule, &first, &error));
  WT_EXPECT_U64("which is what was written", 4096U, first);

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("STREAM_DATA_BLOCKED writes",
               wt_webtransport_stream_data_blocked_write(&w, 8U, 16U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("parsing to its stream and limit",
               wt_webtransport_stream_data_blocked_parse(&capsule, &first, &second, &error));
  WT_EXPECT_U64("the stream", 8U, first);
  WT_EXPECT_U64("and the limit", 16U, second);

  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("STREAMS_BLOCKED writes", wt_webtransport_streams_blocked_write(&w, 1, 12U));
  capsule = decode(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("parsing to its count", wt_webtransport_streams_blocked_parse(&capsule, &first,
                                                                             &error));
  WT_EXPECT_U64("which is what was written", 12U, first);
}

static void test_malformed_values(void) {
  static uint8_t two_values[2] = {0x04U, 0x08U};
  static uint8_t empty[1] = {0x00U};
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint64_t value = 0U;

  /* A trailing byte after the value: the capsule says one thing and carries two, and a
   * layer that read the first and ignored the rest would accept it. */
  capsule.type = WT_CAPSULE_MAX_DATA;
  capsule.value = two_values;
  capsule.value_length = sizeof(two_values);
  capsule.bytes_consumed = 0U;
  WT_EXPECT_STATUS("two values are refused", WT_ERR_PROTOCOL,
                   wt_webtransport_max_data_parse(&capsule, &value, &error));
  WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);

  /* And a value that is not a number at all. */
  capsule.value = empty;
  capsule.value_length = 0U;
  WT_EXPECT_STATUS("an empty value is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_max_data_parse(&capsule, &value, &error));

  /* The right type for a different parser is a caller error, not a malformed capsule. */
  capsule.type = WT_CAPSULE_MAX_DATA;
  capsule.value = NULL;
  capsule.value_length = 0U;
  {
    wt_webtransport_capsule_t other = capsule;
    other.type = WT_CAPSULE_DATA_BLOCKED;
    WT_EXPECT_STATUS("a DATA_BLOCKED capsule is not a MAX_DATA one", WT_ERR_INVALID_ARGUMENT,
                     wt_webtransport_max_data_parse(&other, &value, &error));
  }
}

static void test_limits_only_grow(void) {
  wt_webtransport_flow_limits_t limits;
  uint64_t error = 0U;

  wt_webtransport_flow_limits_init(&limits);
  WT_EXPECT_OK("a first MAX_DATA is accepted",
               wt_webtransport_flow_on_max_data(&limits, 1000U, &error));
  WT_EXPECT_U64("and recorded", 1000U, limits.max_data);
  WT_EXPECT_OK("a larger one is accepted too",
               wt_webtransport_flow_on_max_data(&limits, 2000U, &error));
  WT_EXPECT_U64("replacing it", 2000U, limits.max_data);

  /* The rule: a limit may not shrink. */
  WT_EXPECT_STATUS("a smaller one is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_data(&limits, 1500U, &error));
  WT_EXPECT_U64("with the draft's flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR, error);
  WT_EXPECT_U64("and the old limit intact", 2000U, limits.max_data);

  /* The stream counts follow the same rule, per direction. */
  WT_EXPECT_OK("a bidirectional count is accepted",
               wt_webtransport_flow_on_max_streams(&limits, 1, 8U, &error));
  WT_EXPECT_STATUS("and may not shrink", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_streams(&limits, 1, 4U, &error));
  WT_EXPECT_U64("which is the same code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR, error);
  WT_EXPECT_U64("leaving the count alone", 8U, limits.max_streams_bidi);

  /* The other direction is independent. */
  WT_EXPECT_OK("the unidirectional count is separate",
               wt_webtransport_flow_on_max_streams(&limits, 0, 2U, &error));
  WT_EXPECT_U64("and recorded", 2U, limits.max_streams_uni);
  WT_EXPECT_STATUS("while the bidirectional one still refuses a shrink", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_streams(&limits, 1, 7U, &error));
}

int main(void) {
  test_round_trips();
  test_malformed_values();
  test_limits_only_grow();
  WT_TEST_MAIN_END("wt_webtransport_flow");
}
