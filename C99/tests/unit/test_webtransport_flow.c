/* WebTransport's session flow control (draft-ietf-webtrans-http3-16 section 5.1).
 *
 * Each capsule carries one or two varints, so the tests are about the two ways that goes
 * wrong: a value that is not exactly a number (a trailing byte is not a bigger number)
 * and a connection-level limit that SHRINKS. The second is the rule worth the part: a
 * limit below one already granted would invalidate data sent against the old one, so it
 * is WT_FLOW_CONTROL_ERROR rather than a new limit, and an implementation that simply
 * stored it would accept a peer rewriting its own promise. */

#include "wt_test.h"

#include "webtransport/quic/varint.h"
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

  /* The rule: a limit must STRICTLY increase, so a smaller one and a repeat are both
   * flow-control errors. */
  WT_EXPECT_STATUS("a smaller one is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_data(&limits, 1500U, &error));
  WT_EXPECT_U64("with the draft's flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR, error);
  WT_EXPECT_U64("and the old limit intact", 2000U, limits.max_data);
  WT_EXPECT_STATUS("a repeat is refused too", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_data(&limits, 2000U, &error));
  WT_EXPECT_U64("with the same code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR, error);

  /* The stream counts follow the same rule, per direction. */
  WT_EXPECT_OK("a bidirectional count is accepted",
               wt_webtransport_flow_on_max_streams(&limits, 1, 8U, &error));
  WT_EXPECT_STATUS("and may not shrink", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_streams(&limits, 1, 4U, &error));
  WT_EXPECT_U64("which is the same code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR, error);
  WT_EXPECT_U64("leaving the count alone", 8U, limits.max_streams_bidi);

  WT_EXPECT_STATUS("and a repeat of the count as well", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_streams(&limits, 1, 8U, &error));

  /* The stream ID space has a ceiling: a limit above it is not a limit. */
  WT_EXPECT_STATUS("a count above the draft's ceiling is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_streams(&limits, 1, WT_WEBTRANSPORT_MAX_STREAMS_VALUE + 1U,
                                                       &error));
  WT_EXPECT_U64("with the flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR, error);
  WT_EXPECT_OK("while the ceiling itself is a legal limit",
               wt_webtransport_flow_on_max_streams(&limits, 1, WT_WEBTRANSPORT_MAX_STREAMS_VALUE,
                                                   &error));

  /* The other direction is independent. */
  WT_EXPECT_OK("the unidirectional count is separate",
               wt_webtransport_flow_on_max_streams(&limits, 0, 2U, &error));
  WT_EXPECT_U64("and recorded", 2U, limits.max_streams_uni);
  WT_EXPECT_STATUS("while the bidirectional one still refuses a shrink", WT_ERR_PROTOCOL,
                   wt_webtransport_flow_on_max_streams(&limits, 1, 7U, &error));
}

/* Sections 5.6.2 and 5.6.3: "This value cannot exceed 2^60, as it is not possible to encode stream IDs larger
 * than 2^62-1. Recipients of a capsule with a Maximum Streams value larger than this limit MUST close the
 * WebTransport session with a WT_FLOW_CONTROL_ERROR error code." The ceiling therefore belongs on BOTH sides of
 * the codec: a writer must not produce a capsule its own reader refuses, and a reader must refuse the value with
 * the draft's session code rather than the message error a malformed varint gets. */
static wt_webtransport_capsule_t hand_made_stream_count(uint64_t type, uint64_t value) {
  /* Static: the returned capsule's value is a view into these bytes, which therefore have to outlive it. */
  static uint8_t bytes[32];
  wt_webtransport_capsule_t capsule;
  wt_cursor_t c;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t length = 0U;

  length += wt_quic_varint_encode(type, bytes + length, sizeof(bytes) - length);
  length += wt_quic_varint_encode((uint64_t)wt_quic_varint_size(value), bytes + length,
                                  sizeof(bytes) - length);
  length += wt_quic_varint_encode(value, bytes + length, sizeof(bytes) - length);
  c = wt_cursor_init(bytes, length);
  WT_EXPECT_OK("a hand-made stream-count capsule decodes",
               wt_webtransport_capsule_decode(&c, sizeof(bytes), &capsule, &error));
  return capsule;
}

static void test_the_stream_count_ceiling(void) {
  uint8_t bytes[32];
  wt_writer_t w;
  uint64_t value = 0U;
  uint64_t over = WT_WEBTRANSPORT_MAX_STREAMS_VALUE + 1U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_webtransport_capsule_t capsule;
  static const uint64_t types[] = {WT_CAPSULE_MAX_STREAMS_BIDI, WT_CAPSULE_MAX_STREAMS_UNI,
                                   WT_CAPSULE_STREAMS_BLOCKED_BIDI, WT_CAPSULE_STREAMS_BLOCKED_UNI};
  size_t i;

  /* The writers refuse it, for both capsule types, while the ceiling itself is a legal value. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_STATUS("MAX_STREAMS above the ceiling is refused", WT_ERR_LIMIT,
                   wt_webtransport_max_streams_write(&w, 1, over));
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_STATUS("STREAMS_BLOCKED above it too", WT_ERR_LIMIT,
                   wt_webtransport_streams_blocked_write(&w, 0, over));
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("while the ceiling itself writes",
               wt_webtransport_max_streams_write(&w, 1, WT_WEBTRANSPORT_MAX_STREAMS_VALUE));
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("for the blocked capsule too",
               wt_webtransport_streams_blocked_write(&w, 1, WT_WEBTRANSPORT_MAX_STREAMS_VALUE));

  /* The readers refuse a peer's over-limit capsule. It is built by hand because the writers above no longer
   * produce one, and the value is the varint a peer would send. */
  for (i = 0U; i < sizeof(types) / sizeof(types[0]); i++) {
    capsule = hand_made_stream_count(types[i], over);
    value = 0U;
    error = WT_HTTP3_NO_ERROR;
    if (types[i] == WT_CAPSULE_MAX_STREAMS_BIDI || types[i] == WT_CAPSULE_MAX_STREAMS_UNI) {
      WT_EXPECT_STATUS("an over-limit MAX_STREAMS is refused", WT_ERR_PROTOCOL,
                       wt_webtransport_max_streams_parse(&capsule, &value, &error));
    } else {
      WT_EXPECT_STATUS("an over-limit STREAMS_BLOCKED is refused", WT_ERR_PROTOCOL,
                       wt_webtransport_streams_blocked_parse(&capsule, &value, &error));
    }
    WT_EXPECT_U64("with the draft's flow-control code", WT_WEBTRANSPORT_FLOW_CONTROL_ERROR,
                  (uint64_t)error);
  }

  /* A NULL value with a non-zero length is a caller error the sibling capsule parsers survive: the cursor
   * clamps a NULL buffer to zero bytes rather than reading it, and this assertion keeps it that way (the close
   * parser needed an explicit guard; these did not). */
  capsule.type = WT_CAPSULE_MAX_STREAMS_BIDI;
  capsule.value = NULL;
  capsule.value_length = 4U;
  capsule.bytes_consumed = 0U;
  value = 0U;
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS("a NULL value is refused, not read", WT_ERR_PROTOCOL,
                   wt_webtransport_max_streams_parse(&capsule, &value, &error));
  WT_EXPECT_U64("as a message error", (uint64_t)WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
}

int main(void) {
  test_round_trips();
  test_malformed_values();
  test_limits_only_grow();
  test_the_stream_count_ceiling();
  WT_TEST_MAIN_END("wt_webtransport_flow");
}
