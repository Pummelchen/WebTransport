/* Buffering a stream or datagram that arrives before its session is known
 * (draft-ietf-webtrans-http3-16 section 4.6).
 *
 * The section's rule has four parts and each is asserted here at the interface: the item is PARKED
 * rather than refused or delivered, the parking is BOUNDED, the bound's two halves have the two
 * different answers the section gives them -- a stream over the bound is REJECTED with
 * `WT_BUFFERED_STREAM_REJECTED`, a datagram over it is DROPPED -- and the drain aligns what was
 * parked against the session ID once it is known, delivering what names this session IN ARRIVAL
 * ORDER and dropping what does not.
 *
 * The drain's callbacks here record what they were handed, because the ORDER and the exact bytes are
 * what the rule is about: a buffered stream delivered out of order, or with a piece missing, would
 * pass a test that only counted deliveries. */

#include <string.h>

#include "wt_test.h"

#include "webtransport/webtransport/buffered.h"
#include "webtransport/webtransport/error.h"

#define DELIVERED_MAX 8U

typedef struct delivered_stream {
  uint64_t stream_id;
  int unidirectional;
  size_t length;
  uint8_t bytes[64];
} delivered_stream_t;

typedef struct delivery_log {
  delivered_stream_t streams[DELIVERED_MAX];
  size_t stream_count;
  uint64_t datagrams[DELIVERED_MAX];
  uint8_t datagram_bytes[DELIVERED_MAX][32];
  size_t datagram_lengths[DELIVERED_MAX];
  size_t datagram_count;
  /* A call to fail on, so the drain's error path is reachable: 0 means never fail. */
  size_t fail_on_stream;
} delivery_log_t;

static wt_status_t record_stream(void *context, uint64_t stream_id, int unidirectional,
                                 const uint8_t *data, size_t length) {
  delivery_log_t *log = context;
  delivered_stream_t *entry;

  if (log->fail_on_stream != 0U && log->stream_count + 1U == log->fail_on_stream) {
    return WT_ERR_STATE;
  }
  if (log->stream_count >= DELIVERED_MAX) return WT_ERR_LIMIT;
  entry = &log->streams[log->stream_count++];
  entry->stream_id = stream_id;
  entry->unidirectional = unidirectional;
  entry->length = length;
  if (length > 0U && length <= sizeof(entry->bytes)) memcpy(entry->bytes, data, length);
  return WT_OK;
}

static wt_status_t record_datagram(void *context, uint64_t quarter_stream_id,
                                   const uint8_t *payload, size_t length) {
  delivery_log_t *log = context;

  if (log->datagram_count >= DELIVERED_MAX) return WT_ERR_LIMIT;
  log->datagrams[log->datagram_count] = quarter_stream_id;
  log->datagram_lengths[log->datagram_count] = length;
  if (length > 0U && length <= sizeof(log->datagram_bytes[0])) {
    memcpy(log->datagram_bytes[log->datagram_count], payload, length);
  }
  log->datagram_count++;
  return WT_OK;
}

static void test_a_stream_is_parked_and_delivered(void) {
  wt_webtransport_buffered_t buffer;
  delivery_log_t log;
  size_t delivered = 0U;
  size_t dropped = 0U;

  memset(&log, 0, sizeof(log));
  wt_webtransport_buffered_init(&buffer);
  WT_EXPECT_U64("a new buffer holds no streams", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));

  /* A stream naming a session this endpoint has not accepted yet: parked, not refused. */
  WT_EXPECT_OK("an early stream parks", wt_webtransport_buffered_park_stream(
                                            &buffer, 8U, 4U, 1, (const uint8_t *)"hello", 5U));
  WT_EXPECT_U64("and is held", 1U, (uint64_t)wt_webtransport_buffered_stream_count(&buffer));
  WT_EXPECT_U64("under its session", 4U, buffer.streams[0].session_id);
  WT_EXPECT_U64("with nothing rejected", 0U, wt_webtransport_buffered_streams_rejected(&buffer));

  /* And a datagram for the same session, which the section parks the same way. */
  WT_EXPECT_INT("an early datagram parks", 1,
                wt_webtransport_buffered_park_datagram(&buffer, 1U, (const uint8_t *)"dgram", 5U));
  WT_EXPECT_U64("and is held", 1U, (uint64_t)wt_webtransport_buffered_datagram_count(&buffer));

  /* The session is known now: the stream is delivered and the buffer is empty. */
  WT_EXPECT_OK("the drain delivers", wt_webtransport_buffered_drain_streams(
                                         &buffer, 4U, record_stream, &log, &delivered, &dropped));
  WT_EXPECT_U64("one stream", 1U, (uint64_t)delivered);
  WT_EXPECT_U64("nothing dropped", 0U, (uint64_t)dropped);
  WT_EXPECT_U64("with its ID", 8U, log.streams[0].stream_id);
  WT_EXPECT_INT("its direction", 1, log.streams[0].unidirectional);
  WT_EXPECT_U64("and its bytes", 5U, (uint64_t)log.streams[0].length);
  WT_EXPECT_BYTES("intact", (const uint8_t *)"hello", log.streams[0].bytes, 5U);
  WT_EXPECT_U64("and the buffer is empty afterwards", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));

  WT_EXPECT_OK("the datagram drain delivers too",
               wt_webtransport_buffered_drain_datagrams(&buffer, 1U, record_datagram, &log,
                                                        &delivered, &dropped));
  WT_EXPECT_U64("one datagram", 1U, (uint64_t)delivered);
  WT_EXPECT_U64("with its quarter ID", 1U, log.datagrams[0]);
  WT_EXPECT_BYTES("and its payload", (const uint8_t *)"dgram", log.datagram_bytes[0], 5U);
  WT_EXPECT_U64("and nothing is held", 0U,
                (uint64_t)wt_webtransport_buffered_datagram_count(&buffer));
}

static void test_arrival_order_and_the_other_session(void) {
  wt_webtransport_buffered_t buffer;
  delivery_log_t log;
  size_t delivered = 0U;
  size_t dropped = 0U;

  memset(&log, 0, sizeof(log));
  wt_webtransport_buffered_init(&buffer);

  /* Three streams and two datagrams, interleaved, one of each for another session: the flight a
   * client that sends its CONNECT, its streams and its datagrams together produces. */
  WT_EXPECT_OK("the first parks",
               wt_webtransport_buffered_park_stream(&buffer, 8U, 4U, 1, (const uint8_t *)"a", 1U));
  WT_EXPECT_OK("a stream for another session parks too",
               wt_webtransport_buffered_park_stream(&buffer, 12U, 8U, 1, (const uint8_t *)"b", 1U));
  WT_EXPECT_OK("the second for ours",
               wt_webtransport_buffered_park_stream(&buffer, 16U, 4U, 0, (const uint8_t *)"c", 1U));
  WT_EXPECT_OK("a third for ours",
               wt_webtransport_buffered_park_stream(&buffer, 20U, 4U, 1, (const uint8_t *)"d", 1U));
  WT_EXPECT_INT("our datagram parks", 1,
                wt_webtransport_buffered_park_datagram(&buffer, 1U, (const uint8_t *)"m", 1U));
  WT_EXPECT_INT("and another session's", 1,
                wt_webtransport_buffered_park_datagram(&buffer, 2U, (const uint8_t *)"n", 1U));

  WT_EXPECT_OK("the drain resolves them",
               wt_webtransport_buffered_drain_streams(&buffer, 4U, record_stream, &log, &delivered,
                                                      &dropped));
  WT_EXPECT_U64("delivering the three that name this session", 3U, (uint64_t)delivered);
  WT_EXPECT_U64("and dropping the one that does not", 1U, (uint64_t)dropped);
  /* The order is the arrival order, which is what a session's streams mean. */
  WT_EXPECT_U64("the first delivered is the first parked", 8U, log.streams[0].stream_id);
  WT_EXPECT_U64("then the second", 16U, log.streams[1].stream_id);
  WT_EXPECT_U64("then the third", 20U, log.streams[2].stream_id);
  WT_EXPECT_INT("with each one's direction", 0, log.streams[1].unidirectional);

  WT_EXPECT_OK("the datagram drain resolves its own",
               wt_webtransport_buffered_drain_datagrams(&buffer, 1U, record_datagram, &log,
                                                        &delivered, &dropped));
  WT_EXPECT_U64("delivering ours", 1U, (uint64_t)delivered);
  WT_EXPECT_U64("and dropping the other session's", 1U, (uint64_t)dropped);
  WT_EXPECT_U64("which is the one that was ours", 1U, log.datagrams[0]);
}

static void test_a_stream_in_pieces_appends_in_order(void) {
  wt_webtransport_buffered_t buffer;
  delivery_log_t log;
  size_t delivered = 0U;
  size_t dropped = 0U;

  memset(&log, 0, sizeof(log));
  wt_webtransport_buffered_init(&buffer);

  /* A stream arrives in three frames, as a peer's stream does. The pieces must come back as one
   * stream with its bytes in order -- the alternative, a stream per frame, would deliver a message
   * in pieces the session never asked for. */
  WT_EXPECT_OK("the first piece parks", wt_webtransport_buffered_park_stream(
                                            &buffer, 8U, 4U, 1, (const uint8_t *)"one", 3U));
  WT_EXPECT_OK("the second appends", wt_webtransport_buffered_park_stream(
                                         &buffer, 8U, 4U, 1, (const uint8_t *)"two", 3U));
  WT_EXPECT_OK("and the third", wt_webtransport_buffered_park_stream(&buffer, 8U, 4U, 1,
                                                                     (const uint8_t *)"three", 5U));
  WT_EXPECT_U64("as ONE parked stream", 1U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));
  WT_EXPECT_U64("holding every byte", 11U, (uint64_t)buffer.streams[0].length);

  WT_EXPECT_OK("the drain delivers it",
               wt_webtransport_buffered_drain_streams(&buffer, 4U, record_stream, &log, &delivered,
                                                      &dropped));
  WT_EXPECT_U64("as one delivery", 1U, (uint64_t)delivered);
  WT_EXPECT_U64("of all eleven bytes", 11U, (uint64_t)log.streams[0].length);
  WT_EXPECT_BYTES("in the order they arrived", (const uint8_t *)"onetwothree", log.streams[0].bytes,
                  11U);
}

static void test_the_stream_bound_is_a_rejection(void) {
  wt_webtransport_buffered_t buffer;
  delivery_log_t log;
  size_t delivered = 0U;
  size_t dropped = 0U;
  size_t index;

  memset(&log, 0, sizeof(log));
  wt_webtransport_buffered_init(&buffer);

  /* Fill the hold exactly: the bound is "more than this is rejected", not "this many is rejected". */
  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX; index++) {
    uint64_t stream_id = 8U + (uint64_t)index * 4U;
    WT_EXPECT_OK(
        "a stream under the bound parks",
        wt_webtransport_buffered_park_stream(&buffer, stream_id, 4U, 1, (const uint8_t *)"x", 1U));
  }
  WT_EXPECT_U64("the hold is full", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));

  /* One more: section 4.6's MUST. The status is the caller's instruction to send a reset carrying
   * WT_BUFFERED_STREAM_REJECTED, and the stream's ID is recorded so the caller does not have to be
   * told it twice. */
  WT_EXPECT_STATUS(
      "the stream over the bound is rejected", WT_ERR_LIMIT,
      wt_webtransport_buffered_park_stream(&buffer, 40U, 4U, 1, (const uint8_t *)"y", 1U));
  WT_EXPECT_U64("and the code for it is the one the section names", UINT64_C(0x3994bd84),
                WT_WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED);
  WT_EXPECT_U64("the rejection is counted", 1U, wt_webtransport_buffered_streams_rejected(&buffer));
  WT_EXPECT_U64("and the rejected stream is named", 40U,
                wt_webtransport_buffered_last_rejected_stream_id(&buffer));
  WT_EXPECT_U64("while the hold keeps what it had", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));

  /* The rejected stream is not in the hold, and the ones that are still resolve in order. */
  WT_EXPECT_OK("the drain still delivers the parked ones",
               wt_webtransport_buffered_drain_streams(&buffer, 4U, record_stream, &log, &delivered,
                                                      &dropped));
  WT_EXPECT_U64("all of them", (uint64_t)WT_WEBTRANSPORT_BUFFERED_STREAMS_MAX, (uint64_t)delivered);
  WT_EXPECT_U64("the first is the first parked", 8U, log.streams[0].stream_id);
  WT_EXPECT_TRUE("and the rejected stream was never delivered",
                 log.streams[delivered - 1U].stream_id != 40U);
}

static void test_a_stream_larger_than_the_hold_is_rejected(void) {
  wt_webtransport_buffered_t buffer;
  uint8_t large[WT_WEBTRANSPORT_BUFFERED_STREAM_BYTES_MAX + 1U];

  memset(large, 0x5a, sizeof(large));
  wt_webtransport_buffered_init(&buffer);

  /* A stream whose own bytes do not fit: rejected with the same code, because a stream delivered
   * later with its tail missing would be a corrupt message rather than a short one. */
  WT_EXPECT_STATUS("a stream over the byte hold is rejected", WT_ERR_LIMIT,
                   wt_webtransport_buffered_park_stream(&buffer, 8U, 4U, 1, large, sizeof(large)));
  WT_EXPECT_U64("and nothing is held for it", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));
  WT_EXPECT_U64("with the rejection counted", 1U,
                wt_webtransport_buffered_streams_rejected(&buffer));

  /* And the same rule for a stream that grows past the hold across frames: what was held is given
   * up, because the stream is not parked any more. */
  WT_EXPECT_OK("a piece that fits parks",
               wt_webtransport_buffered_park_stream(&buffer, 12U, 4U, 1, large,
                                                    WT_WEBTRANSPORT_BUFFERED_STREAM_BYTES_MAX));
  WT_EXPECT_U64("held to the bound", 1U, (uint64_t)wt_webtransport_buffered_stream_count(&buffer));
  WT_EXPECT_STATUS(
      "the next byte is a rejection", WT_ERR_LIMIT,
      wt_webtransport_buffered_park_stream(&buffer, 12U, 4U, 1, (const uint8_t *)"z", 1U));
  WT_EXPECT_U64("the stream is not held any more", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));
  WT_EXPECT_U64("and it is named", 12U, wt_webtransport_buffered_last_rejected_stream_id(&buffer));

  /* A zero-length piece of a stream is a legal frame and must not be a rejection. */
  wt_webtransport_buffered_init(&buffer);
  WT_EXPECT_OK("an empty piece parks",
               wt_webtransport_buffered_park_stream(&buffer, 16U, 4U, 0, NULL, 0U));
  WT_EXPECT_U64("holding nothing", 0U, (uint64_t)buffer.streams[0].length);
}

static void test_the_datagram_bound_is_a_drop(void) {
  wt_webtransport_buffered_t buffer;
  uint8_t large[WT_WEBTRANSPORT_BUFFERED_DATAGRAM_BYTES_MAX + 1U];
  size_t index;

  memset(large, 0xa5, sizeof(large));
  wt_webtransport_buffered_init(&buffer);

  for (index = 0U; index < WT_WEBTRANSPORT_BUFFERED_DATAGRAMS_MAX; index++) {
    WT_EXPECT_INT("a datagram under the bound parks", 1,
                  wt_webtransport_buffered_park_datagram(&buffer, 1U, (const uint8_t *)"d", 1U));
  }
  /* The unreliable half's answer: a datagram over the bound is dropped and counted, not rejected --
   * there is nothing to reject, and RFC 9221 section 5.2 does not retransmit one anyway. */
  WT_EXPECT_INT("the next datagram is dropped", 0,
                wt_webtransport_buffered_park_datagram(&buffer, 1U, (const uint8_t *)"d", 1U));
  WT_EXPECT_U64("and counted", 1U, wt_webtransport_buffered_datagrams_dropped(&buffer));
  WT_EXPECT_INT("as is one longer than a datagram can be", 0,
                wt_webtransport_buffered_park_datagram(&buffer, 1U, large, sizeof(large)));
  WT_EXPECT_U64("which is counted too", 2U, wt_webtransport_buffered_datagrams_dropped(&buffer));
  WT_EXPECT_U64("with the hold unchanged", (uint64_t)WT_WEBTRANSPORT_BUFFERED_DATAGRAMS_MAX,
                (uint64_t)wt_webtransport_buffered_datagram_count(&buffer));

  /* A datagram payload may be empty: RFC 9221 allows a DATAGRAM frame with no payload. */
  wt_webtransport_buffered_init(&buffer);
  WT_EXPECT_INT("an empty datagram parks", 1,
                wt_webtransport_buffered_park_datagram(&buffer, 1U, NULL, 0U));
}

static void test_the_drain_stops_at_a_failing_callback(void) {
  wt_webtransport_buffered_t buffer;
  delivery_log_t log;
  size_t delivered = 0U;
  size_t dropped = 0U;

  memset(&log, 0, sizeof(log));
  log.fail_on_stream = 2U; /* the second delivery fails */
  wt_webtransport_buffered_init(&buffer);

  WT_EXPECT_OK("the first parks",
               wt_webtransport_buffered_park_stream(&buffer, 8U, 4U, 1, (const uint8_t *)"a", 1U));
  WT_EXPECT_OK("the second parks",
               wt_webtransport_buffered_park_stream(&buffer, 12U, 4U, 1, (const uint8_t *)"b", 1U));
  WT_EXPECT_OK("the third parks",
               wt_webtransport_buffered_park_stream(&buffer, 16U, 4U, 1, (const uint8_t *)"c", 1U));

  /* The callback's refusal is the drain's, and the streams behind it are not delivered into a
   * session that just failed. What was parked is still resolved: the reference point exists now,
   * so a second drain has nothing to do. */
  WT_EXPECT_STATUS("the drain returns the refusal", WT_ERR_STATE,
                   wt_webtransport_buffered_drain_streams(&buffer, 4U, record_stream, &log,
                                                          &delivered, &dropped));
  WT_EXPECT_U64("one delivery got through", 1U, (uint64_t)delivered);
  WT_EXPECT_U64("and nothing is left parked", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));
  WT_EXPECT_OK("and is a no-op", wt_webtransport_buffered_drain_streams(
                                     &buffer, 4U, record_stream, &log, &delivered, &dropped));
  WT_EXPECT_U64("with no deliveries", 0U, (uint64_t)delivered);
  WT_EXPECT_U64("and no drops", 0U, (uint64_t)dropped);
}

static void test_a_null_drain_only_resolves(void) {
  wt_webtransport_buffered_t buffer;
  size_t delivered = 0U;
  size_t dropped = 0U;

  wt_webtransport_buffered_init(&buffer);
  WT_EXPECT_OK("a stream parks",
               wt_webtransport_buffered_park_stream(&buffer, 8U, 4U, 1, (const uint8_t *)"a", 1U));
  /* A caller with nothing to do with the bytes still has to resolve them, or the buffer fills and
   * every later stream is rejected. A NULL callback says "deliver nowhere". */
  WT_EXPECT_OK(
      "a drain with no callback resolves it",
      wt_webtransport_buffered_drain_streams(&buffer, 4U, NULL, NULL, &delivered, &dropped));
  WT_EXPECT_U64("counting it delivered", 1U, (uint64_t)delivered);
  WT_EXPECT_U64("and holding nothing", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(&buffer));

  /* The accessors are safe on NULL, like the rest of this tree's read-only surface. */
  WT_EXPECT_U64("a null buffer has no streams", 0U,
                (uint64_t)wt_webtransport_buffered_stream_count(NULL));
  WT_EXPECT_U64("no rejections", 0U, wt_webtransport_buffered_streams_rejected(NULL));
  WT_EXPECT_U64("and no dropped datagrams", 0U, wt_webtransport_buffered_datagrams_dropped(NULL));
  WT_EXPECT_U64("and names no rejected stream", 0U,
                wt_webtransport_buffered_last_rejected_stream_id(NULL));
  wt_webtransport_buffered_init(NULL); /* must not crash */
  WT_EXPECT_STATUS("parking on a null buffer is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_webtransport_buffered_park_stream(NULL, 8U, 4U, 1, NULL, 0U));
}

int main(void) {
  test_a_stream_is_parked_and_delivered();
  test_arrival_order_and_the_other_session();
  test_a_stream_in_pieces_appends_in_order();
  test_the_stream_bound_is_a_rejection();
  test_a_stream_larger_than_the_hold_is_rejected();
  test_the_datagram_bound_is_a_drop();
  test_the_drain_stops_at_a_failing_callback();
  test_a_null_drain_only_resolves();
  WT_TEST_MAIN_END("wt_webtransport_buffered");
}
