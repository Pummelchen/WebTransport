/* The bounded tables of HTTP/3 and the session layer, at their bounds (Phase 10).
 *
 * The plan's test port asks for resource exhaustion, and this is what that means here: every table in these
 * layers is FIXED, because a table that grows with a peer is a heap exhaustion path with the peer's name on it.
 * The test drives each one to its bound and asserts three things about what happens then -- the refusal is
 * WT_ERR_LIMIT, it carries NO error code (the bound is this endpoint's, so blaming the peer for it would tell a
 * peer's story about a local limit), and the table does not move: a refused stream must not consume a slot, and
 * a stream that ends must give its slot back, because these are bounds on CONCURRENCY and not lifetime totals.
 *
 * The count assertions are the ones that matter. A table that quietly dropped the entry past its bound would
 * show a short, clean run, and "the peer opened one more stream than we allow" is exactly the case where a
 * silent drop and a refusal look the same from the outside.
 */

#include "wt_test.h"

#include <string.h>

#include "webtransport/http3/driver.h"
#include "webtransport/http3/endpoint.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"

static size_t write_type(uint8_t *out, uint64_t type) {
  return wt_quic_varint_encode(type, out, 8U);
}

static void test_the_peer_stream_table_is_a_concurrency_bound(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint8_t bytes[8];
  size_t length;
  uint64_t index;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  length = write_type(bytes, WT_WEBTRANSPORT_STREAM_UNI);
  length += wt_quic_varint_encode(0U, bytes + length, 8U - length);

  for (index = 0U; index < (uint64_t)WT_HTTP3_ENDPOINT_STREAMS_MAX; index++) {
    WT_EXPECT_OK("a peer stream fits",
                 wt_http3_endpoint_on_uni_stream(&endpoint, 4U + index * 4U, bytes, length, NULL, &kind,
                                                 &error));
  }
  WT_EXPECT_U64("the table is full", (uint64_t)WT_HTTP3_ENDPOINT_STREAMS_MAX,
                (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

  WT_EXPECT_STATUS("one more is refused", WT_ERR_LIMIT,
                   wt_http3_endpoint_on_uni_stream(&endpoint, 4096U, bytes, length, NULL, &kind, &error));
  WT_EXPECT_U64("with no error code, because the bound is ours", (uint64_t)WT_HTTP3_NO_ERROR,
                (uint64_t)error);
  WT_EXPECT_U64("and the refused stream consumed no slot", (uint64_t)WT_HTTP3_ENDPOINT_STREAMS_MAX,
                (uint64_t)wt_http3_endpoint_stream_count(&endpoint));

  /* A stream ending returns its slot: the bound is about how many are open at once. */
  WT_EXPECT_OK("a stream ends", wt_http3_endpoint_on_uni_stream_end(&endpoint, 4U, &error));
  WT_EXPECT_U64("freeing its slot", (uint64_t)(WT_HTTP3_ENDPOINT_STREAMS_MAX - 1U),
                (uint64_t)wt_http3_endpoint_stream_count(&endpoint));
  WT_EXPECT_OK("so another fits", wt_http3_endpoint_on_uni_stream(&endpoint, 4096U, bytes, length, NULL,
                                                                  &kind, &error));
}

static void test_the_request_table_is_a_concurrency_bound(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_request_state_t state = WT_HTTP3_REQUEST_EXPECT_HEADERS;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint64_t index;

  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_CLIENT);
  for (index = 0U; index < (uint64_t)WT_HTTP3_ENDPOINT_REQUESTS_MAX; index++) {
    WT_EXPECT_OK("a request stream opens", wt_http3_endpoint_open_request(&endpoint, index * 4U, &error));
  }
  WT_EXPECT_STATUS("one more is refused", WT_ERR_LIMIT,
                   wt_http3_endpoint_open_request(&endpoint, 4096U, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  /* A duplicate is the caller's mistake and is found BEFORE the bound, so a caller is never told the table is
   * full when the stream is simply already there. */
  WT_EXPECT_STATUS("a duplicate is a state error even when full", WT_ERR_STATE,
                   wt_http3_endpoint_open_request(&endpoint, 0U, &error));
  WT_EXPECT_OK("closing one by reset", wt_http3_endpoint_on_request_reset(&endpoint, 0U));
  WT_EXPECT_OK("frees its slot", wt_http3_endpoint_open_request(&endpoint, 4096U, &error));
  WT_EXPECT_OK("and its state is readable", wt_http3_endpoint_request_state(&endpoint, 4096U, &state));
}

static void test_the_driver_tables_are_bounded(void) {
  wt_http3_endpoint_t endpoint;
  wt_http3_driver_t driver;
  wt_http3_driver_sink_t sink;
  wt_http3_endpoint_stream_kind_t kind = WT_HTTP3_ENDPOINT_STREAM_UNKNOWN;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint8_t half[1];
  uint64_t index;

  /* The pending-prefix table: a stream whose type prefix has not fully arrived. */
  memset(&sink, 0, sizeof(sink));
  wt_http3_endpoint_init(&endpoint, WT_HTTP3_ROLE_SERVER);
  wt_http3_driver_init(&driver, &endpoint);
  half[0] = 0xc0U; /* the first byte of a four-byte varint: nothing is complete yet */
  for (index = 0U; index < (uint64_t)WT_HTTP3_DRIVER_PENDING_MAX; index++) {
    WT_EXPECT_OK("a stream waits for the rest of its prefix",
                 wt_http3_driver_on_uni_stream_data(&driver, 4U + index * 4U, 0U, half, 1U, &kind, NULL,
                                                    NULL, NULL, &error));
  }
  WT_EXPECT_U64("the pending table is full", (uint64_t)WT_HTTP3_DRIVER_PENDING_MAX,
                (uint64_t)wt_http3_driver_pending_count(&driver));
  WT_EXPECT_STATUS("one more waiting stream is refused", WT_ERR_LIMIT,
                   wt_http3_driver_on_uni_stream_data(&driver, 4096U, 0U, half, 1U, &kind, NULL, NULL,
                                                      NULL, &error));
  WT_EXPECT_U64("with no error code", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  WT_EXPECT_OK("a waiting stream may end", wt_http3_driver_on_uni_stream_end(&driver, 4U, &error));
  WT_EXPECT_U64("freeing its slot", (uint64_t)(WT_HTTP3_DRIVER_PENDING_MAX - 1U),
                (uint64_t)wt_http3_driver_pending_count(&driver));

  /* And the frame-boundary table, which bounds how many streams may be mid-frame at once. */
  {
    wt_http3_driver_t frames;
    wt_http3_endpoint_t frames_endpoint;
    uint8_t header[2] = {0x01U, 0x40U}; /* a DATA frame whose payload has not arrived */
    wt_http3_driver_init(&frames, &frames_endpoint);
    for (index = 0U; index < (uint64_t)WT_HTTP3_DRIVER_FRAMES_MAX; index++) {
      WT_EXPECT_OK("a stream is part way through a frame",
                   wt_http3_driver_on_stream_bytes(&frames, index * 4U, header, sizeof(header), 0, 1024U,
                                                   &sink, &error));
    }
    WT_EXPECT_STATUS("one more is refused", WT_ERR_LIMIT,
                     wt_http3_driver_on_stream_bytes(&frames, 4096U, header, sizeof(header), 0, 1024U,
                                                     &sink, &error));
  }
}

int main(void) {
  test_the_peer_stream_table_is_a_concurrency_bound();
  test_the_request_table_is_a_concurrency_bound();
  test_the_driver_tables_are_bounded();
  WT_TEST_MAIN_END("wt_http3_limits");
}
