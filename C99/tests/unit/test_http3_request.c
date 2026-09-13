/* The frames of a request stream, in order (RFC 9114 section 4.1).
 *
 * The shape is short -- HEADERS, DATA*, HEADERS? -- so what the tests cover is
 * every way it can be violated and the two endings: a clean end after the request
 * arrived, and an end before its HEADERS, which is an incomplete request rather
 * than a malformed sequence. That distinction is the one worth holding on to: one
 * is a connection error, the other is the code a server aborts its own response
 * stream with. */

#include "wt_test.h"

#include "webtransport/http3/request.h"

static void test_the_legal_shapes(void) {
  wt_http3_request_stream_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* HEADERS alone: a GET with no body. */
  wt_http3_request_init(&request);
  WT_EXPECT_OK("HEADERS opens the request", wt_http3_request_on_frame(&request,
                                                                     WT_HTTP3_FRAME_HEADERS,
                                                                     &error));
  WT_EXPECT_INT("and the machine expects the body", (int)WT_HTTP3_REQUEST_BODY,
                (int)request.state);
  WT_EXPECT_OK("which may end at once", wt_http3_request_on_end(&request, &error));

  /* HEADERS, DATA, DATA: a request with content. */
  wt_http3_request_init(&request);
  WT_EXPECT_OK("HEADERS", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_OK("DATA", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_OK("and more DATA", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_OK("then the end", wt_http3_request_on_end(&request, &error));

  /* HEADERS, DATA, HEADERS: content and a trailer section. */
  wt_http3_request_init(&request);
  WT_EXPECT_OK("HEADERS", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_OK("DATA", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_OK("then the trailer", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS,
                                                             &error));
  WT_EXPECT_INT("which completes the request", (int)WT_HTTP3_REQUEST_COMPLETE,
                (int)request.state);
  WT_EXPECT_OK("and the stream ends", wt_http3_request_on_end(&request, &error));
}

static void test_invalid_sequences(void) {
  static const uint64_t types[] = {WT_HTTP3_FRAME_DATA,  WT_HTTP3_FRAME_SETTINGS,
                                   WT_HTTP3_FRAME_GOAWAY, WT_HTTP3_FRAME_MAX_PUSH_ID,
                                   WT_HTTP3_FRAME_CANCEL_PUSH, WT_HTTP3_FRAME_PUSH_PROMISE,
                                   0x2aU};
  wt_http3_request_stream_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  size_t i;

  /* Nothing but HEADERS may come first. */
  for (i = 0U; i < sizeof(types) / sizeof(types[0]); i++) {
    wt_http3_request_init(&request);
    WT_EXPECT_STATUS("a frame before the request's HEADERS is invalid", WT_ERR_PROTOCOL,
                     wt_http3_request_on_frame(&request, types[i], &error));
    WT_EXPECT_U64("as unexpected", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  }

  /* After the request's HEADERS, only DATA and the trailer may come. */
  for (i = 0U; i < sizeof(types) / sizeof(types[0]); i++) {
    if (types[i] == WT_HTTP3_FRAME_DATA) continue;
    wt_http3_request_init(&request);
    WT_EXPECT_OK("HEADERS", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
    WT_EXPECT_STATUS("and then a frame that is neither DATA nor a trailer is invalid",
                     WT_ERR_PROTOCOL, wt_http3_request_on_frame(&request, types[i], &error));
    WT_EXPECT_U64("as unexpected", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  }

  /* After the trailer, nothing at all. */
  wt_http3_request_init(&request);
  WT_EXPECT_OK("HEADERS", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_OK("trailer", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_STATUS("DATA after the trailer is invalid", WT_ERR_PROTOCOL,
                   wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_DATA, &error));
  WT_EXPECT_U64("as unexpected", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
  WT_EXPECT_STATUS("and so is a second trailer", WT_ERR_PROTOCOL,
                   wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
}

static void test_endings(void) {
  wt_http3_request_stream_t request;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A stream that ends before the request's HEADERS is an incomplete request, not
   * a malformed frame sequence: section 4.1 has the server abort its RESPONSE
   * stream with this code rather than close the connection. */
  wt_http3_request_init(&request);
  WT_EXPECT_STATUS("an end before HEADERS is an incomplete request", WT_ERR_PROTOCOL,
                   wt_http3_request_on_end(&request, &error));
  WT_EXPECT_U64("with the stream error code", WT_HTTP3_REQUEST_INCOMPLETE, (uint64_t)error);
  WT_EXPECT_STATUS("and a frame after the end is a caller error", WT_ERR_STATE,
                   wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_STATUS("as is a second end", WT_ERR_STATE, wt_http3_request_on_end(&request, &error));

  /* A reset is not an ordering matter: the machine records the end and says
   * nothing about codes. */
  wt_http3_request_init(&request);
  WT_EXPECT_OK("HEADERS", wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_HEADERS, &error));
  WT_EXPECT_OK("a reset ends the stream", wt_http3_request_on_reset(&request));
  WT_EXPECT_INT("which is remembered", 1, request.ended);
  WT_EXPECT_STATUS("so no frame follows it", WT_ERR_STATE,
                   wt_http3_request_on_frame(&request, WT_HTTP3_FRAME_DATA, &error));
}

int main(void) {
  test_the_legal_shapes();
  test_invalid_sequences();
  test_endings();
  WT_TEST_MAIN_END("wt_http3_request");
}
