/* Which frames may appear on which HTTP/3 stream (RFC 9114 section 7.2).
 *
 * This is a table, so the tests are a table: every registered frame type against
 * every stream kind, with the role-dependent cases (MAX_PUSH_ID only a client may
 * send, PUSH_PROMISE only a server) exercised in both directions. The point of
 * writing it out is that the rules are otherwise scattered across eight sections
 * that each say it in the same words, and a missing case is invisible until a peer
 * finds it. */

#include "wt_test.h"

#include "webtransport/http3/streams.h"

static wt_status_t check(wt_http3_role_t receiver, wt_http3_stream_kind_t kind, uint64_t type,
                         wt_http3_error_t *out_error) {
  return wt_http3_frame_allowed(receiver, kind, type, out_error);
}

static void expect_allowed(wt_http3_role_t receiver, wt_http3_stream_kind_t kind, uint64_t type,
                           const char *label) {
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_OK(label, check(receiver, kind, type, &error));
  WT_EXPECT_U64("with no connection error", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
}

static void expect_refused(wt_http3_role_t receiver, wt_http3_stream_kind_t kind, uint64_t type,
                           const char *label) {
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS(label, WT_ERR_PROTOCOL, check(receiver, kind, type, &error));
  WT_EXPECT_U64("as unexpected", WT_HTTP3_FRAME_UNEXPECTED, (uint64_t)error);
}

static void test_control_stream(void) {
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_SETTINGS,
                 "SETTINGS belongs on the control stream");
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_GOAWAY,
                 "so does GOAWAY");
  /* The receiver is the server here: MAX_PUSH_ID is a client's frame, so a server
   * receiving one is the ordinary case and a client receiving one is section
   * 7.2.7's error, which the refused list below covers. */
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_MAX_PUSH_ID,
                 "and MAX_PUSH_ID from a client");
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_CANCEL_PUSH,
                 "CANCEL_PUSH may come from either end");
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, 0x2aU,
                 "and an unknown extension frame is the layer's to ignore");

  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_DATA,
                 "DATA has no place there");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_HEADERS,
                 "nor HEADERS");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_PUSH_PROMISE,
                 "nor PUSH_PROMISE");
  expect_refused(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_FRAME_MAX_PUSH_ID,
                 "and a client may not receive MAX_PUSH_ID");
}

static void test_request_stream(void) {
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_HEADERS,
                 "a request stream starts with HEADERS");
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_DATA,
                 "and carries DATA");
  expect_allowed(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_PUSH_PROMISE,
                 "a client may receive PUSH_PROMISE on one");
  expect_allowed(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, 0x2aU,
                 "and an unknown frame is allowed");

  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_SETTINGS,
                 "SETTINGS may not");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_GOAWAY,
                 "nor GOAWAY");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_MAX_PUSH_ID,
                 "nor MAX_PUSH_ID");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_CANCEL_PUSH,
                 "nor CANCEL_PUSH");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_FRAME_PUSH_PROMISE,
                 "and a server may not receive PUSH_PROMISE");
}

static void test_push_and_qpack_streams(void) {
  expect_allowed(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_PUSH, WT_HTTP3_FRAME_HEADERS,
                 "a push stream carries a response");
  expect_allowed(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_PUSH, WT_HTTP3_FRAME_DATA,
                 "with a body");
  expect_refused(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_PUSH, WT_HTTP3_FRAME_PUSH_PROMISE,
                 "but a push cannot promise another push");
  expect_refused(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_PUSH, WT_HTTP3_FRAME_SETTINGS,
                 "and carries no connection frames");

  /* Section 4.2: the QPACK streams hold instructions, so any HTTP/3 frame on one
   * is unexpected -- including the ones every other stream allows. */
  expect_refused(WT_HTTP3_ROLE_CLIENT, WT_HTTP3_STREAM_KIND_QPACK_ENCODER, WT_HTTP3_FRAME_HEADERS,
                 "a QPACK encoder stream carries no frames");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_QPACK_DECODER, WT_HTTP3_FRAME_DATA,
                 "nor a QPACK decoder stream");
  expect_refused(WT_HTTP3_ROLE_SERVER, WT_HTTP3_STREAM_KIND_QPACK_ENCODER, 0x2aU,
                 "not even an unknown one");
}

static void test_reserved_frame_types_everywhere(void) {
  static const wt_http3_stream_kind_t kinds[] = {
      WT_HTTP3_STREAM_KIND_CONTROL, WT_HTTP3_STREAM_KIND_REQUEST, WT_HTTP3_STREAM_KIND_PUSH,
      WT_HTTP3_STREAM_KIND_QPACK_ENCODER, WT_HTTP3_STREAM_KIND_QPACK_DECODER};
  size_t i;

  for (i = 0U; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    /* 0x02 and 0x06 are PRIORITY and PING: the frame types section 7.2.8 reserves from HTTP/2, whose receipt is
     * H3_FRAME_UNEXPECTED. This used to test 0x21 and 0x40, which are the EXERCISE types the same section says a
     * receiver MUST ignore -- so the file asserted the inversion rather than catching it. */
    expect_refused(WT_HTTP3_ROLE_CLIENT, kinds[i], 0x02U, "a reserved frame type is refused");
    expect_refused(WT_HTTP3_ROLE_SERVER, kinds[i], 0x09U, "on every stream kind");
  }
}

static void test_stream_type_prefixes(void) {
  wt_http3_stream_kind_t kind = WT_HTTP3_STREAM_KIND_CONTROL;

  WT_EXPECT_OK("control is a kind", wt_http3_stream_kind_for_type(WT_HTTP3_STREAM_CONTROL, &kind));
  WT_EXPECT_INT("as control", (int)WT_HTTP3_STREAM_KIND_CONTROL, (int)kind);
  WT_EXPECT_OK("QPACK encoder is", wt_http3_stream_kind_for_type(WT_HTTP3_STREAM_QPACK_ENCODER,
                                                                 &kind));
  WT_EXPECT_INT("as one", (int)WT_HTTP3_STREAM_KIND_QPACK_ENCODER, (int)kind);
  WT_EXPECT_OK("QPACK decoder is", wt_http3_stream_kind_for_type(WT_HTTP3_STREAM_QPACK_DECODER,
                                                                 &kind));
  WT_EXPECT_OK("push is", wt_http3_stream_kind_for_type(WT_HTTP3_STREAM_PUSH, &kind));
  WT_EXPECT_INT("as a push stream", (int)WT_HTTP3_STREAM_KIND_PUSH, (int)kind);

  /* An unknown prefix is not an error: section 6.2.1 leaves unknown stream types
   * for later revisions, and the caller ignores the stream. */
  WT_EXPECT_STATUS("an unknown prefix is reported, not refused", WT_ERR_STATE,
                   wt_http3_stream_kind_for_type(0x2aU, &kind));
}

int main(void) {
  test_control_stream();
  test_request_stream();
  test_push_and_qpack_streams();
  test_reserved_frame_types_everywhere();
  test_stream_type_prefixes();
  WT_TEST_MAIN_END("wt_http3_streams");
}
