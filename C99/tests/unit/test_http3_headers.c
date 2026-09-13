/* HTTP/3 message header section rules (RFC 9114 sections 4.1 to 4.4).
 *
 * The validator is small and the rules are specific, so each test is one rule: the
 * pseudo-headers first, no duplicates, only the ones the message type defines, the
 * request's required set with CONNECT's exception, lowercase names, the forbidden
 * connection-specific fields and `te`. A validator that accepted all of these would
 * still read every well-formed message correctly, which is why they are all here. */

#include "wt_test.h"

#include "webtransport/http3/headers.h"

static void feed(wt_http3_header_validation_t *validation, const char *name, const char *value,
                 const char *label) {
  WT_EXPECT_OK(label, wt_http3_header_validate(validation, (const uint8_t *)name, strlen(name),
                                               (const uint8_t *)value, strlen(value), NULL));
}

static void refuse(wt_http3_header_validation_t *validation, const char *name, const char *value,
                   const char *label) {
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS(label, WT_ERR_PROTOCOL,
                   wt_http3_header_validate(validation, (const uint8_t *)name, strlen(name),
                                            (const uint8_t *)value, strlen(value), &error));
  WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
}

static void test_a_request(void) {
  wt_http3_header_validation_t validation;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "GET", "the method is first");
  feed(&validation, ":scheme", "https", "then the scheme");
  feed(&validation, ":path", "/wt", "then the path");
  feed(&validation, ":authority", "localhost", "and the authority");
  feed(&validation, "content-type", "application/octet-stream", "then a regular field");
  WT_EXPECT_OK("and the request is complete", wt_http3_header_finish(&validation, &error));

  /* CONNECT: no :scheme and :path, and :authority is required. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "CONNECT", "CONNECT begins");
  feed(&validation, ":authority", "localhost", "with an authority");
  WT_EXPECT_OK("and is complete without scheme or path",
               wt_http3_header_finish(&validation, &error));

  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "CONNECT", "CONNECT begins again");
  WT_EXPECT_STATUS("but not without an authority", WT_ERR_PROTOCOL,
                   wt_http3_header_finish(&validation, &error));
  WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);

  /* A response needs :status and nothing else. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_RESPONSE);
  feed(&validation, ":status", "200", "a status");
  feed(&validation, "content-length", "0", "and a regular field");
  WT_EXPECT_OK("so the response is complete", wt_http3_header_finish(&validation, &error));

  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_RESPONSE);
  feed(&validation, "content-length", "0", "a response with no status");
  WT_EXPECT_STATUS("is incomplete", WT_ERR_PROTOCOL, wt_http3_header_finish(&validation, &error));

  /* And a request missing :path is too. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "GET", "a method");
  feed(&validation, ":scheme", "https", "and a scheme");
  WT_EXPECT_STATUS("a request with no path is incomplete", WT_ERR_PROTOCOL,
                   wt_http3_header_finish(&validation, &error));
}

static void test_the_rules(void) {
  wt_http3_header_validation_t validation;

  /* A regular field before a pseudo-header. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, "x-early", "1", "a regular field first");
  refuse(&validation, ":method", "GET", "makes the pseudo-header that follows invalid");

  /* The same pseudo-header twice. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "GET", "a method");
  refuse(&validation, ":method", "POST", "and a second one is refused");

  /* A pseudo-header this message type does not define. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_RESPONSE);
  refuse(&validation, ":path", "/wt", "a response may not carry :path");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":status", "200", "nor may a request carry :status");
  refuse(&validation, ":unknown", "x", "nor is an unknown pseudo-header anything");

  /* Uppercase names. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "X-Test", "1", "an uppercase name is refused");
  refuse(&validation, "content-TYPE", "1", "even one letter of one");

  /* The connection-specific fields, and `te`. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "connection", "close", "connection is forbidden");
  refuse(&validation, "transfer-encoding", "chunked", "and transfer-encoding");
  refuse(&validation, "keep-alive", "timeout=5", "and keep-alive");
  refuse(&validation, "upgrade", "h2c", "and upgrade");
  refuse(&validation, "proxy-connection", "keep-alive", "and proxy-connection");
  refuse(&validation, "te", "gzip", "and te with anything but trailers");

  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "GET", "a fresh request");
  feed(&validation, ":scheme", "https", "with a scheme");
  feed(&validation, ":path", "/", "a path");
  feed(&validation, "te", "trailers", "may carry te: trailers");
}

int main(void) {
  test_a_request();
  test_the_rules();
  WT_TEST_MAIN_END("wt_http3_headers");
}
