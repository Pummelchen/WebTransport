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

/* F-08: a pseudo-header's value is a field value, so the field-content grammar applies to it. A CR, LF or NUL
 * in :method/:scheme/:path/:authority/:protocol used to pass while the regular-field branch refused the same
 * bytes, even though RFC 9114 sections 4.3.1 and 10.3 make "a character not permitted in a field value" a
 * malformed message wherever the value appears. */
static void test_pseudo_header_values(void) {
  wt_http3_header_validation_t validation;

  /* A fresh validation per case: the refusal must be the VALUE's, not a duplicate pseudo-header left behind by
   * an earlier one that the unfixed code wrongly accepted. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":method", "GE\rT", "a method with a CR is refused");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":method", "GE\nT", "and one with an LF");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":scheme", "https\r\nX: y", "a scheme carrying a header injection is refused");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":path", "/a\r\nX: y", "and so is a path");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":authority", "a\nb", "and an authority with a bare LF");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, ":protocol", "webtransport-h3\r", "and a protocol with a CR");

  /* A NUL cannot go through the strlen-based helper, so the value and its length are passed directly. */
  {
    static const uint8_t k_nul_path[3] = {'/', 0x00U, 'x'};
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
    WT_EXPECT_STATUS("a NUL in a pseudo-header value is refused", WT_ERR_PROTOCOL,
                     wt_http3_header_validate(&validation, (const uint8_t *)":path", 5U, k_nul_path,
                                              sizeof(k_nul_path), &error));
    WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  }

  /* And the legal values are still accepted, so the check is a grammar rather than a blanket refusal. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, ":method", "GET", "a token method is accepted");
  feed(&validation, ":scheme", "https", "and a scheme");
  feed(&validation, ":path", "/wt", "and a path");
}

/* The REGULAR field's name and value grammars (headers.c). The fix that split the uppercase-only check into
 * field_name_is_valid (a token) and field_value_is_valid (field-content) had no regression test: every refusal
 * here used to be an uppercase name that the pre-fix code already rejected, so a name with a space or a value
 * carrying CRLF -- the peer-reachable shapes the fix exists for -- were untested. A name that is not a token and
 * a value that is not field-content are both RFC 9114 section 10.3 malformed messages, and the classic stake is
 * the injection: a value this layer accepts and a later writer turns into a second field. */
static void test_regular_field_grammar(void) {
  wt_http3_header_validation_t validation;

  /* A name that is not a token. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "bad name", "1", "a name with a space is refused");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "bad:name", "1", "and a name with a colon");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "bad\tname", "1", "and a name with a tab");

  /* A value that is not field-content: CR, LF and NUL are the bytes that become a second field. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "x-test", "a\r\nX: y", "a value carrying a CRLF injection is refused");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "x-test", "a\rb", "and one carrying a bare CR");
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  refuse(&validation, "x-test", "a\nb", "and one carrying a bare LF");
  {
    /* A NUL cannot go through the strlen-based helper, so the bytes and their length are passed directly. */
    static const uint8_t k_nul_value[3] = {'a', 0x00U, 'b'};
    static const uint8_t k_name[6] = {'x', '-', 't', 'e', 's', 't'};
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
    WT_EXPECT_STATUS("a NUL in a regular field value is refused", WT_ERR_PROTOCOL,
                     wt_http3_header_validate(&validation, k_name, sizeof(k_name), k_nul_value,
                                              sizeof(k_nul_value), &error));
    WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  }
  {
    /* A DEL (0x7f) is the other control the value grammar refuses. */
    static const uint8_t k_del_value[3] = {'a', 0x7fU, 'b'};
    static const uint8_t k_name[6] = {'x', '-', 't', 'e', 's', 't'};
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
    WT_EXPECT_STATUS("a DEL in a value is refused", WT_ERR_PROTOCOL,
                     wt_http3_header_validate(&validation, k_name, sizeof(k_name), k_del_value,
                                              sizeof(k_del_value), &error));
  }

  /* And the legal shapes are still accepted: field-content allows SP and HTAB, a name may use the token's
   * punctuation, and obs-text (above 0x7f) is legal in a value. */
  wt_http3_header_validation_init(&validation, WT_HTTP3_HEADER_REQUEST);
  feed(&validation, "x-test_1", "a b", "a token name and a value with a space are accepted");
  feed(&validation, "x-note", "a\tb", "and one with a tab");
}

int main(void) {
  test_a_request();
  test_the_rules();
  test_pseudo_header_values();
  test_regular_field_grammar();
  WT_TEST_MAIN_END("wt_http3_headers");
}
