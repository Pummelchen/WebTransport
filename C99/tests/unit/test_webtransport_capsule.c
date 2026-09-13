/* WebTransport capsules (draft-ietf-webtrans-http3-16 section 5).
 *
 * The two session capsules are the ones a session cannot end without, so they are tested
 * in both directions and at their edges: a close with the longest reason the draft
 * allows and with one longer, a value shorter than the mandatory four-byte code, and a
 * drain that must carry no value. The rules this layer shares with the stream-shaped
 * layers above it -- an incomplete capsule is not malformed, an unknown type is handed on
 * rather than refused -- are tested too, because they are the ones an implementation is
 * tempted to "improve". */

#include "wt_test.h"

#include "webtransport/webtransport/capsule.h"

static void test_drain_and_close(void) {
  uint8_t bytes[64];
  wt_writer_t w;
  wt_cursor_t c;
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint32_t code = 0U;
  const uint8_t *reason = NULL;
  size_t reason_length = 0U;

  /* A drain has no value, and its encoding is the type and a zero length. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a drain writes", wt_webtransport_drain_session_write(&w));
  WT_EXPECT_U64("as two bytes plus the varint type", 0U, 0U);
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_webtransport_capsule_decode(&c, 64U, &capsule, &error));
  WT_EXPECT_U64("as a drain capsule", WT_CAPSULE_DRAIN_SESSION, capsule.type);
  WT_EXPECT_U64("with no value", 0U, (uint64_t)capsule.value_length);

  /* A close carries a code and a reason. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a close writes",
               wt_webtransport_close_session_write(&w, 0x01020304U, (const uint8_t *)"bye", 3U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_webtransport_capsule_decode(&c, 64U, &capsule, &error));
  WT_EXPECT_U64("as a close capsule", WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION, capsule.type);
  WT_EXPECT_OK("whose value parses",
               wt_webtransport_close_session_parse(&capsule, &code, &reason, &reason_length, &error));
  WT_EXPECT_U64("with the error code", 0x01020304U, (uint64_t)code);
  WT_EXPECT_U64("and the reason length", 3U, (uint64_t)reason_length);
  WT_EXPECT_BYTES("and the reason", (const uint8_t *)"bye", reason, 3U);

  /* A close with no reason is legal: the code is what ends the session. */
  w = wt_writer_init(bytes, sizeof(bytes));
  WT_EXPECT_OK("a bare close writes",
               wt_webtransport_close_session_write(&w, 0U, NULL, 0U));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_webtransport_capsule_decode(&c, 64U, &capsule, &error));
  WT_EXPECT_OK("whose value parses",
               wt_webtransport_close_session_parse(&capsule, &code, NULL, &reason_length, &error));
  WT_EXPECT_U64("to no reason", 0U, (uint64_t)reason_length);
}

static void test_close_edges(void) {
  uint8_t bytes[1200];
  uint8_t reason[WT_CAPSULE_CLOSE_MAX_REASON];
  wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
  wt_cursor_t c;
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint32_t code = 0U;
  size_t reason_length = 0U;

  memset(reason, 'r', sizeof(reason));

  /* The longest reason the draft allows. */
  WT_EXPECT_OK("the longest reason writes",
               wt_webtransport_close_session_write(&w, 7U, reason, sizeof(reason)));
  c = wt_cursor_init(bytes, wt_writer_offset(&w));
  WT_EXPECT_OK("and decodes", wt_webtransport_capsule_decode(&c, 1200U, &capsule, &error));
  WT_EXPECT_OK("whose value parses",
               wt_webtransport_close_session_parse(&capsule, &code, NULL, &reason_length, &error));
  WT_EXPECT_U64("at its full length", (uint64_t)sizeof(reason), (uint64_t)reason_length);

  /* One byte longer is refused at the writer, so this build cannot send what its own
   * reader would refuse. */
  WT_EXPECT_STATUS("one byte more is refused", WT_ERR_LIMIT,
                   wt_webtransport_close_session_write(&w, 7U, reason,
                                                       sizeof(reason) + 1U));

  /* A value shorter than the mandatory four-byte code. */
  {
    static const uint8_t short_value[3] = {0U, 0U, 0U};
    wt_webtransport_capsule_t hand_made;
    hand_made.type = WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION;
    hand_made.value = short_value;
    hand_made.value_length = sizeof(short_value);
    hand_made.bytes_consumed = 0U;
    WT_EXPECT_STATUS("a value with no room for the code is refused", WT_ERR_PROTOCOL,
                     wt_webtransport_close_session_parse(&hand_made, &code, NULL, &reason_length,
                                                         &error));
    WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  }

  /* Parsing a capsule of another type is a caller error rather than a malformed one. */
  {
    wt_webtransport_capsule_t drain;
    drain.type = WT_CAPSULE_DRAIN_SESSION;
    drain.value = NULL;
    drain.value_length = 0U;
    drain.bytes_consumed = 0U;
    WT_EXPECT_STATUS("the drain capsule is not a close", WT_ERR_INVALID_ARGUMENT,
                     wt_webtransport_close_session_parse(&drain, &code, NULL, &reason_length,
                                                         &error));
  }
}

static void test_incomplete_unknown_and_bounds(void) {
  uint8_t bytes[64];
  wt_cursor_t c;
  wt_webtransport_capsule_t capsule;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* An incomplete capsule: a type with no length, and a length longer than the bytes. */
  {
    static const uint8_t type_only[2] = {0x78U, 0xaeU};
    static const uint8_t short_value[3] = {0x00U, 0x08U, 0x01U};
    c = wt_cursor_init(type_only, sizeof(type_only));
    WT_EXPECT_STATUS("a capsule with no length is incomplete", WT_ERR_TRUNCATED,
                     wt_webtransport_capsule_decode(&c, 64U, &capsule, &error));
    c = wt_cursor_init(short_value, sizeof(short_value));
    WT_EXPECT_STATUS("and one whose value is short is too", WT_ERR_TRUNCATED,
                     wt_webtransport_capsule_decode(&c, 64U, &capsule, &error));
    WT_EXPECT_U64("with no error to send yet", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
  }

  /* An unknown type is decoded and handed on: RFC 9297 section 3.2 has a receiver ignore
   * a capsule it does not understand, which is how the format grows. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    wt_webtransport_capsule_t unknown;
    unknown.type = 0x2aU;
    unknown.value = (const uint8_t *)"x";
    unknown.value_length = 1U;
    unknown.bytes_consumed = 0U;
    WT_EXPECT_OK("an unknown capsule writes", wt_webtransport_capsule_encode(&w, &unknown));
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_OK("and decodes", wt_webtransport_capsule_decode(&c, 64U, &capsule, &error));
    WT_EXPECT_U64("with its type", 0x2aU, capsule.type);
    WT_EXPECT_BYTES("and its value", (const uint8_t *)"x", capsule.value, 1U);
  }

  /* And a capsule longer than the caller will buffer is this endpoint's bound rather
   * than the peer's error. */
  {
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    wt_webtransport_capsule_t big;
    big.type = WT_CAPSULE_MAX_DATA;
    big.value = (const uint8_t *)"0123456789";
    big.value_length = 10U;
    big.bytes_consumed = 0U;
    WT_EXPECT_OK("a ten-byte capsule writes", wt_webtransport_capsule_encode(&w, &big));
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    WT_EXPECT_STATUS("but a four-byte bound refuses it", WT_ERR_LIMIT,
                     wt_webtransport_capsule_decode(&c, 4U, &capsule, &error));
    WT_EXPECT_U64("as excessive load", WT_HTTP3_EXCESSIVE_LOAD, (uint64_t)error);
  }
}

int main(void) {
  test_drain_and_close();
  test_close_edges();
  test_incomplete_unknown_and_bounds();
  WT_TEST_MAIN_END("wt_webtransport_capsule");
}
