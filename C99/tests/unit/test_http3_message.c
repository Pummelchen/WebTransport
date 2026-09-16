/* HTTP/3 request and response header sections (RFC 9114 section 4.1).
 *
 * This is the join: a QPACK field section in, a validated message with the values a
 * caller needs out. The tests build the sections with QPACK's own encoder and static
 * table, so they exercise the whole path -- prefix, field lines, Huffman, validation --
 * and then check the two rules that live at THIS layer rather than in either of the
 * others: the :status must be three digits in 100..599, and the values that must be
 * present must also be non-empty. */

#include "wt_test.h"

#include "webtransport/http3/message.h"

static void encode_section(uint8_t *buffer, size_t capacity, size_t *out_length,
                           const wt_qpack_field_line_t *lines, size_t line_count) {
  wt_qpack_header_prefix_t prefix;
  uint8_t scratch[64];
  wt_writer_t w = wt_writer_init(buffer, capacity);

  prefix.required_insert_count = 0U;
  prefix.base = 0U;
  WT_EXPECT_OK("the section writes",
               wt_qpack_field_section_encode(&w, &prefix, 0U, lines, line_count, scratch,
                                             sizeof(scratch)));
  *out_length = wt_writer_offset(&w);
}

static void indexed(uint64_t index, wt_qpack_field_line_t *line) {
  memset(line, 0, sizeof(*line));
  line->kind = WT_QPACK_FIELD_INDEXED_STATIC;
  line->index = index;
}

static void test_a_request(void) {
  wt_http3_message_t message;
  wt_qpack_field_line_t lines[4];
  uint8_t section[64];
  uint8_t scratch[64];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* :method GET (17), :scheme https (23), :path / (1), :authority written out. */
  indexed(17U, &lines[0]);
  indexed(23U, &lines[1]);
  indexed(1U, &lines[2]);
  memset(&lines[3], 0, sizeof(lines[3]));
  lines[3].kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  lines[3].name = (const uint8_t *)":authority";
  lines[3].name_length = 10U;
  lines[3].value = (const uint8_t *)"localhost";
  lines[3].value_length = 9U;
  lines[3].name_huffman = 1;
  lines[3].value_huffman = 1;
  encode_section(section, sizeof(section), &length, lines, 4U);

  WT_EXPECT_OK("a request section decodes",
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL, 0U,
                                       0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_U64("with its method length", 3U, (uint64_t)message.method_length);
  WT_EXPECT_BYTES("and its method", (const uint8_t *)"GET", message.method, 3U);
  WT_EXPECT_BYTES("its scheme", (const uint8_t *)"https", message.scheme, 5U);
  WT_EXPECT_BYTES("its path", (const uint8_t *)"/", message.path, 1U);
  WT_EXPECT_BYTES("and its decoded authority", (const uint8_t *)"localhost", message.authority, 9U);
  WT_EXPECT_INT("with no status", 0, message.has_status);
}

static void test_a_response_and_its_status(void) {
  wt_http3_message_t message;
  wt_qpack_field_line_t lines[1];
  uint8_t section[32];
  uint8_t scratch[64];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* :status 200 is static index 25. */
  indexed(25U, &lines[0]);
  encode_section(section, sizeof(section), &length, lines, 1U);
  WT_EXPECT_OK("a response decodes",
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length, NULL, 0U,
                                       0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_INT("with a status", 1, message.has_status);
  WT_EXPECT_U64("of 200", 200U, message.status);

  /* A status written out: 404, which the static table does not carry. */
  memset(&lines[0], 0, sizeof(lines[0]));
  lines[0].kind = WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC;
  lines[0].index = 24U; /* :status 103 */
  lines[0].value = (const uint8_t *)"404";
  lines[0].value_length = 3U;
  encode_section(section, sizeof(section), &length, lines, 1U);
  WT_EXPECT_OK("another response decodes",
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length, NULL, 0U,
                                       0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_U64("with its own status", 404U, message.status);

  /* A status that is not three digits, and one outside the range. */
  {
    static const char *bad[] = {"20", "999", "2oo", "1000"};
    size_t i;
    for (i = 0U; i < sizeof(bad) / sizeof(bad[0]); i++) {
      memset(&lines[0], 0, sizeof(lines[0]));
      lines[0].kind = WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC;
      lines[0].index = 24U;
      lines[0].value = (const uint8_t *)bad[i];
      lines[0].value_length = strlen(bad[i]);
      encode_section(section, sizeof(section), &length, lines, 1U);
      WT_EXPECT_STATUS("a malformed status is refused", WT_ERR_PROTOCOL,
                       wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length,
                                               NULL, 0U, 0U, scratch, sizeof(scratch), &error));
      WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
    }
  }
}

static void test_empty_values_and_blocked(void) {
  wt_http3_message_t message;
  wt_qpack_dynamic_table_t table;
  wt_qpack_field_line_t lines[3];
  uint8_t section[64];
  uint8_t scratch[64];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* A path that is present but empty: present is not enough, and a caller that only
   * checked presence would accept it. */
  indexed(17U, &lines[0]);
  indexed(23U, &lines[1]);
  memset(&lines[2], 0, sizeof(lines[2]));
  lines[2].kind = WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC;
  lines[2].index = 1U; /* :path */
  lines[2].value = (const uint8_t *)"";
  lines[2].value_length = 0U;
  encode_section(section, sizeof(section), &length, lines, 3U);
  WT_EXPECT_STATUS("an empty :path is refused", WT_ERR_PROTOCOL,
                   wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL,
                                           0U, 0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);

  /* A section that needs insertions the decoder has not received is blocked: the
   * caller waits for the encoder stream rather than closing the connection. */
  {
    wt_qpack_header_prefix_t prefix;
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    prefix.required_insert_count = 2U;
    prefix.base = 2U;
    indexed(1U, &lines[0]);
    WT_EXPECT_OK("a section needing insertions writes",
                 wt_qpack_field_section_encode(&w, &prefix, 8U, lines, 1U, scratch,
                                               sizeof(scratch)));
    length = wt_writer_offset(&w);
  }
  wt_qpack_dynamic_init(&table, 256U);
  WT_EXPECT_STATUS("and is reported as blocked", WT_ERR_AGAIN,
                   wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length,
                                           &table, wt_qpack_max_entries(256U), 0U, scratch,
                                           sizeof(scratch), &error));
  WT_EXPECT_U64("with no error to send the peer", (uint64_t)WT_HTTP3_NO_ERROR, (uint64_t)error);
}

/* RFC 9114 section 4.3.2: a :status is exactly three digits in the range 100..599, which is what this file's
 * own reader enforces (`parse_status`). The encoder guarded only "> 999", so a status of 5 went on the wire as
 * ":status: 005" and 600/999 were written as themselves -- field sections its own reader refuses. A writer must
 * not be able to produce a message the reader rejects. */
static void test_the_encoder_bounds_the_status(void) {
  wt_http3_message_t message;
  uint8_t section[64];
  uint8_t scratch[64];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  static const uint64_t refused[] = {5U, 99U, 600U, 999U};
  static const uint64_t accepted[] = {100U, 200U, 599U};
  size_t i;

  for (i = 0U; i < sizeof(refused) / sizeof(refused[0]); i++) {
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    memset(&message, 0, sizeof(message));
    message.type = WT_HTTP3_HEADER_RESPONSE;
    message.has_status = 1;
    message.status = refused[i];
    error = WT_HTTP3_NO_ERROR;
    WT_EXPECT_STATUS("a status outside 100..599 is refused", WT_ERR_LIMIT,
                     wt_http3_message_encode(&w, &message, 0U, &error));
    WT_EXPECT_U64("as a message error", (uint64_t)WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);
  }

  for (i = 0U; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    memset(&message, 0, sizeof(message));
    message.type = WT_HTTP3_HEADER_RESPONSE;
    message.has_status = 1;
    message.status = accepted[i];
    error = WT_HTTP3_NO_ERROR;
    WT_EXPECT_OK("a status inside the range writes",
                 wt_http3_message_encode(&w, &message, 0U, &error));
    length = wt_writer_offset(&w);
    error = WT_HTTP3_NO_ERROR;
    WT_EXPECT_OK("and this library's own reader accepts it",
                 wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length, NULL, 0U,
                                         0U, scratch, sizeof(scratch), &error));
    WT_EXPECT_U64("with the status that was written", accepted[i], message.status);
  }
}

int main(void) {
  test_a_request();
  test_a_response_and_its_status();
  test_empty_values_and_blocked();
  test_the_encoder_bounds_the_status();
  WT_TEST_MAIN_END("wt_http3_message");
}
