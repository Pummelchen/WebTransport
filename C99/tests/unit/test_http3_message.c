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
  WT_EXPECT_OK(
      "the section writes",
      wt_qpack_field_section_encode(&w, &prefix, 0U, lines, line_count, scratch, sizeof(scratch)));
  *out_length = wt_writer_offset(&w);
}

static void indexed(uint64_t index, wt_qpack_field_line_t *line) {
  memset(line, 0, sizeof(*line));
  line->kind = WT_QPACK_FIELD_INDEXED_STATIC;
  line->index = index;
}

/* One literal-literal field, which is how a section carries a value the static table does not. */
static void named(const char *name, const char *value, wt_qpack_field_line_t *line) {
  memset(line, 0, sizeof(*line));
  line->kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line->name = (const uint8_t *)name;
  line->name_length = strlen(name);
  line->value = (const uint8_t *)value;
  line->value_length = strlen(value);
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
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length, NULL,
                                       0U, 0U, scratch, sizeof(scratch), &error));
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
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length, NULL,
                                       0U, 0U, scratch, sizeof(scratch), &error));
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
    WT_EXPECT_OK(
        "a section needing insertions writes",
        wt_qpack_field_section_encode(&w, &prefix, 8U, lines, 1U, scratch, sizeof(scratch)));
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
                 wt_http3_message_decode(&message, WT_HTTP3_HEADER_RESPONSE, section, length, NULL,
                                         0U, 0U, scratch, sizeof(scratch), &error));
    WT_EXPECT_U64("with the status that was written", accepted[i], message.status);
  }
}

/* RFC 8441 section 4: "On requests that contain the :protocol pseudo-header field, the :scheme and :path
 * pseudo-header fields of the target URI MUST also be included." The validator tracked only "the method was
 * CONNECT", which RFC 9114 section 4.4 exempts from :scheme and :path, so an EXTENDED CONNECT -- a CONNECT that
 * also carries :protocol -- was accepted with no :path; `session_request.c` happened to re-check the path, but
 * every other consumer of the message layer did not. The no-:scheme half was already refused by the non-empty
 * check, so this asserts both halves together and that a PLAIN CONNECT (no :protocol) keeps its exemption. */
static void test_an_extended_connect_requires_scheme_and_path(void) {
  uint8_t section[128];
  uint8_t scratch[64];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_http3_message_t message;

  /* :method CONNECT, :scheme https, :authority localhost, :protocol webtransport-h3 -- and no :path. */
  {
    wt_qpack_field_line_t lines[4];
    named(":method", "CONNECT", &lines[0]);
    named(":scheme", "https", &lines[1]);
    named(":authority", "localhost", &lines[2]);
    named(":protocol", "webtransport-h3", &lines[3]);
    encode_section(section, sizeof(section), &length, lines, 4U);
  }
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS("an extended CONNECT with no :path is refused", WT_ERR_PROTOCOL,
                   wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL,
                                           0U, 0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);

  /* The same request with :protocol but no :scheme: refused by the non-empty check, which is the half that
   * already worked. Asserted here so a change to one half cannot quietly reopen the other. */
  {
    wt_qpack_field_line_t lines[3];
    named(":method", "CONNECT", &lines[0]);
    named(":authority", "localhost", &lines[1]);
    named(":protocol", "webtransport-h3", &lines[2]);
    encode_section(section, sizeof(section), &length, lines, 3U);
  }
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_STATUS("an extended CONNECT with no :scheme is refused", WT_ERR_PROTOCOL,
                   wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL,
                                           0U, 0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_U64("as a message error", WT_HTTP3_MESSAGE_ERROR, (uint64_t)error);

  /* The complete extended CONNECT -- the WebTransport request -- still decodes, with all three values kept. */
  {
    wt_qpack_field_line_t lines[5];
    named(":method", "CONNECT", &lines[0]);
    named(":scheme", "https", &lines[1]);
    named(":authority", "localhost", &lines[2]);
    named(":path", "/wt", &lines[3]);
    named(":protocol", "webtransport-h3", &lines[4]);
    encode_section(section, sizeof(section), &length, lines, 5U);
  }
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_OK("the full extended CONNECT decodes",
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL, 0U,
                                       0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_BYTES("with its path", (const uint8_t *)"/wt", message.path, 3U);
  WT_EXPECT_BYTES("and its protocol", (const uint8_t *)"webtransport-h3", message.protocol, 15U);

  /* A plain CONNECT carries no :protocol and keeps RFC 9114 section 4.4's exemption: no :path required. */
  {
    wt_qpack_field_line_t lines[2];
    named(":method", "CONNECT", &lines[0]);
    named(":authority", "localhost:443", &lines[1]);
    encode_section(section, sizeof(section), &length, lines, 2U);
  }
  error = WT_HTTP3_NO_ERROR;
  WT_EXPECT_OK("a plain CONNECT with no :path still decodes",
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL, 0U,
                                       0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_U64("with no path", 0U, (uint64_t)message.path_length);
  WT_EXPECT_U64("and no protocol", 0U, (uint64_t)message.protocol_length);
}

/* The Origin field, which is how a WebTransport server can apply draft-ietf-webtrans-http3-16 section 3.2 at
 * all: "When the request contains the Origin header, the WebTransport server MUST verify the Origin header ...
 * If the verification fails ... SHOULD reply with status code 403."
 *
 * Origin is a REGULAR field, and the message carried only the pseudo-headers and the status, so the rule was
 * unimplementable through the public API -- `wt_http3_message_decode` validated the field and threw it away,
 * and no consumer could see it. `wt_http3_message_field` reads one named regular field out of the section
 * instead of adding a field to the message structure (which is an ABI break for every consumer and would cover
 * only this one field). The library exposes the value and does not decide which origins are acceptable: that is
 * application policy and stays with the caller. */
static void test_a_regular_field_can_be_read_back(void) {
  uint8_t section[128];
  uint8_t scratch[128];
  size_t length = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_http3_message_t message;
  const uint8_t *value = NULL;
  size_t value_length = 0U;

  {
    wt_qpack_field_line_t lines[6];
    named(":method", "CONNECT", &lines[0]);
    named(":scheme", "https", &lines[1]);
    named(":authority", "localhost", &lines[2]);
    named(":path", "/wt", &lines[3]);
    named(":protocol", "webtransport-h3", &lines[4]);
    named("origin", "https://example.test", &lines[5]);
    encode_section(section, sizeof(section), &length, lines, 6U);
  }

  WT_EXPECT_OK("a request with an Origin decodes",
               wt_http3_message_decode(&message, WT_HTTP3_HEADER_REQUEST, section, length, NULL, 0U,
                                       0U, scratch, sizeof(scratch), &error));
  WT_EXPECT_OK("and the origin can be read back",
               wt_http3_message_field((const uint8_t *)"origin", 6U, section, length, NULL, 0U, 0U,
                                      scratch, sizeof(scratch), &value, &value_length, &error));
  WT_EXPECT_U64("with its length", 20U, (uint64_t)value_length);
  WT_EXPECT_BYTES("and its value", (const uint8_t *)"https://example.test", value, 20U);

  /* A field the section does not carry is ABSENT, which is a different answer from a present but empty one: a
   * caller applying section 3.2 has to know whether the request carried an Origin at all. The name looked up
   * here must be one this section really does not carry -- asking for "origin" again would find the line the
   * block above just wrote and answer WT_OK, which is what a first version of this case asserted against. */
  value = (const uint8_t *)"unchanged";
  value_length = 99U;
  WT_EXPECT_STATUS("a field that is not there is absent, not an error", WT_ERR_STATE,
                   wt_http3_message_field((const uint8_t *)"user-agent", 10U, section, length, NULL,
                                          0U, 0U, scratch, sizeof(scratch), &value, &value_length,
                                          &error));
  WT_EXPECT_TRUE("and the outputs are cleared", value == NULL && value_length == 0U);

  /* The name is compared exactly: a longer or differently-spelled name is not the field, and HTTP/3 requires
   * lowercase names, so `Origin` is not one either. */
  WT_EXPECT_STATUS("a different name does not match", WT_ERR_STATE,
                   wt_http3_message_field((const uint8_t *)"Origins", 7U, section, length, NULL, 0U,
                                          0U, scratch, sizeof(scratch), &value, &value_length,
                                          &error));
  WT_EXPECT_STATUS("and neither does the upper-cased one", WT_ERR_STATE,
                   wt_http3_message_field((const uint8_t *)"Origin", 6U, section, length, NULL, 0U,
                                          0U, scratch, sizeof(scratch), &value, &value_length,
                                          &error));

  /* Missing outputs are refused like every other public entry point's. */
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_message_field((const uint8_t *)"origin", 6U, section, length, NULL, 0U,
                                          0U, scratch, sizeof(scratch), NULL, &value_length,
                                          &error));
}

int main(void) {
  test_a_request();
  test_a_response_and_its_status();
  test_empty_values_and_blocked();
  test_the_encoder_bounds_the_status();
  test_an_extended_connect_requires_scheme_and_path();
  test_a_regular_field_can_be_read_back();
  WT_TEST_MAIN_END("wt_http3_message");
}
