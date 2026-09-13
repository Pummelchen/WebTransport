/* The Headers and QPACK scenarios (Phase 10). */

#include "scenario_headers.h"

#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/webtransport/session_request.h"
#include "webtransport/writer.h"

static void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED, detail);
}

/* One literal-literal field line, so the two round trips below differ in exactly one flag. */
static void literal_line(wt_qpack_field_line_t *line, const uint8_t *name, size_t name_length,
                         const uint8_t *value, size_t value_length, int huffman) {
  memset(line, 0, sizeof(*line));
  line->kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line->never_indexed = 1;
  line->name = name;
  line->name_length = name_length;
  line->value = value;
  line->value_length = value_length;
  line->name_huffman = huffman;
  line->value_huffman = huffman;
}

void wt_scenario_headers_run(wt_cli_report_t *report) {
  /* The negotiation the whole draft rests on: a CONNECT whose :protocol names WebTransport has to survive
   * QPACK byte for byte, because the peer compares that token and nothing else. Every pseudo-header is
   * asserted rather than just the token, so a section that dropped :authority would be caught here. */
  {
    const char *token = WT_WEBTRANSPORT_PROTOCOL_TOKEN;
    const size_t token_length = strlen(token);
    wt_http3_message_t request;
    wt_http3_message_t read_back;
    uint8_t section[256];
    uint8_t scratch[256];
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int wrote;
    int decoded;
    int same;

    memset(&request, 0, sizeof(request));
    request.type = WT_HTTP3_HEADER_REQUEST;
    request.method = (const uint8_t *)"CONNECT";
    request.method_length = 7U;
    request.scheme = (const uint8_t *)"https";
    request.scheme_length = 5U;
    request.authority = (const uint8_t *)"example.com";
    request.authority_length = 11U;
    request.path = (const uint8_t *)"/chat";
    request.path_length = 5U;
    request.protocol = (const uint8_t *)token;
    request.protocol_length = token_length;

    wrote = wt_http3_message_encode(&w, &request, 0U, &error) == WT_OK;
    memset(&read_back, 0, sizeof(read_back));
    decoded = wrote && wt_http3_message_decode(&read_back, WT_HTTP3_HEADER_REQUEST, section,
                                               wt_writer_offset(&w), NULL, 0U, 0U, scratch,
                                               sizeof(scratch), &error) == WT_OK;

    same = decoded && read_back.method_length == 7U &&
           memcmp(read_back.method, "CONNECT", 7U) == 0 && read_back.scheme_length == 5U &&
           memcmp(read_back.scheme, "https", 5U) == 0 && read_back.authority_length == 11U &&
           memcmp(read_back.authority, "example.com", 11U) == 0 && read_back.path_length == 5U &&
           memcmp(read_back.path, "/chat", 5U) == 0 && read_back.protocol_length == token_length &&
           memcmp(read_back.protocol, token, token_length) == 0;

    add(report, "headers-connect-round-trip", same,
        "an extended CONNECT's pseudo-headers and its :protocol survive QPACK encode and decode");
  }

  /* The response is where a status can go wrong quietly: three digits that parse as a number are not the
   * same as a status the decoder accepted. */
  {
    wt_http3_message_t response;
    wt_http3_message_t read_back;
    uint8_t section[64];
    uint8_t scratch[64];
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int wrote;
    int decoded;

    memset(&response, 0, sizeof(response));
    response.type = WT_HTTP3_HEADER_RESPONSE;
    response.status = 200U;
    response.has_status = 1;

    wrote = wt_http3_message_encode(&w, &response, 0U, &error) == WT_OK;
    memset(&read_back, 0, sizeof(read_back));
    decoded = wrote && wt_http3_message_decode(&read_back, WT_HTTP3_HEADER_RESPONSE, section,
                                               wt_writer_offset(&w), NULL, 0U, 0U, scratch,
                                               sizeof(scratch), &error) == WT_OK;

    add(report, "headers-response-round-trip", decoded && read_back.has_status == 1 &&
                                                   read_back.status == 200U,
        "a 200 response keeps its status through the field section");
  }

  /* The static table is the compression every peer can read without state: :path / is entry 1, and the entry
   * the lookup returns has to be the entry the index names. */
  {
    wt_qpack_static_entry_t entry;
    uint64_t index = 0U;
    int found;
    int matched;

    found = wt_qpack_static_find(":path", 5U, "/", 1U, &index) == WT_OK && index == 1U;
    matched = found && wt_qpack_static_entry(index, &entry) == WT_OK && entry.name_length == 5U &&
              memcmp(entry.name, ":path", 5U) == 0 && entry.value_length == 1U &&
              memcmp(entry.value, "/", 1U) == 0;

    add(report, "qpack-static-reference", matched,
        ":path / is static entry 1, and the lookup and the entry agree about it");
  }

  /* A plain literal line, so the encoded form is readable and its length is the sum of its parts. */
  {
    static const uint8_t name[] = "x-conformance";
    static const uint8_t value[] = "plain";
    wt_qpack_field_line_t line;
    wt_qpack_field_line_t read_back;
    uint8_t section[64];
    wt_writer_t w = wt_writer_init(section, sizeof(section));
    wt_cursor_t c;
    int decoded;

    literal_line(&line, name, sizeof(name) - 1U, value, sizeof(value) - 1U, 0);
    decoded = wt_qpack_field_line_encode(&w, &line) == WT_OK;
    c = wt_cursor_init(section, wt_writer_offset(&w));
    memset(&read_back, 0, sizeof(read_back));
    decoded = decoded && wt_qpack_field_line_decode(&c, &read_back) == WT_OK;

    add(report, "qpack-literal-name-round-trip",
        decoded && read_back.kind == WT_QPACK_FIELD_LITERAL_LITERAL_NAME &&
            read_back.name_length == sizeof(name) - 1U &&
            memcmp(read_back.name, name, sizeof(name) - 1U) == 0 &&
            read_back.value_length == sizeof(value) - 1U &&
            memcmp(read_back.value, value, sizeof(value) - 1U) == 0 &&
            read_back.bytes_consumed == wt_writer_offset(&w) && wt_cursor_at_end(&c) != 0,
        "a literal name and value are written and read back with the whole representation consumed");
  }

  /* The same line Huffman-coded. The H bits are part of the representation, so a decoder that reported them
   * clear would describe a different message; and a coded form that is NOT smaller for a repetitive value
   * would mean the table is not being used at all. */
  {
    static const uint8_t name[] = "x-conformance";
    static const uint8_t value[] = "aaaaaaaaaaaaaaaaaaaaaaaa";
    wt_qpack_field_line_t line;
    wt_qpack_field_line_t read_back;
    uint8_t plain[64];
    uint8_t coded[64];
    uint8_t scratch[64];
    uint8_t decoded_bytes[64];
    size_t coded_length = 0U;
    size_t decoded_length = 0U;
    size_t name_length = 0U;
    size_t value_length = 0U;
    wt_writer_t w_plain = wt_writer_init(plain, sizeof(plain));
    wt_writer_t w_coded = wt_writer_init(coded, sizeof(coded));
    wt_cursor_t c;
    int encoded;
    int smaller;
    int round_trip;

    literal_line(&line, name, sizeof(name) - 1U, value, sizeof(value) - 1U, 0);
    encoded = wt_qpack_field_line_encode(&w_plain, &line) == WT_OK;
    literal_line(&line, name, sizeof(name) - 1U, value, sizeof(value) - 1U, 1);
    encoded = encoded && wt_qpack_field_line_encode_coded(&w_coded, &line, scratch, sizeof(scratch)) == WT_OK;
    smaller = encoded && wt_writer_offset(&w_coded) < wt_writer_offset(&w_plain);

    /* The field-line decoder REPORTS the H bits and hands back the coded bytes: inflating them is the Huffman
     * primitive's job, which is why the assertion decodes each string itself rather than comparing the line's
     * bytes with the originals. A test that expected the line to hand back plain text would be asserting that
     * one layer does two layers' work. */
    c = wt_cursor_init(coded, wt_writer_offset(&w_coded));
    memset(&read_back, 0, sizeof(read_back));
    round_trip = encoded && wt_qpack_field_line_decode(&c, &read_back) == WT_OK &&
                 read_back.kind == WT_QPACK_FIELD_LITERAL_LITERAL_NAME && read_back.name_huffman == 1 &&
                 read_back.value_huffman == 1 &&
                 read_back.bytes_consumed == wt_writer_offset(&w_coded) && wt_cursor_at_end(&c) != 0 &&
                 wt_qpack_huffman_decode(read_back.name, read_back.name_length, scratch, sizeof(scratch),
                                         &name_length) == WT_OK &&
                 name_length == sizeof(name) - 1U && memcmp(scratch, name, sizeof(name) - 1U) == 0 &&
                 wt_qpack_huffman_decode(read_back.value, read_back.value_length, scratch, sizeof(scratch),
                                         &value_length) == WT_OK &&
                 value_length == sizeof(value) - 1U && memcmp(scratch, value, sizeof(value) - 1U) == 0;

    /* And the primitive on its own, so a failure says which of the two layers is wrong. */
    round_trip = round_trip &&
                 wt_qpack_huffman_encode(value, sizeof(value) - 1U, decoded_bytes, sizeof(decoded_bytes),
                                         &coded_length) == WT_OK &&
                 wt_qpack_huffman_decode(decoded_bytes, coded_length, scratch, sizeof(scratch),
                                         &decoded_length) == WT_OK &&
                 decoded_length == sizeof(value) - 1U &&
                 memcmp(scratch, value, sizeof(value) - 1U) == 0;

    add(report, "qpack-huffman-round-trip", smaller && round_trip,
        "a Huffman-coded line is shorter than the plain one and comes back with its H bits set");
  }
}
