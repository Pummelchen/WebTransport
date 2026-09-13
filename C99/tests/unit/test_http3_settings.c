/* HTTP/3 SETTINGS (RFC 9114 section 7.2.4).
 *
 * The rules under test are the ones a peer can get wrong: a missing value, a
 * reserved HTTP/2 identifier, a duplicate identifier (a MAY in the section that
 * this build takes), a value ENABLE_CONNECT_PROTOCOL may not have, and a peer
 * that sends more settings than this endpoint holds. The two rules that protect
 * interoperability are tested as hard as the errors: an unknown identifier is
 * stored and ignorable, and the reserved exercise identifiers of the
 * `0x1f * N + 0x21` range are ignored rather than refused, because refusing them
 * would break the one thing they exist to exercise. */

#include "wt_test.h"

#include "webtransport/http3/settings.h"
#include "webtransport/quic/varint.h"

static void write_setting(wt_writer_t *w, uint64_t identifier, uint64_t value) {
  (void)wt_quic_writer_varint(w, identifier);
  (void)wt_quic_writer_varint(w, value);
}

static void test_reserved_and_exerciser_identifiers(void) {
  WT_EXPECT_INT("0x02 is reserved", 1, wt_http3_setting_is_reserved_http2(0x02U));
  WT_EXPECT_INT("0x05 is reserved", 1, wt_http3_setting_is_reserved_http2(0x05U));
  WT_EXPECT_INT("0x06 is not", 0, wt_http3_setting_is_reserved_http2(0x06U));
  WT_EXPECT_INT("nor is the exerciser", 0, wt_http3_setting_is_reserved_http2(0x21U));

  WT_EXPECT_INT("0x21 is an exerciser", 1, wt_http3_setting_is_exerciser(0x21U));
  WT_EXPECT_INT("0x40 is an exerciser", 1, wt_http3_setting_is_exerciser(0x40U));
  WT_EXPECT_INT("0x22 is not", 0, wt_http3_setting_is_exerciser(0x22U));
  WT_EXPECT_INT("nor is the QPACK one", 0, wt_http3_setting_is_exerciser(0x01U));
}

static void test_round_trip_is_ordered(void) {
  uint8_t payload[64];
  wt_http3_settings_t settings;
  wt_http3_settings_t parsed;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  int present = 0;

  wt_http3_settings_init(&settings);
  /* Set out of order, so the encoder's ordering is what puts them right. */
  WT_EXPECT_OK("the field section size is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_MAX_FIELD_SECTION_SIZE, 16384U));
  WT_EXPECT_OK("the table capacity is set",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY, 4096U));
  WT_EXPECT_OK("connect protocol is enabled",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U));
  WT_EXPECT_OK("and the exerciser is included",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_EXERCISER, 0U));
  WT_EXPECT_OK("the payload encodes",
               wt_http3_settings_encode_payload(&w, &settings));

  /* The wire bytes, by hand: 0x01 then 0x06 then 0x08 then 0x21 in ascending
   * identifier order, whatever order they were set in, with 4096 and 16384 in
   * the two-byte varint form. */
  {
    static const uint8_t expected[12] = {0x01U, 0x50U, 0x00U, 0x06U, 0x80U, 0x00U,
                                         0x40U, 0x00U, 0x08U, 0x01U, 0x21U, 0x00U};
    WT_EXPECT_U64("as one pair per setting", (uint64_t)sizeof(expected),
                  (uint64_t)wt_writer_offset(&w));
    WT_EXPECT_BYTES("in ascending identifier order", expected, payload, sizeof(expected));
  }

  WT_EXPECT_OK("and parses back",
               wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("with the table capacity",
                wt_http3_settings_get(&parsed, WT_HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY, &present),
                4096U);
  WT_EXPECT_INT("present", 1, present);
  WT_EXPECT_U64("the field section size",
                wt_http3_settings_get(&parsed, WT_HTTP3_SETTING_MAX_FIELD_SECTION_SIZE, &present),
                16384U);
  WT_EXPECT_U64("connect protocol enabled",
                wt_http3_settings_get(&parsed, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, &present),
                1U);
  WT_EXPECT_U64("and the exerciser stored like any other unknown setting",
                wt_http3_settings_get(&parsed, WT_HTTP3_SETTING_EXERCISER, &present), 0U);
  WT_EXPECT_INT("which is present", 1, present);
  WT_EXPECT_U64("a setting that was never sent is absent",
                wt_http3_settings_get(&parsed, WT_HTTP3_SETTING_H3_DATAGRAM, &present), 0U);
  WT_EXPECT_INT("and reports itself absent", 0, present);
}

static void test_parse_errors(void) {
  uint8_t payload[64];
  wt_http3_settings_t parsed;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w;

  /* A parameter with no value: the payload ends between the identifier and its
   * value. */
  w = wt_writer_init(payload, sizeof(payload));
  (void)wt_quic_writer_varint(&w, WT_HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY);
  WT_EXPECT_STATUS("an identifier with no value is refused", WT_ERR_TRUNCATED,
                   wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("as a settings error", WT_HTTP3_SETTINGS_ERROR, (uint64_t)error);

  /* A reserved HTTP/2 identifier. */
  w = wt_writer_init(payload, sizeof(payload));
  write_setting(&w, 0x03U, 100U);
  WT_EXPECT_STATUS("a reserved identifier is refused", WT_ERR_PROTOCOL,
                   wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("as a settings error", WT_HTTP3_SETTINGS_ERROR, (uint64_t)error);

  /* The same identifier twice, including when it is one this build does not
   * understand: that is why the table holds identifiers rather than values. */
  w = wt_writer_init(payload, sizeof(payload));
  write_setting(&w, WT_HTTP3_SETTING_H3_DATAGRAM, 1U);
  write_setting(&w, WT_HTTP3_SETTING_H3_DATAGRAM, 1U);
  WT_EXPECT_STATUS("a duplicate known identifier is refused", WT_ERR_PROTOCOL,
                   wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("as a settings error", WT_HTTP3_SETTINGS_ERROR, (uint64_t)error);

  w = wt_writer_init(payload, sizeof(payload));
  write_setting(&w, 0x2aU, 1U);
  write_setting(&w, 0x2aU, 2U);
  WT_EXPECT_STATUS("and so is a duplicate unknown one", WT_ERR_PROTOCOL,
                   wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("as a settings error", WT_HTTP3_SETTINGS_ERROR, (uint64_t)error);

  /* ENABLE_CONNECT_PROTOCOL is a boolean. */
  w = wt_writer_init(payload, sizeof(payload));
  write_setting(&w, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 2U);
  WT_EXPECT_STATUS("a non-boolean connect protocol value is refused", WT_ERR_PROTOCOL,
                   wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("as a settings error", WT_HTTP3_SETTINGS_ERROR, (uint64_t)error);
}

static void test_too_many_settings(void) {
  uint8_t payload[256];
  wt_http3_settings_t parsed;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t i;

  /* One more setting than this endpoint will hold: distinct identifiers, each a
   * pair of two bytes, so the frame is well formed and only the count is the
   * problem. */
  for (i = 0U; i <= (size_t)WT_HTTP3_SETTINGS_MAX_ENTRIES; i++) {
    write_setting(&w, (uint64_t)0x100 + (uint64_t)i, 0U);
  }
  WT_EXPECT_STATUS("more settings than the table holds is refused", WT_ERR_LIMIT,
                   wt_http3_settings_parse(payload, wt_writer_offset(&w), &parsed, &error));
  WT_EXPECT_U64("as excessive load", WT_HTTP3_EXCESSIVE_LOAD, (uint64_t)error);
}

static void test_set_refusals(void) {
  wt_http3_settings_t settings;
  wt_http3_settings_t other;
  uint8_t payload[16];
  wt_writer_t w = wt_writer_init(payload, sizeof(payload));
  size_t i;

  wt_http3_settings_init(&settings);
  WT_EXPECT_STATUS("a reserved identifier cannot be set", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_settings_set(&settings, 0x02U, 1U));
  WT_EXPECT_STATUS("a value outside the varint range cannot be", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_settings_set(&settings, WT_HTTP3_SETTING_H3_DATAGRAM,
                                         WT_QUIC_VARINT_MAX + 1U));
  WT_EXPECT_STATUS("a connect protocol value above one cannot be", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_settings_set(&settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 2U));
  WT_EXPECT_OK("a valid one can",
               wt_http3_settings_set(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));
  WT_EXPECT_STATUS("and the same identifier twice is refused", WT_ERR_STATE,
                   wt_http3_settings_set(&settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U));

  /* A set with nothing in it encodes nothing, which is a legal SETTINGS frame and
   * how an endpoint with no preferences answers. */
  wt_http3_settings_init(&other);
  WT_EXPECT_OK("an empty set encodes",
               wt_http3_settings_encode_payload(&w, &other));
  WT_EXPECT_U64("as no bytes", 0U, (uint64_t)wt_writer_offset(&w));

  /* And the table bound is the API's too, not only the parser's. */
  wt_http3_settings_init(&other);
  for (i = 0U; i < (size_t)WT_HTTP3_SETTINGS_MAX_ENTRIES; i++) {
    WT_EXPECT_OK("a setting fits", wt_http3_settings_set(&other, 0x200U + (uint64_t)i, i));
  }
  WT_EXPECT_STATUS("and one more does not", WT_ERR_LIMIT,
                   wt_http3_settings_set(&other, 0x300U, 0U));
}

int main(void) {
  test_reserved_and_exerciser_identifiers();
  test_round_trip_is_ordered();
  test_parse_errors();
  test_too_many_settings();
  test_set_refusals();
  WT_TEST_MAIN_END("wt_http3_settings");
}
