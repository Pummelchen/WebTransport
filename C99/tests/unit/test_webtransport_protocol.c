/* Sub-protocol negotiation: the `wt-protocol` field's Structured Fields values (draft-16 section 3.2).
 *
 * The rules here decide APPLICATION semantics -- which sub-protocol two endpoints speak -- so the cases that
 * matter are the ones where two implementations could disagree: a token that contains one of the bytes the
 * Structured Fields grammar gives meaning to, a list whose separators are spelled differently, a list longer
 * than the receiver's bound, and the selection itself, where both ends must compute the same answer from the
 * same two lists. */

#include "wt_test.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/webtransport/protocol.h"

static wt_status_t decode_str(const char *value, wt_webtransport_protocol_token_t *out) {
  return wt_webtransport_protocol_decode_item((const uint8_t *)value, strlen(value), out);
}

static void test_token_rules(void) {
  WT_EXPECT_TRUE("a plain token is valid",
                 wt_webtransport_protocol_token_valid((const uint8_t *)"chat.v1", 7U) != 0);
  WT_EXPECT_INT("an empty token is not", 0,
                wt_webtransport_protocol_token_valid((const uint8_t *)"", 0U));
  WT_EXPECT_INT("a token with a space is not", 0,
                wt_webtransport_protocol_token_valid((const uint8_t *)"a b", 3U));
  WT_EXPECT_INT("a token with a comma is not", 0,
                wt_webtransport_protocol_token_valid((const uint8_t *)"a,b", 3U));
  WT_EXPECT_INT("a token with a quote is not", 0,
                wt_webtransport_protocol_token_valid((const uint8_t *)"a\"b", 3U));
  WT_EXPECT_INT("a token with a backslash is not", 0,
                wt_webtransport_protocol_token_valid((const uint8_t *)"a\\b", 3U));
  WT_EXPECT_INT("a token with a NUL byte is not", 0,
                wt_webtransport_protocol_token_valid((const uint8_t *)"a\0b", 3U));
  {
    static const uint8_t too_long[WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX + 1U] = {0};
    uint8_t buffer[WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX + 1U];
    memcpy(buffer, too_long, sizeof(buffer));
    memset(buffer, (int)'a', sizeof(buffer));
    WT_EXPECT_INT("a token past the bound is not", 0,
                  wt_webtransport_protocol_token_valid(buffer, sizeof(buffer)));
  }
  {
    static const uint8_t at_bound[WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX] = {0};
    uint8_t buffer[WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX];
    memcpy(buffer, at_bound, sizeof(buffer));
    memset(buffer, (int)'a', sizeof(buffer));
    WT_EXPECT_INT("a token at the bound is", 1,
                  wt_webtransport_protocol_token_valid(buffer, sizeof(buffer)));
  }
}

static void test_item_round_trip(void) {
  uint8_t value[64];
  wt_writer_t w = wt_writer_init(value, sizeof(value));
  wt_webtransport_protocol_token_t token;
  wt_webtransport_protocol_token_t read_back;

  token.bytes = (const uint8_t *)"chat.v1";
  token.length = 7U;
  WT_EXPECT_OK("one item writes", wt_webtransport_protocol_encode_item(&w, &token));
  WT_EXPECT_U64("as a quoted string", 9U, (uint64_t)wt_writer_offset(&w));
  WT_EXPECT_OK("and reads back", wt_webtransport_protocol_decode_item(value, wt_writer_offset(&w),
                                                                     &read_back));
  WT_EXPECT_U64("with its length", 7U, (uint64_t)read_back.length);
  WT_EXPECT_BYTES("and its bytes inside the value", (const uint8_t *)"chat.v1", read_back.bytes, 7U);
}

static void test_item_refusals(void) {
  wt_webtransport_protocol_token_t token;
  wt_webtransport_protocol_token_t read_back;

  /* A value that is not a Structured Fields string item at all. */
  WT_EXPECT_STATUS("a bare token is malformed", WT_ERR_PROTOCOL,
                   decode_str("chat.v1", &read_back));
  WT_EXPECT_STATUS("a number is malformed", WT_ERR_PROTOCOL, decode_str("42", &read_back));
  WT_EXPECT_STATUS("an unterminated string is malformed", WT_ERR_PROTOCOL, decode_str("\"chat", &read_back));
  WT_EXPECT_STATUS("a trailing byte is malformed", WT_ERR_PROTOCOL, decode_str("\"chat\"x", &read_back));
  WT_EXPECT_STATUS("an empty value is malformed", WT_ERR_PROTOCOL, decode_str("", &read_back));
  /* An escape could only decode to a byte the token rules refuse, so it is refused here rather than
   * tolerated and refused later. */
  WT_EXPECT_STATUS("an escaped quote is malformed", WT_ERR_PROTOCOL, decode_str("\"a\\\"b\"", &read_back));
  WT_EXPECT_STATUS("an escaped backslash is malformed", WT_ERR_PROTOCOL, decode_str("\"a\\\\b\"", &read_back));
  /* And an empty token is not a token. */
  WT_EXPECT_STATUS("an empty string is not a token", WT_ERR_PROTOCOL, decode_str("\"\"", &read_back));

  /* Encoding refuses what could not be a token rather than escaping it into a value that decodes to
   * something else. */
  {
    uint8_t value[64];
    wt_writer_t w = wt_writer_init(value, sizeof(value));
    token.bytes = (const uint8_t *)"a\"b";
    token.length = 3U;
    WT_EXPECT_STATUS("an unencodable token is refused", WT_ERR_PROTOCOL,
                     wt_webtransport_protocol_encode_item(&w, &token));
    WT_EXPECT_U64("and nothing is written", 0U, (uint64_t)wt_writer_offset(&w));
  }
}

static void test_list_round_trip(void) {
  uint8_t value[128];
  wt_writer_t w = wt_writer_init(value, sizeof(value));
  wt_webtransport_protocol_list_t list;
  wt_webtransport_protocol_list_t read_back;

  memset(&list, 0, sizeof(list));
  list.tokens[0].bytes = (const uint8_t *)"chat.v1";
  list.tokens[0].length = 7U;
  list.tokens[1].bytes = (const uint8_t *)"chat.v2";
  list.tokens[1].length = 7U;
  list.tokens[2].bytes = (const uint8_t *)"echo";
  list.tokens[2].length = 4U;
  list.count = 3U;

  WT_EXPECT_OK("a list writes", wt_webtransport_protocol_encode_list(&w, &list));
  WT_EXPECT_BYTES("as RFC 8941 writes one", (const uint8_t *)"\"chat.v1\", \"chat.v2\", \"echo\"", value,
                  wt_writer_offset(&w));
  WT_EXPECT_OK("and reads back", wt_webtransport_protocol_decode_list(value, wt_writer_offset(&w),
                                                                     &read_back));
  WT_EXPECT_U64("with its count", 3U, (uint64_t)read_back.count);
  WT_EXPECT_BYTES("and its first token", (const uint8_t *)"chat.v1", read_back.tokens[0].bytes, 7U);
  WT_EXPECT_BYTES("its second", (const uint8_t *)"chat.v2", read_back.tokens[1].bytes, 7U);
  WT_EXPECT_BYTES("and its third", (const uint8_t *)"echo", read_back.tokens[2].bytes, 4U);

  /* The decoded tokens are views into the caller's value, which is what makes the decoder allocation-free. */
  WT_EXPECT_TRUE("the tokens point into the value the caller supplied",
                 read_back.tokens[0].bytes > value && read_back.tokens[0].bytes < value + sizeof(value));
}

static void test_list_spellings(void) {
  wt_webtransport_protocol_list_t read_back;

  /* Whitespace around the separator is part of the grammar, and two peers that disagree about it would
   * disagree about the list. */
  WT_EXPECT_OK("a tight list reads",
               wt_webtransport_protocol_decode_list((const uint8_t *)"\"a\",\"b\"", 7U, &read_back));
  WT_EXPECT_U64("with both tokens", 2U, (uint64_t)read_back.count);
  WT_EXPECT_OK("a padded list reads",
               wt_webtransport_protocol_decode_list((const uint8_t *)"\"a\" , \t\"b\"", 10U, &read_back));
  WT_EXPECT_U64("with both tokens too", 2U, (uint64_t)read_back.count);
  WT_EXPECT_OK("a single item reads as a list of one",
               wt_webtransport_protocol_decode_list((const uint8_t *)"\"only\"", 6U, &read_back));
  WT_EXPECT_U64("with one token", 1U, (uint64_t)read_back.count);

  WT_EXPECT_STATUS("a missing separator is malformed", WT_ERR_PROTOCOL,
                   wt_webtransport_protocol_decode_list((const uint8_t *)"\"a\" \"b\"", 7U, &read_back));
  WT_EXPECT_STATUS("a trailing comma is malformed", WT_ERR_PROTOCOL,
                   wt_webtransport_protocol_decode_list((const uint8_t *)"\"a\",", 4U, &read_back));
  WT_EXPECT_STATUS("an empty value is malformed", WT_ERR_PROTOCOL,
                   wt_webtransport_protocol_decode_list((const uint8_t *)"", 0U, &read_back));
  WT_EXPECT_STATUS("an empty token in a list is malformed", WT_ERR_PROTOCOL,
                   wt_webtransport_protocol_decode_list((const uint8_t *)"\"\",\"b\"", 7U, &read_back));
}

static void test_list_bounds_and_repeats(void) {
  wt_webtransport_protocol_list_t list;
  wt_webtransport_protocol_list_t read_back;
  uint8_t value[512];
  wt_writer_t w = wt_writer_init(value, sizeof(value));
  size_t index;

  /* A repeat is a peer that is confused about what it is asking for, refused rather than deduplicated. */
  WT_EXPECT_STATUS("a repeated token is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_protocol_decode_list((const uint8_t *)"\"a\",\"a\"", 7U, &read_back));

  memset(&list, 0, sizeof(list));
  for (index = 0U; index < (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX; index++) {
    list.tokens[index].bytes = (const uint8_t *)"aaaaaaaa";
    list.tokens[index].length = 8U;
    list.count = index + 1U;
  }
  WT_EXPECT_STATUS("a list at the bound with repeated names is refused", WT_ERR_PROTOCOL,
                   wt_webtransport_protocol_validate(&list));

  /* The same list with distinct names is at the bound and accepted. */
  for (index = 0U; index < (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX; index++) {
    static uint8_t names[WT_WEBTRANSPORT_PROTOCOL_MAX][4];
    names[index][0] = (uint8_t)'a';
    names[index][1] = (uint8_t)('a' + (int)index);
    names[index][2] = (uint8_t)'z';
    names[index][3] = (uint8_t)'\0';
    list.tokens[index].bytes = names[index];
    list.tokens[index].length = 3U;
  }
  WT_EXPECT_OK("a list of distinct tokens at the bound is accepted",
               wt_webtransport_protocol_validate(&list));
  WT_EXPECT_OK("and encodes", wt_webtransport_protocol_encode_list(&w, &list));
  WT_EXPECT_OK("and decodes", wt_webtransport_protocol_decode_list(value, wt_writer_offset(&w),
                                                                   &read_back));
  WT_EXPECT_U64("back to the same count", (uint64_t)WT_WEBTRANSPORT_PROTOCOL_MAX,
                (uint64_t)read_back.count);

  /* One more is a bound, not a malformed list: the list is well-formed and this endpoint will not hold it.
   * The count is set directly because the struct's array IS the bound -- a caller cannot hold a seventeenth
   * token, which is the point of the fixed table. */
  list.count = (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX + 1U;
  WT_EXPECT_STATUS("a list past the bound is WT_ERR_LIMIT", WT_ERR_LIMIT,
                   wt_webtransport_protocol_validate(&list));

  /* And the same bound from a PEER's bytes, which is the direction that matters: seventeen items are
   * well-formed and refused as excessive load rather than stored in part. */
  {
    uint8_t many[512];
    wt_writer_t writer = wt_writer_init(many, sizeof(many));
    size_t item;
    for (item = 0U; item <= (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX; item++) {
      wt_webtransport_protocol_token_t token;
      char name[8];
      (void)snprintf(name, sizeof(name), "p%u", (unsigned)item);
      token.bytes = (const uint8_t *)name;
      token.length = strlen(name);
      if (item > 0U) wt_writer_bytes(&writer, ", ", 2U);
      (void)wt_webtransport_protocol_encode_item(&writer, &token);
    }
    WT_EXPECT_STATUS("a peer's list past the bound is WT_ERR_LIMIT", WT_ERR_LIMIT,
                     wt_webtransport_protocol_decode_list(many, wt_writer_offset(&writer), &read_back));
  }
}

static void test_selection(void) {
  wt_webtransport_protocol_list_t requested;
  wt_webtransport_protocol_list_t supported;
  wt_webtransport_protocol_token_t selected;

  memset(&requested, 0, sizeof(requested));
  memset(&supported, 0, sizeof(supported));
  requested.tokens[0].bytes = (const uint8_t *)"chat.v1";
  requested.tokens[0].length = 7U;
  requested.tokens[1].bytes = (const uint8_t *)"chat.v2";
  requested.tokens[1].length = 7U;
  requested.count = 2U;
  supported.tokens[0].bytes = (const uint8_t *)"chat.v2";
  supported.tokens[0].length = 7U;
  supported.count = 1U;

  WT_EXPECT_INT("the first requested token the server supports is selected", 1,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
  WT_EXPECT_BYTES("which is chat.v2", (const uint8_t *)"chat.v2", selected.bytes, 7U);

  /* The CLIENT's order decides, not the server's: a server that scanned its own list would answer chat.v1
   * here, and the two ends would then speak different protocols. */
  supported.tokens[0].bytes = (const uint8_t *)"chat.v1";
  supported.tokens[1].bytes = (const uint8_t *)"chat.v2";
  supported.tokens[1].length = 7U;
  supported.count = 2U;
  WT_EXPECT_INT("with both supported the client's first choice still wins", 1,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
  WT_EXPECT_BYTES("which is chat.v1", (const uint8_t *)"chat.v1", selected.bytes, 7U);

  /* No overlap: no selection, and the output is cleared so a caller cannot read a stale token as one. */
  selected.bytes = (const uint8_t *)"stale";
  selected.length = 5U;
  supported.tokens[0].bytes = (const uint8_t *)"other";
  supported.tokens[0].length = 5U;
  supported.count = 1U;
  WT_EXPECT_INT("no overlap selects nothing", 0,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
  WT_EXPECT_U64("and clears the output", 0U, (uint64_t)selected.length);
  WT_EXPECT_TRUE("including its bytes", selected.bytes == NULL);
}

static void test_required_selection(void) {
  wt_webtransport_protocol_list_t requested;
  wt_webtransport_protocol_list_t supported;
  wt_webtransport_protocol_token_t selected;

  /* The case a server that REQUIRES a sub-protocol has to answer: the client offered something, the server
   * supports something, and they do not meet. Nothing is selected, which is what makes the refusal legible
   * rather than a session that quietly speaks nothing. */
  memset(&requested, 0, sizeof(requested));
  memset(&supported, 0, sizeof(supported));
  requested.tokens[0].bytes = (const uint8_t *)"chat.v1";
  requested.tokens[0].length = 7U;
  requested.count = 1U;
  supported.tokens[0].bytes = (const uint8_t *)"chat.v9";
  supported.tokens[0].length = 7U;
  supported.count = 1U;
  WT_EXPECT_INT("nothing is selected when the lists do not meet", 0,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
  WT_EXPECT_INT("and an empty request selects nothing", 0,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
  requested.count = 0U;
  WT_EXPECT_INT("from either side", 0,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
  supported.count = 0U;
  WT_EXPECT_INT("including two empty lists", 0,
                wt_webtransport_protocol_select(&requested, &supported, &selected));
}

int main(void) {
  test_token_rules();
  test_item_round_trip();
  test_item_refusals();
  test_list_round_trip();
  test_list_spellings();
  test_list_bounds_and_repeats();
  test_selection();
  test_required_selection();
  WT_TEST_MAIN_END("wt_webtransport_protocol");
}
