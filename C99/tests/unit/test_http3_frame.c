/* HTTP/3 frames and stream type prefixes (RFC 9114 sections 6, 7.2 and 11.2.1).
 *
 * The codec has no state to test, so what these cover is its edges: every
 * registered type round trips, an unknown type is a frame like any other (the
 * codec must not refuse what a future revision defines), a frame whose declared
 * length is not in the buffer is refused rather than read past, a refusal leaves
 * the caller's cursor where it was -- so the caller can say which frame failed --
 * and the stream type prefix is read once, at the front, with a missing one
 * reported as the stream creation error the section names. */

#include "wt_test.h"

#include "webtransport/http3/frame.h"
#include "webtransport/quic/varint.h"

static void test_frame_type_names_and_reserved_range(void) {
  WT_EXPECT_STR("data is named", "data", wt_http3_frame_type_name(WT_HTTP3_FRAME_DATA));
  WT_EXPECT_STR("headers is named", "headers", wt_http3_frame_type_name(WT_HTTP3_FRAME_HEADERS));
  WT_EXPECT_STR("cancel-push is named", "cancel-push",
                wt_http3_frame_type_name(WT_HTTP3_FRAME_CANCEL_PUSH));
  WT_EXPECT_STR("settings is named", "settings", wt_http3_frame_type_name(WT_HTTP3_FRAME_SETTINGS));
  WT_EXPECT_STR("push-promise is named", "push-promise",
                wt_http3_frame_type_name(WT_HTTP3_FRAME_PUSH_PROMISE));
  WT_EXPECT_STR("goaway is named", "goaway", wt_http3_frame_type_name(WT_HTTP3_FRAME_GOAWAY));
  WT_EXPECT_STR("max-push-id is named", "max-push-id",
                wt_http3_frame_type_name(WT_HTTP3_FRAME_MAX_PUSH_ID));
  WT_EXPECT_STR("anything else is unknown", "unknown", wt_http3_frame_type_name(0x2aU));

  /* RFC 9114 section 7.2.8: 0x1f * N + 0x21 was reserved for HTTP/2's frame
   * types. The WebTransport frame type 0x41 is not one of them, and neither is
   * 0x22, which is what an off-by-one in the rule would claim. */
  WT_EXPECT_INT("0x21 is reserved", 1, wt_http3_frame_type_is_reserved(0x21U));
  WT_EXPECT_INT("0x40 is reserved", 1, wt_http3_frame_type_is_reserved(0x40U));
  WT_EXPECT_INT("0x5f is reserved", 1, wt_http3_frame_type_is_reserved(0x5fU));
  WT_EXPECT_INT("0x20 is not", 0, wt_http3_frame_type_is_reserved(0x20U));
  WT_EXPECT_INT("0x22 is not", 0, wt_http3_frame_type_is_reserved(0x22U));
  WT_EXPECT_INT("0x41 is not", 0, wt_http3_frame_type_is_reserved(0x41U));
}

static void test_frames_round_trip(void) {
  static const uint64_t types[] = {
      WT_HTTP3_FRAME_DATA,       WT_HTTP3_FRAME_HEADERS, WT_HTTP3_FRAME_CANCEL_PUSH,
      WT_HTTP3_FRAME_SETTINGS,   WT_HTTP3_FRAME_PUSH_PROMISE, WT_HTTP3_FRAME_GOAWAY,
      WT_HTTP3_FRAME_MAX_PUSH_ID, 0x2aU /* unknown, and a frame all the same */};
  static const uint8_t payload[5] = {0xdeU, 0xadU, 0xbeU, 0xefU, 0x00U};
  uint8_t buffer[64];
  size_t i;

  for (i = 0U; i < sizeof(types) / sizeof(types[0]); i++) {
    wt_http3_frame_t frame = wt_http3_frame_make(types[i]);
    wt_http3_frame_t decoded;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_cursor_t c;
    size_t encoded_size = 0U;

    frame.payload = payload;
    frame.length = sizeof(payload);
    WT_EXPECT_OK("a frame encodes", wt_http3_frame_encode(&w, &frame));
    WT_EXPECT_OK("and its size is known",
                 wt_http3_frame_encoded_size(&frame, &encoded_size));
    WT_EXPECT_U64("which is what was written", (uint64_t)wt_writer_offset(&w),
                  (uint64_t)encoded_size);

    c = wt_cursor_init(buffer, wt_writer_offset(&w));
    WT_EXPECT_OK("and decodes", wt_http3_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("with its type", types[i], decoded.type);
    WT_EXPECT_U64("its length", (uint64_t)sizeof(payload), (uint64_t)decoded.length);
    WT_EXPECT_BYTES("and its payload", payload, decoded.payload, sizeof(payload));
    WT_EXPECT_TRUE("leaving nothing behind", wt_cursor_at_end(&c));
  }
}

static void test_empty_payload_and_prefix_decoding(void) {
  static const uint8_t settings_payload[2] = {0x01U, 0x00U};
  uint8_t buffer[64];
  wt_http3_frame_t empty;
  wt_http3_frame_t with_payload;
  wt_http3_frame_t decoded;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  size_t consumed = 0U;
  size_t first_size;

  /* A frame with no payload is two bytes: the type and a zero length. */
  empty = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);
  WT_EXPECT_OK("an empty frame encodes", wt_http3_frame_encode(&w, &empty));
  WT_EXPECT_U64("as a type and a zero length", 2U, (uint64_t)wt_writer_offset(&w));
  first_size = wt_writer_offset(&w);

  with_payload = wt_http3_frame_make(WT_HTTP3_FRAME_SETTINGS);
  with_payload.payload = settings_payload;
  with_payload.length = sizeof(settings_payload);
  WT_EXPECT_OK("a second frame encodes", wt_http3_frame_encode(&w, &with_payload));

  WT_EXPECT_OK("the first is read from the front",
               wt_http3_frame_decode_prefix(buffer, wt_writer_offset(&w), &decoded, &consumed,
                                            &error));
  WT_EXPECT_U64("with the type of the first", WT_HTTP3_FRAME_DATA, decoded.type);
  WT_EXPECT_U64("a zero length", 0U, (uint64_t)decoded.length);
  WT_EXPECT_U64("and only its own bytes consumed", (uint64_t)first_size, (uint64_t)consumed);

  /* What is left is the second frame, which is what makes the prefix decoder
   * useful for a stream carrying several. */
  WT_EXPECT_OK("the second follows",
               wt_http3_frame_decode_prefix(buffer + consumed, wt_writer_offset(&w) - consumed,
                                            &decoded, &consumed, &error));
  WT_EXPECT_U64("as the settings frame", WT_HTTP3_FRAME_SETTINGS, decoded.type);
  WT_EXPECT_BYTES("with its payload", settings_payload, decoded.payload, sizeof(settings_payload));
}

static void test_truncated_frames_are_refused(void) {
  static const uint8_t type_only[1] = {0x00U};
  static const uint8_t length_without_payload[3] = {0x00U, 0x04U, 0x01U};
  uint8_t huge_length[9];
  wt_http3_frame_t decoded;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  wt_writer_t w;
  wt_cursor_t c;

  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer is not a frame", WT_ERR_TRUNCATED,
                   wt_http3_frame_decode(&c, &decoded, &error));
  WT_EXPECT_U64("and says so", WT_HTTP3_FRAME_ERROR, (uint64_t)error);

  c = wt_cursor_init(type_only, sizeof(type_only));
  WT_EXPECT_STATUS("a type with no length is refused", WT_ERR_TRUNCATED,
                   wt_http3_frame_decode(&c, &decoded, &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);

  c = wt_cursor_init(length_without_payload, sizeof(length_without_payload));
  WT_EXPECT_STATUS("a length longer than the bytes present is refused", WT_ERR_TRUNCATED,
                   wt_http3_frame_decode(&c, &decoded, &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);
  WT_EXPECT_U64("and the cursor did not move", (uint64_t)sizeof(length_without_payload),
                (uint64_t)wt_cursor_remaining(&c));

  /* A length the varint can carry but no buffer can hold: 2^62 - 1. */
  w = wt_writer_init(huge_length, sizeof(huge_length));
  (void)wt_quic_writer_varint(&w, WT_HTTP3_FRAME_DATA);
  (void)wt_quic_writer_varint(&w, WT_QUIC_VARINT_MAX);
  c = wt_cursor_init(huge_length, wt_writer_offset(&w));
  WT_EXPECT_STATUS("a length beyond the buffer is refused", WT_ERR_TRUNCATED,
                   wt_http3_frame_decode(&c, &decoded, &error));
  WT_EXPECT_U64("as a frame error", WT_HTTP3_FRAME_ERROR, (uint64_t)error);
}

static void test_encode_refusals(void) {
  uint8_t buffer[8];
  wt_http3_frame_t frame = wt_http3_frame_make(WT_HTTP3_FRAME_DATA);
  static const uint8_t payload[4] = {1U, 2U, 3U, 4U};
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));

  frame.payload = NULL;
  frame.length = 4U;
  WT_EXPECT_STATUS("a null payload with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_frame_encode(&w, &frame));

  frame.payload = payload;
  frame.length = 0U;
  frame.type = WT_QUIC_VARINT_MAX + 1U;
  WT_EXPECT_STATUS("a type the varint cannot carry is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_frame_encode(&w, &frame));

  frame.type = WT_HTTP3_FRAME_DATA;
  frame.payload = payload;
  frame.length = 4U;
  frame.length = (size_t)WT_QUIC_VARINT_MAX + 1U;
  WT_EXPECT_STATUS("and so is a length", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_frame_encode(&w, &frame));

  /* The writer's own bound, which is a limit rather than a malformed frame. */
  {
    wt_writer_t small = wt_writer_init(buffer, 2U);
    frame.length = 4U;
    WT_EXPECT_STATUS("a frame that does not fit is a limit", WT_ERR_LIMIT,
                     wt_http3_frame_encode(&small, &frame));
  }
}

static void test_stream_type_prefix(void) {
  uint8_t buffer[16];
  wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
  wt_cursor_t c;
  uint64_t type = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  (void)wt_quic_writer_varint(&w, WT_HTTP3_STREAM_CONTROL);
  (void)wt_quic_writer_varint(&w, WT_HTTP3_STREAM_QPACK_ENCODER);
  c = wt_cursor_init(buffer, wt_writer_offset(&w));

  WT_EXPECT_OK("the control stream type reads", wt_http3_stream_type_read(&c, &type, &error));
  WT_EXPECT_U64("as control", WT_HTTP3_STREAM_CONTROL, type);
  WT_EXPECT_OK("and the next one follows", wt_http3_stream_type_read(&c, &type, &error));
  WT_EXPECT_U64("as the QPACK encoder", WT_HTTP3_STREAM_QPACK_ENCODER, type);
  WT_EXPECT_TRUE("with nothing left", wt_cursor_at_end(&c));

  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("a stream with no type is refused", WT_ERR_TRUNCATED,
                   wt_http3_stream_type_read(&c, &type, &error));
  WT_EXPECT_U64("as a stream creation error", WT_HTTP3_STREAM_CREATION_ERROR, (uint64_t)error);

  /* An unknown type is a value, not an error: what to do with it is the stream
   * layer's rule (section 6.2.1 leaves unknown types for future revisions). */
  buffer[0] = 0x2aU;
  c = wt_cursor_init(buffer, 1U);
  WT_EXPECT_OK("an unknown stream type reads", wt_http3_stream_type_read(&c, &type, &error));
  WT_EXPECT_U64("with its value", 0x2aU, type);
}

int main(void) {
  test_frame_type_names_and_reserved_range();
  test_frames_round_trip();
  test_empty_payload_and_prefix_decoding();
  test_truncated_frames_are_refused();
  test_encode_refusals();
  test_stream_type_prefix();
  WT_TEST_MAIN_END("wt_http3_frame");
}
