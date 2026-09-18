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

#include <string.h>

#include "webtransport/http3/frame.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"

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

  /* RFC 9114 section 7.2.8 has TWO reserved families with OPPOSITE outcomes, and both are asserted here
   * because conflating them is what this file used to do: it called `0x1f * N + 0x21` the reserved family (which
   * a peer MAY send and this endpoint MUST ignore) and left the HTTP/2-derived types (which MUST be
   * H3_FRAME_UNEXPECTED) out of the rule entirely.
   *
   * The forbidden family, named by section 11.2.1: PRIORITY 0x02, PING 0x06, WINDOW_UPDATE 0x08,
   * CONTINUATION 0x09. */
  WT_EXPECT_INT("PRIORITY's type is reserved", 1, wt_http3_frame_type_is_reserved(0x02U));
  WT_EXPECT_INT("PING's type is reserved", 1, wt_http3_frame_type_is_reserved(0x06U));
  WT_EXPECT_INT("WINDOW_UPDATE's type is reserved", 1, wt_http3_frame_type_is_reserved(0x08U));
  WT_EXPECT_INT("and CONTINUATION's", 1, wt_http3_frame_type_is_reserved(0x09U));
  WT_EXPECT_INT("while the QPACK setting is not a frame type", 0,
                wt_http3_frame_type_is_reserved(0x01U));
  WT_EXPECT_INT("nor is a DATA frame", 0, wt_http3_frame_type_is_reserved(WT_HTTP3_FRAME_DATA));

  /* The IGNORED family: 0x1f * N + 0x21, which the WebTransport frame type 0x41 is deliberately NOT, and 0x22,
   * which an off-by-one in the arithmetic would claim. */
  WT_EXPECT_INT("0x21 is an exerciser", 1, wt_http3_frame_type_is_exerciser(0x21U));
  WT_EXPECT_INT("0x40 is an exerciser", 1, wt_http3_frame_type_is_exerciser(0x40U));
  WT_EXPECT_INT("0x5f is an exerciser", 1, wt_http3_frame_type_is_exerciser(0x5fU));
  WT_EXPECT_INT("0x20 is not", 0, wt_http3_frame_type_is_exerciser(0x20U));
  WT_EXPECT_INT("0x22 is not", 0, wt_http3_frame_type_is_exerciser(0x22U));
  WT_EXPECT_INT("0x41 is not", 0, wt_http3_frame_type_is_exerciser(0x41U));
  WT_EXPECT_INT("and a reserved HTTP/2 type is not", 0, wt_http3_frame_type_is_exerciser(0x02U));
}

static void test_frames_round_trip(void) {
  static const uint64_t types[] = {
      WT_HTTP3_FRAME_DATA,         WT_HTTP3_FRAME_HEADERS,
      WT_HTTP3_FRAME_CANCEL_PUSH,  WT_HTTP3_FRAME_SETTINGS,
      WT_HTTP3_FRAME_PUSH_PROMISE, WT_HTTP3_FRAME_GOAWAY,
      WT_HTTP3_FRAME_MAX_PUSH_ID,  0x2aU /* unknown, and a frame all the same */};
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
    WT_EXPECT_OK("and its size is known", wt_http3_frame_encoded_size(&frame, &encoded_size));
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

  WT_EXPECT_OK(
      "the first is read from the front",
      wt_http3_frame_decode_prefix(buffer, wt_writer_offset(&w), &decoded, &consumed, &error));
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

/* The DATA frame a CONNECT stream's capsules travel in (WT-249).
 *
 * RFC 9297 section 3.1 makes the capsule protocol the CONTENTS of the request's data stream and RFC 9114 section 4.4
 * permits only DATA frames on the stream that carried CONNECT, so a capsule is not the stream's raw bytes. A capsule
 * carries its own length, so the frame header cannot be written first: this is the reservation-and-wrap pair that
 * lets a caller write its payload once, in the buffer it is going to send. */
static void test_the_data_frame_around_a_connect_streams_capsules(void) {
  uint8_t buffer[32];
  wt_writer_t w;
  size_t payload_length;
  size_t frame_length = 0U;
  wt_http3_frame_t decoded;
  wt_cursor_t c;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  /* The same capsule written without a reservation, which is what the framed payload has to be byte for byte. */
  uint8_t raw[16];
  wt_writer_t rw = wt_writer_init(raw, sizeof(raw));
  size_t raw_length;

  WT_EXPECT_OK("a real capsule is written", wt_webtransport_max_data_write(&rw, 4096U));
  raw_length = wt_writer_offset(&rw);

  /* A payload the reservation can hold, written where the writer put it: the capsule is what the sink sees, and the
   * frame around it is the header the peer reads. */
  w = wt_http3_frame_data_writer(buffer, sizeof(buffer));
  WT_EXPECT_OK("and again through the reserved writer", wt_webtransport_max_data_write(&w, 4096U));
  payload_length = wt_writer_offset(&w);
  WT_EXPECT_U64("the reservation does not change what is written", (uint64_t)raw_length,
                (uint64_t)payload_length);
  WT_EXPECT_OK(
      "the payload is wrapped where it was written",
      wt_http3_frame_wrap_data_in_place(buffer, sizeof(buffer), payload_length, &frame_length));
  WT_EXPECT_U64("and the frame is its header plus that payload",
                (uint64_t)(payload_length + wt_quic_varint_size(WT_HTTP3_FRAME_DATA) +
                           wt_quic_varint_size((uint64_t)payload_length)),
                (uint64_t)frame_length);

  c = wt_cursor_init(buffer, frame_length);
  WT_EXPECT_OK("the frame reads back", wt_http3_frame_decode(&c, &decoded, &error));
  WT_EXPECT_U64("as a DATA frame", WT_HTTP3_FRAME_DATA, decoded.type);
  WT_EXPECT_U64("whose payload is the capsule", (uint64_t)raw_length, (uint64_t)decoded.length);
  WT_EXPECT_BYTES("byte for byte, wherever the reservation put it", raw, decoded.payload,
                  raw_length);
  /* This is the whole point of the fix: the bytes inside the frame DECODE AS A CAPSULE. The raw form did not. */
  {
    wt_cursor_t capsule_cursor = wt_cursor_init(decoded.payload, decoded.length);
    wt_webtransport_capsule_t capsule;
    uint64_t maximum = 0U;

    memset(&capsule, 0, sizeof(capsule));
    WT_EXPECT_OK("the payload decodes as a capsule",
                 wt_webtransport_capsule_decode(&capsule_cursor, decoded.length, &capsule, &error));
    WT_EXPECT_U64("of the type that was written", WT_CAPSULE_MAX_DATA, capsule.type);
    WT_EXPECT_OK("with the value that was written",
                 wt_webtransport_max_data_parse(&capsule, &maximum, &error));
    WT_EXPECT_U64("which is the grant", 4096U, maximum);
  }

  /* An empty payload is a legal DATA frame, and the length varint is then one byte: the reservation is the CEILING
   * of the header, not its size, so the payload has to move. */
  frame_length = 0U;
  WT_EXPECT_OK("an empty payload is wrapped too",
               wt_http3_frame_wrap_data_in_place(buffer, sizeof(buffer), 0U, &frame_length));
  WT_EXPECT_U64("as a two-byte frame", 2U, (uint64_t)frame_length);
  c = wt_cursor_init(buffer, frame_length);
  WT_EXPECT_OK("which reads back", wt_http3_frame_decode(&c, &decoded, &error));
  WT_EXPECT_U64("as an empty DATA frame", 0U, decoded.length);

  /* A buffer that cannot hold the reservation and the payload is refused, and nothing is written. */
  frame_length = 7U;
  WT_EXPECT_STATUS("a buffer without room for the reservation is refused", WT_ERR_LIMIT,
                   wt_http3_frame_wrap_data_in_place(buffer, WT_HTTP3_FRAME_DATA_HEADER_MAX - 1U,
                                                     0U, &frame_length));
  WT_EXPECT_U64("and the length is cleared", 0U, (uint64_t)frame_length);
  WT_EXPECT_STATUS(
      "as is one without room for the payload", WT_ERR_LIMIT,
      wt_http3_frame_wrap_data_in_place(buffer, sizeof(buffer), sizeof(buffer), &frame_length));
  WT_EXPECT_STATUS("and a null buffer", WT_ERR_INVALID_ARGUMENT,
                   wt_http3_frame_wrap_data_in_place(NULL, sizeof(buffer), 0U, &frame_length));

  /* A writer over a buffer too small for the reservation has no capacity at all, so its first write is what fails
   * rather than a frame the caller then cannot wrap. */
  w = wt_http3_frame_data_writer(buffer, WT_HTTP3_FRAME_DATA_HEADER_MAX - 1U);
  (void)wt_quic_writer_varint(&w, 1U);
  WT_EXPECT_TRUE("a writer with no room refuses its first write", wt_writer_ok(&w) == 0);
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
  test_the_data_frame_around_a_connect_streams_capsules();
  test_stream_type_prefix();
  WT_TEST_MAIN_END("wt_http3_frame");
}
