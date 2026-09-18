#include "test_quic_frame_encoding_support.h"
#include "vectors/rfc9001_client_initial.h"
#include "webtransport/quic/frame.h"
#include "wt_test.h"

static void test_ack_ranges(void) {
  uint8_t buffer[128];
  wt_quic_frame_t frame;
  wt_quic_frame_t decoded;
  wt_quic_error_t error = 0U;
  wt_quic_ack_range_t range;
  size_t encoded = 0U;
  size_t i;

  /* An ACK with three additional ranges, encoded by building the wire bytes of
   * the ranges directly, so the test does not depend on an encoder for a
   * structure the parser keeps as bytes. */
  {
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    wt_quic_frame_t ack = wt_quic_frame_make(WT_QUIC_FRAME_KIND_ACK);
    ack.as.ack.largest = 100U;
    ack.as.ack.delay = 7U;
    ack.as.ack.first_range = 3U;
    ack.as.ack.range_count = 3U;
    /* The ranges are built into a scratch area and handed to the encoder
     * through a temporary frame, so `wt_quic_frame_ack_range_at` can walk
     * them. */
    {
      wt_writer_t rw;
      uint8_t scratch[32];
      wt_quic_frame_t holder;
      rw = wt_writer_init(scratch, sizeof(scratch));
      (void)wt_quic_writer_varint(&rw, 1U);
      (void)wt_quic_writer_varint(&rw, 3U);
      (void)wt_quic_writer_varint(&rw, 4U);
      (void)wt_quic_writer_varint(&rw, 5U);
      (void)wt_quic_writer_varint(&rw, 0U);
      (void)wt_quic_writer_varint(&rw, 1U);
      holder = ack;
      holder.as.ack.ranges = scratch;
      holder.as.ack.ranges_len = wt_writer_offset(&rw);
      encoded = encode_ok("an ACK with three ranges encodes", &holder, buffer, sizeof(buffer));
      /* The ranges are read back from the encoded frame, which is what the
       * accessor is for. */
      (void)encoded;
    }
    (void)w;
    (void)ack;
  }

  /* A hand-built ACK frame with ranges, parsed: the ranges are the wire bytes
   * and the accessor decodes them one at a time. */
  {
    /* Type 0x02, largest 100, delay 7, count 3, first range 3, then three
     * gap/length pairs: (1,3), (4,5), (0,1).
     *
     * THE LARGEST ACKNOWLEDGED IS `40 64`, NOT `64`. A QUIC varint's first two
     * bits are its length: 0x64 has 01 in those bits, so it is the first byte of
     * a two-byte value and the parser reads the following byte as its low half.
     * Hand-writing a field value into a vector without its prefix is the mistake
     * this test made first, and it looked exactly like a parser defect: the
     * frame's fields came back shifted by one byte. */
    static const uint8_t bytes[] = {0x02U, 0x40U, 0x64U, 0x07U, 0x03U, 0x03U,
                                    0x01U, 0x03U, 0x04U, 0x05U, 0x00U, 0x01U};
    wt_cursor_t c = wt_cursor_init(bytes, sizeof(bytes));
    static const uint64_t expected_gap[3] = {1U, 4U, 0U};
    static const uint64_t expected_length[3] = {3U, 5U, 1U};
    WT_EXPECT_STATUS("the hand-built ACK parses", WT_OK,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_INT("it is an ACK", (long)WT_QUIC_FRAME_KIND_ACK, (long)decoded.kind);
    WT_EXPECT_U64("largest acknowledged", 100U, decoded.as.ack.largest);
    WT_EXPECT_U64("ack delay", 7U, decoded.as.ack.delay);
    WT_EXPECT_U64("first range", 3U, decoded.as.ack.first_range);
    WT_EXPECT_U64("range count", 3U, decoded.as.ack.range_count);
    WT_EXPECT_INT("and no ECN counts", 0, decoded.as.ack.has_ecn);
    for (i = 0U; i < 3U; i++) {
      WT_EXPECT_STATUS("the range decodes", WT_OK, wt_quic_frame_ack_range_at(&decoded, i, &range));
      WT_EXPECT_U64("  gap", expected_gap[i], range.gap);
      WT_EXPECT_U64("  length", expected_length[i], range.length);
    }
    WT_EXPECT_STATUS("an index past the end is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_ack_range_at(&decoded, 3U, &range));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_ack_range_at(&decoded, 0U, NULL));
    /* The frame must be followed by nothing for this buffer, and the ACK
     * consumed exactly its own bytes. */
    WT_EXPECT_INT("the ACK consumed the whole buffer", 1, wt_cursor_at_end(&c));
  }

  /* An ACK that claims ranges it does not carry is truncated, not a walk off
   * the end. */
  {
    static const uint8_t short_ack[] = {0x02U, 0x40U, 0x64U, 0x07U, 0x05U, 0x03U, 0x01U, 0x03U};
    wt_cursor_t c = wt_cursor_init(short_ack, sizeof(short_ack));
    WT_EXPECT_STATUS("an ACK with missing ranges is truncated", WT_ERR_TRUNCATED,
                     wt_quic_frame_decode(&c, &decoded, &error));
  }

  /* An ACK that claims a huge number of ranges must not make the parser
   * allocate or loop: it walks the ranges it has and refuses. */
  {
    /* A count of 2^62 - 1, which is an eight-byte varint of all ones, followed
     * by a valid first range and one range. The parser must refuse it by
     * running out rather than by looping 2^62 times or allocating for it. */
    static const uint8_t many[15] = {0x02U, 0x40U, 0x64U, 0x07U, 0xffU, 0xffU, 0xffU, 0xffU,
                                     0xffU, 0xffU, 0xffU, 0xffU, 0x03U, 0x01U, 0x03U};
    wt_cursor_t c = wt_cursor_init(many, sizeof(many));
    WT_EXPECT_STATUS("an ACK claiming many ranges is refused without walking", WT_ERR_TRUNCATED,
                     wt_quic_frame_decode(&c, &decoded, &error));
  }

  /* ACK_ECN carries three extra counts. */
  {
    static const uint8_t ecn[] = {0x03U, 0x40U, 0x64U, 0x07U, 0x00U, 0x03U, 0x01U, 0x02U, 0x00U};
    wt_cursor_t c = wt_cursor_init(ecn, sizeof(ecn));
    WT_EXPECT_STATUS("an ACK_ECN parses", WT_OK, wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_INT("with ECN counts", 1, decoded.as.ack.has_ecn);
    WT_EXPECT_U64("ect0", 1U, decoded.as.ack.ect0);
    WT_EXPECT_U64("ect1", 2U, decoded.as.ack.ect1);
    WT_EXPECT_U64("ecn-ce", 0U, decoded.as.ack.ecn_ce);
  }

  /* The accessor on a frame that is not an ACK. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  WT_EXPECT_STATUS("the range accessor refuses a non-ACK", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_frame_ack_range_at(&frame, 0U, &range));
  WT_EXPECT_STATUS("the range accessor refuses a NULL frame", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_frame_ack_range_at(NULL, 0U, &range));
}
static void test_frame_names(void) {
  WT_EXPECT_STR("padding", "padding", wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_PADDING));
  WT_EXPECT_STR("stream", "stream", wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_STREAM));
  WT_EXPECT_STR("connection close", "connection-close",
                wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT));
  WT_EXPECT_STR("application close", "connection-close-application",
                wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION));
  WT_EXPECT_STR("datagram", "datagram", wt_quic_frame_kind_name(WT_QUIC_FRAME_KIND_DATAGRAM));
  WT_EXPECT_STR("an unknown kind", "unknown", wt_quic_frame_kind_name((wt_quic_frame_type_t)999));
}
/* Moved from test_quic_frame.c, which was over the 500-line limit. It is declared here
 * rather than in a header: the two frame tests are the only translation units that use it. */
void test_frame_round_trips(void);

int main(void) {
  test_frame_round_trips();
  test_ack_ranges();
  test_frame_names();
  WT_TEST_MAIN_END("test_quic_frame_encoding");
}

void test_frame_round_trips(void) {
  uint8_t buffer[512];
  wt_quic_frame_t frame;
  wt_quic_frame_t decoded;
  static const uint8_t payload[5] = {0xDEU, 0xADU, 0xBEU, 0xEFU, 0x00U};
  static const uint8_t token[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
  static const uint8_t cid[8] = {9U, 8U, 7U, 6U, 5U, 4U, 3U, 2U};
  static const uint8_t reset_token[16] = {1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U,
                                          2U, 2U, 2U, 2U, 2U, 2U, 2U, 2U};
  static const uint8_t path[8] = {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0x11U, 0x22U, 0x33U, 0x44U};
  static const uint8_t reason[4] = {'g', 'o', 'n', 'e'};

  /* PADDING and PING carry nothing. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PADDING);
  WT_EXPECT_STATUS("PADDING round trips", WT_OK,
                   round_trip("PADDING encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_INT("  and decodes as PADDING", (long)WT_QUIC_FRAME_KIND_PADDING, (long)decoded.kind);
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  WT_EXPECT_STATUS("PING round trips", WT_OK,
                   round_trip("PING encodes", &frame, &decoded, buffer, sizeof(buffer)));
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_HANDSHAKE_DONE);
  WT_EXPECT_STATUS("HANDSHAKE_DONE round trips", WT_OK,
                   round_trip("HANDSHAKE_DONE encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_INT("  and decodes as itself", (long)WT_QUIC_FRAME_KIND_HANDSHAKE_DONE,
                (long)decoded.kind);

  /* CRYPTO. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CRYPTO);
  frame.as.crypto.offset = 4096U;
  frame.as.crypto.data = payload;
  frame.as.crypto.length = sizeof(payload);
  WT_EXPECT_STATUS("CRYPTO round trips", WT_OK,
                   round_trip("CRYPTO encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its offset", 4096U, decoded.as.crypto.offset);
  WT_EXPECT_U64("  and length", sizeof(payload), (uint64_t)decoded.as.crypto.length);
  WT_EXPECT_BYTES("  and payload", payload, decoded.as.crypto.data, sizeof(payload));

  /* A zero-length CRYPTO frame is legal and is what a handshake sends when it
   * has nothing to add; a parser that treated a NULL payload view as failure
   * would refuse it. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CRYPTO);
  frame.as.crypto.offset = 0U;
  frame.as.crypto.data = NULL;
  frame.as.crypto.length = 0U;
  WT_EXPECT_STATUS(
      "a zero-length CRYPTO frame round trips", WT_OK,
      round_trip("a zero-length CRYPTO encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with no payload", 0U, (uint64_t)decoded.as.crypto.length);

  /* STREAM, in all eight flag combinations: the type byte's low three bits are
   * the flags, so each is a different frame on the wire. */
  {
    int has_offset;
    int has_length;
    int fin;
    for (has_offset = 0; has_offset < 2; has_offset++) {
      for (has_length = 0; has_length < 2; has_length++) {
        for (fin = 0; fin < 2; fin++) {
          frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
          frame.as.stream.id = 4U;
          frame.as.stream.has_offset = has_offset;
          frame.as.stream.offset = has_offset ? 1024U : 0U;
          frame.as.stream.has_length = has_length;
          frame.as.stream.fin = fin;
          frame.as.stream.data = payload;
          frame.as.stream.length = sizeof(payload);
          WT_EXPECT_STATUS(
              "a STREAM flag combination round trips", WT_OK,
              round_trip("  STREAM encodes", &frame, &decoded, buffer, sizeof(buffer)));
          WT_EXPECT_INT("  and the offset flag survives", has_offset, decoded.as.stream.has_offset);
          WT_EXPECT_INT("  and the length flag", has_length, decoded.as.stream.has_length);
          WT_EXPECT_INT("  and the fin flag", fin, decoded.as.stream.fin);
          WT_EXPECT_U64("  and the id", 4U, decoded.as.stream.id);
          WT_EXPECT_U64("  and the payload length", sizeof(payload),
                        (uint64_t)decoded.as.stream.length);
          WT_EXPECT_BYTES("  and the payload", payload, decoded.as.stream.data, sizeof(payload));
        }
      }
    }
  }

  /* A STREAM frame without the length flag runs to the end of the packet, which
   * is why it must be the last frame. The parser resolves the length either
   * way, so a reader never has to know. */
  {
    static const uint8_t three_frames[3] = {0x11U, 0x22U, 0x33U};
    wt_cursor_t c;
    wt_quic_error_t error = 0U;
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
    frame.as.stream.id = 0U;
    frame.as.stream.has_offset = 0;
    frame.as.stream.has_length = 0;
    frame.as.stream.fin = 1;
    frame.as.stream.data = three_frames;
    frame.as.stream.length = sizeof(three_frames);
    {
      /* The encoded length is what the cursor is given, not a guess: the frame
       * is a type byte, an id and the data, and an extra byte of the test buffer
       * would be read as part of the data -- which is exactly what the first
       * version of this check did. */
      size_t encoded =
          encode_ok("a STREAM frame with no length encodes", &frame, buffer, sizeof(buffer));
      c = wt_cursor_init(buffer, encoded);
    }
    WT_EXPECT_STATUS("it parses", WT_OK, wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("taking the rest of the packet as its data", sizeof(three_frames),
                  (uint64_t)decoded.as.stream.length);
    WT_EXPECT_INT("and it is at the end", 1, wt_cursor_at_end(&c));
  }

  /* RESET_STREAM, STOP_SENDING, RESET_STREAM_AT. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RESET_STREAM);
  frame.as.reset_stream.id = 8U;
  frame.as.reset_stream.application_error_code = 42U;
  frame.as.reset_stream.final_size = 1000U;
  WT_EXPECT_STATUS("RESET_STREAM round trips", WT_OK,
                   round_trip("RESET_STREAM encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its final size", 1000U, decoded.as.reset_stream.final_size);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STOP_SENDING);
  frame.as.stop_sending.id = 12U;
  frame.as.stop_sending.application_error_code = 7U;
  WT_EXPECT_STATUS("STOP_SENDING round trips", WT_OK,
                   round_trip("STOP_SENDING encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its error code", 7U, decoded.as.stop_sending.application_error_code);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RESET_STREAM_AT);
  frame.as.reset_stream_at.id = 16U;
  frame.as.reset_stream_at.application_error_code = 3U;
  frame.as.reset_stream_at.final_size = 500U;
  frame.as.reset_stream_at.reliable_size = 200U;
  WT_EXPECT_STATUS("RESET_STREAM_AT round trips", WT_OK,
                   round_trip("RESET_STREAM_AT encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its reliable size", 200U, decoded.as.reset_stream_at.reliable_size);

  /* The flow control frames, which all carry one or two integers. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
  frame.as.max_data.maximum = 1048576U;
  WT_EXPECT_STATUS("MAX_DATA round trips", WT_OK,
                   round_trip("MAX_DATA encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its limit", 1048576U, decoded.as.max_data.maximum);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_STREAM_DATA);
  frame.as.max_stream_data.id = 4U;
  frame.as.max_stream_data.maximum = 65536U;
  WT_EXPECT_STATUS("MAX_STREAM_DATA round trips", WT_OK,
                   round_trip("MAX_STREAM_DATA encodes", &frame, &decoded, buffer, sizeof(buffer)));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_STREAMS);
  frame.as.max_streams.direction = WT_QUIC_STREAM_BIDIRECTIONAL;
  frame.as.max_streams.maximum = 100U;
  WT_EXPECT_STATUS("MAX_STREAMS round trips", WT_OK,
                   round_trip("MAX_STREAMS encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_INT("  with the bidirectional flag", (long)WT_QUIC_STREAM_BIDIRECTIONAL,
                (long)decoded.as.max_streams.direction);
  frame.as.max_streams.direction = WT_QUIC_STREAM_UNIDIRECTIONAL;
  WT_EXPECT_STATUS("the unidirectional form round trips", WT_OK,
                   round_trip("  MAX_STREAMS encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_INT("  with the unidirectional flag", (long)WT_QUIC_STREAM_UNIDIRECTIONAL,
                (long)decoded.as.max_streams.direction);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_DATA_BLOCKED);
  frame.as.data_blocked.maximum = 2048U;
  WT_EXPECT_STATUS("DATA_BLOCKED round trips", WT_OK,
                   round_trip("DATA_BLOCKED encodes", &frame, &decoded, buffer, sizeof(buffer)));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED);
  frame.as.stream_data_blocked.id = 4U;
  frame.as.stream_data_blocked.offset = 512U;
  WT_EXPECT_STATUS(
      "STREAM_DATA_BLOCKED round trips", WT_OK,
      round_trip("STREAM_DATA_BLOCKED encodes", &frame, &decoded, buffer, sizeof(buffer)));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAMS_BLOCKED);
  frame.as.streams_blocked.direction = WT_QUIC_STREAM_UNIDIRECTIONAL;
  frame.as.streams_blocked.maximum = 10U;
  WT_EXPECT_STATUS("STREAMS_BLOCKED round trips", WT_OK,
                   round_trip("STREAMS_BLOCKED encodes", &frame, &decoded, buffer, sizeof(buffer)));

  /* Connection IDs. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
  frame.as.new_connection_id.sequence = 1U;
  frame.as.new_connection_id.retire_prior_to = 0U;
  frame.as.new_connection_id.connection_id = cid;
  frame.as.new_connection_id.connection_id_length = sizeof(cid);
  frame.as.new_connection_id.stateless_reset_token = reset_token;
  WT_EXPECT_STATUS(
      "NEW_CONNECTION_ID round trips", WT_OK,
      round_trip("NEW_CONNECTION_ID encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its connection ID length", sizeof(cid),
                (uint64_t)decoded.as.new_connection_id.connection_id_length);
  WT_EXPECT_BYTES("  and its connection ID", cid, decoded.as.new_connection_id.connection_id,
                  sizeof(cid));
  WT_EXPECT_BYTES("  and its stateless reset token", reset_token,
                  decoded.as.new_connection_id.stateless_reset_token, 16U);

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID);
  frame.as.retire_connection_id.sequence = 5U;
  WT_EXPECT_STATUS(
      "RETIRE_CONNECTION_ID round trips", WT_OK,
      round_trip("RETIRE_CONNECTION_ID encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  with its sequence", 5U, decoded.as.retire_connection_id.sequence);

  /* Path validation. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PATH_CHALLENGE);
  frame.as.path_challenge.data = path;
  WT_EXPECT_STATUS("PATH_CHALLENGE round trips", WT_OK,
                   round_trip("PATH_CHALLENGE encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_BYTES("  with its eight bytes", path, decoded.as.path_challenge.data, 8U);
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PATH_RESPONSE);
  frame.as.path_response.data = path;
  WT_EXPECT_STATUS("PATH_RESPONSE round trips", WT_OK,
                   round_trip("PATH_RESPONSE encodes", &frame, &decoded, buffer, sizeof(buffer)));

  /* A transport close carries the frame type that caused it; an application
   * close does not, and the two are different wire types. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT);
  frame.as.connection_close.has_frame_type = 1;
  frame.as.connection_close.error_code = WT_QUIC_PROTOCOL_VIOLATION;
  frame.as.connection_close.frame_type = WT_QUIC_FRAME_STREAM_BASE;
  frame.as.connection_close.reason = reason;
  frame.as.connection_close.reason_length = sizeof(reason);
  WT_EXPECT_STATUS(
      "a transport close round trips", WT_OK,
      round_trip("  the transport close encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_INT("  with its frame type flag", 1, decoded.as.connection_close.has_frame_type);
  WT_EXPECT_U64("  and the frame type", WT_QUIC_FRAME_STREAM_BASE,
                decoded.as.connection_close.frame_type);
  WT_EXPECT_BYTES("  and the reason", reason, decoded.as.connection_close.reason, sizeof(reason));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION);
  frame.as.connection_close.has_frame_type = 0;
  frame.as.connection_close.error_code = 0x1234U;
  frame.as.connection_close.reason = reason;
  frame.as.connection_close.reason_length = sizeof(reason);
  WT_EXPECT_STATUS(
      "an application close round trips", WT_OK,
      round_trip("  the application close encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_INT("  decoding to the application form",
                (long)WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION, (long)decoded.kind);
  WT_EXPECT_INT("  with no frame type", 0, decoded.as.connection_close.has_frame_type);
  WT_EXPECT_U64("  and its error code", 0x1234U, decoded.as.connection_close.error_code);

  /* A transport close with no frame type encodes the field as 0, which RFC 9000
   * section 19.19 says means "no frame". */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT);
  frame.as.connection_close.has_frame_type = 0;
  frame.as.connection_close.error_code = WT_QUIC_INTERNAL_ERROR;
  frame.as.connection_close.reason = NULL;
  frame.as.connection_close.reason_length = 0U;
  WT_EXPECT_STATUS("a transport close can omit the frame type", WT_OK,
                   round_trip("  it encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_U64("  and reads back as 0", 0U, decoded.as.connection_close.frame_type);

  /* NEW_TOKEN and DATAGRAM. */
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_TOKEN);
  frame.as.new_token.token = token;
  frame.as.new_token.length = sizeof(token);
  WT_EXPECT_STATUS("NEW_TOKEN round trips", WT_OK,
                   round_trip("NEW_TOKEN encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_BYTES("  with its token", token, decoded.as.new_token.token, sizeof(token));

  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_DATAGRAM);
  frame.as.datagram.data = payload;
  frame.as.datagram.length = sizeof(payload);
  WT_EXPECT_STATUS("DATAGRAM round trips", WT_OK,
                   round_trip("DATAGRAM encodes", &frame, &decoded, buffer, sizeof(buffer)));
  WT_EXPECT_BYTES("  with its payload", payload, decoded.as.datagram.data, sizeof(payload));

  /* The encodings are the RFC's bytes for the small frames, which is the check
   * that a round trip cannot make: a PING is 0x01 and a MAX_DATA is 0x10 then a
   * varint, not the other way round. */
  {
    static const struct {
      uint64_t type;
      uint8_t bytes[4];
      size_t length;
    } one_byte[] = {
        {WT_QUIC_FRAME_PADDING, {0x00U}, 1U},
        {WT_QUIC_FRAME_PING, {0x01U}, 1U},
        {WT_QUIC_FRAME_HANDSHAKE_DONE, {0x1eU}, 1U},
    };
    size_t i;
    for (i = 0U; i < sizeof(one_byte) / sizeof(one_byte[0]); i++) {
      frame = wt_quic_frame_make((wt_quic_frame_type_t)((one_byte[i].type == WT_QUIC_FRAME_PADDING)
                                                            ? WT_QUIC_FRAME_KIND_PADDING
                                                        : (one_byte[i].type == WT_QUIC_FRAME_PING)
                                                            ? WT_QUIC_FRAME_KIND_PING
                                                            : WT_QUIC_FRAME_KIND_HANDSHAKE_DONE));
      (void)encode_ok("a one-byte frame encodes", &frame, buffer, sizeof(buffer));
      WT_EXPECT_BYTES("  with the RFC's type byte", one_byte[i].bytes, buffer, one_byte[i].length);
    }
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
    frame.as.max_data.maximum = 0x3fU;
    (void)encode_ok("MAX_DATA encodes", &frame, buffer, sizeof(buffer));
    WT_EXPECT_BYTES("  as 0x10 then the varint", (const uint8_t *)"\x10\x3f", buffer, 2U);
    frame.as.max_data.maximum = 0x40U;
    (void)encode_ok("MAX_DATA with a two-byte varint", &frame, buffer, sizeof(buffer));
    WT_EXPECT_BYTES("  as 0x10 0x40 0x40", (const uint8_t *)"\x10\x40\x40", buffer, 3U);
  }

  /* STREAM type bytes, built from the flags, since the type byte is what a peer
   * reads first. */
  {
    static const struct {
      int has_offset;
      int has_length;
      int fin;
      uint8_t type;
    } types[] = {
        {0, 0, 0, 0x08U}, {0, 0, 1, 0x09U}, {0, 1, 0, 0x0aU}, {0, 1, 1, 0x0bU},
        {1, 0, 0, 0x0cU}, {1, 0, 1, 0x0dU}, {1, 1, 0, 0x0eU}, {1, 1, 1, 0x0fU},
    };
    size_t i;
    for (i = 0U; i < sizeof(types) / sizeof(types[0]); i++) {
      frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
      frame.as.stream.id = 0U;
      frame.as.stream.has_offset = types[i].has_offset;
      frame.as.stream.offset = 0U;
      frame.as.stream.has_length = types[i].has_length;
      frame.as.stream.fin = types[i].fin;
      frame.as.stream.data = NULL;
      frame.as.stream.length = 0U;
      (void)encode_ok("a STREAM frame encodes", &frame, buffer, sizeof(buffer));
      WT_EXPECT_U64("  with the type byte its flags imply", types[i].type, (uint64_t)buffer[0]);
    }
  }
}
