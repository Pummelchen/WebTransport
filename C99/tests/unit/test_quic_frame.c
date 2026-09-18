#include "test_quic_frame_encoding_support.h"
#include "vectors/rfc9001_client_initial.h"
#include "webtransport/quic/frame.h"
#include "wt_test.h"

static void test_rfc9001_crypto_frame(void) {
  wt_cursor_t c;
  wt_quic_frame_t frame;
  wt_quic_error_t error = 0U;
  uint64_t crypto_frames = 0U;
  uint64_t padding_frames = 0U;
  uint64_t others = 0U;

  c = wt_cursor_init(WT_RFC9001_CLIENT_INITIAL_PAYLOAD, WT_RFC9001_CLIENT_INITIAL_PAYLOAD_LEN);

  /* The first frame is the CRYPTO frame the RFC prints. */
  WT_EXPECT_STATUS("the RFC's CRYPTO frame parses", WT_OK,
                   wt_quic_frame_decode(&c, &frame, &error));
  WT_EXPECT_INT("it is a CRYPTO frame", (long)WT_QUIC_FRAME_KIND_CRYPTO, (long)frame.kind);
  WT_EXPECT_U64("with offset 0", WT_RFC9001_CLIENT_INITIAL_CRYPTO_OFFSET, frame.as.crypto.offset);
  WT_EXPECT_U64("and the RFC's length", WT_RFC9001_CLIENT_INITIAL_CRYPTO_LENGTH,
                (uint64_t)frame.as.crypto.length);
  /* The payload is the TLS ClientHello, which begins with the handshake type
   * and its three-byte length: 0x01 (ClientHello), 0x0000ed (237). A parser that
   * pointed at the wrong offset would land somewhere else in the packet. */
  WT_EXPECT_BYTES("and the payload is the TLS ClientHello",
                  (const uint8_t *)"\x01\x00\x00\xed\x03\x03", frame.as.crypto.data, 6U);
  /* The frame's own bytes, as printed: type 6, offset 0, a two-byte length of
   * 241. */
  WT_EXPECT_BYTES("the frame's header is the RFC's", (const uint8_t *)"\x06\x00\x40\xf1",
                  WT_RFC9001_CLIENT_INITIAL_PAYLOAD, 4U);

  /* What follows is exactly the padding the RFC describes and nothing else. */
  while (wt_cursor_remaining(&c) > 0U) {
    WT_EXPECT_STATUS("the next frame parses", WT_OK, wt_quic_frame_decode(&c, &frame, &error));
    if (frame.kind == WT_QUIC_FRAME_KIND_PADDING) {
      padding_frames++;
    } else if (frame.kind == WT_QUIC_FRAME_KIND_CRYPTO) {
      crypto_frames++;
    } else {
      others++;
    }
  }
  WT_EXPECT_U64("there is exactly one CRYPTO frame", 0U, crypto_frames);
  WT_EXPECT_U64("no other frame kind appears", 0U, others);
  WT_EXPECT_U64("and the rest is PADDING", (uint64_t)WT_RFC9001_CLIENT_INITIAL_PADDING_COUNT,
                padding_frames);
  WT_EXPECT_U64("which accounts for every byte of the payload",
                (uint64_t)WT_RFC9001_CLIENT_INITIAL_PAYLOAD_LEN,
                4U + (uint64_t)WT_RFC9001_CLIENT_INITIAL_CRYPTO_LENGTH + padding_frames);
}
static void test_frame_refusals(void) {
  uint8_t buffer[64];
  wt_quic_frame_t frame;
  wt_quic_frame_t decoded;
  wt_quic_error_t error = 0U;
  wt_cursor_t c;

  /* An unknown frame type is a FRAME_ENCODING_ERROR, not something to skip:
   * RFC 9000 section 12.4. 0x20 is not assigned and is not in the STREAM range
   * or the extension range. */
  {
    static const uint8_t unknown[2] = {0x20U, 0x00U};
    error = 0U;
    c = wt_cursor_init(unknown, sizeof(unknown));
    WT_EXPECT_STATUS("an unknown frame type is refused", WT_ERR_PROTOCOL,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("  as a frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);
    WT_EXPECT_U64("  and nothing was consumed beyond the type", 1U, (uint64_t)c.offset);
  }
  /* A type that is not minimally encoded is a PROTOCOL_VIOLATION: RFC 9000
   * section 12.4 again, and this is the check that needs the decoder to report
   * the encoding's size. */
  {
    static const uint8_t padded_ping[4] = {0x80U, 0x00U, 0x00U, 0x01U};
    error = 0U;
    c = wt_cursor_init(padded_ping, sizeof(padded_ping));
    WT_EXPECT_STATUS("a non-minimal frame type is refused", WT_ERR_PROTOCOL,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("  as a protocol violation", WT_QUIC_PROTOCOL_VIOLATION, error);
  }
  /* An empty cursor has no frame at all. */
  c = wt_cursor_init(NULL, 0U);
  WT_EXPECT_STATUS("an empty buffer has no frame", WT_ERR_TRUNCATED,
                   wt_quic_frame_decode(&c, &decoded, &error));

  /* Truncated bodies: each frame kind with its last byte missing. */
  {
    static const struct {
      const char *label;
      uint8_t header[8];
      size_t length;
    } truncated[] = {
        {"CRYPTO without its length", {0x06U, 0x00U}, 2U},
        {"CRYPTO whose length overruns", {0x06U, 0x00U, 0x40U, 0xffU}, 4U},
        {"RESET_STREAM with no fields", {0x04U}, 1U},
        {"STOP_SENDING with one field", {0x05U, 0x00U}, 2U},
        {"MAX_DATA with no value", {0x10U}, 1U},
        {"MAX_STREAM_DATA with no value", {0x11U, 0x00U}, 2U},
        {"MAX_STREAMS with no value", {0x12U}, 1U},
        {"NEW_CONNECTION_ID with no length byte", {0x18U, 0x00U, 0x00U}, 3U},
        {"NEW_CONNECTION_ID with no token", {0x18U, 0x00U, 0x00U, 0x08U}, 4U},
        {"RETIRE_CONNECTION_ID with no sequence", {0x19U}, 1U},
        {"PATH_CHALLENGE with seven bytes", {0x1aU, 1U, 2U, 3U, 4U, 5U, 6U, 7U}, 8U},
        {"PATH_RESPONSE with nothing", {0x1bU}, 1U},
        {"CONNECTION_CLOSE with no reason length", {0x1cU, 0x00U, 0x00U}, 3U},
        /* A NEW_TOKEN with a zero length is refused as a frame encoding error
         * rather than as truncation -- an empty token is malformed whether or
         * not the body arrived -- so it is checked in the refusals section
         * below and not here. */
        {"NEW_TOKEN with a length but no token", {0x07U, 0x04U, 0x01U}, 3U},
    };
    size_t i;
    for (i = 0U; i < sizeof(truncated) / sizeof(truncated[0]); i++) {
      c = wt_cursor_init(truncated[i].header, truncated[i].length);
      WT_EXPECT_STATUS(truncated[i].label, WT_ERR_TRUNCATED,
                       wt_quic_frame_decode(&c, &decoded, &error));
    }
    /* The PATH_CHALLENGE case above is a type byte and seven of its eight
     * bytes; one more makes a whole frame, which is checked to parse so that the
     * refusal above is about the missing byte and not about the frame. */
    {
      static const uint8_t whole[9] = {0x1aU, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
      c = wt_cursor_init(whole, sizeof(whole));
      WT_EXPECT_STATUS("nine bytes is a whole PATH_CHALLENGE", WT_OK,
                       wt_quic_frame_decode(&c, &decoded, &error));
      WT_EXPECT_BYTES("  with its eight bytes", whole + 1, decoded.as.path_challenge.data, 8U);
    }
    /* AUD-0022: the refused NEW_TOKEN above must leave the whole frame zeroed, not a NULL
     * token beside the wire's unvalidated length. The status is the contract -- a caller that
     * checks it never reads this -- but a frame with no valid token in it should not carry a
     * length that looks like one. */
    c = wt_cursor_init((const uint8_t *)"\x07\x04\x01", 3U);
    WT_EXPECT_STATUS("a NEW_TOKEN with a missing body is refused", WT_ERR_TRUNCATED,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("  and leaves no length behind for the token it did not get", 0U,
                  decoded.as.new_token.token_length);
    WT_EXPECT_U64("  nor a size", 0U, (uint64_t)decoded.as.new_token.length);
  }

  /* Each field whose value the RFC gives a rule. */
  {
    static const uint8_t zero_token[1] = {0x00U};
    /* NEW_TOKEN with an empty token: RFC 9000 section 19.7. */
    c = wt_cursor_init((const uint8_t *)"\x07\x00", 2U);
    error = 0U;
    WT_EXPECT_STATUS("an empty NEW_TOKEN is refused", WT_ERR_PROTOCOL,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("  as a frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);

    /* NEW_CONNECTION_ID with a length of 0 and of 21: RFC 9000 section 19.15,
     * which says "less than 1 and greater than 20". */
    c = wt_cursor_init((const uint8_t *)"\x18\x00\x00\x00", 4U);
    error = 0U;
    WT_EXPECT_STATUS("a zero-length connection ID is refused", WT_ERR_PROTOCOL,
                     wt_quic_frame_decode(&c, &decoded, &error));
    WT_EXPECT_U64("  as a frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);
    {
      uint8_t too_long[40] = {0x18U, 0x00U, 0x00U, 0x15U};
      c = wt_cursor_init(too_long, sizeof(too_long));
      error = 0U;
      WT_EXPECT_STATUS("a 21-byte connection ID is refused", WT_ERR_PROTOCOL,
                       wt_quic_frame_decode(&c, &decoded, &error));
    }
    /* A retire_prior_to above the sequence would retire the ID being issued. */
    {
      uint8_t bad_retire[32] = {0x18U, 0x01U, 0x02U, 0x08U};
      c = wt_cursor_init(bad_retire, sizeof(bad_retire));
      error = 0U;
      WT_EXPECT_STATUS("retire_prior_to above the sequence is refused", WT_ERR_PROTOCOL,
                       wt_quic_frame_decode(&c, &decoded, &error));
    }
    /* RESET_STREAM_AT with a reliable size above the final size. */
    {
      uint8_t bad_reset[8] = {0x24U, 0x00U, 0x00U, 0x0aU, 0x14U};
      c = wt_cursor_init(bad_reset, sizeof(bad_reset));
      error = 0U;
      WT_EXPECT_STATUS("a reliable size above the final size is refused", WT_ERR_PROTOCOL,
                       wt_quic_frame_decode(&c, &decoded, &error));
      WT_EXPECT_U64("  as a frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);
    }
    /* A stream count above 2^60: RFC 9000 section 19.11. The varint for 2^60 is
     * eight bytes, 0xf0 followed by seven zeros. */
    {
      static const uint8_t too_many[9] = {0x12U, 0xf0U, 0x00U, 0x00U, 0x00U,
                                          0x00U, 0x00U, 0x00U, 0x00U};
      c = wt_cursor_init(too_many, sizeof(too_many));
      error = 0U;
      WT_EXPECT_STATUS("a stream count above 2^60 is refused", WT_ERR_PROTOCOL,
                       wt_quic_frame_decode(&c, &decoded, &error));
      WT_EXPECT_U64("  as a frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);
    }
    (void)zero_token;
  }

  /* A length field too large to be a size_t is an overflow and not a walk off
   * the end. The varint for 2^62 - 1 is eight bytes of 0xff after the prefix. */
  {
    static const uint8_t huge[10] = {0x06U, 0x00U, 0xffU, 0xffU, 0xffU,
                                     0xffU, 0xffU, 0xffU, 0xffU, 0xffU};
    c = wt_cursor_init(huge, sizeof(huge));
    error = 0U;
    WT_EXPECT_STATUS("a length that cannot be a size is refused", WT_ERR_TRUNCATED,
                     wt_quic_frame_decode(&c, &decoded, &error));
  }

  /* The encoder refuses to build a frame this parser would refuse to read, which
   * is the property that keeps a library from emitting something it cannot
   * accept. */
  {
    wt_writer_t w = wt_writer_init(buffer, sizeof(buffer));
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID);
    frame.as.new_connection_id.connection_id_length = 21U;
    frame.as.new_connection_id.connection_id = (const uint8_t *)"x";
    frame.as.new_connection_id.stateless_reset_token = (const uint8_t *)"x";
    WT_EXPECT_STATUS("encoding a 21-byte connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_encode(&w, &frame));

    w = wt_writer_init(buffer, sizeof(buffer));
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_NEW_TOKEN);
    frame.as.new_token.token = NULL;
    frame.as.new_token.length = 0U;
    WT_EXPECT_STATUS("encoding an empty NEW_TOKEN is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_encode(&w, &frame));

    w = wt_writer_init(buffer, sizeof(buffer));
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_RESET_STREAM_AT);
    frame.as.reset_stream_at.final_size = 10U;
    frame.as.reset_stream_at.reliable_size = 11U;
    WT_EXPECT_STATUS("encoding a reliable size above the final size is refused",
                     WT_ERR_INVALID_ARGUMENT, wt_quic_frame_encode(&w, &frame));

    w = wt_writer_init(buffer, sizeof(buffer));
    frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_STREAM);
    frame.as.stream.id = 0U;
    frame.as.stream.has_length = 1;
    frame.as.stream.length = 64U;
    frame.as.stream.data = buffer;
    WT_EXPECT_STATUS("encoding into a buffer that is too small is a limit", WT_ERR_LIMIT,
                     wt_quic_frame_encode(&w, &frame));

    WT_EXPECT_STATUS("a NULL writer is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_encode(NULL, &frame));
    w = wt_writer_init(buffer, sizeof(buffer));
    WT_EXPECT_STATUS("a NULL frame is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_encode(&w, NULL));
    WT_EXPECT_STATUS("a NULL cursor is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_decode(NULL, &decoded, &error));
    WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                     wt_quic_frame_decode(&c, NULL, &error));
  }

  /* A frame decoded with no error out-parameter still reports its status, which
   * is the property that a caller which only cares about control flow needs. */
  {
    static const uint8_t unknown[1] = {0x20U};
    c = wt_cursor_init(unknown, sizeof(unknown));
    WT_EXPECT_STATUS("the error out-parameter is optional", WT_ERR_PROTOCOL,
                     wt_quic_frame_decode(&c, &decoded, NULL));
  }
}
static void test_frame_walk(void) {
  uint8_t buffer[64];
  wt_writer_t w;
  wt_quic_frame_t frame;
  wt_quic_error_t error = 0U;
  wt_status_t status;

  /* Three frames in one buffer: PADDING, PING, MAX_DATA. */
  w = wt_writer_init(buffer, sizeof(buffer));
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PADDING);
  WT_EXPECT_STATUS("PADDING", WT_OK, wt_quic_frame_encode(&w, &frame));
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  WT_EXPECT_STATUS("PING", WT_OK, wt_quic_frame_encode(&w, &frame));
  frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
  frame.as.max_data.maximum = 5U;
  WT_EXPECT_STATUS("MAX_DATA", WT_OK, wt_quic_frame_encode(&w, &frame));

  {
    uint64_t counts[32];
    size_t i;
    for (i = 0U; i < 32U; i++)
      counts[i] = 0U;
    WT_EXPECT_STATUS(
        "the walk visits every frame", WT_OK,
        wt_quic_frames_decode(buffer, wt_writer_offset(&w), count_frames, counts, &error));
    WT_EXPECT_U64("one PADDING", 1U, counts[WT_QUIC_FRAME_KIND_PADDING]);
    WT_EXPECT_U64("one PING", 1U, counts[WT_QUIC_FRAME_KIND_PING]);
    WT_EXPECT_U64("one MAX_DATA", 1U, counts[WT_QUIC_FRAME_KIND_MAX_DATA]);
  }

  /* A visitor can stop the walk by returning a status, which is how a caller
   * that has seen a connection close ends the parse without the parser knowing
   * why. */
  {
    uint64_t seen = 0U;
    status = wt_quic_frames_decode(buffer, wt_writer_offset(&w), stop_at_ping, &seen, &error);
    WT_EXPECT_STATUS("the visitor's status ends the walk", WT_ERR_CLOSED, status);
    WT_EXPECT_U64("after two frames", 2U, seen);
  }

  /* A malformed frame in the middle stops the walk and reports the code. */
  {
    uint8_t bad[8] = {0x01U, 0x20U, 0x00U};
    uint64_t counts[32];
    size_t i;
    for (i = 0U; i < 32U; i++)
      counts[i] = 0U;
    error = 0U;
    WT_EXPECT_STATUS("a malformed frame stops the walk", WT_ERR_PROTOCOL,
                     wt_quic_frames_decode(bad, 3U, count_frames, counts, &error));
    WT_EXPECT_U64("  with the frame encoding error", WT_QUIC_FRAME_ENCODING_ERROR, error);
    WT_EXPECT_U64("  and one frame was visited", 1U, counts[WT_QUIC_FRAME_KIND_PING]);
  }

  /* No visitor is allowed: a caller that only wants the parse to be checked. */
  WT_EXPECT_STATUS("a NULL visitor checks without visiting", WT_OK,
                   wt_quic_frames_decode(buffer, wt_writer_offset(&w), NULL, NULL, &error));
  WT_EXPECT_STATUS("a NULL buffer with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_frames_decode(NULL, 4U, NULL, NULL, &error));
  WT_EXPECT_STATUS("an empty buffer has no frames", WT_OK,
                   wt_quic_frames_decode(NULL, 0U, NULL, NULL, &error));
  WT_EXPECT_STATUS("a NULL error out-parameter is allowed", WT_OK,
                   wt_quic_frames_decode(buffer, wt_writer_offset(&w), NULL, NULL, NULL));
}
int main(void) {
  test_rfc9001_crypto_frame();
  test_frame_refusals();
  test_frame_walk();
  WT_TEST_MAIN_END("test_quic_frame");
}
