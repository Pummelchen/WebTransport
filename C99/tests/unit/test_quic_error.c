/* QUIC transport error codes.
 *
 * The names and the code values are wire values the peer sees, so they are
 * pinned: a code that moved would make a close message mean something else. The
 * crypto range is the one with arithmetic in it, so it is checked at both ends.
 */

#include "wt_test.h"

#include "webtransport/quic/error.h"

int main(void) {
  wt_quic_error_t error = 0U;

  /* The values are RFC 9000 section 20.1, checked as literals rather than
   * against themselves. */
  WT_EXPECT_U64("NO_ERROR is 0x00", 0x00U, WT_QUIC_NO_ERROR);
  WT_EXPECT_U64("INTERNAL_ERROR is 0x01", 0x01U, WT_QUIC_INTERNAL_ERROR);
  WT_EXPECT_U64("CONNECTION_REFUSED is 0x02", 0x02U, WT_QUIC_CONNECTION_REFUSED);
  WT_EXPECT_U64("FLOW_CONTROL_ERROR is 0x03", 0x03U, WT_QUIC_FLOW_CONTROL_ERROR);
  WT_EXPECT_U64("STREAM_LIMIT_ERROR is 0x04", 0x04U, WT_QUIC_STREAM_LIMIT_ERROR);
  WT_EXPECT_U64("STREAM_STATE_ERROR is 0x05", 0x05U, WT_QUIC_STREAM_STATE_ERROR);
  WT_EXPECT_U64("FINAL_SIZE_ERROR is 0x06", 0x06U, WT_QUIC_FINAL_SIZE_ERROR);
  WT_EXPECT_U64("FRAME_ENCODING_ERROR is 0x07", 0x07U, WT_QUIC_FRAME_ENCODING_ERROR);
  WT_EXPECT_U64("TRANSPORT_PARAMETER_ERROR is 0x08", 0x08U, WT_QUIC_TRANSPORT_PARAMETER_ERROR);
  WT_EXPECT_U64("CONNECTION_ID_LIMIT_ERROR is 0x09", 0x09U, WT_QUIC_CONNECTION_ID_LIMIT_ERROR);
  WT_EXPECT_U64("PROTOCOL_VIOLATION is 0x0a", 0x0aU, WT_QUIC_PROTOCOL_VIOLATION);
  WT_EXPECT_U64("INVALID_TOKEN is 0x0b", 0x0bU, WT_QUIC_INVALID_TOKEN);
  WT_EXPECT_U64("APPLICATION_ERROR is 0x0c", 0x0cU, WT_QUIC_APPLICATION_ERROR);
  WT_EXPECT_U64("CRYPTO_BUFFER_EXCEEDED is 0x0d", 0x0dU, WT_QUIC_CRYPTO_BUFFER_EXCEEDED);
  WT_EXPECT_U64("KEY_UPDATE_ERROR is 0x0e", 0x0eU, WT_QUIC_KEY_UPDATE_ERROR);
  WT_EXPECT_U64("AEAD_LIMIT_REACHED is 0x0f", 0x0fU, WT_QUIC_AEAD_LIMIT_REACHED);
  WT_EXPECT_U64("NO_VIABLE_PATH is 0x10", 0x10U, WT_QUIC_NO_VIABLE_PATH);
  WT_EXPECT_U64("the crypto range starts at 0x0100", 0x0100U, WT_QUIC_CRYPTO_ERROR_BASE);
  WT_EXPECT_U64("and ends at 0x01ff", 0x01ffU, WT_QUIC_CRYPTO_ERROR_LAST);

  /* A TLS alert becomes 0x0100 plus the alert, which is how a handshake failure
   * reaches the peer as a QUIC close. */
  WT_EXPECT_OK("alert 0 is in range", wt_quic_crypto_error(0U, &error));
  WT_EXPECT_U64("alert 0 is 0x0100", 0x0100U, error);
  WT_EXPECT_OK("alert 120 is in range", wt_quic_crypto_error(120U, &error));
  WT_EXPECT_U64("no_application_protocol is 0x0178", 0x0178U, error);
  WT_EXPECT_U64("and it is the crypto range", 0x0178U, 0x0100U + 120U);
  WT_EXPECT_OK("alert 255 is in range", wt_quic_crypto_error(255U, &error));
  WT_EXPECT_U64("alert 255 is 0x01ff", 0x01ffU, error);
  WT_EXPECT_STATUS("a NULL output is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_crypto_error(1U, NULL));

  /* The range test, at both ends and just outside. */
  WT_EXPECT_INT("0x0100 is crypto", 1, wt_quic_error_is_crypto(0x0100U));
  WT_EXPECT_INT("0x01ff is crypto", 1, wt_quic_error_is_crypto(0x01ffU));
  WT_EXPECT_INT("0x00ff is not", 0, wt_quic_error_is_crypto(0x00ffU));
  WT_EXPECT_INT("0x0200 is not", 0, wt_quic_error_is_crypto(0x0200U));
  WT_EXPECT_INT("a QUIC code is not crypto", 0,
                wt_quic_error_is_crypto(WT_QUIC_PROTOCOL_VIOLATION));

  /* Names are stable. An unknown code has a name rather than a crash, and the
   * crypto range shares one name because the alert is in the low byte. */
  WT_EXPECT_STR("no error", "no-error", wt_quic_error_name(WT_QUIC_NO_ERROR));
  WT_EXPECT_STR("protocol violation", "protocol-violation",
                wt_quic_error_name(WT_QUIC_PROTOCOL_VIOLATION));
  WT_EXPECT_STR("frame encoding", "frame-encoding-error",
                wt_quic_error_name(WT_QUIC_FRAME_ENCODING_ERROR));
  WT_EXPECT_STR("flow control", "flow-control-error",
                wt_quic_error_name(WT_QUIC_FLOW_CONTROL_ERROR));
  WT_EXPECT_STR("the crypto range", "crypto", wt_quic_error_name(0x0178U));
  WT_EXPECT_STR("an unassigned code", "unknown", wt_quic_error_name(0x4000U));

  WT_TEST_MAIN_END("wt_quic_error");
}
