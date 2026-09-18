/* QUIC transport parameters (RFC 9000 section 18).
 *
 * The parser's job is narrow on purpose: framing and duplicates. RFC 9000
 * section 7.4.2 requires an unknown parameter to be ignored, so a parser that
 * refused one would break the extension, and section 7.4 makes a duplicate a
 * TRANSPORT_PARAMETER_ERROR, so a parser that accepted one would accept a peer
 * that cannot decide what it means. The value rules of section 18.2 are a
 * separate check, and each of them is tested here against the boundary the RFC
 * names rather than against a value that happens to be wrong.
 */

#include "wt_test.h"

#include "webtransport/quic/transport_parameters.h"
#include "test_quic_transport_parameters_limits_support.h"


/* F-05: two RFC 9000 section 18.2 rules the check did not have. Section 4.6: a max_streams transport
 * parameter above 2^60 MUST be closed with TRANSPORT_PARAMETER_ERROR ("2^60" itself is allowed; only greater
 * is an error). Section 18.2: stateless_reset_token is valid only for a server, so a server MUST treat receipt
 * from a client as TRANSPORT_PARAMETER_ERROR -- which is why the check now takes the sending role. */
static void test_stream_limits_and_a_clients_reset_token(void) {
  wt_quic_transport_parameters_t check;
  static const uint8_t sixteen[16] = {0};
  const uint64_t over_two_to_sixty = (UINT64_C(1) << 60) + 1U;
  wt_quic_error_t error = 0U;
  uint64_t offender = 0U;

  /* 2^60 is the boundary and is legal; one above it is not, in either direction. */
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                                 UINT64_C(1) << 60);
  WT_EXPECT_STATUS("initial_max_streams_bidi of 2^60 is accepted", WT_OK,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
                                                 over_two_to_sixty);
  error = 0U;
  offender = 0U;
  WT_EXPECT_STATUS("initial_max_streams_bidi above 2^60 is refused", WT_ERR_PROTOCOL,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  WT_EXPECT_U64("  as a transport parameter error", WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
  WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, offender);

  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                                 UINT64_C(1) << 60);
  WT_EXPECT_STATUS("initial_max_streams_uni of 2^60 is accepted", WT_OK,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_integer(&check, WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI,
                                                 over_two_to_sixty);
  error = 0U;
  offender = 0U;
  WT_EXPECT_STATUS("initial_max_streams_uni above 2^60 is refused", WT_ERR_PROTOCOL,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI, offender);

  /* A sixteen-byte token is well formed either way; only a CLIENT sending one is the error. */
  wt_quic_transport_parameters_init(&check);
  (void)wt_quic_transport_parameters_add_bytes(&check, WT_QUIC_TP_STATELESS_RESET_TOKEN, sixteen,
                                               sizeof(sixteen));
  WT_EXPECT_STATUS("a server's stateless_reset_token is accepted", WT_OK,
                   wt_quic_transport_parameters_check(&check, 0, &error, &offender));
  error = 0U;
  offender = 0U;
  WT_EXPECT_STATUS("a client's stateless_reset_token is refused", WT_ERR_PROTOCOL,
                   wt_quic_transport_parameters_check(&check, 1, &error, &offender));
  WT_EXPECT_U64("  as a transport parameter error", WT_QUIC_TRANSPORT_PARAMETER_ERROR, error);
  WT_EXPECT_U64("  naming the parameter", WT_QUIC_TP_STATELESS_RESET_TOKEN, offender);
}

int main(void) {
  test_stream_limits_and_a_clients_reset_token();
  WT_TEST_MAIN_END("test_quic_transport_parameters_limits");
}
