/* Shared by the two halves of test_quic_transport_parameters.c after the split.
 * Composed in the order it has to be read: guard, includes, body defines, shared helpers.
 * The defines come before the helpers because the helpers use them, and `static inline`
 * because a file-static helper cannot cross a translation unit. */
#ifndef TEST_QUIC_TRANSPORT_PARAMETERS_STREAM_LIMITS_AND_A_CLIENTS_RESET_TOKEN_SUPPORT_H
#define TEST_QUIC_TRANSPORT_PARAMETERS_STREAM_LIMITS_AND_A_CLIENTS_RESET_TOKEN_SUPPORT_H

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



#endif
