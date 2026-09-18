/* Shared by the two halves of test_quic_packet.c after the split.
 * Composed in the order it has to be read: guard, includes, body defines, shared helpers.
 * The defines come before the helpers because the helpers use them, and `static inline`
 * because a file-static helper cannot cross a translation unit. */
#ifndef TEST_QUIC_PACKET_A_ZERO_LENGTH_DESTINATION_CONNECTION_ID_SUPPORT_H
#define TEST_QUIC_PACKET_A_ZERO_LENGTH_DESTINATION_CONNECTION_ID_SUPPORT_H

/* QUIC packet headers (RFC 9000 sections 17.2 and 17.3).
 *
 * The vector that matters is RFC 9001 appendix A.2's client Initial header,
 * printed as `c300000001088394c8f03e5157080000449e00000002`: a long header, type
 * Initial, version 1, an 8-byte destination connection ID, an empty source
 * connection ID, an empty token, a Length of 1182 and a 4-byte packet number of
 * 2. Decoding it and re-encoding it byte for byte is a check against the RFC's
 * bytes rather than against this code.
 *
 * The refusals are the rest: the fixed bit, the reserved bits, a connection ID
 * above twenty bytes, a Retry where a long header was expected, and truncation
 * at every field boundary.
 */

#include "wt_test.h"

#include "webtransport/quic/packet.h"

#include "rfc9001_retry.h"

#endif
