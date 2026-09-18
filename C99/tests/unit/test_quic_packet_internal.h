/* Shared declarations for the split `test_quic_packet` translation units.
 *
 * `test_quic_packet.c` holds `main` and the header/token/Retry tests that were already there; the
 * restored corpora that the `ce1e708` split dropped live in the topic files beside it, each named
 * after the behaviour it owns. The entry points are non-static so `main` can call across the file
 * boundary, and the harness tally is shared by tests/wt_test.c because a translation unit no longer
 * owns its own count. */

#ifndef WT_TEST_QUIC_PACKET_INTERNAL_H
#define WT_TEST_QUIC_PACKET_INTERNAL_H

#include "wt_test.h"

#include "webtransport/quic/packet.h"

#include "rfc9001_retry.h"

/* test_quic_packet_header.c: the round trips and the names. */
void test_the_rfc9001_a2_client_initial_header(void);
void test_the_first_byte_classification(void);
void test_a_handshake_packet_round_trips(void);
void test_an_initial_with_a_large_token_round_trips(void);
void test_a_short_header_round_trips(void);
void test_a_coalesced_datagram_walks_by_reported_sizes(void);
void test_the_packet_type_names(void);

/* test_quic_packet_refusals.c: what the decoders and encoders must refuse. */
void test_the_long_header_refusals(void);
void test_the_encoding_refusals(void);

/* test_quic_packet_retry.c: the Retry shape, its minimum, and the underflow regression. */
void test_a_retry_packet_round_trips(void);

#endif /* WT_TEST_QUIC_PACKET_INTERNAL_H */
