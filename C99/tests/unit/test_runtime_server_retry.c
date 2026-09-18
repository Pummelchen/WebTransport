/* The server's half of a Retry (WT-168): answer an Initial, then check the token that comes back.
 *
 * The two halves are tested against EACH OTHER rather than against literals, because that is the property the
 * protocol needs and the one a test can hold: the Retry this module builds must be acceptable to a CLIENT
 * (`test_quic_connection` drives the real client against a hand-built Retry), and the token in the client's answer
 * must be acceptable to this module. Here the "client" is a synthetic Initial built with the packet codec, which
 * is enough to check the four rules this flow adds on top of the token module: the Source Connection ID the Retry
 * chose is the one the answer must be addressed to, the token must come from the address the packet came from,
 * an Initial WITHOUT a token is a request for a Retry, and one WITH a token is not.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/packet.h"
#include "webtransport/quic/protection.h"
#include "webtransport/runtime/server_retry.h"

static const uint8_t k_client_source_id[8] = {0x01U, 0x02U, 0x03U, 0x04U,
                                              0x05U, 0x06U, 0x07U, 0x08U};
static const uint8_t k_original_destination_id[8] = {0xa1U, 0xa2U, 0xa3U, 0xa4U,
                                                     0xa5U, 0xa6U, 0xa7U, 0xa8U};

/* One Initial packet as the client's own encoder writes it: a header, an optional token, a packet number and a
 * payload (which this module never looks at). The payload is a PING, so the packet is a packet. */
static size_t build_initial(uint8_t *out, size_t capacity, const uint8_t *destination,
                            size_t destination_length, const uint8_t *token, size_t token_length) {
  static const uint8_t k_payload[] = {0x01U};
  wt_writer_t w = wt_writer_init(out, capacity);

  WT_EXPECT_OK("the Initial encodes",
               wt_quic_long_header_encode(&w, WT_QUIC_PACKET_INITIAL, WT_QUIC_VERSION_1,
                                          destination, destination_length, k_client_source_id,
                                          sizeof(k_client_source_id), token, token_length, 0U, 1U,
                                          k_payload, sizeof(k_payload)));
  return wt_writer_offset(&w);
}

/* A peer address in the canonical form, differing only in the port so that two peers can be told apart. */
static void peer_address(uint16_t port, wt_udp_address_t *out) {
  memset(out, 0, sizeof(*out));
  out->family = WT_UDP_IPV6;
  out->port = port;
  out->bytes[15] = 0x01U;
}

int main(void) {
  wt_runtime_server_retry_t retry;
  wt_udp_address_t client_address;
  wt_udp_address_t other_address;
  uint8_t initial[512];
  uint8_t answer[512];
  uint8_t retry_packet[WT_RUNTIME_SERVER_RETRY_MAX];
  uint8_t original[WT_QUIC_MAX_CONNECTION_ID_LENGTH];
  size_t initial_length;
  size_t answer_length;
  size_t retry_length = 0U;
  size_t original_length = 0U;
  size_t source_length = 0U;
  const uint8_t *source;
  int is_retry = -1;
  int accepted = -1;
  const uint64_t k_now = 500000U;
  wt_quic_retry_packet_t decoded;

  peer_address(44330U, &client_address);
  peer_address(44331U, &other_address);

  /* Arming draws a secret and an ID, and refuses a connection ID length a connection could not have. */
  WT_EXPECT_STATUS("a zero-length connection ID is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_server_retry_arm(&retry, 0U, 1000000U));
  WT_EXPECT_STATUS("and one longer than a connection ID", WT_ERR_INVALID_ARGUMENT,
                   wt_runtime_server_retry_arm(&retry, 21U, 1000000U));
  WT_EXPECT_OK("a server arms", wt_runtime_server_retry_arm(&retry, 8U, 1000000U));
  source = wt_runtime_server_retry_source_id(&retry, &source_length);
  WT_EXPECT_TRUE("it chose a Source Connection ID", source != NULL);
  WT_EXPECT_U64("of the length it was given", 8U, (uint64_t)source_length);
  WT_EXPECT_INT("and has sent nothing yet", 0, (int)retry.retries_sent);

  /* The client's first Initial carries no token, so it is a request for a Retry. */
  initial_length = build_initial(initial, sizeof(initial), k_original_destination_id,
                                 sizeof(k_original_destination_id), NULL, 0U);
  WT_EXPECT_OK("a Retry is built",
               wt_runtime_server_retry_build(&retry, initial, initial_length, &client_address,
                                             k_now, retry_packet, sizeof(retry_packet),
                                             &retry_length, &is_retry));
  WT_EXPECT_INT("which IS a Retry", 1, is_retry);
  WT_EXPECT_U64("and the server counted it", 1U, (uint64_t)retry.retries_sent);
  WT_EXPECT_TRUE("with bytes in it", retry_length > WT_AEAD_TAG_LEN);

  /* What it built: a Retry addressed from the client's Source Connection ID, carrying the new ID and a token the
   * client must echo, with an integrity tag computed over the ORIGINAL destination connection ID. */
  {
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    WT_EXPECT_OK("the Retry decodes",
                 wt_quic_retry_packet_decode(retry_packet, retry_length, &decoded, &error));
    WT_EXPECT_BYTES("addressed from the client's Source Connection ID", k_client_source_id,
                    decoded.destination_connection_id, sizeof(k_client_source_id));
    WT_EXPECT_U64("with the server's chosen ID as its source", 8U,
                  (uint64_t)decoded.source_connection_id_len);
    WT_EXPECT_BYTES("which is the one it armed", source, decoded.source_connection_id,
                    source_length);
    WT_EXPECT_TRUE("and a token to echo", decoded.token_len > 0U);
    WT_EXPECT_OK("whose integrity tag the client's own check accepts",
                 wt_quic_retry_integrity_verify(k_original_destination_id,
                                                sizeof(k_original_destination_id), retry_packet,
                                                retry_length));
  }

  /* A datagram that is not an Initial is not a request for anything: no Retry, no counter. */
  /* The client addresses the Retry's SOURCE connection ID now (RFC 9000 section 17.2.5.1), which is the rule the
   * accept path turns on: an answer addressed anywhere else is not this Retry's answer. */
  answer_length = build_initial(answer, sizeof(answer), decoded.source_connection_id,
                                decoded.source_connection_id_len, decoded.token, decoded.token_len);
  WT_EXPECT_OK("an Initial that already carries a token is answered with nothing",
               wt_runtime_server_retry_build(&retry, answer, answer_length, &client_address, k_now,
                                             retry_packet, sizeof(retry_packet), &retry_length,
                                             &is_retry));
  WT_EXPECT_INT("so no Retry goes out", 0, is_retry);
  WT_EXPECT_U64("and the count did not move", 1U, (uint64_t)retry.retries_sent);
  {
    uint8_t junk[8] = {0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U};
    WT_EXPECT_OK("and a datagram that is not a packet at all is ignored",
                 wt_runtime_server_retry_build(&retry, junk, sizeof(junk), &client_address, k_now,
                                               retry_packet, sizeof(retry_packet), &retry_length,
                                               &is_retry));
    WT_EXPECT_INT("with nothing sent", 0, is_retry);
  }

  /* The client comes back with the token, addressing the Retry's Source Connection ID. */
  WT_EXPECT_OK("the answer is accepted",
               wt_runtime_server_retry_accept(&retry, answer, answer_length, &client_address, k_now,
                                              original, sizeof(original), &original_length,
                                              &accepted));
  WT_EXPECT_INT("the token is this server's for this peer", 1, accepted);
  WT_EXPECT_U64("and it hands back the original destination connection ID", 8U,
                (uint64_t)original_length);
  WT_EXPECT_BYTES("byte for byte", k_original_destination_id, original,
                  sizeof(k_original_destination_id));
  WT_EXPECT_U64("with nothing refused", 0U, (uint64_t)retry.tokens_refused);

  /* And the three ways it is NOT accepted, each of which means the same thing to a caller (answer again) but is a
   * separate rule: the wrong address, a token addressed to another connection ID, and a tampered token. */
  WT_EXPECT_STATUS("a token replayed from another address does not validate", WT_ERR_AUTHENTICATION,
                   wt_runtime_server_retry_accept(&retry, answer, answer_length, &other_address,
                                                  k_now, original, sizeof(original),
                                                  &original_length, &accepted));
  WT_EXPECT_INT("so the answer is not accepted", 0, accepted);
  WT_EXPECT_U64("and the refusal is counted", 1U, (uint64_t)retry.tokens_refused);

  {
    uint8_t elsewhere[512];
    size_t elsewhere_length =
        build_initial(elsewhere, sizeof(elsewhere), k_original_destination_id,
                      sizeof(k_original_destination_id), decoded.token, decoded.token_len);
    WT_EXPECT_OK("a token sent to another connection ID is read",
                 wt_runtime_server_retry_accept(&retry, elsewhere, elsewhere_length,
                                                &client_address, k_now, original, sizeof(original),
                                                &original_length, &accepted));
    WT_EXPECT_INT("and is not this Retry's answer", 0, accepted);
    /* Not counted as a refusal: the packet was not addressed to this Retry at all, so there was no token of this
     * server's to refuse. The distinction is what keeps the counter about FORGERY rather than about traffic. */
    WT_EXPECT_U64("and it is not a token refusal", 1U, (uint64_t)retry.tokens_refused);
  }
  {
    uint8_t tampered[512];
    size_t tampered_length;
    size_t i;
    /* Tamper with a byte INSIDE the token, which the header decode exposes as a view: the token starts after the
     * two connection IDs, and this test reaches it through the encoded packet rather than by guessing. */
    memcpy(tampered, answer, answer_length);
    for (i = 0U; i + 1U < answer_length; i++) {
      if (memcmp(tampered + i, decoded.token, decoded.token_len) == 0) {
        tampered[i + 1U] ^= 0x01U;
        break;
      }
    }
    tampered_length = (size_t)answer_length;
    WT_EXPECT_STATUS("a tampered token does not validate", WT_ERR_AUTHENTICATION,
                     wt_runtime_server_retry_accept(&retry, tampered, tampered_length,
                                                    &client_address, k_now, original,
                                                    sizeof(original), &original_length, &accepted));
    WT_EXPECT_INT("so it is not accepted", 0, accepted);
    WT_EXPECT_U64("which is the second refusal", 2U, (uint64_t)retry.tokens_refused);
  }

  /* An Initial with no token at all is not an answer to a Retry. */
  WT_EXPECT_OK("an Initial without a token is read",
               wt_runtime_server_retry_accept(&retry, initial, initial_length, &client_address,
                                              k_now, original, sizeof(original), &original_length,
                                              &accepted));
  WT_EXPECT_INT("and is not an answer either", 0, accepted);

  /* The token's age is the caller's bound, and zero means no bound. The bound is set on the ARMED object rather
   * than by arming again, because arming again draws a new secret and would make the old token a forgery instead
   * of a stale one -- which is exactly the difference the two answers carry. */
  retry.token_max_age = 0U;
  WT_EXPECT_OK("an old answer with no bound is accepted",
               wt_runtime_server_retry_accept(&retry, answer, answer_length, &client_address,
                                              k_now + 99999999U, original, sizeof(original),
                                              &original_length, &accepted));
  WT_EXPECT_INT("because zero disables the check", 1, accepted);
  retry.token_max_age = 1000U;
  WT_EXPECT_STATUS("a bounded server refuses an answer older than its bound", WT_ERR_STATE,
                   wt_runtime_server_retry_accept(&retry, answer, answer_length, &client_address,
                                                  k_now + 1001U, original, sizeof(original),
                                                  &original_length, &accepted));
  WT_EXPECT_INT("and says so rather than calling it a forgery", 0, accepted);
  WT_EXPECT_U64("with the refusal counted", 3U, (uint64_t)retry.tokens_refused);

  WT_TEST_MAIN_END("wt_runtime_server_retry");
}
