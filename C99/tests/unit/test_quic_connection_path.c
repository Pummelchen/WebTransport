/* The path tests for the connection runtime. */

/* WT-172: PATH VALIDATION. Three rules, each tested where it can fail on its own.
 *
 * RFC 9000 section 8.2.2: "An endpoint MUST NOT delay transmission of a packet containing a PATH_RESPONSE frame
 * unless constrained by congestion control" -- so the echo goes out from inside the receive, and a test that had
 * to call `flush` first would be testing the wrong thing.
 *
 * Section 8.2.1: a challenge's payload must be NEW on every attempt, because a repeated one is indistinguishable
 * from an attacker's replay of an old challenge. The retry is therefore driven by the TIMER (section 8.2.4), not
 * by the loss machinery: a retransmitted PATH_CHALLENGE would carry the payload that must not repeat.
 *
 * Section 8.2.3: the path is validated when a response carries the payload this endpoint challenged with, and a
 * response that carries anything else (including a stranger's) validates nothing. */

#include "test_quic_connection_internal.h"

/* A frame that is NOT a PATH_CHALLENGE must not be handled as one (WT-194).
 *
 * The dispatch sent PING, CRYPTO, NEW_TOKEN, DATA_BLOCKED and STREAMS_BLOCKED to `handle_path_challenge`,
 * which reads `frame->as.path_challenge.data`. For those kinds that member holds the previous frame's bytes,
 * and for DATA_BLOCKED it is a varint limit -- not a pointer at all. The NULL check passed, and eight bytes
 * were copied from that address: a peer that sent one of those frames took this endpoint down with SIGSEGV.
 * Measured against real peers rather than reasoned about: quinn, quiche and h3 each send a PING, and all three
 * crashed this client until the labels were separated.
 *
 * DATA_BLOCKED then PING in ONE packet is that state deterministically, which is why this sends two frames
 * rather than a PING on its own -- a PING alone leaves the union zeroed by `wt_quic_frame_make` and would pass
 * even with the defect in place. */
void test_a_frame_that_is_not_a_challenge_is_not_handled_as_one(void) {
  connection_pair_t pair;
  wt_quic_frame_t blocked = wt_quic_frame_make(WT_QUIC_FRAME_KIND_DATA_BLOCKED);
  wt_quic_frame_t ping = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PING);
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 114000000U;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_path_pair(&pair, 0x31U);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x31U + i);
  WT_EXPECT_OK("the sender's keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));

  /* The limit is what the union holds where a pointer would be read. 0x2e is the address the real crash read
   * from, so this uses it rather than a round number. */
  blocked.as.data_blocked.maximum = 0x2eU;
  send_two_frames_from_side(&pair, &blocked, &ping, &keys, 0U, k_dcid, sizeof(k_dcid));

  /* Before the fix this call did not return. */
  receive_on(&pair.client, &pair.client_socket, now);

  WT_EXPECT_U64("the PING reaches the handler", 1U,
                (uint64_t)witness_frames_of(&pair.client_witness, WT_QUIC_FRAME_KIND_PING));
  WT_EXPECT_U64("and is not answered with a PATH_RESPONSE", 0U,
                wt_quic_connection_path_responses_sent(&pair.client));

  close_pair(&pair);
}

void test_a_path_challenge_is_echoed_immediately(void) {
  connection_pair_t pair;
  wt_quic_frame_t challenge = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PATH_CHALLENGE);
  static const uint8_t k_payload[WT_QUIC_PATH_CHALLENGE_LENGTH] = {0xa0U, 0xa1U, 0xa2U, 0xa3U,
                                                                  0xa4U, 0xa5U, 0xa6U, 0xa7U};
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 112000000U;
  const recorded_frame_t *echo;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_path_pair(&pair, 0x21U);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x21U + i);
  WT_EXPECT_OK("the sender's keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));

  /* The peer challenges the path this connection is on. */
  challenge.as.path_challenge.data = k_payload;
  send_frame_from_side(&pair, 1, &challenge, &keys, 0U, k_dcid, sizeof(k_dcid));
  receive_on(&pair.client, &pair.client_socket, now);

  WT_EXPECT_U64("the challenge reached the handler", 1U,
                (uint64_t)witness_frames_of(&pair.client_witness, WT_QUIC_FRAME_KIND_PATH_CHALLENGE));
  WT_EXPECT_U64("and one response went out", 1U, wt_quic_connection_path_responses_sent(&pair.client));

  /* And the echo is on the wire WITHOUT a flush between the challenge and this read -- which is section 8.2.2's
   * "MUST NOT delay" as a measurement rather than a claim. The peer here is the test's own server connection, so
   * the frame it was handed is the frame the client sent. */
  receive_on(&pair.server, &pair.server_socket, now);
  echo = witness_frame(&pair.server_witness, WT_QUIC_FRAME_KIND_PATH_RESPONSE, 0U);
  WT_EXPECT_TRUE("the peer was handed a PATH_RESPONSE", echo != NULL);
  if (echo != NULL) {
    WT_EXPECT_BYTES("carrying the payload it challenged with, byte for byte", k_payload, echo->data,
                    WT_QUIC_PATH_CHALLENGE_LENGTH);
  }

  close_pair(&pair);
}

void test_a_path_is_validated_by_its_own_response(void) {
  connection_pair_t pair;
  wt_quic_frame_t response = wt_quic_frame_make(WT_QUIC_FRAME_KIND_PATH_RESPONSE);
  static const uint8_t k_stranger[WT_QUIC_PATH_CHALLENGE_LENGTH] = {0xeeU, 0xeeU, 0xeeU, 0xeeU,
                                                                    0xeeU, 0xeeU, 0xeeU, 0xeeU};
  wt_quic_packet_keys_t keys;
  uint8_t secret[WT_SHA256_LEN];
  uint64_t now = 113000000U;
  uint64_t matched_before;
  size_t i;

  open_pair(WT_UDP_IPV4, &pair);
  arm_path_pair(&pair, 0x31U);
  for (i = 0U; i < sizeof(secret); i++) secret[i] = (uint8_t)(0x31U + i);
  WT_EXPECT_OK("the sender's keys", wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, &keys));

  WT_EXPECT_OK("a validation starts", wt_quic_connection_validate_path(&pair.client, now));
  WT_EXPECT_INT("which the connection reports as running", 1, wt_quic_connection_path_validating(&pair.client));
  WT_EXPECT_U64("with one challenge on the wire", 1U, wt_quic_connection_path_challenges_sent(&pair.client));
  WT_EXPECT_INT("and nothing validated yet", 0, wt_quic_connection_path_validated(&pair.client));

  /* The challenge went out inside the call, so it is on the server socket already -- and the peer here is a real
   * connection, which ECHOES it (section 8.2.2). That echo is the response, so no packet is hand-built for the
   * success case: the flow is the protocol's own. */
  receive_on(&pair.server, &pair.server_socket, now);
  WT_EXPECT_U64("the peer was challenged", 1U,
                (uint64_t)witness_frames_of(&pair.server_witness, WT_QUIC_FRAME_KIND_PATH_CHALLENGE));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_INT("its echo validates the path", 1, wt_quic_connection_path_validated(&pair.client));
  WT_EXPECT_INT("and the validation is over", 0, wt_quic_connection_path_validating(&pair.client));
  WT_EXPECT_U64("with no failures", 0U, wt_quic_connection_path_validation_failures(&pair.client));

  /* A response that is not this challenge's payload validates nothing (section 8.2.3), which needs its own
   * validation: the peer's echo of the NEXT challenge is thrown away first, precisely so that the hand-built
   * response below is the only answer that arrives. */
  matched_before = pair.client.path_responses_matched;
  WT_EXPECT_OK("a second validation starts", wt_quic_connection_validate_path(&pair.client, now));
  WT_EXPECT_INT("and is running", 1, wt_quic_connection_path_validating(&pair.client));
  receive_on(&pair.server, &pair.server_socket, now);
  discard_one_datagram(&pair.client_socket);
  response.as.path_response.data = k_stranger;
  send_frame_from_side(&pair, 1, &response, &keys, 1U, k_dcid, sizeof(k_dcid));
  now += 1000U;
  receive_on(&pair.client, &pair.client_socket, now);
  WT_EXPECT_U64("a stranger's response matches nothing", matched_before, pair.client.path_responses_matched);
  WT_EXPECT_INT("so the second validation is still running", 1,
                wt_quic_connection_path_validating(&pair.client));

  close_pair(&pair);
}

void test_a_path_that_does_not_answer_is_given_up_on(void) {
  connection_pair_t pair;
  /* Zeroed rather than left to the first assignment: the comparison below runs only when both payloads were
   * actually read, and a compiler cannot always prove that -- mingw's optimiser said so with
   * -Wmaybe-uninitialized, which this tree treats as an error (WT-134's own lesson, learned again). */
  uint8_t first[WT_QUIC_PATH_CHALLENGE_LENGTH] = {0U};
  uint8_t second[WT_QUIC_PATH_CHALLENGE_LENGTH] = {0U};
  uint64_t now = 114000000U;
  unsigned attempt;
  const recorded_frame_t *sent;

  open_pair(WT_UDP_IPV4, &pair);
  arm_path_pair(&pair, 0x41U);

  WT_EXPECT_OK("a validation starts", wt_quic_connection_validate_path(&pair.client, now));
  WT_EXPECT_OK("the challenge goes out", wt_udp_wait(&pair.server_socket, 2000000U));
  receive_on(&pair.server, &pair.server_socket, now);
  sent = witness_frame(&pair.server_witness, WT_QUIC_FRAME_KIND_PATH_CHALLENGE, 0U);
  WT_EXPECT_TRUE("which the peer sees", sent != NULL);
  if (sent != NULL) memcpy(first, sent->data, WT_QUIC_PATH_CHALLENGE_LENGTH);

  /* The peer never answers. Each probe timeout sends the NEXT attempt, with a payload nothing has seen before --
   * and the timer is the connection's own probe timeout, so the test advances the clock by more than that rather
   * than by a number the implementation could change. */
  for (attempt = 1U; attempt < WT_QUIC_PATH_VALIDATION_ATTEMPTS; attempt++) {
    unsigned drained;
    now += 2000000U;
    WT_EXPECT_OK("the timer runs", wt_quic_connection_on_timeout(&pair.client, now));
    WT_EXPECT_U64("which sends another challenge", (uint64_t)(attempt + 1U),
                  wt_quic_connection_path_challenges_sent(&pair.client));
    /* The SAME timer also sends what a probe timeout owes -- the challenges are ack-eliciting packets nothing has
     * acknowledged -- so the peer's socket has more than the challenge on it, and a test that delivered one
     * datagram per attempt would compare the payload of whichever packet happened to arrive first. Everything
     * queued is delivered, and the challenge is then read from what the peer's handler was given. */
    for (drained = 0U; drained < 4U; drained++) {
      if (wt_udp_wait(&pair.server_socket, 20000U) != WT_OK) break;
      receive_on(&pair.server, &pair.server_socket, now);
    }
    WT_EXPECT_U64("the peer has seen every challenge so far", (uint64_t)(attempt + 1U),
                  (uint64_t)witness_frames_of(&pair.server_witness, WT_QUIC_FRAME_KIND_PATH_CHALLENGE));
    sent = witness_frame(&pair.server_witness, WT_QUIC_FRAME_KIND_PATH_CHALLENGE, attempt);
    WT_EXPECT_TRUE("with the newest one among them", sent != NULL);
    if (sent == NULL) continue;
    memcpy(second, sent->data, WT_QUIC_PATH_CHALLENGE_LENGTH);
    WT_EXPECT_INT("whose payload is NEW, which section 8.2.1 requires", 0,
                  memcmp(first, second, WT_QUIC_PATH_CHALLENGE_LENGTH) == 0);
  }

  /* And the bound: one more timeout, and the path is declared unvalidated rather than challenged for ever. */
  now += 2000000U;
  WT_EXPECT_OK("the last timer runs", wt_quic_connection_on_timeout(&pair.client, now));
  WT_EXPECT_INT("the path is no longer being validated", 0,
                wt_quic_connection_path_validating(&pair.client));
  WT_EXPECT_U64("and the failure is counted for the caller", 1U,
                wt_quic_connection_path_validation_failures(&pair.client));
  WT_EXPECT_U64("after exactly the attempts the bound allows", (uint64_t)WT_QUIC_PATH_VALIDATION_ATTEMPTS,
                wt_quic_connection_path_challenges_sent(&pair.client));
  WT_EXPECT_INT("with the path never validated", 0, wt_quic_connection_path_validated(&pair.client));

  close_pair(&pair);
}

