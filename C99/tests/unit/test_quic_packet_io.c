/* Packet input and output: the seam between the wire and the connection.
 *
 * THE ORDER OF THE TWO PROTECTIONS IS THE POINT OF THIS FILE. A packet sealed before its header was
 * protected, or read before its header was unprotected, is not merely a different implementation of
 * the same thing: the header protection sample is taken from the ciphertext (RFC 9001 section 5.4.2),
 * so protecting first changes the sample, and the packet number's own length is hidden by the mask,
 * so a reader that parses the header before removing it reconstructs the wrong number. A round trip
 * that shared one mistake between its two halves would pass, so the tamper tests here check that a
 * packet cannot be read through the wrong path and that every byte the AEAD covers matters.
 *
 * A THIRD THING IS CHECKED HERE BECAUSE ONLY THIS LAYER CAN SEE IT: the short header does not carry
 * the length of its destination connection ID, so the reader has to be told it. Told the wrong one it
 * looks for the packet number in the middle of the ID, and it must fail rather than return a packet.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/quic/packet.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/protection.h"

static const uint8_t k_dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t k_scid[4] = {9, 10, 11, 12};
static const uint8_t k_frames[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

/* A key set from fixed bytes, so a failure is reproducible. The whole set -- key, IV, header
 * protection key, their lengths and the AEAD -- comes from the one derivation, which is also what
 * keeps the lengths right for whichever suite is in use rather than a copy of them here. */
static void make_keys(uint8_t seed, wt_quic_packet_keys_t *out) {
  uint8_t secret[WT_SHA256_LEN];
  size_t i;

  for (i = 0; i < sizeof(secret); i++)
    secret[i] = (uint8_t)(seed + i);
  WT_EXPECT_OK("the packet keys derive",
               wt_quic_packet_keys_from_secret(secret, WT_AEAD_AES_128_GCM, out));
}

static void test_short_header_round_trip(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[256];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;

  make_keys(1U, &keys);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 0x1234U;
  build.packet_number_length = 4U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;

  WT_EXPECT_OK("a short header packet builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  /* First byte, connection ID, four bytes of packet number, frames, and a tag. */
  WT_EXPECT_U64("and is every byte of that",
                1U + sizeof(k_dcid) + 4U + sizeof(k_frames) + WT_AEAD_TAG_LEN,
                (uint64_t)packet_len);

  WT_EXPECT_INT("the buffer holds ciphertext before it is read", 1,
                memcmp(packet + 1U + sizeof(k_dcid) + 4U, k_frames, sizeof(k_frames)) != 0);

  memset(&received, 0, sizeof(received));
  WT_EXPECT_OK("and reads back",
               wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received));
  WT_EXPECT_INT("as a short header", 1, received.short_header);
  WT_EXPECT_U64("with its packet number", 0x1234U, received.packet_number);
  WT_EXPECT_U64("encoded in the four bytes it was given", 4U,
                (uint64_t)received.packet_number_length);
  WT_EXPECT_U64("a header through the packet number", 1U + sizeof(k_dcid) + 4U,
                (uint64_t)received.header_len);
  WT_EXPECT_U64("the whole datagram", (uint64_t)packet_len, (uint64_t)received.total_len);
  WT_EXPECT_U64("and its payload", (uint64_t)sizeof(k_frames), (uint64_t)received.payload_len);
  WT_EXPECT_BYTES("which is what was sent", k_frames, received.payload, sizeof(k_frames));
  WT_EXPECT_INT("with the key phase it was given", 0, received.key_phase);
  WT_EXPECT_U64("and the destination connection ID in view", sizeof(k_dcid),
                (uint64_t)received.destination_connection_id_len);
  WT_EXPECT_BYTES("whose bytes are the datagram's", k_dcid, received.destination_connection_id,
                  sizeof(k_dcid));

  wt_quic_packet_keys_clear(&keys);
}

static void test_long_header_round_trip(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[256];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;

  make_keys(2U, &keys);
  memset(&build, 0, sizeof(build));
  build.type = WT_QUIC_PACKET_HANDSHAKE;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.source_connection_id = k_scid;
  build.source_connection_id_len = sizeof(k_scid);
  build.packet_number = 42U;
  build.packet_number_length = 2U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;

  WT_EXPECT_OK("a long header packet builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  WT_EXPECT_U64("and holds its payload and tag at least", 1,
                (uint64_t)(packet_len > sizeof(k_frames) + WT_AEAD_TAG_LEN));

  memset(&received, 0, sizeof(received));
  /* A long header carries its destination connection ID length, so the reader is not told one. */
  WT_EXPECT_OK("and reads back", wt_quic_packet_read(packet, packet_len, &keys, 0U, 0U, &received));
  WT_EXPECT_INT("as a long header", 0, received.short_header);
  WT_EXPECT_U64("of its type", (uint64_t)WT_QUIC_PACKET_HANDSHAKE, (uint64_t)received.type);
  WT_EXPECT_U64("its version", (uint64_t)WT_QUIC_VERSION_1, (uint64_t)received.version);
  WT_EXPECT_U64("its packet number", 42U, received.packet_number);
  WT_EXPECT_U64("in two bytes", 2U, (uint64_t)received.packet_number_length);
  WT_EXPECT_U64("its payload", (uint64_t)sizeof(k_frames), (uint64_t)received.payload_len);
  WT_EXPECT_BYTES("which is what was sent", k_frames, received.payload, sizeof(k_frames));
  WT_EXPECT_BYTES("its destination connection ID", k_dcid, received.destination_connection_id,
                  sizeof(k_dcid));
  WT_EXPECT_BYTES("and its source connection ID", k_scid, received.source_connection_id,
                  sizeof(k_scid));

  /* Every byte the builder wrote is accounted for: the header, the payload and the tag are the
   * packet, which is what makes `total_len` the place the next coalesced packet starts. */
  WT_EXPECT_U64("the whole packet", (uint64_t)packet_len, (uint64_t)received.total_len);
  WT_EXPECT_U64("which is header, payload and tag", (uint64_t)packet_len,
                (uint64_t)(received.header_len + received.payload_len + WT_AEAD_TAG_LEN));

  wt_quic_packet_keys_clear(&keys);
}

/* With an Initial packet the token sits between the connection IDs and the Length field, so the packet
 * number's offset is not a fixed distance from the start. A reader that assumed one would find the
 * number inside the token. */
static void test_initial_with_token(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[512];
  uint8_t token[37];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;
  size_t i;

  for (i = 0; i < sizeof(token); i++)
    token[i] = (uint8_t)(0x40U + i);
  make_keys(3U, &keys);
  memset(&build, 0, sizeof(build));
  build.type = WT_QUIC_PACKET_INITIAL;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.source_connection_id = k_scid;
  build.source_connection_id_len = sizeof(k_scid);
  build.token = token;
  build.token_len = sizeof(token);
  build.packet_number = 0x0102U;
  build.packet_number_length = 3U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;

  WT_EXPECT_OK("an Initial packet with a token builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  memset(&received, 0, sizeof(received));
  WT_EXPECT_OK("and reads back", wt_quic_packet_read(packet, packet_len, &keys, 0U, 0U, &received));
  WT_EXPECT_U64("with its packet number", 0x0102U, received.packet_number);
  WT_EXPECT_U64("in three bytes", 3U, (uint64_t)received.packet_number_length);
  WT_EXPECT_BYTES("and its payload", k_frames, received.payload, sizeof(k_frames));
  /* The header the AEAD authenticated covers the token, so it is longer than the same packet without
   * one, and a reader that skipped the token would have every later offset wrong by its length. */
  WT_EXPECT_U64(
      "and the header ends after the token",
      (uint64_t)(1U + 4U + 1U + sizeof(k_dcid) + 1U + sizeof(k_scid) + 2U + sizeof(token) + 3U),
      (uint64_t)received.header_len);

  wt_quic_packet_keys_clear(&keys);
}

/* The packet number on the wire is a fraction of the real one, reconstructed against the largest this
 * endpoint has seen (RFC 9000 appendix A.3). These are the cases where the truncated bytes and the
 * real number differ, which is where an implementation that returned the bytes as read would fail. */
static void test_packet_number_reconstruction(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[256];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;
  static const uint64_t numbers[] = {0U, 1U, 255U, 256U, 0x1234U, 0xffffffU, 0x1000000U};
  size_t i;

  make_keys(4U, &keys);
  for (i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
    uint64_t largest = numbers[i] >= 4U ? numbers[i] - 3U : 0U;

    memset(&build, 0, sizeof(build));
    build.short_header = 1;
    build.destination_connection_id = k_dcid;
    build.destination_connection_id_len = sizeof(k_dcid);
    build.packet_number = numbers[i];
    build.packet_number_length = 2U;
    build.payload = k_frames;
    build.payload_len = sizeof(k_frames);
    build.keys = &keys;
    WT_EXPECT_OK("the packet builds",
                 wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));

    memset(&received, 0, sizeof(received));
    WT_EXPECT_OK("and reads back", wt_quic_packet_read(packet, packet_len, &keys, largest,
                                                       sizeof(k_dcid), &received));
    WT_EXPECT_U64("with the number the sender meant", numbers[i], received.packet_number);
  }
  wt_quic_packet_keys_clear(&keys);
}

/* Every byte the AEAD covers must matter. A flipped bit either makes the read refuse the packet or
 * makes the payload differ; it can never produce the frames that were sent. */
static void test_tamper_is_refused(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[256];
  uint8_t saved[256];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;
  size_t i;

  make_keys(5U, &keys);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 7U;
  build.packet_number_length = 2U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  memcpy(saved, packet, packet_len);

  for (i = 0; i < packet_len; i++) {
    wt_status_t status;

    memcpy(packet, saved, packet_len);
    packet[i] ^= 0x01U;
    memset(&received, 0, sizeof(received));
    status = wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received);
    if (status == WT_OK) {
      WT_EXPECT_TRUE("a flipped byte never yields the frames that were sent",
                     received.payload_len != sizeof(k_frames) ||
                         memcmp(received.payload, k_frames, sizeof(k_frames)) != 0);
    }
  }

  /* The tag itself. A tag that does not verify is WT_ERR_AUTHENTICATION and not WT_ERR_PROTOCOL:
   * status.h reserves the latter for bytes that violate the protocol, and a packet that was not
   * produced by the holder of the key is the ordinary case on a hostile network. Whether that is a
   * discarded datagram or a closed connection is the caller's decision, which is why this layer does
   * not make it. */
  memcpy(packet, saved, packet_len);
  packet[packet_len - 1U] ^= 0x80U;
  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS("a flipped tag fails authentication", WT_ERR_AUTHENTICATION,
                   wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received));

  /* And one byte of the connection ID: a packet for another connection is refused, not returned. */
  memcpy(packet, saved, packet_len);
  packet[1] ^= 0xffU;
  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS("a packet for another connection fails authentication", WT_ERR_AUTHENTICATION,
                   wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received));

  wt_quic_packet_keys_clear(&keys);
}

/* The wrong length for the local connection ID moves the packet number into the ID. Nothing about the
 * packet is then right, and it must not be read as one. */
static void test_wrong_connection_id_len(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[256];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;

  make_keys(6U, &keys);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 99U;
  build.packet_number_length = 2U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));

  /* Both lengths must be refused, and WHICH CHECK REFUSES THEM IS A PROPERTY OF THE MASK, so the test
   * pins the refusal rather than its name: the sample is taken from the wrong offset, so the unmasked
   * first byte is arbitrary -- the decoder may refuse it as a reserved bit or a wrong form, which is
   * WT_ERR_PROTOCOL -- and if it survives that, the packet number and the associated data are wrong
   * and the tag fails, which is WT_ERR_AUTHENTICATION. What must never happen is a packet. */
  memset(&received, 0, sizeof(received));
  WT_EXPECT_TRUE("a shorter connection ID than the packet's is refused",
                 wt_quic_packet_read(packet, packet_len, &keys, 0U, 4U, &received) != WT_OK);
  WT_EXPECT_U64("and nothing was read", 0U, (uint64_t)received.payload_len);
  memset(&received, 0, sizeof(received));
  WT_EXPECT_TRUE("and a longer one is refused too",
                 wt_quic_packet_read(packet, packet_len, &keys, 0U, 12U, &received) != WT_OK);
  WT_EXPECT_U64("and nothing was read", 0U, (uint64_t)received.payload_len);

  wt_quic_packet_keys_clear(&keys);
}

/* A Retry and a Version Negotiation are not protected by the AEAD these keys belong to: a Retry has
 * its own integrity tag and a Version Negotiation is a list of versions. Neither has a packet number,
 * so treating one as a protected packet would read the low bits of its first byte as a length. */
static void test_unprotected_packets_are_refused(void) {
  uint8_t retry[1U + 4U + 1U + 8U + 1U + 4U + 8U + 16U];
  uint8_t vn[1U + 4U + 1U + 8U + 1U + 4U + 4U];
  uint8_t tag[16] = {0};
  uint8_t token[8] = {0};
  wt_writer_t w;
  size_t vn_len;
  wt_quic_packet_keys_t keys;
  wt_quic_received_packet_t received;
  wt_quic_packet_kind_t kind = WT_QUIC_PACKET_KIND_LONG;
  size_t retry_len;

  make_keys(7U, &keys);

  w = wt_writer_init(retry, sizeof(retry));
  WT_EXPECT_OK("a Retry encodes",
               wt_quic_retry_packet_encode(&w, WT_QUIC_VERSION_1, k_dcid, sizeof(k_dcid), k_scid,
                                           sizeof(k_scid), token, sizeof(token), tag));
  WT_EXPECT_TRUE("and the writer fitted it", wt_writer_ok(&w));
  retry_len = wt_writer_offset(&w);
  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS("a Retry is not read as a protected packet", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_read(retry, retry_len, &keys, 0U, 0U, &received));

  /* A Version Negotiation by hand: a long header whose version is zero, which is what makes it one
   * (RFC 9000 section 17.2.1). It carries no Length field and no packet number. */
  vn[0] = 0x80U;
  vn[1] = 0U;
  vn[2] = 0U;
  vn[3] = 0U;
  vn[4] = 0U;
  vn[5] = sizeof(k_dcid);
  memcpy(vn + 6U, k_dcid, sizeof(k_dcid));
  vn[6U + sizeof(k_dcid)] = sizeof(k_scid);
  memcpy(vn + 7U + sizeof(k_dcid), k_scid, sizeof(k_scid));
  vn_len = 7U + sizeof(k_dcid) + sizeof(k_scid) + 4U;
  WT_EXPECT_OK("the hand-built datagram is recognised", wt_quic_packet_kind(vn, vn_len, &kind));
  WT_EXPECT_U64("as a Version Negotiation", (uint64_t)WT_QUIC_PACKET_KIND_VERSION_NEGOTIATION,
                (uint64_t)kind);
  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS("which is not read as a protected packet", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_read(vn, vn_len, &keys, 0U, 0U, &received));

  wt_quic_packet_keys_clear(&keys);
}

/* A datagram shorter than the packet it claims to hold must be refused before anything is read out of
 * it, at every length from zero to one short of the whole. */
static void test_truncated_is_refused(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[256];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;
  size_t cut;

  make_keys(8U, &keys);
  memset(&build, 0, sizeof(build));
  build.type = WT_QUIC_PACKET_INITIAL;
  build.version = WT_QUIC_VERSION_1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.source_connection_id = k_scid;
  build.source_connection_id_len = sizeof(k_scid);
  build.packet_number = 5U;
  build.packet_number_length = 1U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;
  WT_EXPECT_OK("the packet builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));

  for (cut = 0U; cut < packet_len; cut++) {
    memset(&received, 0, sizeof(received));
    WT_EXPECT_TRUE("a datagram cut short is never a packet",
                   wt_quic_packet_read(packet, cut, &keys, 0U, 0U, &received) != WT_OK);
  }

  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS("an empty datagram is a truncation", WT_ERR_TRUNCATED,
                   wt_quic_packet_read(packet, 0U, &keys, 0U, 0U, &received));
  WT_EXPECT_STATUS("a null datagram is a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_read(NULL, 8U, &keys, 0U, 0U, &received));
  WT_EXPECT_STATUS("null keys are a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_read(packet, packet_len, NULL, 0U, 0U, &received));
  WT_EXPECT_STATUS("and nowhere to put the result is one too", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_read(packet, packet_len, &keys, 0U, 0U, NULL));

  wt_quic_packet_keys_clear(&keys);
}

/* A build with nowhere to put the packet, or with a payload that is not there, is a caller error and
 * must not be reported as a packet of some length. */
static void test_build_rejects_bad_arguments(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[64];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  const size_t exact = 1U + sizeof(k_dcid) + 2U + sizeof(k_frames) + WT_AEAD_TAG_LEN;

  make_keys(9U, &keys);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number_length = 2U;
  build.payload = k_frames;
  build.payload_len = sizeof(k_frames);
  build.keys = &keys;

  WT_EXPECT_OK("the exact capacity is enough",
               wt_quic_packet_build(&build, packet, exact, &packet_len));
  WT_EXPECT_U64("and produces that many bytes", (uint64_t)exact, (uint64_t)packet_len);

  WT_EXPECT_STATUS("no parameters is a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(NULL, packet, sizeof(packet), &packet_len));
  WT_EXPECT_STATUS("nowhere to write is a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, NULL, sizeof(packet), &packet_len));
  WT_EXPECT_STATUS("and nowhere to report the length is one too", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), NULL));
  WT_EXPECT_STATUS("one byte short of the packet is a limit", WT_ERR_LIMIT,
                   wt_quic_packet_build(&build, packet, exact - 1U, &packet_len));
  WT_EXPECT_U64("and nothing was reported", 0U, (uint64_t)packet_len);
  build.keys = NULL;
  WT_EXPECT_STATUS("no keys is a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  build.keys = &keys;
  build.payload = NULL;
  WT_EXPECT_STATUS("a length without a payload is a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  build.payload = k_frames;
  build.packet_number_length = 0U;
  WT_EXPECT_STATUS("a packet number of no bytes is a bad argument", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  build.packet_number_length = 5U;
  WT_EXPECT_STATUS("and one of five bytes is too", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  build.packet_number_length = 2U;
  /* A short header has no source connection ID and no token: a caller that set one is asking for a
   * packet that cannot exist. */
  build.source_connection_id_len = sizeof(k_scid);
  WT_EXPECT_STATUS("a source connection ID on a short header is a bad argument",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  build.source_connection_id_len = 0U;
  build.token_len = 1U;
  WT_EXPECT_STATUS("and so is a token on one", WT_ERR_INVALID_ARGUMENT,
                   wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));

  wt_quic_packet_keys_clear(&keys);
}

/* An empty payload is a packet whose frames are all empty, which is legal -- but it is also the case
 * where the header protection sample decides whether the packet can exist at all. The sample starts
 * four bytes after the start of the packet number (RFC 9001 section 5.4.2) and is sixteen bytes long,
 * so with an eight byte connection ID the packet number must be the full four bytes for the sample to
 * fit inside a packet whose only other bytes are the tag. That is a real minimum, not a quirk of this
 * implementation: it is one of the reasons a QUIC datagram has a minimum size. */
static void test_empty_payload(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[64];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;

  make_keys(10U, &keys);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 3U;
  build.packet_number_length = 1U;
  build.payload = NULL;
  build.payload_len = 0U;
  build.keys = &keys;
  /* 1 + 8 + 1 + 16 = 26 bytes, and the sample would run to byte 29, so the builder pads the plaintext
   * with three PADDING frames rather than refusing to encode a packet it could send (RFC 9000 section
   * 19.1). A packet with no frames at all is legal for the same reason: PADDING is a frame. */
  WT_EXPECT_OK("an empty payload is padded until the packet can carry a sample",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  WT_EXPECT_U64("to exactly the sample's reach", 1U + sizeof(k_dcid) + 1U + 3U + WT_AEAD_TAG_LEN,
                (uint64_t)packet_len);

  memset(&received, 0, sizeof(received));
  WT_EXPECT_OK("and reads back",
               wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received));
  WT_EXPECT_U64("as the padding the sender added", 3U, (uint64_t)received.payload_len);
  WT_EXPECT_U64("with its packet number", 3U, received.packet_number);
  wt_quic_packet_keys_clear(&keys);
}

/* RFC 9001 section 5.4.2: a packet that cannot be sampled cannot be protected, so a sender whose frame
 * is shorter than the sample pads the plaintext. This is what lets a two-byte frame such as
 * RETIRE_CONNECTION_ID or PING travel on its own, and it is checked here with the frame bytes a caller
 * would hand over rather than with an empty payload. */
static void test_short_payload_is_padded(void) {
  wt_quic_packet_keys_t keys;
  uint8_t packet[64];
  size_t packet_len = 0U;
  wt_quic_packet_build_t build;
  wt_quic_received_packet_t received;
  /* RETIRE_CONNECTION_ID for sequence 1: the frame type then the sequence. */
  static const uint8_t retire_sequence_one[2] = {0x19U, 0x01U};

  make_keys(11U, &keys);
  memset(&build, 0, sizeof(build));
  build.short_header = 1;
  build.destination_connection_id = k_dcid;
  build.destination_connection_id_len = sizeof(k_dcid);
  build.packet_number = 0U;
  build.packet_number_length = 1U;
  build.payload = retire_sequence_one;
  build.payload_len = sizeof(retire_sequence_one);
  build.keys = &keys;
  WT_EXPECT_OK("a two-byte frame builds",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  WT_EXPECT_U64("in a packet padded to the sample's reach",
                1U + sizeof(k_dcid) + 1U + 3U + WT_AEAD_TAG_LEN, (uint64_t)packet_len);

  memset(&received, 0, sizeof(received));
  WT_EXPECT_OK("and reads back",
               wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received));
  WT_EXPECT_U64("with the frame and its padding", 3U, (uint64_t)received.payload_len);
  WT_EXPECT_BYTES("keeping the frame's bytes", retire_sequence_one, received.payload,
                  sizeof(retire_sequence_one));
  WT_EXPECT_U64("and filling the rest with PADDING", 0U, (uint64_t)received.payload[2]);

  /* A four-byte packet number already provides the four bytes the sample starts past, so no padding is
   * added and the packet carries the frame alone. */
  build.packet_number_length = 4U;
  WT_EXPECT_OK("a full packet number needs no padding",
               wt_quic_packet_build(&build, packet, sizeof(packet), &packet_len));
  WT_EXPECT_U64("so the packet is header, frame and tag",
                1U + sizeof(k_dcid) + 4U + sizeof(retire_sequence_one) + WT_AEAD_TAG_LEN,
                (uint64_t)packet_len);
  memset(&received, 0, sizeof(received));
  WT_EXPECT_OK("and reads back",
               wt_quic_packet_read(packet, packet_len, &keys, 0U, sizeof(k_dcid), &received));
  WT_EXPECT_U64("with just the frame", (uint64_t)sizeof(retire_sequence_one),
                (uint64_t)received.payload_len);
  wt_quic_packet_keys_clear(&keys);
}

/* A header that cannot be parsed is NOT a violation by the peer (WT-167).
 *
 * RFC 9000 section 17.2 requires the fixed bit to be set and makes non-zero reserved bits a connection error
 * only "after removing both packet and header protection". Both fields are inside the AEAD's associated data, so
 * a header that fails to parse -- or reads as reserved bits set because it was protected with a key set this
 * endpoint no longer holds -- is a packet that cannot be shown to come from the peer. RFC 9001 section 5.3 makes
 * that a DISCARD, which at this layer is WT_ERR_AUTHENTICATION. Refusing it as PROTOCOL_VIOLATION is what made a
 * successful quiche interop report `"firstReceiveError":"protocol"`: quiche's answer to an Initial the Retry had
 * already invalidated arrived protected with the retired keys.
 */
static void test_a_header_that_cannot_be_parsed_is_not_a_violation(void) {
  /* Twenty-nine bytes, which is the shortest packet that can be READ at all: the header runs to offset nine,
   * the Length covers one packet number byte and nineteen of payload, and header protection's sample needs
   * sixteen bytes starting four bytes past the packet number (RFC 9001 section 5.4.2). */
  uint8_t packet[29];
  wt_quic_packet_keys_t keys;
  wt_quic_received_packet_t received;

  make_keys(9U, &keys);
  memset(packet, 0, sizeof(packet));
  packet[0] = 0x80U; /* a long header, an Initial, with the fixed bit CLEAR */
  packet[4] = 0x01U; /* version 1 */
  packet[5] = 0x00U; /* a zero-length Destination Connection ID */
  packet[6] = 0x00U; /* and a zero-length Source Connection ID */
  packet[7] = 0x00U; /* no token */
  packet[8] = 20U;   /* Length: one packet number byte and nineteen of payload */
  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS(
      "a header without the fixed bit is DISCARDED, not refused", WT_ERR_AUTHENTICATION,
      wt_quic_packet_read(packet, sizeof(packet), &keys, 0U, sizeof(k_dcid), &received));

  /* And the ordering that makes it safe: a header with the RESERVED bits set and a tag that does not verify is
   * the same answer -- the packet never authenticated, so nothing about it is a protocol violation yet. */
  packet[0] = 0xccU; /* fixed bit back on, reserved bits set, one-byte packet number */
  memset(&received, 0, sizeof(received));
  WT_EXPECT_STATUS(
      "reserved bits and a bad tag are a failed authentication", WT_ERR_AUTHENTICATION,
      wt_quic_packet_read(packet, sizeof(packet), &keys, 0U, sizeof(k_dcid), &received));
  wt_quic_packet_keys_clear(&keys);
}

int main(void) {
  test_short_header_round_trip();
  test_long_header_round_trip();
  test_initial_with_token();
  test_packet_number_reconstruction();
  test_tamper_is_refused();
  test_a_header_that_cannot_be_parsed_is_not_a_violation();
  test_wrong_connection_id_len();
  test_unprotected_packets_are_refused();
  test_truncated_is_refused();
  test_build_rejects_bad_arguments();
  test_empty_payload();
  test_short_payload_is_padded();

  WT_TEST_MAIN_END("wt_quic_packet_io");
}
