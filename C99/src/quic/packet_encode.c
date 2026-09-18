/* QUIC packet headers. See webtransport/quic/packet.h.
 *
 * Both decoders read the first byte first and dispatch on its top bit, and both
 * check the fixed bit and -- for a long header -- the reserved bits, because
 * those are the fields that decide whether the bytes are a QUIC packet at all
 * before any of the rest can be trusted.
 *
 * The Length field is re-derived on encode rather than taken from the caller.
 * RFC 9000 section 17.2 defines it as the packet number length plus the payload
 * length, and an API that let a caller pass it separately would let the two
 * disagree -- a class of defect that is silent until a peer refuses the packet
 * for a reason that names neither field.
 */

#include "webtransport/quic/packet.h"

#include "webtransport/checked.h"
#include "webtransport/endian.h"
#include "webtransport/quic/packet_number.h"

#include <string.h>

#include "packet_internal.h"

static void wt_quic_write_connection_id(wt_writer_t *w, const uint8_t *id, size_t id_len) {
  wt_writer_u8(w, (uint8_t)id_len);
  wt_writer_bytes(w, id, id_len);
}

/* The body both encoders share. `with_payload` is 0 for the prefix form, where the caller is going
 * to produce the payload itself and only needs the header -- and the Length field, which is computed
 * here from the payload length the caller states, so the two forms cannot disagree about it. */
static wt_status_t long_header_encode(wt_writer_t *w, wt_quic_packet_type_t type, uint32_t version,
                                      const uint8_t *destination_connection_id,
                                      size_t destination_connection_id_len,
                                      const uint8_t *source_connection_id,
                                      size_t source_connection_id_len, const uint8_t *token,
                                      size_t token_len, uint64_t packet_number,
                                      size_t packet_number_len, const uint8_t *payload,
                                      size_t payload_len, int with_payload) {
  uint8_t first;
  uint8_t packet_number_bytes[4];
  size_t length_field;

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A Retry has a different shape and its own encoder; a Version Negotiation
   * packet is not a packet with a type at all. */
  if (type == WT_QUIC_PACKET_RETRY) return WT_ERR_INVALID_ARGUMENT;
  if ((type != WT_QUIC_PACKET_INITIAL && type != WT_QUIC_PACKET_ZERO_RTT &&
       type != WT_QUIC_PACKET_HANDSHAKE)) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN ||
      source_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (destination_connection_id_len != 0U && destination_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (source_connection_id_len != 0U && source_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (packet_number_len == 0U || packet_number_len > 4U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The token belongs to Initial packets only. A caller that set one on another
   * type is asking for a packet the peer will not parse. */
  if (type != WT_QUIC_PACKET_INITIAL && token_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (token_len != 0U && token == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (with_payload && payload_len != 0U && payload == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  first = (uint8_t)((unsigned int)WT_QUIC_LONG_HEADER_BIT | (unsigned int)WT_QUIC_FIXED_BIT |
                    ((unsigned int)type << 4) | (unsigned int)(packet_number_len - 1U));
  if (packet_number_len !=
      wt_quic_packet_number_encode(packet_number, packet_number_len, packet_number_bytes)) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The Length field is computed here, never taken from the caller. */
  if (wt_checked_add_size(packet_number_len, payload_len, &length_field) != WT_OK) {
    return WT_ERR_OVERFLOW;
  }
  if (wt_quic_varint_size((uint64_t)length_field) == 0U) {
    return WT_ERR_OVERFLOW;
  }

  wt_writer_u8(w, first);
  wt_writer_u32(w, version);
  wt_quic_write_connection_id(w, destination_connection_id, destination_connection_id_len);
  wt_quic_write_connection_id(w, source_connection_id, source_connection_id_len);
  if (type == WT_QUIC_PACKET_INITIAL) {
    (void)wt_quic_writer_varint(w, (uint64_t)token_len);
    wt_writer_bytes(w, token, token_len);
  }
  (void)wt_quic_writer_varint(w, (uint64_t)length_field);
  wt_writer_bytes(w, packet_number_bytes, packet_number_len);
  if (with_payload) wt_writer_bytes(w, payload, payload_len);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_quic_long_header_encode(wt_writer_t *w, wt_quic_packet_type_t type, uint32_t version,
                                       const uint8_t *destination_connection_id,
                                       size_t destination_connection_id_len,
                                       const uint8_t *source_connection_id,
                                       size_t source_connection_id_len, const uint8_t *token,
                                       size_t token_len, uint64_t packet_number,
                                       size_t packet_number_len, const uint8_t *payload,
                                       size_t payload_len) {
  return long_header_encode(w, type, version, destination_connection_id,
                            destination_connection_id_len, source_connection_id,
                            source_connection_id_len, token, token_len, packet_number,
                            packet_number_len, payload, payload_len, 1);
}

wt_status_t wt_quic_long_header_encode_prefix(
    wt_writer_t *w, wt_quic_packet_type_t type, uint32_t version,
    const uint8_t *destination_connection_id, size_t destination_connection_id_len,
    const uint8_t *source_connection_id, size_t source_connection_id_len, const uint8_t *token,
    size_t token_len, uint64_t packet_number, size_t packet_number_len, size_t payload_len) {
  return long_header_encode(w, type, version, destination_connection_id,
                            destination_connection_id_len, source_connection_id,
                            source_connection_id_len, token, token_len, packet_number,
                            packet_number_len, NULL, payload_len, 0);
}

wt_status_t wt_quic_short_header_encode(wt_writer_t *w, const uint8_t *destination_connection_id,
                                        size_t destination_connection_id_len,
                                        uint64_t packet_number, size_t packet_number_len,
                                        int key_phase, int spin, const uint8_t *payload,
                                        size_t payload_len) {
  uint8_t first;
  uint8_t packet_number_bytes[4];

  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (destination_connection_id_len != 0U && destination_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (packet_number_len == 0U || packet_number_len > 4U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (payload_len != 0U && payload == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (wt_quic_packet_number_encode(packet_number, packet_number_len, packet_number_bytes) !=
      packet_number_len) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  first = (uint8_t)(WT_QUIC_FIXED_BIT | (uint8_t)(packet_number_len - 1U));
  if (spin) first |= WT_QUIC_SPIN_BIT;
  if (key_phase) first |= WT_QUIC_KEY_PHASE_BIT;
  wt_writer_u8(w, first);
  wt_writer_bytes(w, destination_connection_id, destination_connection_id_len);
  wt_writer_bytes(w, packet_number_bytes, packet_number_len);
  wt_writer_bytes(w, payload, payload_len);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_quic_retry_packet_encode(wt_writer_t *w, uint32_t version,
                                        const uint8_t *destination_connection_id,
                                        size_t destination_connection_id_len,
                                        const uint8_t *source_connection_id,
                                        size_t source_connection_id_len, const uint8_t *token,
                                        size_t token_len, const uint8_t integrity_tag[16]) {
  if (w == NULL || integrity_tag == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (destination_connection_id_len > WT_QUIC_MAX_CID_LEN ||
      source_connection_id_len > WT_QUIC_MAX_CID_LEN) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The same argument guards as the long header encoder: a non-zero length with a NULL pointer is a caller
   * error, and `wt_writer_bytes` would dereference it (WT-239). A zero-length field ignores its pointer. */
  if (destination_connection_id_len != 0U && destination_connection_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (token_len != 0U && token == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (source_connection_id_len == 0U || source_connection_id == NULL) {
    /* RFC 9000 section 17.2.5: the Source Connection ID in a Retry is the one the
     * server chose, and a server that has not chosen one cannot retry. */
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* RFC 9000 section 17.2.5 gives a Retry an `Unused (4)` field where the protected types put their reserved
   * bits and packet number length. Its value is arbitrary, so this encoder writes zero -- the same choice the
   * RFC's own A.4 example does not make (it writes 0xf), which is why the decoder must ignore the field. */
  wt_writer_u8(w, (uint8_t)(WT_QUIC_LONG_HEADER_BIT | WT_QUIC_FIXED_BIT |
                            ((uint8_t)WT_QUIC_PACKET_RETRY << 4)));
  wt_writer_u32(w, version);
  wt_quic_write_connection_id(w, destination_connection_id, destination_connection_id_len);
  wt_quic_write_connection_id(w, source_connection_id, source_connection_id_len);
  wt_writer_bytes(w, token, token_len);
  wt_writer_bytes(w, integrity_tag, WT_QUIC_RETRY_INTEGRITY_TAG_LEN);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}
