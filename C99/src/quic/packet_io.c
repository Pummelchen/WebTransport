/* One packet out, one packet in. See webtransport/quic/packet_io.h. */

#include "webtransport/quic/packet_io.h"

#include <string.h>

#include "webtransport/quic/packet_number.h"
#include "webtransport/writer.h"

wt_status_t wt_quic_packet_build(const wt_quic_packet_build_t *params, uint8_t *out,
                                 size_t capacity, size_t *out_len) {
  wt_writer_t w;
  size_t header_len;
  size_t ciphertext_len;
  wt_status_t status;

  if (params == NULL || out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  if (params->keys == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (params->payload == NULL && params->payload_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->packet_number_length == 0U || params->packet_number_length > 4U) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The ciphertext is the payload plus the tag, and its length is what the Length field covers. */
  if (params->payload_len > SIZE_MAX - WT_AEAD_TAG_LEN) return WT_ERR_OVERFLOW;
  ciphertext_len = params->payload_len + WT_AEAD_TAG_LEN;
  if (capacity < ciphertext_len) return WT_ERR_LIMIT;

  /* The header first: the AEAD authenticates it. */
  w = wt_writer_init(out, capacity);
  if (params->short_header) {
    if (params->source_connection_id_len != 0U || params->token_len != 0U) {
      /* Neither field exists in a short header, so a caller that set one is asking for a packet that
       * cannot be encoded rather than one that will be wrong. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    status = wt_quic_short_header_encode(&w, params->destination_connection_id,
                                        params->destination_connection_id_len,
                                        params->packet_number,
                                        params->packet_number_length, params->key_phase,
                                        0, NULL, 0U);
  } else {
    status = wt_quic_long_header_encode_prefix(
        &w, params->type, params->version, params->destination_connection_id,
        params->destination_connection_id_len, params->source_connection_id,
        params->source_connection_id_len, params->token, params->token_len,
        params->packet_number, params->packet_number_length, ciphertext_len);
  }
  if (status != WT_OK) return status;
  header_len = wt_writer_offset(&w);
  if (capacity - header_len < ciphertext_len) return WT_ERR_LIMIT;

  /* The payload, sealed with the header as associated data. */
  status = wt_quic_protect_frames(params->keys, params->packet_number, out, header_len,
                                  params->payload, params->payload_len, out + header_len,
                                  capacity - header_len, &ciphertext_len);
  if (status != WT_OK) {
    memset(out, 0, header_len);
    return status;
  }

  /* Header protection last, because its sample comes from the ciphertext. */
  status = wt_quic_protect_header(params->keys->aead, params->keys->hp, params->keys->hp_len,
                                  out, header_len + ciphertext_len,
                                  header_len - params->packet_number_length,
                                  params->packet_number_length);
  if (status != WT_OK) {
    memset(out, 0, header_len + ciphertext_len);
    return status;
  }
  *out_len = header_len + ciphertext_len;
  return WT_OK;
}

wt_status_t wt_quic_packet_read(uint8_t *packet, size_t length,
                                const wt_quic_packet_keys_t *keys,
                                uint64_t largest_received,
                                size_t local_connection_id_len,
                                wt_quic_received_packet_t *out) {
  size_t pn_offset = 0U;
  size_t total_len = 0U;
  size_t pn_len = 0U;
  int short_header = 0;
  wt_status_t status;

  if (packet == NULL || keys == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  /* The packet number's offset cannot come from a decoder: the number's own length is behind the mask.
   * It comes from the layout, and with it the length of the packet -- which for a long header is the
   * Length field's and not the datagram's, because a datagram may hold several packets. */
  status = wt_quic_protected_pn_offset(packet, length, local_connection_id_len, &pn_offset,
                                       &total_len, &short_header);
  if (status != WT_OK) return status;

  /* Header protection first: its sample is the ciphertext, and the packet number length it reveals is
   * what the rest of this function is measured against. */
  status = wt_quic_unprotect_header(keys->aead, keys->hp, keys->hp_len, packet, total_len,
                                    pn_offset, &pn_len);
  if (status != WT_OK) return status;

  /* Parsed again now that the mask is off: the first byte's low bits are the real packet number
   * length, so the header's own lengths are now the ones the sender wrote. */
  {
    wt_cursor_t cursor = wt_cursor_init(packet, total_len);
    wt_quic_error_t error;
    uint64_t truncated;
    size_t header_len;
    const uint8_t *payload;
    size_t payload_len;

    if (short_header) {
      wt_quic_short_header_t header;
      status = wt_quic_short_header_decode(&cursor, local_connection_id_len, &header, &error);
      if (status != WT_OK) return status;
      /* `type` is left zeroed: a short header does not carry one, and which space it belongs to is
       * what the keys the caller chose say. */
      out->key_phase = header.key_phase;
      out->destination_connection_id = header.destination_connection_id;
      out->destination_connection_id_len = header.destination_connection_id_len;
      header_len = header.header_len;
      payload = header.payload;
      payload_len = header.payload_len;
      truncated = header.packet_number;
      out->packet_number_length = header.packet_number_len;
    } else {
      wt_quic_long_header_t header;
      status = wt_quic_long_header_decode(&cursor, &header, &error);
      if (status != WT_OK) return status;
      out->type = header.type;
      out->version = header.version;
      out->destination_connection_id = header.destination_connection_id;
      out->destination_connection_id_len = header.destination_connection_id_len;
      out->source_connection_id = header.source_connection_id;
      out->source_connection_id_len = header.source_connection_id_len;
      header_len = header.header_len;
      payload = header.payload;
      payload_len = header.payload_len;
      truncated = header.packet_number;
      out->packet_number_length = header.packet_number_len;
    }
    /* The packet number is the truncated one against the largest this endpoint has seen, and it is
     * read after the mask is off -- which is the whole reason the order here is what it is. */
    out->packet_number = wt_quic_packet_number_decode(truncated, out->packet_number_length,
                                                      largest_received);
    out->header_len = header_len;
    out->short_header = short_header;
    out->total_len = total_len;
    if (payload_len < WT_AEAD_TAG_LEN) return WT_ERR_TRUNCATED;
    /* The payload, authenticated with the header through the packet number as associated data. */
    status = wt_quic_unprotect_frames(keys, out->packet_number, packet, header_len, packet + header_len,
                                      payload_len - WT_AEAD_TAG_LEN,
                                      payload + payload_len - WT_AEAD_TAG_LEN);
    if (status != WT_OK) return status;
    out->payload = packet + header_len;
    out->payload_len = payload_len - WT_AEAD_TAG_LEN;
  }
  return WT_OK;
}
