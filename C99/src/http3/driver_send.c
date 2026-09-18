/* Driving an HTTP/3 endpoint from a connection (Phase 9): the outbound half.
 *
 * This is what this endpoint opens and writes: its own control and QPACK streams, a request, a
 * message's field section, a WebTransport data stream with the draft's prefix, the CONNECT whose
 * stream IS the session, and a datagram. The saved request is also what a probe timeout resends. */

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/http3/driver.h"

#include "webtransport/webtransport/error.h"

#include "webtransport/cursor.h"
#include <string.h>

#include "webtransport/quic/stream.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

#include "driver_internal.h"

/* ---------------------------------------------- sending through a transport */

wt_status_t wt_http3_driver_start_own_streams(wt_http3_driver_t *driver,
                                              const wt_http3_driver_transport_t *transport,
                                              const wt_http3_settings_t *settings, uint64_t now) {
  uint64_t stream_id = 0U;
  wt_writer_t w;
  size_t length;
  wt_status_t status;
  int i;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || transport->send_stream == NULL || settings == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* Each stream is BUILT before it is opened, and that order is deliberate: the once-per-
   * connection rules are applied while the bytes are built, so a second call refuses without
   * opening a stream it would then have nothing to send on. An orphaned stream is a stream the
   * peer sees and this endpoint cannot explain.
   *
   * The frame goes into the first half of the scratch and its payload into the second, so the
   * two cannot overlap while a payload is smaller than half the buffer -- which the SETTINGS
   * encoder's own bound enforces. */
  w = wt_writer_init(driver->scratch, sizeof(driver->scratch) / 2U);
  status = wt_http3_driver_start_control(driver, settings,
                                         driver->scratch + sizeof(driver->scratch) / 2U,
                                         sizeof(driver->scratch) / 2U, &w);
  if (status != WT_OK) return status;
  length = wt_writer_offset(&w);
  status = transport->open_stream(transport->context, 0, &stream_id, now);
  if (status != WT_OK) return status;
  status = transport->send_stream(transport->context, stream_id, driver->scratch, length, 0, now);
  if (status != WT_OK) return status;

  /* The two QPACK streams: their prefixes alone, since what follows on them is the QPACK
   * layer's to write. */
  for (i = 0; i < 2; i++) {
    w = wt_writer_init(driver->scratch, sizeof(driver->scratch) / 2U);
    status = wt_http3_driver_start_qpack_stream(driver, i == 0 ? 1 : 0, &w);
    if (status != WT_OK) return status;
    length = wt_writer_offset(&w);
    status = transport->open_stream(transport->context, 0, &stream_id, now);
    if (status != WT_OK) return status;
    status = transport->send_stream(transport->context, stream_id, driver->scratch, length, 0, now);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}

wt_status_t wt_http3_driver_open_request(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport, uint64_t now,
                                         uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || out_stream_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* A request stream is BIDIRECTIONAL and this endpoint initiates it: HTTP/3 has no server-initiated
   * request, which the endpoint's own rule also enforces. */
  status = transport->open_stream(transport->context, 1, &stream_id, now);
  if (status != WT_OK) return status;
  status = wt_http3_endpoint_open_request(driver->endpoint, stream_id, out_error);
  if (status != WT_OK) return status;
  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_message(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport,
                                         uint64_t stream_id, const wt_http3_message_t *message,
                                         uint64_t peer_max_entries, int fin, uint64_t now) {
  wt_writer_t w;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The section is measured into its own buffer and the frame written into `scratch`: writing the frame over the
   * bytes the section was measured into is an overlapping `memcpy` (the writer moves the section down by the
   * frame header's length inside the same buffer), which is undefined behaviour and was ASan's
   * `memcpy-param-overlap` in an audit. */
  w = wt_writer_init(driver->scratch, sizeof(driver->scratch));
  status = wt_http3_endpoint_write_headers(driver->endpoint, message, peer_max_entries,
                                           driver->section, sizeof(driver->section), &w, NULL);
  if (status != WT_OK) return status;
  /* Retained on the way out: a probe timeout may have to send these very bytes again (WT-135). */
  driver->request_stream_id = stream_id;
  driver->request_length = wt_writer_offset(&w);
  driver->request_retained = 1;
  return transport->send_stream(transport->context, stream_id, driver->scratch,
                                wt_writer_offset(&w), fin, now);
}

wt_status_t wt_http3_driver_open_data_stream(wt_http3_driver_t *driver,
                                             const wt_http3_driver_transport_t *transport,
                                             int unidirectional, const uint8_t *data, size_t length,
                                             int fin, uint64_t now, uint64_t *out_stream_id) {
  uint8_t framed[WT_HTTP3_DRIVER_PREFIX_MAX + WT_HTTP3_DRIVER_SCRATCH];
  wt_writer_t w = wt_writer_init(framed, sizeof(framed));
  uint64_t stream_id = 0U;
  size_t prefix_length = 0U;
  wt_status_t status;

  if (driver == NULL || driver->endpoint == NULL || transport == NULL ||
      transport->open_stream == NULL || transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (length > (size_t)WT_HTTP3_DRIVER_SCRATCH) return WT_ERR_LIMIT;
  /* The session must be known before a stream names it: a prefix that names no session is one the peer has to
   * refuse, which is a worse outcome than saying so here. */
  if (driver->session_id_set == 0) return WT_ERR_STATE;
  /* Section 6: an endpoint that has learned its session is over "MUST NOT send any new datagrams or open any new
   * streams", so a data stream after that point is refused by name rather than sent into a session nobody has. */
  if (driver->session_ended != 0) return WT_ERR_STATE;
  if (driver->data_stream_count >= WT_HTTP3_DRIVER_DATA_STREAMS_MAX) return WT_ERR_LIMIT;

  if (wt_webtransport_stream_prefix_write(&w, unidirectional, driver->session_id) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  /* Where the prefix ended, taken HERE rather than recomputed: it is the offset before the payload is written,
   * and it is what a later reset of this stream has to commit to (section 4.4). */
  prefix_length = wt_writer_offset(&w);
  wt_writer_bytes(&w, data, length);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;

  /* Opened before the prefix is written, because which class of stream the ID is comes from the transport and
   * the prefix's type has to agree with it. */
  status = transport->open_stream(transport->context, unidirectional ? 0 : 1, &stream_id, now);
  if (status != WT_OK) return status;
  if (wt_quic_stream_id_is_bidirectional(stream_id) != (unidirectional ? 0 : 1)) {
    /* The transport handed back a stream of the other class, so this prefix would describe the wrong thing. */
    return WT_ERR_STATE;
  }

  status =
      transport->send_stream(transport->context, stream_id, framed, wt_writer_offset(&w), fin, now);
  if (status != WT_OK) return status;

  /* Remembered only once the bytes are away: an owner that has not sent anything yet would make the receive
   * path treat the stream as this endpoint's data stream while the peer has no reason to know it exists. The
   * prefix length recorded is the one THIS endpoint wrote, which is what a reset has to commit to. */
  status = remember_data_stream(driver, stream_id, (uint64_t)prefix_length, driver->session_id,
                                driver->session_id_set);
  if (status != WT_OK) return status;
  if (out_stream_id != NULL) *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_resend_request(wt_http3_driver_t *driver,
                                           const wt_http3_driver_transport_t *transport,
                                           uint64_t now) {
  if (driver == NULL || transport == NULL || transport->send_stream == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (driver->request_retained == 0 || driver->request_length == 0U) return WT_ERR_STATE;
  return transport->send_stream(transport->context, driver->request_stream_id, driver->scratch,
                                driver->request_length, 0, now);
}

wt_status_t wt_http3_driver_classify_bidi_start(const uint8_t *bytes, size_t length,
                                                wt_http3_bidi_start_kind_t *out_kind,
                                                uint64_t *out_session_id, size_t *out_consumed) {
  wt_cursor_t cursor;
  uint64_t type = 0U;
  uint64_t session_id = 0U;
  size_t type_bytes;
  size_t session_bytes;

  if (out_kind == NULL || out_session_id == NULL || out_consumed == NULL)
    return WT_ERR_INVALID_ARGUMENT;
  *out_kind = WT_HTTP3_BIDI_START_REQUEST;
  *out_session_id = 0U;
  *out_consumed = 0U;
  if (bytes == NULL) return length == 0U ? WT_OK : WT_ERR_INVALID_ARGUMENT;

  cursor = wt_cursor_init(bytes, length);
  if (wt_quic_varint_decode(&cursor, &type) != WT_OK) {
    /* Not even the type has arrived. On a stream that is a wait: the caller comes back with more bytes. */
    return WT_ERR_TRUNCATED;
  }
  if (type != WT_WEBTRANSPORT_STREAM_BIDI) {
    /* An HTTP/3 request stream, and the type varint it "has" is really the first byte of a QPACK prefix. */
    return WT_OK;
  }
  type_bytes = length - wt_cursor_remaining(&cursor);
  if (wt_quic_varint_decode(&cursor, &session_id) != WT_OK) return WT_ERR_TRUNCATED;
  session_bytes = (length - type_bytes) - wt_cursor_remaining(&cursor);
  *out_kind = WT_HTTP3_BIDI_START_WEBTRANSPORT;
  *out_session_id = session_id;
  *out_consumed = type_bytes + session_bytes;
  return WT_OK;
}

wt_status_t wt_http3_driver_open_session_stream(wt_http3_driver_t *driver,
                                                const wt_http3_driver_transport_t *transport,
                                                const wt_http3_settings_t *settings, uint64_t now,
                                                uint64_t *out_stream_id,
                                                wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL || settings == NULL ||
      out_stream_id == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The endpoint's own streams first: a CONNECT cannot be interpreted by a peer that has not been told what
   * this endpoint's SETTINGS say, and the QPACK streams are what any field section may reference. */
  status = wt_http3_driver_start_own_streams(driver, transport, settings, now);
  if (status != WT_OK) return status;

  status = wt_http3_driver_open_request(driver, transport, now, &stream_id, out_error);
  if (status != WT_OK) return status;
  /* The session IS the request stream (draft-16 section 3.2: "Session IDs are derived from the stream ID of the
   * CONNECT stream"), so this is where the driver learns which session it serves -- and a prefix it writes or
   * reads names this stream's ID. Nothing else sets it, which is why a data stream had no session to name. */
  wt_http3_driver_set_session_id(driver, stream_id);
  /* And it is a WebTransport CONNECT stream from here on: the RESPONSE is the one HTTP/3 frame still to come on
   * it, and everything the server sends after that is a capsule on this session (WT-164). Marked BEFORE the
   * request goes out, because the answer can arrive in the very next packet and a mark made after sending would
   * race it. */
  status = wt_http3_driver_mark_capsule_stream(driver, stream_id, 1);
  if (status != WT_OK) return status;

  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_session_request(wt_http3_driver_t *driver,
                                                 const wt_http3_driver_transport_t *transport,
                                                 uint64_t stream_id, const char *authority,
                                                 const char *path, uint64_t peer_max_entries,
                                                 uint64_t now, wt_http3_error_t *out_error) {
  wt_http3_message_t request;
  const char *token;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (driver == NULL || driver->endpoint == NULL || transport == NULL || authority == NULL ||
      path == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  /* The extended CONNECT of draft-16 section 3.1, as the fields the request line needs: CONNECT with a
   * :protocol, over https, for the authority and path the caller named. */
  memset(&request, 0, sizeof(request));
  request.type = WT_HTTP3_HEADER_REQUEST;
  request.method = (const uint8_t *)"CONNECT";
  request.method_length = 7U;
  request.scheme = (const uint8_t *)"https";
  request.scheme_length = 5U;
  request.authority = (const uint8_t *)authority;
  request.authority_length = strlen(authority);
  request.path = (const uint8_t *)path;
  request.path_length = strlen(path);
  /* The token is this endpoint's choice, not a constant: draft-16 section 3.2 names `webtransport-h3` and that
   * is the default, while a peer that predates the rename needs the pre-draft `webtransport` and gets it only
   * when the caller selected it (see `wt_http3_driver_set_upgrade_token`). */
  token = wt_webtransport_upgrade_token_value(driver->upgrade_token);
  request.protocol = (const uint8_t *)token;
  request.protocol_length = strlen(token);

  return wt_http3_driver_send_message(driver, transport, stream_id, &request, peer_max_entries, 0,
                                      now);
}

wt_status_t wt_http3_driver_start_session(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const wt_http3_settings_t *settings,
                                          const char *authority, const char *path,
                                          uint64_t peer_max_entries, uint64_t now,
                                          uint64_t *out_stream_id, wt_http3_error_t *out_error) {
  uint64_t stream_id = 0U;
  wt_status_t status;

  if (out_stream_id == NULL) return WT_ERR_INVALID_ARGUMENT;
  status =
      wt_http3_driver_open_session_stream(driver, transport, settings, now, &stream_id, out_error);
  if (status != WT_OK) return status;
  status = wt_http3_driver_send_session_request(driver, transport, stream_id, authority, path,
                                                peer_max_entries, now, out_error);
  if (status != WT_OK) return status;
  *out_stream_id = stream_id;
  return WT_OK;
}

wt_status_t wt_http3_driver_send_response(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          uint64_t stream_id, uint32_t status,
                                          uint64_t peer_max_entries, int fin, uint64_t now) {
  wt_http3_message_t response;

  if (driver == NULL || driver->endpoint == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The request stream this answers IS the session (draft-16 section 3.2), so answering it is also the moment
   * this endpoint knows which session its own streams and prefixes name. */
  wt_http3_driver_set_session_id(driver, stream_id);
  memset(&response, 0, sizeof(response));
  response.type = WT_HTTP3_HEADER_RESPONSE;
  response.status = (uint64_t)status;
  response.has_status = 1;
  return wt_http3_driver_send_message(driver, transport, stream_id, &response, peer_max_entries,
                                      fin, now);
}

wt_status_t wt_http3_driver_send_datagram(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const uint8_t *data, size_t length) {
  if (driver == NULL || transport == NULL || transport->send_datagram == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* Section 6's other MUST NOT: a datagram is not sent into a session that is over. */
  if (driver->session_ended != 0) return WT_ERR_STATE;
  return transport->send_datagram(transport->context, data, length);
}
