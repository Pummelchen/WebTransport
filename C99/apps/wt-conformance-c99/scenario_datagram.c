/* The interop matrix scenarios (Phase 10). */

#include "scenario_matrix.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/api/flow.h"
#include "webtransport/api/session.h"
#include "webtransport/cursor.h"
#include "webtransport/http3/control.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/endpoint.h"
#include "webtransport/http3/goaway.h"
#include "webtransport/http3/role.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/writer.h"

#include "webtransport/http3/frame.h"

#include "webtransport/quic/datagram.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/webtransport/session_request.h"

#include "scenario_matrix_support.h"

static size_t write_datagram_payload(uint8_t *out, size_t capacity, uint64_t quarter,
                                     const char *payload) {
  wt_writer_t w = wt_writer_init(out, capacity);
  size_t length = strlen(payload);
  if (wt_webtransport_datagram_write(&w, quarter, (const uint8_t *)payload, length) != WT_OK)
    return 0U;
  return wt_writer_offset(&w);
}

void wt_scenario_datagram_matrix(wt_cli_report_t *report) {
  matrix_row_t rows[WT_MATRIX_MAX_CASES];
  unsigned count = 0U;
  uint8_t framed[64];
  size_t framed_length = 0U;

  /* A datagram in each direction. The framing is symmetric -- the quarter stream id is the sender's session,
   * whichever end sent it -- and the payload is whatever follows it. */
  {
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok =
        (framed_length = write_datagram_payload(framed, sizeof(framed), 1U, "client-dgram")) > 0U &&
        wt_webtransport_datagram_parse(framed, framed_length, &quarter, &payload, &payload_length,
                                       &error) == WT_OK &&
        quarter == 1U && payload_length == 12U && memcmp(payload, "client-dgram", 12U) == 0;
    rows[count].name = "a client datagram carries its quarter id and payload";
    rows[count].held = ok;
    count++;
  }
  {
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok =
        (framed_length = write_datagram_payload(framed, sizeof(framed), 0U, "server-dgram")) > 0U &&
        wt_webtransport_datagram_parse(framed, framed_length, &quarter, &payload, &payload_length,
                                       &error) == WT_OK &&
        quarter == 0U && payload_length == 12U && memcmp(payload, "server-dgram", 12U) == 0;
    rows[count].name = "a server datagram carries its quarter id and payload";
    rows[count].held = ok;
    count++;
  }

  /* The mapping a receiver routes with, in both directions. */
  {
    int ok = wt_webtransport_session_id_from_quarter(1U) == 4U &&
             wt_webtransport_quarter_stream_id(4U) == 1U;
    rows[count].name = "a quarter id and a session id name each other";
    rows[count].held = ok;
    count++;
  }

  /* A datagram is a WHOLE unit, so these two are malformed rather than early: on a stream the same bytes
   * would be a wait, which is the difference the packet layer's rule makes. */
  {
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_datagram_parse(framed, 0U, NULL, NULL, NULL, &error) != WT_OK &&
             error == WT_HTTP3_DATAGRAM_ERROR;
    rows[count].name = "an empty datagram is malformed";
    rows[count].held = ok;
    count++;
  }
  {
    static const uint8_t partial[] = {0xffU};
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_datagram_parse(partial, sizeof(partial), NULL, NULL, NULL, &error) !=
                 WT_OK &&
             error == WT_HTTP3_DATAGRAM_ERROR;
    rows[count].name = "a quarter id that did not all arrive is malformed";
    rows[count].held = ok;
    count++;
  }

  /* A datagram for a session this endpoint does not have: the framing is fine and the owner is nobody, so it
   * is dropped rather than handed to a neighbour. */
  {
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    uint64_t quarter = 0U;
    uint64_t owner = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = (framed_length = write_datagram_payload(framed, sizeof(framed), 2U, "unknown")) > 0U &&
             wt_webtransport_datagram_parse(framed, framed_length, &quarter, &payload,
                                            &payload_length, &error) == WT_OK;
    owner = wt_webtransport_session_id_from_quarter(quarter);
    ok = ok && owner != 0U && owner != 4U;
    rows[count].name = "a datagram naming a session that is not here has no owner";
    rows[count].held = ok;
    count++;
  }

  /* The send-side bound: a peer that accepts no datagrams gets no payload, a packet with no room gets none, and
   * the payload that IS returned is the largest that fits BOTH bounds -- asserted by re-deriving the definition
   * rather than by restating the arithmetic. */
  {
    int ok = wt_quic_datagram_max_payload(0U, 1200U, 30U) == 0U &&
             wt_quic_datagram_max_payload(1200U, 30U, 30U) == 0U;
    rows[count].name = "no payload fits a peer that accepts none, or a packet with no room";
    rows[count].held = ok;
    count++;
  }
  {
    static const uint64_t limits[3] = {1200U, 100U, 20U};
    unsigned index;
    int ok = 1;
    for (index = 0U; index < 3U; index++) {
      const uint64_t packet_size = 1200U;
      const uint64_t overhead = 30U;
      uint64_t room = packet_size - overhead;
      uint64_t payload = wt_quic_datagram_max_payload(limits[index], packet_size, overhead);
      uint64_t bigger;
      if (payload == 0U || payload > room) {
        ok = 0;
        break;
      }
      if (1U + (uint64_t)wt_quic_varint_size(payload) + payload > limits[index]) {
        ok = 0;
        break;
      }
      bigger = payload + 1U;
      if (bigger <= room && 1U + (uint64_t)wt_quic_varint_size(bigger) + bigger <= limits[index]) {
        ok = 0;
        break;
      }
    }
    rows[count].name = "the payload bound is the largest that fits the frame and the packet";
    rows[count].held = ok;
    count++;
  }

  report_matrix(report, "interop-datagram-matrix", "datagram interop cases", rows, count);
}
