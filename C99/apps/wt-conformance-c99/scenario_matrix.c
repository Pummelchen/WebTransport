/* The interop matrix scenarios (Phase 10). */

#include "scenario_matrix.h"

#include <stdio.h>
#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/goaway.h"
#include "webtransport/http3/role.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/writer.h"

#include "webtransport/http3/frame.h"

#include "webtransport/quic/datagram.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/quic/varint.h"

#define WT_MATRIX_MAX_CASES 12U

/* One row of a matrix: what the case is, and whether it held. */
typedef struct matrix_row {
  const char *name;
  int held;
} matrix_row_t;

static void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED, detail);
}

/* Write one row and, at the end, the count. EVERY failing row is named, because "eleven of thirteen" is not
 * a debugging aid on its own. */
static void report_matrix(wt_cli_report_t *report, const char *scenario, const char *noun,
                          const matrix_row_t *rows, unsigned count) {
  char detail[256];
  unsigned index;
  unsigned failed = 0U;

  for (index = 0U; index < count; index++) {
    if (rows[index].held == 0) failed++;
  }
  if (failed == 0U) {
    (void)snprintf(detail, sizeof(detail), "%u of %u %s hold", count, count, noun);
  } else {
    int used = snprintf(detail, sizeof(detail), "%u of %u cases failed:", failed, count);
    for (index = 0U; index < count; index++) {
      if (rows[index].held == 0 && used > 0 && (size_t)used < sizeof(detail)) {
        used += snprintf(detail + used, sizeof(detail) - (size_t)used, " \"%s\"", rows[index].name);
      }
    }
  }
  add(report, scenario, failed == 0U, detail);
}

void wt_scenario_matrix_run(wt_cli_report_t *report) {
  matrix_row_t rows[WT_MATRIX_MAX_CASES];
  unsigned count = 0U;
  uint8_t prefix[16];
  uint8_t classified_bytes[16];
  size_t prefix_length = 0U;
  size_t classified_length = 0U;

  /* The bytes a peer would send for a bidirectional prefix, written by the encoder rather than transcribed,
   * so every case below that classifies them is classifying what this library produces. */
  {
    wt_writer_t w = wt_writer_init(prefix, sizeof(prefix));
    if (wt_webtransport_stream_prefix_write(&w, 0, 4U) == WT_OK) {
      prefix_length = wt_writer_offset(&w);
      memcpy(classified_bytes, prefix, prefix_length);
      classified_length = prefix_length;
    }
  }

  /* A bidirectional prefix: written, then read back with its direction and its session. */
  {
    wt_writer_t w = wt_writer_init(prefix, sizeof(prefix));
    wt_cursor_t c;
    int direction = -1;
    uint64_t session_id = 0U;
    int ok = wt_webtransport_stream_prefix_write(&w, 0, 4U) == WT_OK;
    c = wt_cursor_init(prefix, wt_writer_offset(&w));
    ok = ok && wt_webtransport_stream_prefix_parse(&c, &direction, &session_id, NULL) == WT_OK &&
         direction == 0 && session_id == 4U && wt_cursor_at_end(&c) != 0;
    rows[count].name = "a bidirectional prefix round-trips";
    rows[count].held = ok;
    count++;
  }

  /* A unidirectional prefix, the same way: the two types carry different rules, so the flag is the assertion. */
  {
    wt_writer_t w = wt_writer_init(prefix, sizeof(prefix));
    wt_cursor_t c;
    int direction = -1;
    uint64_t session_id = 0U;
    int ok = wt_webtransport_stream_prefix_write(&w, 1, 4U) == WT_OK;
    c = wt_cursor_init(prefix, wt_writer_offset(&w));
    ok = ok && wt_webtransport_stream_prefix_parse(&c, &direction, &session_id, NULL) == WT_OK &&
         direction == 1 && session_id == 4U;
    rows[count].name = "a unidirectional prefix round-trips";
    rows[count].held = ok;
    count++;
  }

  /* A caller asking for a session that cannot exist is a bug rather than a peer, and the write must leave
   * nothing behind: half a prefix in a buffer is a stream this endpoint would then send as something else. */
  {
    wt_writer_t w = wt_writer_init(prefix, sizeof(prefix));
    int ok = wt_webtransport_stream_prefix_write(&w, 1, 2U) != WT_OK && wt_writer_offset(&w) == 0U;
    rows[count].name = "a prefix for a stream that cannot be a session is refused and writes nothing";
    rows[count].held = ok;
    count++;
  }

  /* The PEER's side of the same rule: a prefix naming a stream that cannot be a session is H3_ID_ERROR, and a
   * prefix whose type is not a WebTransport one is H3_FRAME_UNEXPECTED.
   *
   * The bytes are the encoder's, with ONE byte changed -- the session -- rather than written out by hand. The
   * type and the session are varints, and the two-byte form's first byte is easy to get wrong: 0x41 is a
   * two-byte form's PREFIX, so a hand-written {0x41, 0x02} is the single varint 258, not the type 0x41 followed
   * by the session 2. That mistake is what the first version of this matrix made. */
  {
    wt_writer_t w = wt_writer_init(prefix, sizeof(prefix));
    wt_cursor_t c;
    int direction = -1;
    uint64_t session_id = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_stream_prefix_write(&w, 0, 4U) == WT_OK && wt_writer_offset(&w) > 0U;
    if (ok) {
      prefix[wt_writer_offset(&w) - 1U] = 0x02U; /* session 2: a client-initiated UNIDIRECTIONAL stream */
      c = wt_cursor_init(prefix, wt_writer_offset(&w));
      ok = wt_webtransport_stream_prefix_parse(&c, &direction, &session_id, &error) != WT_OK &&
           error == WT_HTTP3_ID_ERROR;
    }
    rows[count].name = "a peer prefix naming a non-session is H3_ID_ERROR";
    rows[count].held = ok;
    count++;
  }
  {
    static const uint8_t other_type[] = {0x00U, 0x04U};
    wt_cursor_t c = wt_cursor_init(other_type, sizeof(other_type));
    int direction = -1;
    uint64_t session_id = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_stream_prefix_parse(&c, &direction, &session_id, &error) != WT_OK &&
             error == WT_HTTP3_FRAME_UNEXPECTED;
    rows[count].name = "a peer prefix of another stream type is H3_FRAME_UNEXPECTED";
    rows[count].held = ok;
    count++;
  }

  /* Incomplete is a wait on a stream, never a refusal: the rest may be in the next packet. */
  {
    static const uint8_t half[] = {0x41U};
    wt_cursor_t c = wt_cursor_init(half, sizeof(half));
    int direction = -1;
    uint64_t session_id = 0U;
    int ok = wt_webtransport_stream_prefix_parse(&c, &direction, &session_id, NULL) == WT_ERR_TRUNCATED;
    rows[count].name = "half a prefix is a wait rather than a refusal";
    rows[count].held = ok;
    count++;
  }

  /* The classifier the driver routes with, on the bytes the encoder just wrote: the session it names and the
   * number of bytes it consumed are both part of the answer, because the payload starts after them. */
  {
    wt_http3_bidi_start_kind_t kind = WT_HTTP3_BIDI_START_REQUEST;
    uint64_t session_id = 0U;
    size_t consumed = 0U;
    int ok = classified_length > 0U &&
             wt_http3_driver_classify_bidi_start(classified_bytes, classified_length, &kind, &session_id,
                                                 &consumed) == WT_OK &&
             kind == WT_HTTP3_BIDI_START_WEBTRANSPORT && session_id == 4U && consumed == classified_length;
    rows[count].name = "a WebTransport start is classified with its session and its length";
    rows[count].held = ok;
    count++;
  }

  /* An HTTP/3 request stream's first bytes are not a WebTransport prefix, and the classifier is what decides
   * that: type 0x00 is the control stream's, not the draft's. */
  {
    static const uint8_t request_start[] = {0x00U, 0x04U, 0x80U};
    wt_http3_bidi_start_kind_t kind = WT_HTTP3_BIDI_START_WEBTRANSPORT;
    uint64_t session_id = 0U;
    size_t consumed = 0U;
    int ok = wt_http3_driver_classify_bidi_start(request_start, sizeof(request_start), &kind, &session_id,
                                                 &consumed) == WT_OK &&
             kind == WT_HTTP3_BIDI_START_REQUEST && consumed == 0U;
    rows[count].name = "a request start is not classified as WebTransport";
    rows[count].held = ok;
    count++;
  }

  /* The two waits: the type alone, and a session id whose varint is only half arrived. */
  {
    static const uint8_t type_only[] = {0x41U};
    wt_http3_bidi_start_kind_t kind = WT_HTTP3_BIDI_START_WEBTRANSPORT;
    uint64_t session_id = 0U;
    size_t consumed = 0U;
    int ok = wt_http3_driver_classify_bidi_start(type_only, sizeof(type_only), &kind, &session_id, &consumed) ==
             WT_ERR_TRUNCATED;
    rows[count].name = "the type byte alone decides nothing yet";
    rows[count].held = ok;
    count++;
  }
  {
    /* A session whose id needs the two-byte varint form (64), classified with its last byte missing: the
     * encoder measures the prefix, so the case is "one byte short of a real one" rather than a guess. */
    wt_writer_t w = wt_writer_init(prefix, sizeof(prefix));
    wt_http3_bidi_start_kind_t kind = WT_HTTP3_BIDI_START_REQUEST;
    uint64_t session_id = 0U;
    size_t consumed = 0U;
    int ok = wt_webtransport_stream_prefix_write(&w, 0, 64U) == WT_OK && wt_writer_offset(&w) > 1U &&
             wt_http3_driver_classify_bidi_start(prefix, wt_writer_offset(&w) - 1U, &kind, &session_id,
                                                 &consumed) == WT_ERR_TRUNCATED;
    rows[count].name = "a session id split across the boundary is a wait";
    rows[count].held = ok;
    count++;
  }

  /* The predicate every direction test is built on. */
  {
    int ok = wt_webtransport_is_session_stream_id(0U) == 1 && wt_webtransport_is_session_stream_id(4U) == 1 &&
             wt_webtransport_is_session_stream_id(2U) == 0 && wt_webtransport_is_session_stream_id(3U) == 0;
    rows[count].name = "the session predicate is a statement about the stream type";
    rows[count].held = ok;
    count++;
  }

  report_matrix(report, "interop-stream-matrix", "stream interop cases", rows, count);
}

/* One framed datagram, written the way a sender does it. */
static size_t write_datagram_payload(uint8_t *out, size_t capacity, uint64_t quarter, const char *payload) {
  wt_writer_t w = wt_writer_init(out, capacity);
  size_t length = strlen(payload);
  if (wt_webtransport_datagram_write(&w, quarter, (const uint8_t *)payload, length) != WT_OK) return 0U;
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
    int ok = (framed_length = write_datagram_payload(framed, sizeof(framed), 1U, "client-dgram")) > 0U &&
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
    int ok = (framed_length = write_datagram_payload(framed, sizeof(framed), 0U, "server-dgram")) > 0U &&
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
             error == WT_HTTP3_MESSAGE_ERROR;
    rows[count].name = "an empty datagram is malformed";
    rows[count].held = ok;
    count++;
  }
  {
    static const uint8_t partial[] = {0xffU};
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_datagram_parse(partial, sizeof(partial), NULL, NULL, NULL, &error) != WT_OK &&
             error == WT_HTTP3_MESSAGE_ERROR;
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
             wt_webtransport_datagram_parse(framed, framed_length, &quarter, &payload, &payload_length,
                                            &error) == WT_OK;
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

void wt_scenario_goaway_close_drain_matrix(wt_cli_report_t *report) {
  matrix_row_t rows[WT_MATRIX_MAX_CASES];
  unsigned count = 0U;

  /* A GOAWAY gates the streams it names: it says which identifiers the sender will still process, so
   * everything at or above it is refused and everything below it is not. */
  {
    wt_http3_goaway_t goaway;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok;
    wt_http3_goaway_init(&goaway);
    (void)wt_http3_goaway_on_received(&goaway, WT_HTTP3_ROLE_SERVER, 4U, &error);
    ok = wt_http3_goaway_rejects_stream(&goaway, 0U) == 0 && wt_http3_goaway_rejects_stream(&goaway, 4U) == 1 &&
         wt_http3_goaway_rejects_stream(&goaway, 8U) == 1 &&
         wt_http3_goaway_allows_new_requests(&goaway) == 0;
    rows[count].name = "a GOAWAY gates the streams at or above its identifier";
    rows[count].held = ok;
    count++;
  }

  /* A drain, in either direction, is what stops NEW streams: the session is still alive, which is the whole
   * point of a drain rather than a close. */
  {
    wt_webtransport_session_t session;
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    ok = wt_webtransport_session_on_drain(&session, 0) == WT_OK &&
         session.state == WT_WEBTRANSPORT_SESSION_DRAINING &&
         session.drain_received == 1 && wt_webtransport_session_allows_new_streams(&session) == 0;
    rows[count].name = "a received drain stops new streams";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_session_t session;
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    ok = wt_webtransport_session_on_drain(&session, 1) == WT_OK &&
         session.state == WT_WEBTRANSPORT_SESSION_DRAINING && session.drain_sent == 1 &&
         wt_webtransport_session_allows_new_streams(&session) == 0;
    rows[count].name = "a sent drain stops new streams";
    rows[count].held = ok;
    count++;
  }

  /* A drain repeated is not an error -- a peer may send it twice while it is shutting down -- and it does not
   * end the session: the close capsule can still be written afterwards. */
  {
    wt_webtransport_session_t session;
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    ok = wt_webtransport_session_on_drain(&session, 0) == WT_OK &&
         wt_webtransport_session_on_drain(&session, 0) == WT_OK &&
         session.state == WT_WEBTRANSPORT_SESSION_DRAINING;
    rows[count].name = "a repeated drain is accepted and does not close the session";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_session_t session;
    uint8_t bytes[64];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    (void)wt_webtransport_session_on_drain(&session, 0);
    ok = wt_webtransport_session_write_close(&session, &w, 0U, NULL, 0U) == WT_OK;
    rows[count].name = "a draining session can still write its close";
    rows[count].held = ok;
    count++;
  }

  /* The close, and the two rules that go with it: the first code is the session's, and a capsule after the end
   * is a message the peer has no state for. */
  {
    wt_webtransport_session_t session;
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    (void)wt_webtransport_session_on_close(&session, 1, 22U);
    ok = session.state == WT_WEBTRANSPORT_SESSION_CLOSED && session.close_error_set == 1 &&
         session.close_error_code == 22U && wt_webtransport_session_allows_new_streams(&session) == 0;
    rows[count].name = "a close ends the session with its own code";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_session_t session;
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    (void)wt_webtransport_session_on_close(&session, 1, 22U);
    (void)wt_webtransport_session_on_close(&session, 0, 99U);
    ok = session.close_error_code == 22U;
    rows[count].name = "the first close's code is the one the session keeps";
    rows[count].held = ok;
    count++;
  }
  {
    wt_webtransport_session_t session;
    uint8_t bytes[64];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    int ok;
    wt_webtransport_session_init(&session);
    (void)wt_webtransport_session_established(&session);
    (void)wt_webtransport_session_on_close(&session, 1, 22U);
    ok = wt_webtransport_session_write_close(&session, &w, 22U, NULL, 0U) != WT_OK;
    rows[count].name = "a capsule after the end is refused";
    rows[count].held = ok;
    count++;
  }

  /* The capsule itself: the code and the reason a peer reads, which is what a close is FOR. */
  {
    static const uint8_t reason[] = "interop done";
    uint8_t bytes[64];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    wt_cursor_t c;
    wt_webtransport_capsule_t capsule;
    uint32_t code = 0U;
    const uint8_t *read_reason = NULL;
    size_t read_length = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_close_session_write(&w, 22U, reason, sizeof(reason) - 1U) == WT_OK;
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    memset(&capsule, 0, sizeof(capsule));
    ok = ok && wt_webtransport_capsule_decode(&c, sizeof(bytes), &capsule, &error) == WT_OK &&
         capsule.type == WT_CAPSULE_CLOSE_WEBTRANSPORT_SESSION &&
         wt_webtransport_close_session_parse(&capsule, &code, &read_reason, &read_length, &error) == WT_OK &&
         code == 22U && read_length == sizeof(reason) - 1U &&
         memcmp(read_reason, reason, sizeof(reason) - 1U) == 0;
    rows[count].name = "the close capsule carries its code and its reason";
    rows[count].held = ok;
    count++;
  }

  /* The drain capsule, which has no value at all: a peer that reads one finds the type and nothing else. */
  {
    uint8_t bytes[16];
    wt_writer_t w = wt_writer_init(bytes, sizeof(bytes));
    wt_cursor_t c;
    wt_webtransport_capsule_t capsule;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    int ok = wt_webtransport_drain_session_write(&w) == WT_OK;
    c = wt_cursor_init(bytes, wt_writer_offset(&w));
    memset(&capsule, 0, sizeof(capsule));
    ok = ok && wt_webtransport_capsule_decode(&c, sizeof(bytes), &capsule, &error) == WT_OK &&
         capsule.type == WT_CAPSULE_DRAIN_SESSION && capsule.value_length == 0U &&
         capsule.bytes_consumed == wt_writer_offset(&w);
    rows[count].name = "the drain capsule carries no value";
    rows[count].held = ok;
    count++;
  }

  report_matrix(report, "interop-goaway-close-drain-matrix", "goaway, close and drain cases", rows, count);
}
