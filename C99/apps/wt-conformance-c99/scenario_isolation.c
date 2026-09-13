/* The multi-session isolation scenarios (Phase 10). */

#include "scenario_isolation.h"

#include <string.h>

#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/writer.h"

#define WT_ISOLATION_SLOTS 2U
#define WT_ISOLATION_PAYLOAD_MAX 32U

typedef struct isolation_session {
  uint64_t session_id;
  wt_webtransport_session_t session;
  uint8_t payload[WT_ISOLATION_PAYLOAD_MAX];
  size_t payload_length;
  unsigned datagrams;
} isolation_session_t;

typedef struct isolation_pair {
  isolation_session_t sessions[WT_ISOLATION_SLOTS];
  size_t count;
} isolation_pair_t;

static void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED, detail);
}

static isolation_session_t *session_for_id(isolation_pair_t *pair, uint64_t session_id) {
  size_t index;
  for (index = 0U; index < pair->count; index++) {
    if (pair->sessions[index].session_id == session_id) return &pair->sessions[index];
  }
  return NULL;
}

/* One datagram, delivered the way a receiver does it: parse, map the quarter stream id to a session id, and
 * find that session in the table. A datagram whose session is not in the table is DROPPED -- not delivered
 * anywhere and not an error, which is what the draft asks of a receiver. The return value is whether it was
 * delivered, so a scenario can assert the drop rather than infer it. */
static int deliver(isolation_pair_t *pair, const uint8_t *datagram, size_t length) {
  const uint8_t *payload = NULL;
  size_t payload_length = 0U;
  uint64_t quarter = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  isolation_session_t *owner;

  if (wt_webtransport_datagram_parse(datagram, length, &quarter, &payload, &payload_length, &error) != WT_OK) {
    return 0;
  }
  owner = session_for_id(pair, wt_webtransport_session_id_from_quarter(quarter));
  if (owner == NULL) return 0;
  if (payload_length > sizeof(owner->payload)) return 0;
  if (payload_length > 0U) memcpy(owner->payload, payload, payload_length);
  owner->payload_length = payload_length;
  owner->datagrams++;
  return 1;
}

static size_t write_datagram(uint8_t *out, size_t capacity, uint64_t quarter, const char *payload) {
  wt_writer_t w = wt_writer_init(out, capacity);
  size_t length = strlen(payload);
  if (wt_webtransport_datagram_write(&w, quarter, (const uint8_t *)payload, length) != WT_OK) return 0U;
  return wt_writer_offset(&w);
}

void wt_scenario_isolation_run(wt_cli_report_t *report) {
  isolation_pair_t pair;
  uint8_t datagram[64];
  size_t length;
  size_t index;
  int established = 1;
  int mapped;

  memset(&pair, 0, sizeof(pair));
  for (index = 0U; index < WT_ISOLATION_SLOTS; index++) {
    /* Session ids 0 and 4 are the first two client-initiated bidirectional streams, which is where a session
     * lives; a quarter stream id is then 0 and 1, so the two are told apart by the framing alone. */
    pair.sessions[index].session_id = (uint64_t)index * 4U;
    wt_webtransport_session_init(&pair.sessions[index].session);
    pair.count = index + 1U;
    if (wt_webtransport_session_established(&pair.sessions[index].session) != WT_OK) established = 0;
  }
  mapped = wt_webtransport_session_id_from_quarter(0U) == 0U &&
           wt_webtransport_session_id_from_quarter(1U) == 4U &&
           wt_webtransport_session_id_from_quarter(2U) == 8U &&
           wt_webtransport_quarter_stream_id(4U) == 1U;

  /* Two datagrams, one per session, with different payloads: each must reach its own session and leave the
   * other untouched. */
  length = write_datagram(datagram, sizeof(datagram), 0U, "one");
  {
    int first_delivered = length > 0U && deliver(&pair, datagram, length) == 1;
    length = write_datagram(datagram, sizeof(datagram), 1U, "two");
    {
      int second_delivered = length > 0U && deliver(&pair, datagram, length) == 1;
      int routed = first_delivered && second_delivered && pair.sessions[0].datagrams == 1U &&
                   pair.sessions[1].datagrams == 1U && pair.sessions[0].payload_length == 3U &&
                   memcmp(pair.sessions[0].payload, "one", 3U) == 0 &&
                   pair.sessions[1].payload_length == 3U &&
                   memcmp(pair.sessions[1].payload, "two", 3U) == 0;

      /* A close on the first session: its own state moves, and the second is not touched. This is the half a
       * single-session test cannot see -- state that lives per session rather than per connection. */
      (void)wt_webtransport_session_on_close(&pair.sessions[0].session, 1, 7U);

      add(report, "multi-session-isolation",
          established && mapped && routed &&
              pair.sessions[0].session.state == WT_WEBTRANSPORT_SESSION_CLOSED &&
              pair.sessions[0].session.close_error_set == 1 &&
              pair.sessions[0].session.close_error_code == 7U &&
              wt_webtransport_session_allows_new_streams(&pair.sessions[0].session) == 0 &&
              pair.sessions[1].session.state == WT_WEBTRANSPORT_SESSION_ESTABLISHED &&
              pair.sessions[1].session.close_error_set == 0 &&
              wt_webtransport_session_allows_new_streams(&pair.sessions[1].session) == 1,
          "two sessions differ by quarter id, each datagram reaches its own, and a close moves one only");
    }
  }

  /* A datagram naming a session this endpoint does not have -- quarter 2 is session 8 -- is dropped, and
   * dropping it leaves both live sessions exactly as they were. */
  {
    unsigned first_before = pair.sessions[0].datagrams;
    unsigned second_before = pair.sessions[1].datagrams;
    int delivered;

    length = write_datagram(datagram, sizeof(datagram), 2U, "three");
    delivered = length > 0U && deliver(&pair, datagram, length) == 1;

    add(report, "datagram-unknown-session",
        length > 0U && delivered == 0 && pair.sessions[0].datagrams == first_before &&
            pair.sessions[1].datagrams == second_before &&
            pair.sessions[1].payload_length == 3U &&
            memcmp(pair.sessions[1].payload, "two", 3U) == 0 &&
            session_for_id(&pair, 8U) == NULL,
        "a datagram for an unknown session is dropped rather than delivered to a neighbour");
  }
}
