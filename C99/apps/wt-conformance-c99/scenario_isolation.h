/* The isolation scenarios: two sessions in one connection, and a datagram that belongs to neither (Phase 10).
 *
 * The Swift suite asks these two questions of its in-process pair -- `multi-session-isolation` and
 * `datagram-unknown-session` -- and the C99 report could not ask either, because every scenario it had was one
 * session.
 *
 * What the library owns here and what it does not is the point of the file: the draft's framing carries the
 * QUARTER stream id, and `wt_webtransport_datagram_parse` plus `wt_webtransport_session_id_from_quarter` turn
 * that into the session id the datagram belongs to. Which session OBJECT that id names is the receiver's own
 * table -- the library hands the id to the caller, exactly as it does for a CONNECT -- so the table below is
 * written out rather than hidden, and the assertions are about the library's values: the mapping, the framing,
 * and the fact that one session's state never moves another's.
 */

#ifndef WT_CONFORMANCE_SCENARIO_ISOLATION_H
#define WT_CONFORMANCE_SCENARIO_ISOLATION_H

#include "webtransport/cli/report.h"

/* Add this tool's multi-session isolation scenarios to the report. */
void wt_scenario_isolation_run(wt_cli_report_t *report);

#endif /* WT_CONFORMANCE_SCENARIO_ISOLATION_H */
