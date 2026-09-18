/* Shared by the matrix scenarios after they were split into their own modules.
 * `static inline` rather than an exported symbol: these are reporting helpers, not part
 * of the tool, and a translation unit that does not call one must not warn about it. */
#ifndef WT_CONFORMANCE_SCENARIO_MATRIX_SUPPORT_H
#define WT_CONFORMANCE_SCENARIO_MATRIX_SUPPORT_H

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

#define WT_MATRIX_MAX_CASES 12U

/* One row of a matrix: what the case is, and whether it held. */
typedef struct matrix_row {
  const char *name;
  int held;
} matrix_row_t;

static inline void add(wt_cli_report_t *report, const char *name, int ok, const char *detail) {
  (void)wt_cli_report_add(report, name, ok != 0 ? WT_CLI_RESULT_PASSED : WT_CLI_RESULT_FAILED,
                          detail);
}

/* Write one row and, at the end, the count. EVERY failing row is named, because "eleven of thirteen" is not
 * a debugging aid on its own. */
static inline void report_matrix(wt_cli_report_t *report, const char *scenario, const char *noun,
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

#endif
