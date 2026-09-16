/* Declarations shared across the HTTP/3 driver's translation units.
 *
 * These were `static` in the single driver.c. They are internal linkage rather than static because the
 * file is now several, and this is the only place their prototypes live: a future reader must not
 * tighten one back to `static` without moving its callers too. Nothing here is part of the installed
 * API (see webtransport/http3/driver.h).
 *
 * The four are the tables the parts share: the data-stream table and the pending-prefix table are
 * written by the sending and the receiving halves, and settling a capsule stream is what the frame
 * loop does when the HEADERS frame that turns a CONNECT stream into capsules completes. */

#ifndef WT_HTTP3_DRIVER_INTERNAL_H
#define WT_HTTP3_DRIVER_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/driver.h"

wt_status_t remember_data_stream(wt_http3_driver_t *driver, uint64_t stream_id,
                                 uint64_t our_prefix_length, uint64_t session_id,
                                 int session_id_set);
wt_http3_driver_pending_t *find_pending(wt_http3_driver_t *driver, uint64_t stream_id);
void forget_pending(wt_http3_driver_t *driver, uint64_t stream_id);
void settle_capsule_stream(wt_http3_driver_t *driver, uint64_t stream_id);

#endif /* WT_HTTP3_DRIVER_INTERNAL_H */
