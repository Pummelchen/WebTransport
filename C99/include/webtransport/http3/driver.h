/* Driving an HTTP/3 endpoint from a connection (Phase 9).
 *
 * `endpoint.h` owns the per-connection HTTP/3 state but knows nothing about how bytes
 * arrive. This is the seam between the two: it takes stream events the way a connection
 * reports them -- a stream ID, an offset, the bytes, and whether the peer finished -- and
 * turns an opening unidirectional stream into a classified one.
 *
 * The reason it exists rather than a direct call to `wt_http3_endpoint_on_uni_stream` is
 * REASSEMBLY. A stream's type prefix is a varint, and a varint can be split across frames: a
 * peer may open a stream and send one byte of `0xC0 0x00 ...` in its first packet and the
 * rest in the next. The endpoint's classifier wants the whole prefix, and it is right to --
 * deciding a stream's type from half a varint is exactly the mistake that makes an
 * implementation read someone else's stream. So the driver holds at most the first eight
 * bytes of each opening stream (the longest prefix QUIC's varint can make) until they add up
 * to a prefix, and it holds them in a FIXED table, because a buffer that grows with the
 * number of streams a peer opens is a heap exhaustion path with the peer's name on it.
 *
 * A prefix must also arrive at offset zero: a stream whose type prefix is not at its start
 * is not that type, and `WT_ERR_STATE` says the caller's own accounting is wrong rather than
 * blaming the peer.
 */

#ifndef WEBTRANSPORT_HTTP3_DRIVER_H
#define WEBTRANSPORT_HTTP3_DRIVER_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/endpoint.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The longest type prefix a peer can send: a varint is at most eight bytes. */
#define WT_HTTP3_DRIVER_PREFIX_MAX 8U

/* How many opening streams may be waiting for the rest of their prefix at once. A peer that
 * opens more than this before completing any of them is refused with WT_ERR_LIMIT rather
 * than given more memory. */
#define WT_HTTP3_DRIVER_PENDING_MAX 8U

typedef struct wt_http3_driver_pending {
  uint64_t stream_id;
  uint8_t bytes[WT_HTTP3_DRIVER_PREFIX_MAX];
  size_t length;
} wt_http3_driver_pending_t;

typedef struct wt_http3_driver {
  /* The endpoint whose streams these are. Not owned. */
  wt_http3_endpoint_t *endpoint;
  wt_http3_driver_pending_t pending[WT_HTTP3_DRIVER_PENDING_MAX];
  size_t pending_count;
} wt_http3_driver_t;

void wt_http3_driver_init(wt_http3_driver_t *driver, wt_http3_endpoint_t *endpoint);

/* One unidirectional stream's bytes, as a connection reported them.
 *
 * On the frame that completes the prefix, `out_kind` is set and `out_payload` points at the
 * bytes AFTER the prefix, within the caller's own `data` -- so it lives as long as that
 * buffer, and the driver copies nothing. On an earlier frame `out_kind` is left as UNKNOWN
 * and `*out_payload_length` is zero: the prefix is not yet a prefix, and the caller sends
 * the rest.
 *
 * `out_prefix_consumed` reports how many of THIS frame's bytes went to the prefix, which is
 * what a caller replaying buffered bytes needs. */
wt_status_t wt_http3_driver_on_uni_stream_data(wt_http3_driver_t *driver, uint64_t stream_id,
                                               uint64_t offset, const uint8_t *data, size_t length,
                                               wt_http3_endpoint_stream_kind_t *out_kind,
                                               const uint8_t **out_payload,
                                               size_t *out_payload_length,
                                               size_t *out_prefix_consumed,
                                               wt_http3_error_t *out_error);

/* A peer's unidirectional stream ended: the endpoint is told so its rules apply (a control
 * stream ending is the error itself), and any half-received prefix is dropped -- a stream
 * that ended before its type was complete never had one. */
wt_status_t wt_http3_driver_on_uni_stream_end(wt_http3_driver_t *driver, uint64_t stream_id,
                                              wt_http3_error_t *out_error);

/* How many opening streams are waiting for the rest of their prefix, for a caller that logs
 * occupancy or bounds its own buffering. */
size_t wt_http3_driver_pending_count(const wt_http3_driver_t *driver);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_DRIVER_H */
