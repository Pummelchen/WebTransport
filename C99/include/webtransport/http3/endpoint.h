/* The HTTP/3 endpoint's own streams (Phase 9).
 *
 * Everything below this header is a state machine for one concern: the control stream, the
 * frame rules, QPACK, the request stream. This is the layer that OWNS them for one
 * connection, and its whole job is the lifecycle a consumer never sees:
 *
 *   - our own unidirectional streams, opened once each. The control stream carries the type
 *     prefix `0x00` and then SETTINGS; the QPACK streams carry `0x02` and `0x03`. Sending a
 *     second one of any of them is the caller's error (WT_ERR_STATE), because sections
 *     6.2.1 and 4.2 of QPACK make "one per connection" part of the protocol rather than a
 *     style choice.
 *
 *   - the peer's unidirectional streams, classified by their type prefix. The rules here
 *     are the RFC's and are deliberately asymmetric with the receiving side of a frame
 *     parser: an UNKNOWN type is not an error at all (section 6.2.1 leaves unknown types
 *     for future revisions, and the endpoint simply stops reading that stream), while a
 *     SECOND control stream, a second QPACK stream, or a push stream this endpoint never
 *     asked for commits the connection to an error with the code the RFC names.
 *
 *   - the draft-16 WebTransport unidirectional stream (`0x54`), which is not HTTP/3's to
 *     interpret. It is classified and handed to the layer above; the HTTP/3 core must not
 *     treat it as unknown-and-ignored, or a session's own streams would silently disappear.
 *
 * The peer-stream table is fixed. It is a bound this endpoint published rather than one
 * that grows with a peer's appetite, and running into it is WT_ERR_LIMIT -- this endpoint's
 * own limit -- and not an HTTP/3 error code.
 */

#ifndef WEBTRANSPORT_HTTP3_ENDPOINT_H
#define WEBTRANSPORT_HTTP3_ENDPOINT_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/control.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/role.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The largest number of peer unidirectional streams one endpoint tracks at once. A
 * connection has three of HTTP/3's own at most, plus the draft's WebTransport streams,
 * which are bounded by the session's own stream table. */
#define WT_HTTP3_ENDPOINT_STREAMS_MAX 32U

typedef enum wt_http3_endpoint_stream_kind {
  WT_HTTP3_ENDPOINT_STREAM_CONTROL = 0,
  WT_HTTP3_ENDPOINT_STREAM_PUSH = 1,
  WT_HTTP3_ENDPOINT_STREAM_QPACK_ENCODER = 2,
  WT_HTTP3_ENDPOINT_STREAM_QPACK_DECODER = 3,
  /* The draft-16 WebTransport unidirectional stream (0x54). */
  WT_HTTP3_ENDPOINT_STREAM_WEBTRANSPORT = 4,
  /* A type this build does not know. Section 6.2.1: ignore the stream, do not fail. */
  WT_HTTP3_ENDPOINT_STREAM_UNKNOWN = 5
} wt_http3_endpoint_stream_kind_t;

typedef struct wt_http3_endpoint_stream {
  uint64_t stream_id;
  wt_http3_endpoint_stream_kind_t kind;
  /* The type prefix's wire value, kept so a caller can log what it saw without decoding it
   * again -- and so a test can assert the endpoint classified what was actually sent. */
  uint64_t type;
} wt_http3_endpoint_stream_t;

typedef struct wt_http3_endpoint {
  wt_http3_role_t role;
  /* The peer's control stream, with the rules that make a second one an error. */
  wt_http3_control_stream_t peer_control;
  int peer_qpack_encoder_seen;
  int peer_qpack_decoder_seen;
  int peer_webtransport_streams_seen;
  /* Our own streams, sent at most once each. */
  int control_sent;
  int qpack_encoder_sent;
  int qpack_decoder_sent;
  /* The peer's unidirectional streams while they live. */
  wt_http3_endpoint_stream_t streams[WT_HTTP3_ENDPOINT_STREAMS_MAX];
  size_t stream_count;
} wt_http3_endpoint_t;

void wt_http3_endpoint_init(wt_http3_endpoint_t *endpoint, wt_http3_role_t role);

/* Write the type prefix of one of OUR unidirectional streams. The caller sends these bytes
 * as the first thing on a newly opened stream. A second call for the same kind is
 * WT_ERR_STATE. The control stream's SETTINGS frame is written by the caller, with
 * `wt_http3_frame_encode` and the SETTINGS encoder, because what this endpoint's settings
 * say is a decision the layer above owns. */
wt_status_t wt_http3_endpoint_write_prefix(wt_http3_endpoint_t *endpoint,
                                           wt_http3_endpoint_stream_kind_t kind, wt_writer_t *w);

/* A peer unidirectional stream's opening bytes: its type prefix, and possibly more. Reads
 * the varint type, classifies the stream, records it, applies the once-only rules, and
 * reports how many bytes the prefix took so the caller continues at the right offset.
 * `out_kind` is always set when the call succeeds, including for UNKNOWN. */
wt_status_t wt_http3_endpoint_on_uni_stream(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                            const uint8_t *bytes, size_t length,
                                            size_t *out_consumed,
                                            wt_http3_endpoint_stream_kind_t *out_kind,
                                            wt_http3_error_t *out_error);

/* A frame arrived on the peer's control stream: the endpoint forwards it to the control
 * machine, which is where the "SETTINGS first, and only once" rule lives. WT_ERR_STATE when
 * the stream was never opened. */
wt_status_t wt_http3_endpoint_on_control_frame(wt_http3_endpoint_t *endpoint, uint64_t type,
                                               wt_http3_error_t *out_error);

/* A peer unidirectional stream ended. The peer's control stream ending is
 * H3_CLOSED_CRITICAL_STREAM whether or not SETTINGS had arrived; any other stream is
 * simply forgotten. */
wt_status_t wt_http3_endpoint_on_uni_stream_end(wt_http3_endpoint_t *endpoint, uint64_t stream_id,
                                                wt_http3_error_t *out_error);

/* The recorded kind of a peer stream, for a caller routing its data. Returns
 * WT_HTTP3_ENDPOINT_STREAM_UNKNOWN when the stream is not one the endpoint recorded. */
wt_http3_endpoint_stream_kind_t wt_http3_endpoint_stream_kind(
    const wt_http3_endpoint_t *endpoint, uint64_t stream_id);

/* How many peer streams the endpoint is tracking, for a caller that logs occupancy. */
size_t wt_http3_endpoint_stream_count(const wt_http3_endpoint_t *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_ENDPOINT_H */
