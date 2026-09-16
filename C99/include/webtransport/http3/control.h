/* The peer's HTTP/3 control stream (RFC 9114 section 6.2.1).
 *
 * Each side opens exactly one control stream and its first frame is its
 * SETTINGS. Everything else about the stream is a rule about what a peer may do
 * with it, and all four are connection errors:
 *
 *   - a first frame that is not SETTINGS is H3_MISSING_SETTINGS;
 *   - a second control stream from the same peer is H3_STREAM_CREATION_ERROR;
 *   - the stream closing at any point is H3_CLOSED_CRITICAL_STREAM, because the
 *     connection's whole configuration travels on it and a closed one cannot be
 *     reopened (section 6.2.1: "the sender MUST NOT close the control stream");
 *   - a frame the section does not allow there -- DATA, HEADERS, PUSH_PROMISE, a
 *     second SETTINGS, or one of the frame types section 7.2.8 reserved for
 *     HTTP/2 -- is H3_FRAME_UNEXPECTED.
 *
 * The state machine decides PERMISSION from the frame type, and -- for the one
 * frame whose payload it owns -- reassembles that payload so the existing
 * SETTINGS validator can read it. What a GOAWAY or MAX_PUSH_ID frame says is
 * parsed by whoever owns that frame, which is why the payload call takes a frame
 * type and ignores everything that is not SETTINGS.
 *
 * The driver feeds it: a frame on the peer's control stream has its type checked
 * once, when the frame's header completes, and each piece of the frame's payload
 * is handed to `wt_http3_control_on_frame_payload`, which buffers SETTINGS across
 * the pieces the connection delivered it in.
 */

#ifndef WEBTRANSPORT_HTTP3_CONTROL_H
#define WEBTRANSPORT_HTTP3_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/http3/settings.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How much of the peer's SETTINGS payload this control machine will reassemble, before it
 * refuses the frame with H3_EXCESSIVE_LOAD -- the code `wt_http3_settings_parse` itself uses
 * when a peer asks for a bigger table than this endpoint published, and the same shape as
 * `WT_HTTP3_SETTINGS_MAX_ENTRIES`. The number is this endpoint's bound and not the peer's:
 * 512 bytes is room for the sixteen settings the parser will store at their longest varint
 * encoding (16 * 16 = 256) plus the exercise setting RFC 9114 section 7.2.4.1 says a sender
 * SHOULD include, with headroom, and a real peer sends a handful. The driver's own
 * `max_frame_bytes` bound is checked first, so a frame longer than that is already refused
 * before any of it reaches this buffer. */
#define WT_HTTP3_CONTROL_SETTINGS_MAX 512U

typedef struct wt_http3_control_stream {
  /* The peer's control stream exists. A second one is an error, so this outlives
   * any single stream object. */
  int opened;
  /* Its SETTINGS frame has been processed, which is what makes every later frame
   * subject to the frame rules rather than to the first-frame rule. */
  int settings_received;
  /* The stream ended. The connection is committed to an error by then. */
  int closed;
  /* The SETTINGS payload while it is being reassembled. A frame's payload arrives in as many
   * pieces as the connection chose, and it is the VALIDATOR, not the framer, that has to see
   * the whole thing: `wt_http3_settings_parse` refuses a duplicate identifier, and a duplicate
   * split across two pieces is still a duplicate. The buffer is fixed, so the bound is this
   * endpoint's rather than the peer's appetite. */
  uint8_t settings_payload[WT_HTTP3_CONTROL_SETTINGS_MAX];
  size_t settings_length;
  /* Whether the bound above was already exceeded, so every later piece of the same frame keeps
   * reporting the same refusal instead of quietly restarting the reassembly. */
  int settings_failed;
} wt_http3_control_stream_t;

void wt_http3_control_init(wt_http3_control_stream_t *control);

/* The peer opened a stream whose type prefix says control (0x00). A second one is
 * H3_STREAM_CREATION_ERROR. */
wt_status_t wt_http3_control_peer_opened(wt_http3_control_stream_t *control,
                                         wt_http3_error_t *out_error);

/* A frame arrived on the peer's control stream. Sets `out_error` to the code the
 * rule names and returns WT_ERR_PROTOCOL when it may not be there, and
 * WT_ERR_STATE when the caller's own ordering is wrong (a frame before the stream
 * was opened, or after it closed). */
wt_status_t wt_http3_control_on_frame(wt_http3_control_stream_t *control, uint64_t type,
                                      wt_http3_error_t *out_error);

/* One piece of a frame's payload on the peer's control stream, exactly as the frame sink
 * reports a frame: in order, with `last` set on the piece that completes it.
 *
 * Only SETTINGS is this machine's to read (RFC 9114 section 7.2.4); a piece of any other frame
 * type is ignored, because GOAWAY and MAX_PUSH_ID belong to whoever owns them. The SETTINGS
 * pieces are buffered -- the driver deliberately does not buffer a payload -- and the completed
 * frame is handed to `wt_http3_settings_parse`, so the rules that module already knows (a
 * duplicate identifier, a reserved HTTP/2 identifier, an out-of-range boolean, a payload that
 * ends between an identifier and its value) all become this machine's answer. The duplicate
 * identifier is RFC 9114 section 7.2.4's MAY that this implementation takes: "The same setting
 * identifier MUST NOT occur more than once in the SETTINGS frame. A receiver MAY treat the
 * presence of duplicate setting identifiers as a connection error of type H3_SETTINGS_ERROR."
 *
 * `out_error` is H3_SETTINGS_ERROR for a payload the parser refuses, H3_EXCESSIVE_LOAD when the
 * payload is longer than `WT_HTTP3_CONTROL_SETTINGS_MAX`, and H3_NO_ERROR otherwise. A call
 * before `wt_http3_control_on_frame` accepted the frame is WT_ERR_STATE, the caller's own
 * ordering. */
wt_status_t wt_http3_control_on_frame_payload(wt_http3_control_stream_t *control, uint64_t type,
                                              const uint8_t *payload, size_t length, int last,
                                              wt_http3_error_t *out_error);

/* The peer's control stream ended, for any reason. Always
 * H3_CLOSED_CRITICAL_STREAM, whether or not SETTINGS had arrived: section 6.2.1
 * makes the closure itself the error. */
wt_status_t wt_http3_control_on_closed(wt_http3_control_stream_t *control,
                                       wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_CONTROL_H */
