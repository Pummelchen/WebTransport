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
#include "webtransport/http3/settings.h"
#include "webtransport/quic/connection.h"
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

/* The longest frame header: two varints, at most eight bytes each. */
#define WT_HTTP3_DRIVER_FRAME_HEADER_MAX 16U

/* How many streams may be mid-frame at once. Each holds only a frame header, so this is a
 * limit on interleaving rather than on memory; a stream past it is WT_ERR_LIMIT. */
#define WT_HTTP3_DRIVER_FRAMES_MAX 8U

typedef struct wt_http3_driver_frame_state {
  uint64_t stream_id;
  uint8_t header[WT_HTTP3_DRIVER_FRAME_HEADER_MAX];
  size_t header_length;
  int in_frame;
  uint64_t type;
  uint64_t payload_length;
  uint64_t payload_received;
} wt_http3_driver_frame_state_t;

/* ---------------------------------------------- sending, without knowing QUIC

 * The endpoint has to open streams and send bytes, and this header deliberately does not name
 * a QUIC connection to do it: the transport is a small table of three calls. That keeps the
 * HTTP/3 layer independent of the connection implementation -- and it makes the outbound half
 * testable against a recording transport, which is how the bytes this layer produces are
 * checked without standing up a handshake.

 * The driver owns one scratch buffer for the bytes it sends, because a frame is measured
 * before it is written (a length prefix's width depends on the length) and the measurement
 * needs somewhere to live. It is a bound like every other one here: a section that does not
 * fit is WT_ERR_LIMIT with no error code, and the caller can raise
 * `WT_HTTP3_DRIVER_SCRATCH` by compiling its own copy or send the section itself. */

#define WT_HTTP3_DRIVER_SCRATCH 1024U

typedef wt_status_t (*wt_http3_open_stream_fn)(void *context, int bidirectional,
                                               uint64_t *out_stream_id, uint64_t now);
typedef wt_status_t (*wt_http3_send_stream_fn)(void *context, uint64_t stream_id,
                                               const uint8_t *data, size_t length, int fin,
                                               uint64_t now);
typedef wt_status_t (*wt_http3_send_datagram_fn)(void *context, const uint8_t *data,
                                                 size_t length);

typedef struct wt_http3_driver_transport {
  /* Open a stream this endpoint initiates, and say what ID it got. */
  wt_http3_open_stream_fn open_stream;
  /* Send bytes on a stream. `fin` ends it. */
  wt_http3_send_stream_fn send_stream;
  wt_http3_send_datagram_fn send_datagram;
  void *context;
} wt_http3_driver_transport_t;

typedef struct wt_http3_driver {
  /* The endpoint whose streams these are. Not owned. */
  wt_http3_endpoint_t *endpoint;
  wt_http3_driver_pending_t pending[WT_HTTP3_DRIVER_PENDING_MAX];
  size_t pending_count;
  /* Streams part way through a frame's header. */
  wt_http3_driver_frame_state_t frames[WT_HTTP3_DRIVER_FRAMES_MAX];
  size_t frame_count;
  /* The bytes of the message being sent, measured before the frame around them is written. */
  uint8_t scratch[WT_HTTP3_DRIVER_SCRATCH];
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

/* ---------------------------------------------- frame boundaries on a stream

 * A stream carries a sequence of HTTP/3 frames, and a frame's own header -- a type varint
 * and a length varint -- can be SPLIT across the STREAM frames a connection hands over, the
 * same way a stream's type prefix can. This part of the driver reassembles the boundary, and
 * it deliberately does NOT buffer the payload: it reports the frame's payload to a sink in
 * whatever pieces arrive, with a `last` flag on the final one.
 *
 * That division is the point. The driver's job is framing, and framing needs sixteen bytes of
 * state per stream; the PAYLOAD is policy -- how much of a HEADERS section this endpoint will
 * hold is a bound, and a bound belongs to whoever owns the memory. A driver that buffered
 * every stream's frames would be carrying that policy silently, with a fixed size nobody
 * chose.
 *
 * The one thing the driver does bound is the frame's declared length, because a length is
 * the peer's to choose and this endpoint has to refuse absurdity before the sink allocates
 * for it: over `max_frame_bytes` it is H3_EXCESSIVE_LOAD. */

/* What a frame's payload is delivered to. Called once per piece that arrives, in order, with
 * `last` set on the piece that completes the frame; a zero-length frame reports one piece of
 * zero bytes with `last` set, so a sink never has to special-case an empty frame. */
typedef wt_status_t (*wt_http3_frame_sink_fn)(void *context, uint64_t stream_id, uint64_t type,
                                              const uint8_t *payload, size_t length, int last);

/* The peer's own stream data, which is NOT HTTP/3 framing: a WebTransport stream's bytes
 * after its prefix are the session's, and a datagram's payload is the session's too. The
 * driver does not interpret them -- it hands them over, because what they mean is the
 * session layer's business and buffering them is a bound that layer owns. */
typedef wt_status_t (*wt_http3_stream_data_fn)(void *context, uint64_t stream_id,
                                              const uint8_t *data, size_t length, int fin);
typedef wt_status_t (*wt_http3_datagram_fn)(void *context, const uint8_t *data, size_t length);

typedef struct wt_http3_driver_sink {
  wt_http3_frame_sink_fn on_frame_payload;
  wt_http3_stream_data_fn on_stream_data;
  wt_http3_datagram_fn on_datagram;
  void *context;
} wt_http3_driver_sink_t;

/* Bytes arriving on a stream that carries HTTP/3 frames (the control stream, the QPACK
 * streams, a request stream). `fin` says the peer ended the stream here.
 *
 * WT_ERR_TRUNCATED means the stream ended in the middle of a frame: an incomplete frame on a
 * stream is not malformed until there is nothing more coming, which is what `fin` decides. */
wt_status_t wt_http3_driver_on_stream_bytes(wt_http3_driver_t *driver, uint64_t stream_id,
                                            const uint8_t *data, size_t length, int fin,
                                            uint64_t max_frame_bytes,
                                            const wt_http3_driver_sink_t *sink,
                                            wt_http3_error_t *out_error);

/* Forget a stream's half-read frame when the stream ends or is reset. Returns whether one was
 * in progress, which is what a caller needs to decide between WT_ERR_TRUNCATED and silence. */
int wt_http3_driver_forget_frame(wt_http3_driver_t *driver, uint64_t stream_id);

/* One frame the connection handed over, routed to whichever of the sink's callbacks owns it.
 *
 * This is the shape `wt_quic_connection_set_handlers` wants, so a caller installs the driver
 * directly:
 *
 *     wt_quic_connection_set_handlers(&connection, wt_http3_driver_on_quic_frame, &driver, ...);
 *
 * What it routes, and why each has to be here rather than in the connection layer:
 *   - a STREAM frame on a peer-initiated unidirectional stream: the type prefix is
 *     reassembled, and then the bytes are either HTTP/3 frames (control, QPACK) or the
 *     session's own data (the draft's stream type), which is a distinction only the HTTP/3
 *     layer can make;
 *   - a STREAM frame on a peer-initiated bidirectional stream: a request stream, whose frames
 *     are the CONNECT and its response;
 *   - a DATAGRAM frame: the session's datagram payload, handed over uninterpreted.
 *
 * A frame on a stream THIS endpoint initiated is not routed: it is the connection's to track
 * and this layer has nothing to do with the peer's answer on a stream it did not receive.
 * Unhandled frame kinds are ignored, which is what a frame handler is for. */
wt_status_t wt_http3_driver_on_quic_frame(void *context, wt_quic_space_t space,
                                          const wt_quic_frame_t *frame,
                                          const wt_http3_driver_sink_t *sink,
                                          uint64_t max_frame_bytes);

/* Open and start the three streams HTTP/3 requires of an endpoint: the control stream with its
 * SETTINGS, and both QPACK streams. Each is opened once; a second call is WT_ERR_STATE from the
 * endpoint's own rules, and nothing is sent. */
wt_status_t wt_http3_driver_start_own_streams(wt_http3_driver_t *driver,
                                              const wt_http3_driver_transport_t *transport,
                                              const wt_http3_settings_t *settings, uint64_t now);

/* Send a request, a response or a trailer on a stream this endpoint owns, as a HEADERS frame.
 * `peer_max_entries` is the peer's advertised QPACK capacity, from its SETTINGS. */
wt_status_t wt_http3_driver_send_message(wt_http3_driver_t *driver,
                                         const wt_http3_driver_transport_t *transport,
                                         uint64_t stream_id, const wt_http3_message_t *message,
                                         uint64_t peer_max_entries, int fin, uint64_t now);

/* Send a datagram: the payload is the session's, and this layer passes it through. */
wt_status_t wt_http3_driver_send_datagram(wt_http3_driver_t *driver,
                                          const wt_http3_driver_transport_t *transport,
                                          const uint8_t *data, size_t length);

/* Start this endpoint's control stream: the type prefix, then the SETTINGS frame built from
 * `settings`. The bytes go into the caller's writer, which is the stream the connection
 * opened for them.
 *
 * The frame can only be written once its length is known, so the SETTINGS payload is
 * measured into `scratch` first -- the same measure-then-write rule every length on this wire
 * follows. A payload that does not fit the scratch is WT_ERR_LIMIT with no error code: it is
 * this endpoint's buffer and its own choice of settings, not anything a peer did.
 *
 * Sending a second control stream is refused by the endpoint's own one-per-connection rule
 * (WT_ERR_STATE), so this is safe to call on a session that may already have started one. */
wt_status_t wt_http3_driver_start_control(wt_http3_driver_t *driver, const wt_http3_settings_t *settings,
                                          uint8_t *scratch, size_t scratch_capacity, wt_writer_t *w);

/* Start one of this endpoint's QPACK streams: the type prefix alone, because what follows on
 * it is the QPACK layer's to write. `encoder` selects the encoder stream (0x02) or the
 * decoder stream (0x03), and a second one of either is WT_ERR_STATE. */
wt_status_t wt_http3_driver_start_qpack_stream(wt_http3_driver_t *driver, int encoder,
                                               wt_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_DRIVER_H */
