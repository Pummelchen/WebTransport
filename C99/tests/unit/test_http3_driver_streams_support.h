/* Shared by the two halves of the driver-stream tests after the split.
 * `static inline` so each translation unit gets its own copy without an unused-function
 * warning in the one that does not call a given helper. The file-static originals could
 * not cross a translation unit; the fake types travel with the helpers that read them. */
#ifndef WT_TEST_HTTP3_DRIVER_STREAMS_SUPPORT_H
#define WT_TEST_HTTP3_DRIVER_STREAMS_SUPPORT_H

#include "wt_test.h"

#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/connection.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session_request.h"

#define RECORDED_STREAMS 8U
#define RECORDED_BYTES 512U

typedef struct recording {
  struct {
    int bidirectional;
    int opened;
    uint8_t bytes[RECORDED_BYTES];
    size_t length;
  } streams[RECORDED_STREAMS];
  size_t count;
  size_t datagrams;
} recording_t;

typedef struct data_stream_fake {
  int opened;
  int opened_bidirectional;
  uint64_t stream_id;
  uint8_t sent[64];
  size_t sent_length;
  int sent_fin;
} data_stream_fake_t;
typedef struct data_stream_sink {
  unsigned calls;
  uint64_t stream_id;
  uint8_t bytes[64];
  size_t length;
  int fin;
} data_stream_sink_t;
typedef struct capsule_sink {
  wt_http3_driver_t *driver;
  int mark_on_headers;
  int mark_headers_pending;
  unsigned frame_calls;
  uint64_t frame_type;
  uint8_t frame_bytes[64];
  size_t frame_length;
  int frame_last;
  unsigned data_calls;
  uint8_t data_bytes[64];
  size_t data_length;
  int data_fin;
} capsule_sink_t;

static inline wt_status_t record_open(void *context, int bidirectional, uint64_t *out_stream_id,
                                      uint64_t now) {
  recording_t *recording = context;
  (void)now;
  if (recording->count >= RECORDED_STREAMS) return WT_ERR_LIMIT;
  recording->streams[recording->count].bidirectional = bidirectional;
  recording->streams[recording->count].opened = 1;
  recording->streams[recording->count].length = 0U;
  *out_stream_id = (uint64_t)recording->count;
  recording->count++;
  return WT_OK;
}

static inline wt_status_t record_send(void *context, uint64_t stream_id, const uint8_t *data,
                                      size_t length, int fin, uint64_t now) {
  recording_t *recording = context;
  (void)fin;
  (void)now;
  if (stream_id >= recording->count) return WT_ERR_INVALID_ARGUMENT;
  if (recording->streams[stream_id].length + length > RECORDED_BYTES) return WT_ERR_LIMIT;
  memcpy(recording->streams[stream_id].bytes + recording->streams[stream_id].length, data, length);
  recording->streams[stream_id].length += length;
  return WT_OK;
}

static inline wt_status_t record_datagram(void *context, const uint8_t *data, size_t length) {
  recording_t *recording = context;
  (void)data;
  (void)length;
  recording->datagrams++;
  return WT_OK;
}

static inline wt_status_t data_stream_open(void *context, int bidirectional,
                                           uint64_t *out_stream_id, uint64_t now) {
  data_stream_fake_t *fake = context;
  (void)now;
  if (fake->opened != 0) return WT_ERR_STATE;
  fake->opened = 1;
  fake->opened_bidirectional = bidirectional;
  /* RFC 9000 section 2.1: the low bit says who initiated the stream (clear for this endpoint), the next says
   * the direction. */
  fake->stream_id = bidirectional ? 0U : 2U;
  *out_stream_id = fake->stream_id;
  return WT_OK;
}

static inline wt_status_t data_stream_send(void *context, uint64_t stream_id, const uint8_t *data,
                                           size_t length, int fin, uint64_t now) {
  data_stream_fake_t *fake = context;
  (void)now;
  if (stream_id != fake->stream_id) return WT_ERR_INVALID_ARGUMENT;
  if (fake->sent_length + length > sizeof(fake->sent)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(fake->sent + fake->sent_length, data, length);
  fake->sent_length += length;
  fake->sent_fin = fin;
  return WT_OK;
}

static inline wt_status_t data_stream_on_data(void *context, uint64_t stream_id,
                                              const uint8_t *data, size_t length, int fin) {
  data_stream_sink_t *sink = context;
  sink->calls++;
  sink->stream_id = stream_id;
  if (length > sizeof(sink->bytes)) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(sink->bytes, data, length);
  sink->length = length;
  sink->fin = fin;
  return WT_OK;
}

/* A transport that hands out the stream IDs a REAL connection would: client-initiated bidirectional IDs
 * (0, 4, 8, ...) for a bidirectional open and client-initiated unidirectional ones (2, 6, 10, ...) otherwise. The
 * recording transport above returns 0, 1, 2, 3..., which cannot carry a session: a session IS its CONNECT
 * stream, so only some stream IDs can be one (draft-16 section 3.2), and the prefix writer refuses the rest. */
typedef struct class_fake {
  uint64_t next_bidi; /* 0, 4, 8, ... */
  uint64_t next_uni;  /* 2, 6, 10, ... */
  uint8_t bytes[16][256];
  size_t lengths[16];
  uint64_t send_order[16];
  size_t send_count;
} class_fake_t;

static inline wt_status_t class_open(void *context, int bidirectional, uint64_t *out_stream_id,
                                     uint64_t now) {
  class_fake_t *fake = context;
  (void)now;
  if (bidirectional != 0) {
    *out_stream_id = fake->next_bidi;
    fake->next_bidi += 4U;
  } else {
    *out_stream_id = fake->next_uni;
    fake->next_uni += 4U;
  }
  return WT_OK;
}

static inline wt_status_t class_send(void *context, uint64_t stream_id, const uint8_t *data,
                                     size_t length, int fin, uint64_t now) {
  class_fake_t *fake = context;
  (void)fin;
  (void)now;
  if (stream_id >= 16U) return WT_ERR_INVALID_ARGUMENT;
  if (fake->lengths[stream_id] + length > sizeof(fake->bytes[0])) return WT_ERR_LIMIT;
  if (length > 0U) memcpy(fake->bytes[stream_id] + fake->lengths[stream_id], data, length);
  fake->lengths[stream_id] += length;
  /* The ORDER of the writes is the claim under test, so it is recorded rather than inferred from a stream's
   * contents: "the data stream went first" is a statement about time. */
  if (fake->send_count < 16U) fake->send_order[fake->send_count] = stream_id;
  fake->send_count++;
  return WT_OK;
}

/* The session start SPLIT in two, so that a data stream can go out in between (WT-189). Draft-16 section 4.6
 * describes a client that sends "a SETTINGS frame, multiple WebTransport CONNECT requests, WebTransport data
 * streams, and WebTransport datagrams all within a single flight", and until this split the tree could not
 * express it: `start_session` opened the request stream and wrote the CONNECT in one call, so nothing could
 * precede the CONNECT and a server's parking path could not be reached from the tools at all. */

#endif
