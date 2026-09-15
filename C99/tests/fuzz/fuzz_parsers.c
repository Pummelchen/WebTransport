/* Parser fuzzing (WT-175): the plan's "parser fuzzing for QUIC varints, QUIC frames, transport parameters,
 * HTTP/3 frames, QPACK, capsules, and WebTransport stream prefixes", as one libFuzzer target.
 *
 * The malformed-input corpora in the unit suites already drive every parser with a deterministic pseudo-random
 * byte stream, which is how each one's error paths were written. What they cannot do is SEARCH: they run a fixed
 * number of fixed inputs on every build, so they prove the cases somebody thought of and nothing more. A fuzzer
 * explores the ones nobody did, and under AddressSanitizer an out-of-bounds read is a failure rather than a
 * plausible value -- which is the point of running this beside the suite rather than instead of it.
 *
 * ONE TARGET, SEVEN FAMILIES, selected by the FIRST byte of the input and listed in `k_families`. One target
 * rather than seven keeps the build and the CI smoke run to one binary and one corpus; the price is that a crash
 * artifact has to be told which family it came from, which is why the family is printed to stderr before the
 * parse (libFuzzer prints its own report after) and why `k_families[selector % count]` is stable.
 *
 * EVERY CALL IS GIVEN A BOUND. A parser fuzzer that let a length field size an allocation would be fuzzing the
 * allocator rather than the parser, so the caps here are the same ones the library is configured with: the
 * corpus input is capped by libFuzzer (`-max_len`), and `MAX_LENGTH` below is what a capsule may claim.
 *
 * Nothing here is built into the library or the tools: this file is compiled only for the fuzzing target, which
 * is a test artifact and is never installed.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webtransport/cursor.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/goaway.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/http3/settings.h"
#include "webtransport/quic/frame.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/quic/varint.h"
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/framing.h"

/* How large a value the parsers under test are allowed to buffer. The library's own callers pass a bound of this
 * order; a fuzzer that passed SIZE_MAX would be asking the parsers to trust the input, which is the one thing
 * they must never do. */
#define FUZZ_MAX_LENGTH 16384U

static const char *const k_families[] = {
    "quic-varint",     "quic-frames",  "transport-parameters", "http3-frames",
    "qpack",           "capsules",     "webtransport-prefix",  "http3-settings-goaway",
};

/* QUIC varints: the sized form is what the frame decoder uses, so both are driven. A varint parser is where an
 * 8-byte prefix meeting a 3-byte buffer has to be refused rather than read. */
static void fuzz_varints(const uint8_t *data, size_t size) {
  wt_cursor_t cursor = wt_cursor_init(data, size);

  while (cursor.offset < cursor.len) {
    uint64_t value = 0U;
    size_t width = 0U;
    if (wt_quic_varint_decode_sized(&cursor, &value, &width) != WT_OK) break;
    if (width == 0U) break; /* a decoder that consumed nothing cannot make progress */
  }
}

/* QUIC frames: every frame in the buffer, which is what a packet's payload is. */
static void fuzz_quic_frames(const uint8_t *data, size_t size) {
  wt_cursor_t cursor = wt_cursor_init(data, size);

  while (cursor.offset < cursor.len) {
    wt_quic_frame_t frame;
    wt_quic_error_t error = WT_QUIC_NO_ERROR;
    if (wt_quic_frame_decode(&cursor, &frame, &error) != WT_OK) break;
  }
}

/* Transport parameters: decode, then the section 18.2 check, which is a second parser over the same bytes. */
static void fuzz_transport_parameters(const uint8_t *data, size_t size) {
  wt_quic_transport_parameters_t params;
  wt_quic_error_t error = WT_QUIC_NO_ERROR;

  uint64_t offender = 0U;

  if (wt_quic_transport_parameters_decode(data, size, &params, &error) != WT_OK) return;
  (void)wt_quic_transport_parameters_check(&params, 0, &error, &offender);
  /* And a lookup for a parameter that is usually absent, because the getter walks the list. */
  {
    const uint8_t *value = NULL;
    size_t value_length = 0U;
    (void)wt_quic_transport_parameters_get(&params, WT_QUIC_TP_INITIAL_MAX_DATA, &value, &value_length);
  }
}

/* HTTP/3 frames: the cursor form, and the prefix form that reports how much it consumed. */
static void fuzz_http3_frames(const uint8_t *data, size_t size) {
  wt_cursor_t cursor = wt_cursor_init(data, size);

  while (cursor.offset < cursor.len) {
    wt_http3_frame_t frame;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    if (wt_http3_frame_decode(&cursor, &frame, &error) != WT_OK) break;
  }
  {
    wt_http3_frame_t frame;
    size_t consumed = 0U;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    (void)wt_http3_frame_decode_prefix(data, size, &frame, &consumed, &error);
  }
}

/* QPACK: the three primitive decoders and the field line, which is the composed one. */
static void fuzz_qpack(const uint8_t *data, size_t size) {
  wt_cursor_t cursor = wt_cursor_init(data, size);

  while (cursor.offset < cursor.len) {
    uint64_t value = 0U;
    if (wt_qpack_integer_decode(&cursor, 4U, &value) != WT_OK) break;
  }
  {
    wt_cursor_t strings = wt_cursor_init(data, size);
    while (strings.offset < strings.len) {
      const uint8_t *bytes = NULL;
      size_t length = 0U;
      if (wt_qpack_string_decode(&strings, &bytes, &length, NULL) != WT_OK) break;
    }
  }
  {
    /* A field line reads both halves, so it is the parse most likely to catch a length that disagrees with what
     * follows it. */
    wt_cursor_t line = wt_cursor_init(data, size);
    wt_qpack_field_line_t field;
    (void)wt_qpack_field_line_decode(&line, &field);
  }
  {
    /* Huffman is a second decoder over the same family of bytes, and its table is the one a fuzzer is most
     * likely to walk off the end of. */
    uint8_t decoded[256];
    size_t decoded_length = 0U;
    (void)wt_qpack_huffman_decode(data, size, decoded, sizeof(decoded), &decoded_length);
  }
}

/* Capsules: the WebTransport session's own values on the CONNECT stream. */
static void fuzz_capsules(const uint8_t *data, size_t size) {
  wt_cursor_t cursor = wt_cursor_init(data, size);

  while (cursor.offset < cursor.len) {
    wt_webtransport_capsule_t capsule;
    wt_http3_error_t error = WT_HTTP3_NO_ERROR;
    if (wt_webtransport_capsule_decode(&cursor, FUZZ_MAX_LENGTH, &capsule, &error) != WT_OK) break;
  }
}

/* WebTransport stream and datagram prefixes. */
static void fuzz_webtransport_prefix(const uint8_t *data, size_t size) {
  wt_cursor_t cursor = wt_cursor_init(data, size);
  int unidirectional = 0;
  uint64_t session_id = 0U;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;

  (void)wt_webtransport_stream_prefix_parse(&cursor, &unidirectional, &session_id, &error);
}

/* The HTTP/3 control-stream values, which are HTTP/3 frames with their own payload parsers. */
static void fuzz_http3_settings_goaway(const uint8_t *data, size_t size) {
  wt_http3_settings_t settings;
  wt_http3_error_t error = WT_HTTP3_NO_ERROR;
  uint64_t identifier = 0U;

  (void)wt_http3_settings_parse(data, size, &settings, &error);
  (void)wt_http3_goaway_decode_payload(data, size, &identifier, &error);
}

/* Declared before its definition because libFuzzer's entry point has no header to include, and this project
 * treats a missing prototype as an error (-Wmissing-prototypes): the convention is the declaration. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned selector;

  if (data == NULL || size == 0U) return 0;
  selector = (unsigned)data[0] % (unsigned)(sizeof(k_families) / sizeof(k_families[0]));

  /* Printed BEFORE the parse: on a crash this is the line that says which parser the artifact belongs to, and
   * libFuzzer's own report follows it on the same stream. */
  if (getenv("FUZZ_VERBOSE") != NULL) {
    fprintf(stderr, "fuzz: family=%s size=%zu\n", k_families[selector], size);
  }

  switch (selector) {
    case 0U: fuzz_varints(data + 1, size - 1U); break;
    case 1U: fuzz_quic_frames(data + 1, size - 1U); break;
    case 2U: fuzz_transport_parameters(data + 1, size - 1U); break;
    case 3U: fuzz_http3_frames(data + 1, size - 1U); break;
    case 4U: fuzz_qpack(data + 1, size - 1U); break;
    case 5U: fuzz_capsules(data + 1, size - 1U); break;
    case 6U: fuzz_webtransport_prefix(data + 1, size - 1U); break;
    case 7U: fuzz_http3_settings_goaway(data + 1, size - 1U); break;
    default: break;
  }
  return 0;
}
