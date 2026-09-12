/* A consumer of the installed C99 package.
 *
 * It uses enough of the public surface to catch an installed header that is
 * missing an include of its own, a target that does not carry its include
 * directory, and a config file that does not export what it promises. It is not
 * a functional test -- the unit tests are -- so it checks values and exits.
 */

#include <stdio.h>
#include <string.h>

#include "webtransport/buffer.h"
#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/version.h"
#include "webtransport/writer.h"

int main(void) {
  wt_buf_t buf = wt_buf_init(NULL);
  wt_cursor_t cursor;
  uint8_t bytes[4];
  wt_writer_t writer;

  if (strcmp(wt_status_name(WT_ERR_PROTOCOL), "protocol") != 0) return 1;
  if (buf.data != NULL || buf.len != 0U) return 1;

  if (wt_buf_append(&buf, "\x01\x02\x03", 3U) != WT_OK) return 1;
  cursor = wt_buf_cursor(&buf);
  if (wt_cursor_u8(&cursor) != 0x01U) return 1;
  if (wt_cursor_u16(&cursor) != 0x0203U) return 1;
  if (!wt_cursor_at_end(&cursor)) return 1;

  writer = wt_writer_init(bytes, sizeof(bytes));
  wt_writer_u32(&writer, 0x01020304U);
  if (!wt_writer_ok(&writer)) return 1;
  if (bytes[0] != 0x01U || bytes[3] != 0x04U) return 1;

  printf("webtransport-c99 %s (%s): package consumer ok\n", wt_version_string(),
         wt_protocol_draft());
  wt_buf_free(&buf);
  return 0;
}
