/* The Windows branch of the platform header, compiled and nothing more (WT-134).
 *
 * `src/runtime/udp_platform.h` has carried a `_WIN32` branch since the first portability round, marked NOT
 * VERIFIED because nothing in this repository compiled it. This file is the smallest thing that can change
 * that: it names all six of the branch's operations and the datagram structure, so a cross-compiler says
 * whether they COMPILE. Nothing is linked, no socket is opened, and no behaviour is asserted -- "it compiles"
 * is the claim, and the header says exactly that much.
 *
 * `scripts/check-windows-platform.sh` compiles this with a mingw cross-compiler, and skips with a reason on a
 * machine that has none. */
#include "udp_platform.h"

int wt_udp_platform_probe(wt_udp_handle_t handle) {
  char bytes[8];
  struct sockaddr_storage storage;
  int length = (int)sizeof(storage);
  wt_udp_platform_message_t message;
  size_t written = 0U;
  memset(&storage, 0, sizeof(storage));
  memset(&message, 0, sizeof(message));
  message.bytes = bytes;
  message.capacity = sizeof(bytes);
  message.address = &storage;
  message.address_length = &length;
  message.flags_in = WT_UDP_PLATFORM_PEEK | WT_UDP_PLATFORM_FULL_LENGTH;
  if (wt_udp_platform_acquire() != 0) return -1;
  if (wt_udp_platform_set_nonblocking(handle) != 0) return -2;
  if (wt_udp_platform_wait_readable(handle, 0) < 0) return -3;
  if (wt_udp_platform_send_message(handle, (const struct sockaddr *)&storage, length, bytes, sizeof(bytes),
                                   &written) != 0) {
    return wt_udp_platform_last_error();
  }
  if (wt_udp_platform_receive_message(handle, &message) != 0) return wt_udp_platform_last_error();
  (void)wt_udp_platform_close(handle);
  wt_udp_platform_release();
  return (int)message.bytes_out + (int)written + (message.flags_out & WT_UDP_PLATFORM_TRUNCATED);
}
