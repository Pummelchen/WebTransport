/* The Windows branch of the platform layer, compiled and nothing more (WT-134).
 *
 * `src/runtime/udp_platform.h` has carried a `_WIN32` branch since the first portability round, marked NOT
 * VERIFIED because nothing in this repository compiled it. This file is the smallest thing that can change that:
 * it names EVERY function the branch defines, so a cross-compiler says whether they compile. Nothing is linked,
 * no socket is opened, and no behaviour is asserted -- "it compiles" is the claim, and the header says exactly
 * that much.
 *
 * Every function is named because a branch is only compiled in the places it is used: the first version of this
 * probe named the six operations and the cross-compile then failed the whole header with `-Werror=unused-function`
 * for the seven address and error helpers `udp.c` had just stopped carrying. A probe that names the whole surface
 * is what keeps that from being discovered by the NEXT person to add one.
 *
 * `scripts/check-windows-platform.sh` compiles this file, and `src/runtime/udp.c`, with a mingw cross-compiler --
 * and skips with a reason on a machine that has none.
 */

#include "udp_platform.h"

int wt_udp_platform_probe(wt_udp_handle_t handle) {
  char bytes[8];
  char text[64];
  struct sockaddr_storage storage;
  struct sockaddr_storage from;
  wt_udp_address_t address;
  wt_udp_socklen_t length_in = (wt_udp_socklen_t)sizeof(from);
  wt_udp_socklen_t length_out = 0;
  wt_udp_platform_message_t message;
  size_t written = 0U;
  int domain;

  memset(&storage, 0, sizeof(storage));
  memset(&from, 0, sizeof(from));
  memset(&address, 0, sizeof(address));
  memset(&message, 0, sizeof(message));
  message.bytes = bytes;
  message.capacity = sizeof(bytes);
  message.address = &storage;
  message.address_length = &length_in;
  message.flags_in = WT_UDP_PLATFORM_PEEK | WT_UDP_PLATFORM_FULL_LENGTH;

  /* The handles and the lifetime. */
  if (wt_udp_platform_acquire() != 0) return -1;
  if (wt_udp_platform_set_nonblocking(handle) != 0) return -2;
  if (wt_udp_platform_wait_readable(handle, 0) < 0) return -3;
  if (wt_udp_platform_send_message(handle, (const struct sockaddr *)&storage, (int)sizeof(storage),
                                   bytes, sizeof(bytes), &written) != 0) {
    return wt_udp_platform_last_error();
  }
  if (wt_udp_platform_receive_message(handle, &message) != 0) return wt_udp_platform_last_error();
  (void)wt_udp_platform_close(handle);
  wt_udp_platform_release();

  /* The addresses and the error classification. Guarded so that nothing here would touch a socket if this were
   * ever run: the point is that the compiler sees every call. */
  domain = wt_udp_platform_family_domain(WT_UDP_IPV4);
  if (domain < 0) return -4;
  address.family = WT_UDP_IPV4;
  address.port = 1U;
  if (wt_udp_platform_address_to_storage(&address, &storage, &length_out) != WT_OK) return -5;
  if (wt_udp_platform_address_from_storage((const struct sockaddr *)&from, length_in, &address) !=
      WT_OK) {
    return -6;
  }
  if (wt_udp_platform_parse_address("127.0.0.1", domain, address.bytes) < 0) return -7;
  if (wt_udp_platform_format_address(domain, address.bytes, text, sizeof(text)) == 0U) return -8;
  if (handle == WT_UDP_INVALID_HANDLE) {
    if (wt_udp_platform_set_v6_only(handle, 1) != 0) return -9;
  }
  if (wt_udp_platform_status_of_error(0) == WT_ERR_CLOSED) return -10;

  return (int)message.bytes_out + (int)written + (message.flags_out & WT_UDP_PLATFORM_TRUNCATED) +
         (int)strlen(text);
}
