/* The five things about a socket that differ between platforms (WT-134).
 *
 * This header is private, and it exists so that `udp.c` names ONE operation per platform difference instead of
 * spelling POSIX in a dozen places: closing, non-blocking mode, waiting for readability, the error number, the
 * invalid handle, and the datagram calls themselves. The inventory of everything a port needs is `docs/PORTABILITY.md`, and
 * `scripts/check-portability.sh` keeps that document complete.
 *
 * The POSIX side is what this project builds and tests today. The `_WIN32` side is written from the inventory
 * and is NOT verified -- nothing in this repository runs it yet -- so it is marked as such rather than presented
 * as working: a port that claims to be done before it has been built once is the failure this project refuses.
 */

#ifndef WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H
#define WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H

#if defined(_WIN32)

/* Not verified: no build in this repository compiles this branch yet. */
#include <winsock2.h>
#include <ws2tcpip.h>

typedef SOCKET wt_udp_handle_t;
#define WT_UDP_INVALID_HANDLE INVALID_SOCKET

#else

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

typedef int wt_udp_handle_t;
#define WT_UDP_INVALID_HANDLE (-1)

#endif

/* The datagram calls, which differ in more than a name: a platform's way of receiving one datagram WITH its
 * sender and its truncation flag. The structure is hoisted above both branches because it is the shape the two
 * sides share, and only the CALLS differ -- which is why the handle it names is defined above it.
 *
 * `flags_in` asks for behaviour, `flags_out` reports what happened:
 *
 *   WT_UDP_PLATFORM_PEEK         leave the datagram in the queue (POSIX MSG_PEEK)
 *   WT_UDP_PLATFORM_FULL_LENGTH  report the datagram's own length, not the copied one (POSIX MSG_TRUNC as an
 *                                input flag). On Windows a peek cannot see past the buffer, so this cannot be
 *                                honoured and `bytes_out` is what was copied -- which is why the portability
 *                                document says a Windows listener must HOLD the datagram it looked at
 *   WT_UDP_PLATFORM_TRUNCATED    reported: the datagram was longer than the buffer
 */
typedef struct wt_udp_platform_message {
  void *bytes;
  size_t capacity;
  struct sockaddr_storage *address;
  int *address_length;
  int flags_in;
  int flags_out;
  size_t bytes_out;
} wt_udp_platform_message_t;

#define WT_UDP_PLATFORM_PEEK ((int)0x01)
#define WT_UDP_PLATFORM_FULL_LENGTH ((int)0x02)
#define WT_UDP_PLATFORM_TRUNCATED ((int)0x04)

/* The two calls are defined below, once per branch, as `static` like the four above them: a prototype here
 * would have to be `static` too, and one that is not is the "static declaration follows non-static
 * declaration" error this file first produced. */

#if defined(_WIN32)

/* WSAStartup belongs to the socket lifetime, and this layer is the only place in the library that touches the
 * operating system at all: a reference count here means a caller cannot forget it, and cannot call it twice.
 * The count is the number of OPEN sockets, so the last close is what releases Winsock. */
static int wt_udp_platform_acquire(void) {
  static int open_sockets = 0;
  if (open_sockets == 0) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return -1;
  }
  open_sockets++;
  return 0;
}

static void wt_udp_platform_release(void) {
  static int open_sockets = 0;
  if (open_sockets == 0) return;
  open_sockets--;
  if (open_sockets == 0) (void)WSACleanup();
}

static int wt_udp_platform_close(wt_udp_handle_t handle) { return closesocket(handle); }

static int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle) {
  u_long one = 1UL;
  /* `FIONBIO` is a `long` on Windows whose value does not fit a SIGNED long (0x8004667E > LONG_MAX), and mingw
   * says so: the cast is what the platform's own headers expect, and the cross-compile is what found it. */
  return ioctlsocket(handle, (long)FIONBIO, &one) == 0 ? 0 : -1;
}

/* WSAPoll has the same shape as poll, which is the one piece of luck in this port. */
static int wt_udp_platform_wait_readable(wt_udp_handle_t handle, int timeout_ms) {
  WSAPOLLFD entry;
  entry.fd = handle;
  entry.events = POLLRDNORM;
  entry.revents = 0;
  return WSAPoll(&entry, 1UL, timeout_ms);
}

static int wt_udp_platform_last_error(void) { return (int)WSAGetLastError(); }

static int wt_udp_platform_send_message(wt_udp_handle_t handle, const struct sockaddr *to, int to_length,
                                        const void *bytes, size_t length, size_t *out_written) {
  int written = sendto(handle, (const char *)bytes, (int)length, 0, to, to_length);
  if (written == SOCKET_ERROR) return -1;
  if (out_written != NULL) *out_written = (size_t)written;
  return 0;
}

static int wt_udp_platform_receive_message(wt_udp_handle_t handle, wt_udp_platform_message_t *message) {
  int flags = 0;
  int received;
  if ((message->flags_in & WT_UDP_PLATFORM_PEEK) != 0) flags |= MSG_PEEK;
  received = recvfrom(handle, (char *)message->bytes, (int)message->capacity, flags,
                      (struct sockaddr *)message->address, message->address_length);
  if (received == SOCKET_ERROR) return -1;
  message->bytes_out = (size_t)received;
  message->flags_out = 0;
  /* A peek cannot see past the buffer on Windows, so a full buffer is the only signal there is. The caller
   * holds the datagram rather than looking at it twice -- see the structure's comment above. */
  if ((size_t)received == message->capacity) message->flags_out |= WT_UDP_PLATFORM_TRUNCATED;
  return 0;
}

#else

/* The POSIX side has nothing to start or stop: the two calls exist so that `udp.c` names one lifetime on
 * both platforms, and a no-op that says why is better than an `#if` at the call site. */
static int wt_udp_platform_acquire(void) { return 0; }

static void wt_udp_platform_release(void) {}

static int wt_udp_platform_close(wt_udp_handle_t handle) { return close(handle); }

static int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle) {
  int flags = fcntl(handle, F_GETFL, 0);
  if (flags < 0) return -1;
  return fcntl(handle, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
}

static int wt_udp_platform_wait_readable(wt_udp_handle_t handle, int timeout_ms) {
  struct pollfd entry;
  entry.fd = handle;
  entry.events = POLLIN;
  entry.revents = 0;
  return poll(&entry, 1UL, timeout_ms);
}

static int wt_udp_platform_last_error(void) { return errno; }

static int wt_udp_platform_send_message(wt_udp_handle_t handle, const struct sockaddr *to, int to_length,
                                        const void *bytes, size_t length, size_t *out_written) {
  ssize_t written = sendto(handle, bytes, length, 0, to, (socklen_t)to_length);
  if (written < 0) return -1;
  if (out_written != NULL) *out_written = (size_t)written;
  return 0;
}

static int wt_udp_platform_receive_message(wt_udp_handle_t handle, wt_udp_platform_message_t *message) {
  struct iovec iov;
  struct msghdr msg;
  int flags = 0;
  ssize_t received;

  memset(&iov, 0, sizeof(iov));
  memset(&msg, 0, sizeof(msg));
  iov.iov_base = message->bytes;
  iov.iov_len = message->capacity;
  msg.msg_name = message->address;
  msg.msg_namelen = (message->address != NULL && message->address_length != NULL)
                        ? (socklen_t)*message->address_length
                        : (socklen_t)0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if ((message->flags_in & WT_UDP_PLATFORM_PEEK) != 0) flags |= MSG_PEEK;
  /* MSG_TRUNC as an INPUT flag asks for the datagram's own length; without it the count is what was copied.
   * Either way msg_flags reports whether the datagram was longer than the buffer, which is what keeps a
   * caller from parsing the prefix of a packet as if it were the packet (WT-36). */
  if ((message->flags_in & WT_UDP_PLATFORM_FULL_LENGTH) != 0) flags |= MSG_TRUNC;

  received = recvmsg(handle, &msg, flags);
  if (received < 0) return -1;
  message->bytes_out = (size_t)received;
  message->flags_out = 0;
  if ((msg.msg_flags & MSG_TRUNC) != 0) message->flags_out |= WT_UDP_PLATFORM_TRUNCATED;
  if (message->address_length != NULL) *message->address_length = (int)msg.msg_namelen;
  return 0;
}

#endif

#endif /* WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H */
