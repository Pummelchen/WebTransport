/* The five things about a socket that differ between platforms (WT-134).
 *
 * This header is private, and it exists so that `udp.c` names ONE operation per platform difference instead of
 * spelling POSIX in a dozen places: closing, non-blocking mode, waiting for readability, the error number and
 * the invalid handle. The inventory of everything a port needs is `docs/PORTABILITY.md`, and
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

static int wt_udp_platform_close(wt_udp_handle_t handle) { return closesocket(handle); }

static int wt_udp_platform_set_nonblocking(wt_udp_handle_t handle) {
  u_long one = 1UL;
  return ioctlsocket(handle, FIONBIO, &one) == 0 ? 0 : -1;
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

#else

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

typedef int wt_udp_handle_t;
#define WT_UDP_INVALID_HANDLE (-1)

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

#endif

#endif /* WEBTRANSPORT_RUNTIME_UDP_PLATFORM_H */
