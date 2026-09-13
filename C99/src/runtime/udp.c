/* The UDP socket surface. See webtransport/runtime/udp.h.
 *
 * The only POSIX file in the tree. Every conversion between this library's types and the platform's
 * happens inside this file, and so does every classification of a syscall failure, so that nothing
 * above it has to know which platform it is on.
 */

#include "webtransport/runtime/udp.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The platform differences live in one private header: closing, non-blocking mode, readability and the error
 * number. The socket types and the datagram calls are still POSIX here, which is the NEXT step of WT-134 and is
 * written down in docs/PORTABILITY.md rather than pretended away. */
#include "udp_platform.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "webtransport/time.h"

/* How many bytes of an IPv4 address are meaningful, and of an IPv6 one. Named because the literal 4
 * and 16 appear wherever the two families are told apart. */
#define WT_UDP_IPV4_BYTES 4U
#define WT_UDP_IPV6_BYTES 16U
#define WT_UDP_MAX_PORT 65535U

/* One place where a platform failure becomes a status.
 *
 * The mapping is deliberately narrow: a failure this layer cannot classify is WT_ERR_IO rather than a
 * guess, because a caller that reads "limit" or "closed" acts on it, and a wrong classification is
 * worse than a vague one. The classes that DO have names here are the ones a QUIC runtime branches on:
 * a full send buffer is retried (WT_ERR_AGAIN), an unreachable peer is a dead path (WT_ERR_CLOSED), a
 * refused bind is a limit (WT_ERR_LIMIT), and a datagram the kernel will not carry is also a limit. */
static wt_status_t map_errno(int error) {
  switch (error) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EINTR:
      /* A signal interrupted the call, or a non-blocking socket had nothing to give. Both mean "ask
       * again", which is what a caller's event loop does anyway. */
      return WT_ERR_AGAIN;
    case EMSGSIZE:
      /* The datagram is larger than the path, or than UDP, can carry. */
      return WT_ERR_LIMIT;
    case ENOBUFS:
    case ENOMEM:
      return WT_ERR_OUT_OF_MEMORY;
    case ETIMEDOUT:
      return WT_ERR_TIMEOUT;
    case ECONNREFUSED:
      /* An ICMP port-unreachable from a previous send, reported here. For QUIC that is a path with
       * nobody on the other end, which is what CLOSED says. */
    case ENETUNREACH:
    case EHOSTUNREACH:
    case ENETDOWN:
    case EHOSTDOWN:
      return WT_ERR_CLOSED;
    case EADDRINUSE:
    case EADDRNOTAVAIL:
    case EACCES:
    case EPERM:
      /* A bind or a send the system refused: a port already taken, an address this host does not
       * have, or a privilege it does not grant. Refused rather than malformed, which is WT_ERR_LIMIT. */
      return WT_ERR_LIMIT;
    case EAFNOSUPPORT:
    case EPROTONOSUPPORT:
    case EOPNOTSUPP:
      return WT_ERR_UNSUPPORTED;
    case EISCONN:
    case EALREADY:
    case ENOTCONN:
      return WT_ERR_STATE;
    case EBADF:
    case EINVAL:
    case EDESTADDRREQ:
      return WT_ERR_INVALID_ARGUMENT;
    default:
      /* EIO and the hundred platform-specific values: reported as what they are, an I/O failure this
       * layer does not classify, rather than folded into a name that means something else. */
      return WT_ERR_IO;
  }
}

/* The socket address for one of this library's addresses. Both families are turned into the same
 * `struct sockaddr_storage`, so the callers below do not branch on the family more than once. */
static wt_status_t to_sockaddr(const wt_udp_address_t *address, struct sockaddr_storage *out,
                               socklen_t *out_len) {
  memset(out, 0, sizeof(*out));
  if (address->family == WT_UDP_IPV4) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)(void *)out;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(address->port);
    memcpy(&v4->sin_addr, address->bytes, WT_UDP_IPV4_BYTES);
    *out_len = (socklen_t)sizeof(*v4);
    return WT_OK;
  }
  if (address->family == WT_UDP_IPV6) {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)(void *)out;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(address->port);
    memcpy(&v6->sin6_addr, address->bytes, WT_UDP_IPV6_BYTES);
    v6->sin6_scope_id = address->scope_id;
    *out_len = (socklen_t)sizeof(*v6);
    return WT_OK;
  }
  return WT_ERR_INVALID_ARGUMENT;
}

/* And back. A family this library does not carry -- an IPv4-mapped address on a dual-stack socket,
 * say -- is WT_ERR_UNSUPPORTED rather than a silent zero, because a connection keyed on a zeroed
 * address would be the wrong connection. */
static wt_status_t from_sockaddr(const struct sockaddr *from, socklen_t from_len,
                                 wt_udp_address_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (from->sa_family == AF_INET) {
    const struct sockaddr_in *v4 = (const struct sockaddr_in *)(const void *)from;
    if (from_len < (socklen_t)sizeof(*v4)) return WT_ERR_INVALID_ARGUMENT;
    out->family = WT_UDP_IPV4;
    out->port = ntohs(v4->sin_port);
    memcpy(out->bytes, &v4->sin_addr, WT_UDP_IPV4_BYTES);
    return WT_OK;
  }
  if (from->sa_family == AF_INET6) {
    const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)(const void *)from;
    if (from_len < (socklen_t)sizeof(*v6)) return WT_ERR_INVALID_ARGUMENT;
    out->family = WT_UDP_IPV6;
    out->port = ntohs(v6->sin6_port);
    memcpy(out->bytes, &v6->sin6_addr, WT_UDP_IPV6_BYTES);
    out->scope_id = v6->sin6_scope_id;
    return WT_OK;
  }
  return WT_ERR_UNSUPPORTED;
}

static int family_of(wt_udp_family_t family) {
  return family == WT_UDP_IPV4 ? AF_INET : (family == WT_UDP_IPV6 ? AF_INET6 : -1);
}

const char *wt_udp_family_name(wt_udp_family_t family) {
  switch (family) {
    case WT_UDP_IPV4:
      return "ipv4";
    case WT_UDP_IPV6:
      return "ipv6";
  }
  return "unknown";
}

void wt_udp_address_loopback(wt_udp_family_t family, wt_udp_address_t *out) {
  if (out == NULL) return;
  memset(out, 0, sizeof(*out));
  out->family = family;
  if (family == WT_UDP_IPV4) {
    /* 127.0.0.1, written out rather than taken from INADDR_LOOPBACK: that constant is BSD and not
     * POSIX, and WT-14 found that defining _POSIX_C_SOURCE on one host removed it. The final 1 is
     * part of the address -- 127.0.0.0 is a network, not the loopback host, and binding it fails with
     * EADDRNOTAVAIL. */
    out->bytes[0] = 127U;
    out->bytes[3] = 1U;
  } else {
    /* ::1 in network order: fifteen zero bytes and a one. */
    out->bytes[15] = 1U;
  }
}

int wt_udp_address_equal(const wt_udp_address_t *a, const wt_udp_address_t *b) {
  size_t length;
  if (a == NULL || b == NULL) return 0;
  if (a->family != b->family || a->port != b->port || a->scope_id != b->scope_id) return 0;
  length = a->family == WT_UDP_IPV4 ? WT_UDP_IPV4_BYTES : WT_UDP_IPV6_BYTES;
  return memcmp(a->bytes, b->bytes, length) == 0;
}

wt_status_t wt_udp_socket_open(wt_udp_socket_t *out, wt_udp_family_t family) {
  int domain = family_of(family);
  int fd;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  out->fd = -1;
  out->family = family;
  out->port = 0U;
  if (domain < 0) return WT_ERR_INVALID_ARGUMENT;

  fd = socket(domain, SOCK_DGRAM, 0);
  if (fd < 0) return map_errno(wt_udp_platform_last_error());

  /* Non-blocking from the start: a socket that blocked on receive would make the connection runtime's
   * timers unenforceable, and setting it here means no caller can forget. */
  if (wt_udp_platform_set_nonblocking(fd) != 0) {
    int error = wt_udp_platform_last_error();
    (void)wt_udp_platform_close(fd);
    return map_errno(error);
  }

  if (family == WT_UDP_IPV6) {
    /* Set rather than left to the platform: Linux and the BSDs disagree about the default, and a
     * socket that is sometimes dual-stack would make "which family is this connection" depend on the
     * host. One because a dual-stack socket would also receive IPv4-mapped addresses, which this
     * library's address type reports as a family it does not carry. */
    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, (socklen_t)sizeof(on)) < 0) {
      int error = wt_udp_platform_last_error();
      (void)wt_udp_platform_close(fd);
      return map_errno(error);
    }
  }

  out->fd = fd;
  return WT_OK;
}

wt_status_t wt_udp_bind(wt_udp_socket_t *socket, const wt_udp_address_t *address) {
  struct sockaddr_storage storage;
  socklen_t storage_len = 0;
  wt_status_t status;

  if (socket == NULL || address == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd < 0) return WT_ERR_STATE;
  if (address->family != socket->family) {
    /* An IPv4 address cannot be bound to an IPv6 socket here: IPV6_V6ONLY is on, and a silent
     * mismatch would bind the wrong thing. */
    return WT_ERR_INVALID_ARGUMENT;
  }
  status = to_sockaddr(address, &storage, &storage_len);
  if (status != WT_OK) return status;
  if (bind(socket->fd, (const struct sockaddr *)(const void *)&storage, storage_len) < 0) {
    return map_errno(wt_udp_platform_last_error());
  }
  socket->port = address->port;
  {
    uint16_t bound = 0U;
    wt_status_t status_port = wt_udp_local_port(socket, &bound);
    if (status_port != WT_OK) return status_port;
    socket->port = bound;
  }
  return WT_OK;
}

wt_status_t wt_udp_bind_loopback(wt_udp_socket_t *socket, uint16_t port, uint16_t *out_port) {
  wt_udp_address_t address;
  wt_status_t status;

  if (socket == NULL) return WT_ERR_INVALID_ARGUMENT;
  wt_udp_address_loopback(socket->family, &address);
  address.port = port;
  status = wt_udp_bind(socket, &address);
  if (status != WT_OK) return status;
  return wt_udp_local_port(socket, out_port);
}

wt_status_t wt_udp_local_port(const wt_udp_socket_t *socket, uint16_t *out_port) {
  struct sockaddr_storage storage;
  socklen_t storage_len = (socklen_t)sizeof(storage);

  if (socket == NULL || out_port == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd < 0) return WT_ERR_STATE;
  memset(&storage, 0, sizeof(storage));
  if (getsockname(socket->fd, (struct sockaddr *)(void *)&storage, &storage_len) < 0) {
    return map_errno(wt_udp_platform_last_error());
  }
  if (storage.ss_family == AF_INET) {
    *out_port = ntohs(((const struct sockaddr_in *)(const void *)&storage)->sin_port);
    return WT_OK;
  }
  if (storage.ss_family == AF_INET6) {
    *out_port = ntohs(((const struct sockaddr_in6 *)(const void *)&storage)->sin6_port);
    return WT_OK;
  }
  return WT_ERR_UNSUPPORTED;
}

void wt_udp_close(wt_udp_socket_t *socket) {
  if (socket == NULL) return;
  if (socket->fd >= 0) {
    /* The descriptor is cleared before the call: a close that restarts on a signal or a second call
     * must not close a descriptor number the process has since reused. */
    int fd = socket->fd;
    socket->fd = -1;
    (void)wt_udp_platform_close(fd);
  }
  socket->port = 0U;
}

wt_status_t wt_udp_send(const wt_udp_socket_t *socket, const wt_udp_address_t *to,
                        const uint8_t *data, size_t length) {
  struct sockaddr_storage storage;
  socklen_t storage_len = 0;
  ssize_t written;
  wt_status_t status;

  if (socket == NULL || to == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd < 0) return WT_ERR_STATE;
  if (data == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  /* Larger than UDP can carry, refused here rather than at the syscall: the number is knowable, and a
   * caller that asks for the impossible should be told which bound it broke. */
  if (length > WT_UDP_MAX_DATAGRAM) return WT_ERR_LIMIT;
  if (to->family != socket->family) return WT_ERR_INVALID_ARGUMENT;

  status = to_sockaddr(to, &storage, &storage_len);
  if (status != WT_OK) return status;
  written = sendto(socket->fd, data, length, 0, (const struct sockaddr *)(const void *)&storage,
                   storage_len);
  if (written < 0) return map_errno(wt_udp_platform_last_error());
  /* A datagram is sent whole or not at all, so a short count is not a partial send: it is a platform
   * that did something this layer does not describe. */
  if ((size_t)written != length) return WT_ERR_IO;
  return WT_OK;
}

wt_status_t wt_udp_receive(const wt_udp_socket_t *socket, uint8_t *buffer, size_t capacity,
                           size_t *out_length, wt_udp_address_t *out_from) {
  struct sockaddr_storage storage;
  struct iovec iov;
  struct msghdr message;
  ssize_t received;
  wt_status_t status;

  if (socket == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd < 0) return WT_ERR_STATE;
  if (buffer == NULL && capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;

  memset(&storage, 0, sizeof(storage));
  memset(&iov, 0, sizeof(iov));
  memset(&message, 0, sizeof(message));
  iov.iov_base = buffer;
  iov.iov_len = capacity;
  message.msg_name = &storage;
  message.msg_namelen = (socklen_t)sizeof(storage);
  message.msg_iov = &iov;
  message.msg_iovlen = 1;

  /* recvmsg rather than recvfrom so that MSG_TRUNC is reported in `msg_flags`: a receive that only
   * returned a short count would leave a caller unable to tell a truncated datagram from a peer that
   * sent a small one (WT-36). */
  received = recvmsg(socket->fd, &message, 0);
  if (received < 0) return map_errno(errno);

  /* The sender is reported even when the datagram is discarded, because it is known and it is what a
   * diagnostic needs. */
  if (out_from != NULL) {
    status = from_sockaddr((const struct sockaddr *)(const void *)&storage, message.msg_namelen,
                           out_from);
    if (status != WT_OK) return status;
  }

  if ((message.msg_flags & MSG_TRUNC) != 0) {
    /* The datagram was larger than the buffer, so its bytes are not the datagram. Nothing is written
     * to the length, which is what keeps a caller from parsing the prefix of a packet. */
    return WT_ERR_TRUNCATED;
  }
  *out_length = (size_t)received;
  return WT_OK;
}

wt_status_t wt_udp_peek(const wt_udp_socket_t *socket, uint8_t *buffer, size_t capacity,
                        size_t *out_length, size_t *out_available, wt_udp_address_t *out_from) {
  struct sockaddr_storage storage;
  struct iovec iov;
  struct msghdr message;
  ssize_t received;
  wt_status_t status;

  if (socket == NULL || out_length == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd < 0) return WT_ERR_STATE;
  if (buffer == NULL && capacity != 0U) return WT_ERR_INVALID_ARGUMENT;
  *out_length = 0U;
  if (out_available != NULL) *out_available = 0U;

  memset(&storage, 0, sizeof(storage));
  memset(&iov, 0, sizeof(iov));
  memset(&message, 0, sizeof(message));
  iov.iov_base = buffer;
  iov.iov_len = capacity;
  message.msg_name = &storage;
  message.msg_namelen = (socklen_t)sizeof(storage);
  message.msg_iov = &iov;
  message.msg_iovlen = 1;

  /* MSG_PEEK is the whole point: the datagram is read and left in the queue, so the connection's own receive
   * finds it exactly where it was. MSG_TRUNC is not an error here as it is in `wt_udp_receive`: this call is
   * reporting what is there, and the length it reports is the datagram's own. */
  received = recvmsg(socket->fd, &message, MSG_PEEK | MSG_TRUNC);
  if (received < 0) return map_errno(errno);

  if (out_from != NULL) {
    status = from_sockaddr((const struct sockaddr *)(const void *)&storage, message.msg_namelen, out_from);
    if (status != WT_OK) return status;
  }
  *out_length = (size_t)received;
  if (out_available != NULL) {
    size_t copied = (size_t)received < capacity ? (size_t)received : capacity;
    *out_available = copied;
  }
  return WT_OK;
}

wt_status_t wt_udp_wait(const wt_udp_socket_t *socket, uint64_t timeout_micros) {
  struct pollfd entry;
  int timeout_ms;
  int ready;

  if (socket == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (socket->fd < 0) return WT_ERR_STATE;

  /* poll takes milliseconds and an int, so the conversion is bounded here: a caller asking for longer
   * than an int can express in milliseconds gets the longest wait the platform can represent rather
   * than a negative value that would mean "do not block". */
  if (timeout_micros == WT_UDP_WAIT_FOREVER) {
    timeout_ms = -1;
  } else if (timeout_micros / 1000U > (uint64_t)INT32_MAX) {
    timeout_ms = INT32_MAX;
  } else {
    /* Rounded up: a wait of one microsecond must not become a wait of none, which would turn a
     * deadline into a spin. */
    timeout_ms = (int)((timeout_micros + 999U) / 1000U);
  }

  entry.fd = socket->fd;
  entry.events = POLLIN;
  /* A pending error or a hangup is reported through these and only surfaced by a receive attempt, so
   * they are waited on as well: otherwise a socket with an error would never look ready and the
   * caller would time out instead of learning what happened. */
  entry.revents = 0;

  ready = wt_udp_platform_wait_readable(entry.fd, timeout_ms);
  if (ready < 0) return map_errno(errno);
  if (ready == 0) return WT_ERR_TIMEOUT;
  return WT_OK;
}

wt_status_t wt_udp_address_parse(const char *text, uint16_t port, wt_udp_address_t *out) {
  char host[64];
  const char *scope = NULL;
  size_t length;
  unsigned long scope_id = 0UL;
  int family;

  if (text == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  length = strlen(text);
  if (length == 0U || length >= sizeof(host)) return WT_ERR_INVALID_ARGUMENT;
  memcpy(host, text, length + 1U);

  /* A scope id is written as a percent sign and a number: fe80::1%4. It is part of the address for a
   * link-local one and is not understood by inet_pton, so it is taken off here and put back by the
   * formatter. */
  scope = strchr(host, '%');
  if (scope != NULL) {
    char *end = NULL;
    host[(size_t)(scope - host)] = '\0';
    errno = 0;
    scope_id = strtoul(scope + 1, &end, 10);
    if (end == scope + 1 || *end != '\0' || errno != 0 || scope_id > UINT32_MAX) {
      return WT_ERR_INVALID_ARGUMENT;
    }
  }

  if (strchr(host, ':') != NULL) {
    family = AF_INET6;
    out->family = WT_UDP_IPV6;
  } else {
    family = AF_INET;
    out->family = WT_UDP_IPV4;
  }
  if (scope_id != 0UL && out->family != WT_UDP_IPV6) return WT_ERR_INVALID_ARGUMENT;

  if (inet_pton(family, host, out->bytes) != 1) return WT_ERR_INVALID_ARGUMENT;
  /* A scope on an address that cannot have one is a mistake worth reporting rather than dropping. */
  if (scope_id != 0UL) {
    /* A scope id means "on this interface", which only an address that is per-interface can carry:
     * fe80::/10 is link-local and ff02::/16 is link-local multicast, and every other address is
     * global, so a scope on one is a mistake worth reporting rather than dropping. */
    const uint8_t first = out->bytes[0];
    const uint8_t second = out->bytes[1];
    const int link_local = (first == 0xfeU && (second & 0xc0U) == 0x80U);
    const int multicast = (first == 0xffU && second == 0x02U);
    if (!link_local && !multicast) return WT_ERR_INVALID_ARGUMENT;
  }
  out->scope_id = (uint32_t)scope_id;
  out->port = port;
  return WT_OK;
}

wt_status_t wt_udp_address_parse_host_port(const char *text, wt_udp_address_t *out) {
  char host[64];
  const char *colon;
  const char *port_text;
  unsigned long port = 0UL;
  char *end = NULL;
  size_t host_len;
  wt_udp_address_t parsed;
  wt_status_t status;

  if (text == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));

  if (text[0] == '[') {
    /* An IPv6 literal is bracketed because a colon means the port and is also part of the address. */
    const char *close = strchr(text, ']');
    if (close == NULL) return WT_ERR_INVALID_ARGUMENT;
    host_len = (size_t)(close - text - 1);
    if (host_len == 0U || host_len >= sizeof(host)) return WT_ERR_INVALID_ARGUMENT;
    memcpy(host, text + 1, host_len);
    host[host_len] = '\0';
    if (close[1] != ':') return WT_ERR_INVALID_ARGUMENT;
    port_text = close + 2;
  } else {
    colon = strrchr(text, ':');
    if (colon == NULL) return WT_ERR_INVALID_ARGUMENT;
    host_len = (size_t)(colon - text);
    if (host_len == 0U || host_len >= sizeof(host)) return WT_ERR_INVALID_ARGUMENT;
    memcpy(host, text, host_len);
    host[host_len] = '\0';
    if (strchr(host, ':') != NULL) {
      /* An unbracketed address with more than one colon is ambiguous, and guessing which colon is the
       * port is how "[::1]:443" becomes an address nobody meant. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    port_text = colon + 1;
  }

  errno = 0;
  port = strtoul(port_text, &end, 10);
  if (end == port_text || *end != '\0' || errno != 0 || port > WT_UDP_MAX_PORT) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  status = wt_udp_address_parse(host, (uint16_t)port, &parsed);
  if (status != WT_OK) return status;
  *out = parsed;
  return WT_OK;
}

size_t wt_udp_address_format(const wt_udp_address_t *address, char *out, size_t capacity) {
  char host[64];
  char text[80];
  int written;
  size_t length;

  if (address == NULL) return 0U;
  if (capacity != 0U && out != NULL) out[0] = '\0';

  if (address->family == WT_UDP_IPV4) {
    if (inet_ntop(AF_INET, address->bytes, host, (socklen_t)sizeof(host)) == NULL) return 0U;
    written = snprintf(text, sizeof(text), "%s:%u", host, (unsigned int)address->port);
  } else if (address->family == WT_UDP_IPV6) {
    if (inet_ntop(AF_INET6, address->bytes, host, (socklen_t)sizeof(host)) == NULL) return 0U;
    if (address->scope_id != 0U) {
      written = snprintf(text, sizeof(text), "[%s%%%u]:%u", host, (unsigned int)address->scope_id,
                         (unsigned int)address->port);
    } else {
      written = snprintf(text, sizeof(text), "[%s]:%u", host, (unsigned int)address->port);
    }
  } else {
    return 0U;
  }
  if (written < 0) return 0U;
  length = (size_t)written;
  if (out == NULL || capacity == 0U) return length;
  /* snprintf truncates safely, and the terminator is written even when the address does not fit, which
   * is what the header promises. */
  (void)snprintf(out, capacity, "%s", text);
  return length;
}
