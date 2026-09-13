# Platform surface, and what a Windows or FreeBSD build needs (WT-134)

The plan's Definition of Done asks for CI on macOS 26, Debian, **FreeBSD** and **Windows 11**, and the last two
are not a YAML edit: the code has to be portable first, or the job is red on its first run and stays red. This
document is the inventory of what is platform-specific and the adaptation each item needs, and
`scripts/check-portability.sh` keeps it complete by grepping the tree for the POSIX-only symbols listed here.

FreeBSD is close to Debian for this codebase: the POSIX calls are the same and `poll`, `recvmsg`, `sendmsg` and
`inet_pton` all exist. What differs is the toolchain and the OpenSSL package, which is a CI-job decision rather
than a code change.

Windows is the real work. Every item below is a place where the current code assumes POSIX:

| Surface | Where | Windows equivalent |
| --- | --- | --- |
| Socket headers | `sys/socket.h`, `netinet/in.h`, `arpa/inet.h`, `unistd.h`, `sys/uio.h` | `winsock2.h`, `ws2tcpip.h`, and `WS2tcpip.h` supplies `inet_pton` |
| Library initialisation | none today | `WSAStartup`/`WSACleanup` once per process, which the runtime has no place for yet |
| Linking | none today | `ws2_32` |
| The socket type | `int fd` inside `wt_udp_socket_t` | `SOCKET`, which is unsigned and has `INVALID_SOCKET` rather than `-1` |
| Closing | `close` | `closesocket` |
| Non-blocking mode | `fcntl(fd, F_SETFL, O_NONBLOCK)` | `ioctlsocket(fd, FIONBIO, &one)`, a different function with a different failure mode |
| Readiness | `poll` | `WSAPoll` (same shape, `pollfd` spelled the same way) |
| Errors | `errno` | `WSAGetLastError`, and the socket error numbers are a different set |
| Scatter/gather | `struct iovec`, `recvmsg`/`sendmsg` | `WSABUF`, `WSARecvFrom`/`WSASendTo`, with the same information in different fields |
| `MSG_PEEK`/`MSG_TRUNC` | `wt_udp_peek` | `MSG_PEEK` exists; `MSG_TRUNC` on a peek does NOT report the datagram's full length, so the peek needs the receive-then-hold shape instead (the runtime session already has the pending table an implementation would need) |
| Sending and receiving | `sendto`/`recvfrom` in the datagram paths | `WSASendTo`/`WSARecvFrom`, which take the same arguments in a different shape |
| `snprintf` | several | present in MSVC 2015 and later |
| OpenSSL | `tls/`, `crypto/` | a Windows build of OpenSSL 3, and a decision about which one (vcpkg, the OpenSSL installers, or a vendored build) |

## The adaptation the code needs, in order

1. **DONE** -- a private header (`src/runtime/udp_platform.h`) names four of the five differences: `close`,
   non-blocking mode, readiness and the error number (`wt_udp_platform_close`,
   `wt_udp_platform_set_nonblocking`, `wt_udp_platform_wait_readable`, `wt_udp_platform_last_error`), plus the
   handle type. `udp.c` names those operations now rather than spelling POSIX in a dozen places. The `_WIN32`
   branches are written from this inventory and are **not verified** -- nothing here builds them -- and they say
   so in the header. What remains in `udp.c` is the datagram calls themselves (`recvmsg`/`sendmsg` with
   `struct iovec`) and the public `int fd` field, which a Windows port must widen to `SOCKET`.
2. `WSAStartup` somewhere that owns a process lifetime: the UDP layer is the only place this library touches the
   operating system, so a reference count there is the natural home.
3. The `wt_udp_peek` difference above, which is behavioural rather than syntactic: on Windows a peek cannot see
   the whole datagram, so a listener must hold the datagram it looked at. The runtime session's pending table is
   the shape that needs.
4. A CMake branch that links `ws2_32` and finds OpenSSL, and a CI job that builds it.

**Status:** the inventory is complete and mechanically checked; step 1 (the platform header) is done and verified
on POSIX, where behaviour is unchanged; steps 2 to 4 are not, and no Windows job is added until they are -- a job
that cannot pass is worse than an absent one, because it teaches people to ignore CI.

## The two symbols this document is checked for

The checker greps for the POSIX-only calls that a port must replace: `fcntl`, `close`, `poll`, `recvmsg`,
`sendmsg`, `recvfrom`, `sendto`, `inet_pton` and `O_NONBLOCK`. Every occurrence of a POSIX-only name in the
library must appear in the table above, which is how the document stays complete as the code moves -- it caught
`sendto` and `recvfrom` missing on its first run, which is exactly the rot it exists to prevent.
