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

1. **DONE** -- a private header (`src/runtime/udp_platform.h`) names every difference: `close`, non-blocking
   mode, readiness, the error number AND its classification, the datagram calls (`wt_udp_platform_close`,
   `wt_udp_platform_set_nonblocking`, `wt_udp_platform_wait_readable`, `wt_udp_platform_last_error`,
   `wt_udp_platform_status_of_error`, `wt_udp_platform_send_message`, `wt_udp_platform_receive_message` over
   `wt_udp_platform_message_t`), the handle type and the socket lifetime, and the ADDRESS conversions
   (`wt_udp_platform_address_to_storage`, `..._from_storage`, `..._family_domain`, `..._parse_address`,
   `..._format_address`, `..._set_v6_only`) over this library's own address type. `udp.c` names those calls and
   no longer includes a socket header or names `AF_INET`, `sockaddr_in`, `inet_pton` or `ntohs` itself.
   **`udp.c` compiles for Windows**, which is the claim this step is measured by.
2. **DONE** -- `WSAStartup` is owned by the socket lifetime in the same header: `wt_udp_platform_acquire` is
   called before the socket is made and released in `wt_udp_close`, with the count being the number of OPEN
   sockets, so the last close is what releases Winsock and a failed open releases it too. The POSIX side has
   the same two calls as no-ops. The public handle is `intptr_t` (`WT_UDP_INVALID_FD` is `(intptr_t)-1`, which
   is both POSIX's `-1` and Windows' `INVALID_SOCKET`) because a `SOCKET` is pointer-sized.
3. The `wt_udp_peek` difference, which is behavioural rather than syntactic and is now named in the header
   rather than discovered: on Windows a peek cannot see past the caller's buffer, so the `FULL_LENGTH` flag
   cannot be honoured there and a listener must hold the datagram it looked at. The runtime session's pending
   table is the shape that needs.
4. A CMake branch that links `ws2_32` (**DONE**) and finds OpenSSL, and a CI job that builds it.

**Status:** the inventory is complete and mechanically checked; the platform header is done and verified on
POSIX, where behaviour is unchanged; the socket lifetime and `ws2_32` are done; and the `_WIN32` branch is no
longer "written from the inventory" but **COMPILED**, which is a smaller claim than "the port works" and a much
larger one than nothing.

`scripts/check-windows-platform.sh` compiles the branch with a mingw cross-compiler -- the same warnings the
POSIX build turns into errors -- and reports `unsupported` with that reason on a machine that has none. CI
installs one where it can. **It found real defects, one after another, and each was a thing the inventory had not
named:**

- `FIONBIO` does not fit a signed `long` on Windows (`0x8004667E` is above `LONG_MAX`);
- `EHOSTDOWN` does not exist there at all, which is why the error CLASSIFICATION (not just the number) belongs
  to the platform: `wt_udp_platform_status_of_error` is now one function per branch;
- `inet_ntop` takes a `size_t` on Windows and a `socklen_t` on POSIX, so the capacity has a platform name too;
- `setsockopt` wants `const char *` for its option value there and `const void *` here, which is why
  `wt_udp_platform_set_v6_only` exists rather than an `#if` at the call site.

That is the difference between an inventory and a compiler, and it is the argument for checking a branch
rather than describing it.

What remains is the Windows RUNNER and FreeBSD. A job that cannot pass is worse than an absent one, because it
teaches people to ignore CI -- and the cross-compile is what makes a job plausible now: `udp.c` compiles for the
platform, while what a runner would still need is a linked build (OpenSSL for Windows) and a way to run the
tests there.

## The two symbols this document is checked for

The checker greps for the POSIX-only calls that a port must replace: `fcntl`, `close`, `poll`, `recvmsg`,
`sendmsg`, `recvfrom`, `sendto`, `inet_pton` and `O_NONBLOCK`. Every occurrence of a POSIX-only name in the
library must appear in the table above, which is how the document stays complete as the code moves -- it caught
`sendto` and `recvfrom` missing on its first run, which is exactly the rot it exists to prevent.
