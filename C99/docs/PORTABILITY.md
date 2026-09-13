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

`scripts/check-windows-platform.sh` now sweeps the **whole tree** -- every source in `src/`, `tests/` and
`apps/` -- with the include paths and the one define CMake gives them, and they all compile for Windows: 73 + 99
sources. That is the claim a runner needs before it is worth adding, measured rather than hoped for. The sweep
found two more defects that clang had been silent about: a dead local `wt_webtransport_capsule_t` in
`src/webtransport/capsule.c` (GCC's `-Wunused-but-set-variable`, which clang does not diagnose) and a unit test
comparing a platform handle with `-1` rather than the sentinel. It also showed why an ad-hoc loop is not a
check: eight files "failed" only because the loop omitted the include paths and the trust-fixture define CMake
supplies.

**The tree also LINKS for Windows.** `scripts/check-windows-build.sh` configures the whole tree with
`cmake/toolchains/mingw-w64.cmake` and a Windows OpenSSL (the MSYS2 package is a plain tarball, so no Windows
runner or MSYS2 installation is needed), and builds **86 PE32+ executables** plus `libwebtransport.dll`. CI runs
it on the Linux leg, where the cross-compiler is, and the step is no longer allowed to fail: it was
`continue-on-error` while nobody had seen it finish, and it has now been run to completion by hand -- which is
the only honest reason to enforce a job. Not run -- that needs Windows or Wine -- but linked.

**The link found a defect the compile could not**, and it is the kind only an optimiser sees: in a Release build
GCC could not prove that the loop writing `compression_methods[i]` from the peer's compression-methods length
stayed inside `compression_methods[4]`, and said so with `-Wstringop-overflow`. An explicit bound check did not
satisfy it, because the index came from a struct member -- and the right answer was to stop describing
generality the message does not have: a TLS 1.3 ClientHello's vector is ONE byte, so `src/tls/handshake.c` now
writes the byte by index, which is both inside the table and what RFC 8446 section 4.1.2 says.

**The compile sweep is LIVE, not decorative**: it caught a real warning the moment the session's capsule
scenarios landed -- `-Wformat-truncation` on a `snprintf` whose `%s` argument was the same size as its
destination, which clang accepts and mingw's GCC refuses (`apps/wt-conformance-c99/scenario_capsules.c` and
`scenario_refusal_wire.c` now bound the interpolation with a precision). A check that has never caught anything
is a check nobody has tested; this one is on its second real find.

What remains is the Windows RUNNER and FreeBSD, and both are now ONE thing: a way to RUN what already builds. The
tree compiles for Windows (73 + 99 sources, warnings-as-errors), links for Windows (86 PE32+ executables and a
shared library, enforced in CI), and the FreeBSD surface is the Debian one by the inventory. A job that cannot
pass is worse than an absent one, because it teaches people to ignore CI -- so the runner is named rather than
guessed at: Windows 11 needs OpenSSL there and something to execute the test binaries, FreeBSD needs a runner
GitHub does not provide natively, and neither is a code change this tree can make and verify from here.

## The two symbols this document is checked for

The checker greps for the POSIX-only calls that a port must replace: `fcntl`, `close`, `poll`, `recvmsg`,
`sendmsg`, `recvfrom`, `sendto`, `inet_pton` and `O_NONBLOCK`. Every occurrence of a POSIX-only name in the
library must appear in the table above, which is how the document stays complete as the code moves -- it caught
`sendto` and `recvfrom` missing on its first run, which is exactly the rot it exists to prevent.
