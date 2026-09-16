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
| Creating a socket | `socket` | exists in Winsock, but only after `WSAStartup`, and it returns a `SOCKET` |
| Binding | `bind` | exists in Winsock with the same name and the same `sockaddr` shape |
| Socket options | `setsockopt`, `getsockopt` | the same names; the option value is `const char *` on Windows and `const void *` on POSIX, and the length type differs |
| Closing | `close` | `closesocket` |
| Non-blocking mode | `fcntl(fd, F_SETFL, O_NONBLOCK)` | `ioctlsocket(fd, FIONBIO, &one)`, a different function with a different failure mode |
| Readiness | `poll` | `WSAPoll` (same shape, `pollfd` spelled the same way) |
| Errors | `errno` | `WSAGetLastError`, and the socket error numbers are a different set |
| Scatter/gather | `struct iovec`, `recvmsg`/`sendmsg` | `WSABUF`, and `WSARecvMsg` for a receive that carries the sender, the datagram's own length and its truncation, reached through `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_WSARECVMSG)` |
| `MSG_PEEK`/`MSG_TRUNC` | `wt_udp_peek` | `MSG_PEEK` exists and travels in `WSAMSG.dwFlags` (the input flag of `WSARecvMsg`, whose prototype is five parameters); a datagram larger than the buffer comes back as the ERROR `WSAEMSGSIZE` with the sender filled, and there is no way to ask for the datagram's own length past the caller's buffer, so the peek needs the receive-then-hold shape instead (the runtime session already has the pending table an implementation would need). **This is not a Windows-only difference**, which is worth saying because this document said it was: `MSG_TRUNC` as an INPUT flag is Linux-specific, so macOS and the BSDs also report the copied count rather than the datagram's own length. `webtransport/runtime/udp.h` states the contract per platform and the POSIX suite asserts the invariants that hold on all of them |
| Sending and receiving | `sendto`/`recvfrom` in the datagram paths | `WSASendTo` for the send, `WSARecvMsg` for the receive, and `recvfrom` as the fallback for a provider whose `WSARecvMsg` is unusable -- it reports the sender and the truncation correctly, and cannot see past the buffer on a peek |
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
   **And that paragraph was fiction for a round**: the count was declared `static` inside EACH function, which
   is two objects, so `release` decremented its own zero and returned early and `WSACleanup` was unreachable
   while `acquire`'s count grew forever. An adversarial audit found it by replicating the two bodies. The count
   is at file scope now, and the fix is a reminder that "the last close releases Winsock" is a claim about a
   VARIABLE, not about a design.
3. The `wt_udp_peek` difference, which is behavioural rather than syntactic and is now named in the header
   rather than discovered: on Windows a peek cannot see past the caller's buffer, so the `FULL_LENGTH` flag
   cannot be honoured there and a listener must hold the datagram it looked at. The runtime session's pending
   table is the shape that needs. **Measured, not assumed**: `tests/windows/test_windows_udp.c` asserts the
   rest of the receive contract on a real pair of loopback sockets, on both receive paths, and deliberately
   does NOT assert the length past the buffer, because that is the behaviour this platform does not have.
4. A CMake branch that links `ws2_32` (**DONE**) and finds OpenSSL, and a CI job that builds it.
5. **DONE** -- the receive itself. Windows has no `recvmsg`, so the datagram-with-sender comes from
   `WSARecvMsg`, an extension function reached through
   `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSAID_WSARECVMSG)`; `sendto` and `WSASendTo` are the same call
   with the arguments in a different order. The extension is OPTIONAL, so
   `wt_udp_platform_recvfrom_message` answers the call where a provider has no usable one, and it is a
   documented degradation rather than a second implementation: same sender, same truncation report, no
   `FULL_LENGTH`. `WT-199` is the defect that made this item real -- the first version declared the extension's
   prototype BY HAND, with a sixth `lpdwFlags` parameter that does not exist, so every call through it handed
   `&flags` to `lpOverlapped`; a cross-compile cannot see that (the declaration was this tree's own) and Wine
   answered `WSAENOTSOCK` to every receive, which is how it was found. The prototype is now the platform's own
   `LPFN_WSARECVMSG`, and the flags travel in `WSAMSG.dwFlags` where the documentation puts them.

**Status:** the inventory is complete and mechanically checked; the platform header is done and verified on
POSIX, where behaviour is unchanged; the socket lifetime and `ws2_32` are done; and the `_WIN32` branch is no
longer "written from the inventory" but **COMPILED, LINKED and RUN** -- under Wine, with its receive contract
asserted on both of its paths by its own test. The one claim that is still not made is the one this document
will not make for Wine: **it has not run on Windows itself.**

`scripts/check-windows-platform.sh` compiles the branch with a mingw cross-compiler under a **seven-flag subset**
of the project's warning set -- `-Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual` --
and reports `unsupported` with that reason on a machine that has none. CI installs one where it can. The FULL
project set (the twenty-four flags `cmake/WTCompilerWarnings.cmake` probes and applies to every target, with
`-Werror`) is what the Windows **build** enforces: `scripts/check-windows-build.sh` configures the tree with the
mingw toolchain and CMake, so every Windows translation unit is compiled under the same warnings-as-errors set
as POSIX. The sweep is the cheaper branch check; it is not the full set, and this document said it was.
**It found real defects, one after another, and each was a thing the inventory had not
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
`apps/` -- with the include paths and the one define CMake gives them, and they all compile for Windows: **76
library sources and 108 test, probe and app sources**, which is the script's own count (the compile-only
`tests/windows/platform_probe.c` is compiled by the earlier step instead). That is the claim a runner needs
before it is worth adding, measured rather than hoped for. The sweep found two more defects that clang had been
silent about: a dead local `wt_webtransport_capsule_t` in `src/webtransport/capsule.c` (GCC's
`-Wunused-but-set-variable`, which clang does not diagnose) and a unit test comparing a platform handle with
`-1` rather than the sentinel. It also showed why an ad-hoc loop is not a check: eight files "failed" only
because the loop omitted the include paths and the trust-fixture define CMake supplies.

**The tree also LINKS for Windows.** `scripts/check-windows-build.sh` configures the whole tree with
`cmake/toolchains/mingw-w64.cmake` and a Windows OpenSSL (the MSYS2 package is a plain tarball, so no Windows
runner or MSYS2 installation is needed), and builds **91 PE32+ executables** plus `libwebtransport.dll` -- the
count is the script's own, and the two that are not test or app binaries are CMake's compiler probe and the
Windows-only datagram test. CI runs it on the Linux leg, where the cross-compiler is, and the step is no longer
allowed to fail: it was `continue-on-error` while nobody had seen it finish, and it has now been run to
completion by hand -- which is the only honest reason to enforce a job. It is also no longer only linked:
`scripts/check-windows-wine.sh` is the sibling that RUNS the result, and the paragraph further down is its
aggregate.

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

**The tree RUNS for Windows, under Wine.** `scripts/check-windows-wine.sh` executes every linked test binary
through Wine and reports the aggregate. On the VPS, with the mingw cross-build: **85 test executables ran, 85
passed, 0 failed, 0 hung; the runner sums the per-binary check counts and reports 64,900 checks.** (The same
runner reports 64,778 checks over 84 programs natively on Debian 13; the difference is the Windows-only datagram
test plus the per-platform counts a few tests assert.) That is the
claim the section above could not make — "linked, not run" — and it is the first time this tree has executed on
a Windows target at all. The count moved twice since the first Wine run, and both moves are the point of the
paragraphs below: **84 → 85** because a new Windows-only test now measures the datagram layer directly, and
**82 of 84 passing → 85 of 85** because running the tree found real defects.

> **Correction (2026-09-16, `F-repo-ops-22`).** This paragraph previously read "reports 91,674 checks". That
> number was never one the runner produced: the summing was added with a `$`-anchored pattern, Wine writes the
> Windows binary's stdout as CRLF, so the pattern matched nothing and the runner printed **0 checks** while also
> printing "85 executable(s) printed no check total (a hang or a load failure)". Measured at the commit that
> introduced the summing (`a2d995e`: `ran 85 ... 0 checks`) and on the merged tree. The pattern now reads through
> `tr -d '\r'`, a missing total fails the run instead of being counted, and the numbers above are the measured
> ones. Nothing else in this section changes.

**And running it found three defects that linking could not.** They are the whole reason a runner is worth
having, and all three are fixed and re-measured rather than recorded:

- **`test_runtime_udp`, 6 of 177 checks** — the datagram-truncation contract of `WT-36` did not hold on the
  `_WIN32` socket branch: `receiving it into a small buffer is a truncation` wanted `truncated` and got `limit`,
  the sender was not named where it should be, and a later read wanted `ok` and 8 bytes and got `truncated` and
  0. `WT-199`.
- **`test_quic_connection`, 6 of 2276 checks** — the Retry path (`WT-168`) failed two assertions on Windows:
  `the destination is the Retry's Source Connection ID, byte for byte` and `and the TOKEN is on the wire as the
  peer sent it` were both `expected true`, with four further checks following from them. `WT-200`. Nothing in
  that path is endian- or alignment-dependent, and the cause turned out to be the same receive path as the item
  above: a Retry's acceptance depends on reading datagrams the old receive was dropping or mis-reporting.
- **The extension's prototype, declared by hand.** `WSARecvMsg` has FIVE parameters and carries `MSG_PEEK` and
  `MSG_TRUNC` in `WSAMSG.dwFlags`. The first version of `wt_udp_platform_receive_message` declared its own
  six-parameter signature with an `lpdwFlags` argument — the shape `WSASendMsg` has — and called the provider
  with `&flags` in the `lpOverlapped` position. **The compile sweep could not see it, because the declaration
  was this tree's own**, and Wine answered `WSAENOTSOCK` to every such receive. It is the clearest case in this
  document of a claim a compiler cannot check: a hand-copied prototype of somebody else's ABI is only checked
  against itself. `#include <mswsock.h>` already declares `LPFN_WSARECVMSG`, and the code now calls through
  `WSAIoctl` with `WSAID_WSARECVMSG` and uses the platform's own typedef.

**The three fixes are measured, not asserted.** With the fallback compiled OUT, so that only the `WSARecvMsg`
path can answer, `test_runtime_udp` passes all 177 checks and `test_quic_connection` all 2276 — which is what
makes "the documented prototype works" a measurement rather than a reading of the documentation. And the
fallback itself is covered by the new `tests/windows/test_windows_udp.c`, which drives **both** receive paths
against a real pair of loopback sockets and asserts the shared contract on each: a datagram that exactly fills
the buffer is not called truncated, an oversized one is, the sender is named on both paths, and a peek leaves
the datagram in the queue. It is registered only where `WIN32` is true, so the POSIX suite's list is unchanged.
`WT-199` and `WT-200` are closed in the [[Project Tracker|Project-Tracker]]; what remains open is the Windows
RUNNER (`WT-224`, an enforced native Windows CI leg), because Wine is a faithful Win32 implementation and not Windows: everything here is **under Wine** until
a Windows machine says otherwise, and the WSARecvMsg path in particular is one Wine happens to answer correctly.

**The measurements themselves are in the tree**, because the code's comments quote them.
`tests/windows/probe-recvfrom.c` and `tests/windows/probe-recvmsg-arity.c` assert nothing and print what the
provider answers; they were written in a scratch directory, and a claim that points at a scratch file is a claim
nobody can re-run. The compile sweep builds them with the same warnings-as-errors as everything else, and
`scripts/check-windows-wine.sh` does not run them -- they are evidence, not tests, and the tests they support
are `test_windows_udp` and `test_runtime_udp`.

**Two setup facts cost a session, so they are written down.** `wine64` is not on `PATH` on Ubuntu or Debian —
the package ships no wrapper and the binary is `/usr/lib/wine/wine64`, so `wine64 --version` is "command not
found" while the runtime is installed. And a test executable imports **two** DLL sets: the target's OpenSSL
*and* the tree's own `libwebtransport.dll`. Wine resolves a PE's imports from the executable's own directory
first, so a missing DLL there is a load failure — status `c0000135`, whose low byte is the silent `rc=53` every
test reported on the first run, with the reason only visible on stderr under a debug channel. Both are handled
by the script, and the `WINEPREFIX` is initialized with a bounded `wineboot -u` before any test runs, so a hang
is attributable to a test rather than to first-use setup.

**The tree also RUNS on FreeBSD.** A FreeBSD 15.1-RELEASE-p3 guest (`GENERIC` amd64) on this host, booted
under QEMU with TCG because the host exposes no nested virtualisation, builds the tree with its base system's
clang 19.1.7 plus `cmake` and `ninja` from packages, and then passes the whole suite: **96 of 96 CTest tests**,
including the ten that spawn both CLI tools and exchange over a real socket in two processes.

**Running there found one thing, and it is in the test harness rather than in the tree.** The first pass failed
8 of 96 — every `wt_cli_*` process test — and the reason was in the failure output rather than in the protocol:
`check-cli-session.sh: python3: not found`, followed by `a report is not valid JSON`. The sessions themselves
had **worked**: the client reported `status=ok`, `established=true`, `responseStatus=200`, `receivedBytes=4`,
and the server reported the same. Those scripts parse the tools' JSON reports with `python3`, which is **not in
FreeBSD's base system**, so an absent interpreter read as a protocol failure. With `pkg install python3` the
same ten tests pass and nothing else changes. That is a real dependency the scripts have and do not declare,
and it is recorded as `WT-201` rather than papered over — a check that reports "the protocol is broken" when it
means "this host has no python3" is the shape of failure this document exists to prevent.

What remains is a **runner this project does not control**. The tree compiles for Windows (76 + 108 sources,
warnings-as-errors), links for Windows (91 PE32+ executables and a shared library, enforced in CI), and now
executes for Windows: **85 of 85 test executables green under Wine**. It builds and passes its whole suite on
FreeBSD. What is missing is a CI *job* for each (`WT-223` FreeBSD, `WT-224` Windows), because GitHub provides no FreeBSD runner and the Windows leg
can only compile, link and (via Wine) run on a Linux runner. A job that cannot pass is worse than an absent one,
because it teaches people to ignore CI — so the gap is named rather than guessed at, and the evidence that a
Windows or FreeBSD runner would have something green to run is now in this document rather than in an inventory.

## The two symbols this document is checked for

The checker greps for the POSIX-only calls that a port must replace: `fcntl`, `close`, `poll`, `recvmsg`,
`sendmsg`, `recvfrom`, `sendto`, `inet_pton` and `O_NONBLOCK`. Every occurrence of a POSIX-only name in the
library must appear in the table above, which is how the document stays complete as the code moves -- it caught
`sendto` and `recvfrom` missing on its first run, which is exactly the rot it exists to prevent.
