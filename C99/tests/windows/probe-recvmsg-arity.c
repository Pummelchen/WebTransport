/* Which `WSARecvMsg` prototype the provider actually implements (WT-199).
 *
 * This is a PROBE rather than a test: it asserts nothing, prints both calls' results, and exists because
 * `src/runtime/udp_platform.h` makes a claim that no compiler in this tree can check -- that the extension
 * function takes FIVE parameters and carries its flags in `WSAMSG.dwFlags`, and that a hand-written
 * six-parameter declaration with an `lpdwFlags` argument calls a function that is not there.
 *
 * Run it under Wine (`x86_64-w64-mingw32-gcc probe-recvmsg-arity.c -o probe-recvmsg-arity.exe -lws2_32`, then
 * the Wine binary) or on Windows; nothing in the build runs it.
 *
 * What it measured, on the Wine used for this tree, against ONE provider and ONE datagram at a time:
 *
 *   ioctl: ok bytes=8 pointer=...          (the extension pointer is handed out)
 *   5-arg, 9 into 64    : rc=0 err=0 received=9 ... namelen=16 family=2
 *   6-arg, 9 into 64    : rc=-1 err=10038  (WSAENOTSOCK) received=0 namelen=128 family=0
 *   5-arg peek 9 into 4 : rc=-1 err=10040  (WSAEMSGSIZE) namelen=16 family=2
 *   5-arg after that peek: rc=0 received=9  (the peek did NOT consume the datagram)
 *
 * The first two lines are the whole point: the DOCUMENTED call receives the datagram with its sender, and the
 * six-parameter call is answered with `WSAENOTSOCK` while leaving the queue untouched -- the `&flags` argument
 * lands in `lpOverlapped`, so the provider is being asked for an overlapped receive it was never given an
 * OVERLAPPED for. `mswsock.h`'s own `LPFN_WSARECVMSG` is the five-parameter one, which is why the library now
 * uses that typedef instead of a copy.
 */
#include <mswsock.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* The documented prototype: exactly mingw's own `LPFN_WSARECVMSG`. */
typedef INT(WINAPI *recvmsg5_fn)(SOCKET, LPWSAMSG, LPDWORD, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);
/* The signature this tree used to declare by hand, for the contrast. */
typedef INT(WINAPI *recvmsg6_fn)(SOCKET, LPWSAMSG, LPDWORD, LPDWORD, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static SOCKET a, b;
static struct sockaddr_in addr;

static void send_bytes(const char *bytes, int length) {
  sendto(b, bytes, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

static void call5(const char *label, recvmsg5_fn fn, int peek, int capacity) {
  char buf[64];
  struct sockaddr_storage from;
  WSABUF buffer;
  WSAMSG msg;
  DWORD received = 0;
  int rc;

  memset(&from, 0, sizeof(from));
  buffer.buf = buf;
  buffer.len = (ULONG)capacity;
  memset(&msg, 0, sizeof(msg));
  msg.name = (struct sockaddr *)(void *)&from;
  msg.namelen = (INT)sizeof(from);
  msg.lpBuffers = &buffer;
  msg.dwBufferCount = 1;
  /* INPUT: MSG_PEEK belongs HERE, in the structure, per the documented prototype. */
  msg.dwFlags = peek ? MSG_PEEK : 0;
  WSASetLastError(0);
  rc = fn(a, &msg, &received, NULL, NULL);
  printf("%s: rc=%d err=%d received=%lu dwFlags=0x%lx (MSG_TRUNC=%d) namelen=%d family=%d\n", label,
         rc, WSAGetLastError(), (unsigned long)received, (unsigned long)msg.dwFlags,
         (msg.dwFlags & MSG_TRUNC) != 0, (int)msg.namelen, from.ss_family);
}

static void call6(const char *label, recvmsg6_fn fn, int peek, int capacity) {
  char buf[64];
  struct sockaddr_storage from;
  WSABUF buffer;
  WSAMSG msg;
  DWORD received = 0;
  DWORD flags = peek ? MSG_PEEK : 0;
  int rc;

  memset(&from, 0, sizeof(from));
  buffer.buf = buf;
  buffer.len = (ULONG)capacity;
  memset(&msg, 0, sizeof(msg));
  msg.name = (struct sockaddr *)(void *)&from;
  msg.namelen = (INT)sizeof(from);
  msg.lpBuffers = &buffer;
  msg.dwBufferCount = 1;
  WSASetLastError(0);
  rc = fn(a, &msg, &received, &flags, NULL, NULL);
  printf("%s: rc=%d err=%d received=%lu outflags=0x%lx msg.dwFlags=0x%lx namelen=%d family=%d\n",
         label, rc, WSAGetLastError(), (unsigned long)received, (unsigned long)flags,
         (unsigned long)msg.dwFlags, (int)msg.namelen, from.ss_family);
}

int main(void) {
  WSADATA data;
  recvmsg5_fn five = NULL;
  int local_len = (int)sizeof(addr);
  GUID guid = WSAID_WSARECVMSG;
  DWORD bytes = 0;

  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
    printf("WSAStartup failed\n");
    return 1;
  }
  a = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  b = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(0x7f000001);
  if (bind(a, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    printf("bind failed\n");
    return 1;
  }
  if (getsockname(a, (struct sockaddr *)&addr, &local_len) != 0) {
    printf("getsockname failed\n");
    return 1;
  }

  if (WSAIoctl(a, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, (DWORD)sizeof(guid), &five,
               (DWORD)sizeof(five), &bytes, NULL, NULL) == SOCKET_ERROR) {
    printf("ioctl: FAILED err=%d\n", WSAGetLastError());
    return 1;
  }
  printf("ioctl: ok bytes=%lu pointer=%p\n", (unsigned long)bytes, (void *)five);

  /* 1. A datagram that fits, five parameters. */
  send_bytes("123456789", 9);
  call5("5-arg, 9 into 64    ", five, 0, 64);

  /* 2. The same, through the six-parameter signature the tree declared by hand. */
  send_bytes("123456789", 9);
  call6("6-arg, 9 into 64    ", (recvmsg6_fn)(void *)five, 0, 64);

  /* 3. A PEEK of a datagram that does NOT fit, five parameters: MSG_PEEK in the structure. */
  send_bytes("123456789", 9);
  call5("5-arg peek 9 into 4 ", five, 1, 4);
  /* If the peek did not consume it, this reads the same datagram back. */
  call5("5-arg after that peek", five, 0, 64);

  /* 4. The same peek through the six-parameter call, to see where MSG_PEEK ends up. */
  send_bytes("123456789", 9);
  call6("6-arg peek 9 into 4 ", (recvmsg6_fn)(void *)five, 1, 4);
  call5("5-arg after that peek", five, 0, 64);

  WSACleanup();
  return 0;
}
