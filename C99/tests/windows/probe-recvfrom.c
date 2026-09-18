/* What WINDOWS `recvfrom` does with a datagram larger than the buffer (WT-199).
 *
 * This is a PROBE rather than a test: it asserts nothing and prints what the provider answers, and it exists
 * because `src/runtime/udp_platform.h` makes three claims about `recvfrom` in its FALLBACK path that are worth
 * more as measurements than as reasoning. Run it under Wine (`x86_64-w64-mingw32-gcc probe-recvfrom.c -o
 * probe-recvfrom.exe -lws2_32`, then the Wine binary) or on Windows; nothing in the build runs it.
 *
 * What it measured, on the Wine used for this tree:
 *
 *   1. a datagram that EXACTLY fills the buffer returns its full count with NO error -- so a datagram filling
 *      the buffer is not evidence of truncation, and is why the truncation is taken from the error rather than
 *      guessed from the count;
 *   2. a datagram that does not fit FAILS with `WSAEMSGSIZE`, consumes the datagram, AND still fills the
 *      sender's address -- which is what lets the fallback report both the truncation and who sent it;
 *   3. the same with `MSG_PEEK` fails the same way and leaves the datagram in the queue, so a listener can look
 *      at a datagram without consuming it;
 *   4. a NULL buffer with a zero length is NOT `WSAEFAULT`: it is `WSAEMSGSIZE` and it consumes the datagram,
 *      which is the shape the layer's zero-capacity case has.
 */
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static SOCKET a, b;
static struct sockaddr_in addr;

static void fill_queue(int count) {
  int i;
  for (i = 0; i < count; i++)
    sendto(b, "123456789", 9, 0, (struct sockaddr *)&addr, sizeof(addr));
}

int main(void) {
  WSADATA data;
  struct sockaddr_in from;
  int addr_len = (int)sizeof(addr);
  int from_len;
  char buf[64];
  char one = 0;
  int rc;

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
  if (getsockname(a, (struct sockaddr *)&addr, &addr_len) != 0) {
    printf("getsockname failed\n");
    return 1;
  }

  printf("--- 1: a 4-byte datagram into a 4-byte buffer (must be OK, not truncated) ---\n");
  sendto(b, "abcd", 4, 0, (struct sockaddr *)&addr, sizeof(addr));
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 4, 0, (struct sockaddr *)&from, &from_len);
  printf("rc=%d err=%d from_family=%d from_port=%u\n", rc, WSAGetLastError(), from.sin_family,
         (unsigned)ntohs(from.sin_port));

  printf("--- 2: a 9-byte datagram into a 4-byte buffer ---\n");
  sendto(b, "123456789", 9, 0, (struct sockaddr *)&addr, sizeof(addr));
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 4, 0, (struct sockaddr *)&from, &from_len);
  printf("rc=%d err=%d (10040 is WSAEMSGSIZE) from_family=%d from_port=%u from_len=%d\n", rc,
         WSAGetLastError(), from.sin_family, (unsigned)ntohs(from.sin_port), from_len);

  printf(
      "--- 3: the same with MSG_PEEK, then two 64-byte receives (both must find a datagram) ---\n");
  fill_queue(2);
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 4, MSG_PEEK, (struct sockaddr *)&from, &from_len);
  printf("rc=%d err=%d from_family=%d from_port=%u from_len=%d\n", rc, WSAGetLastError(),
         from.sin_family, (unsigned)ntohs(from.sin_port), from_len);
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 64, 0, (struct sockaddr *)&from, &from_len);
  printf("after the peek: rc=%d err=%d\n", rc, WSAGetLastError());
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 64, 0, (struct sockaddr *)&from, &from_len);
  printf("and the next one: rc=%d err=%d\n", rc, WSAGetLastError());

  printf("--- 4: an EXACT-FIT datagram peeked into an exact-fit buffer, then received ---\n");
  sendto(b, "abcd", 4, 0, (struct sockaddr *)&addr, sizeof(addr));
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 4, MSG_PEEK, (struct sockaddr *)&from, &from_len);
  printf("peek 4 into 4: rc=%d err=%d from_family=%d\n", rc, WSAGetLastError(), from.sin_family);
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, buf, 4, 0, (struct sockaddr *)&from, &from_len);
  printf("then receive 4 into 4: rc=%d err=%d (10035 is WSAEWOULDBLOCK: the peek CONSUMED it)\n",
         rc, WSAGetLastError());

  printf("--- 5: a zero-length buffer, NULL and one stand-in byte (two datagrams, one for each "
         "call) ---\n");
  fill_queue(2);
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, NULL, 0, 0, (struct sockaddr *)&from, &from_len);
  printf("NULL,0: rc=%d err=%d from_family=%d\n", rc, WSAGetLastError(), from.sin_family);
  memset(&from, 0, sizeof(from));
  from_len = (int)sizeof(from);
  rc = recvfrom(a, &one, 0, 0, (struct sockaddr *)&from, &from_len);
  printf("&one,0: rc=%d err=%d from_family=%d from_len=%d\n", rc, WSAGetLastError(),
         from.sin_family, from_len);

  WSACleanup();
  return 0;
}
