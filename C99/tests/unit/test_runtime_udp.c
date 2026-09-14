/* The UDP socket surface.
 *
 * THIS IS THE ONE TEST IN THE TREE THAT USES THE REAL NETWORK, and it is a unit test rather than an
 * integration test because the thing under test is a syscall wrapper: a fake socket would test the
 * fake. It runs on the loopback interface only, opens two real sockets per case, and closes them, so
 * it needs no network, no privileges and no port that another process might hold -- every port here
 * is chosen by the kernel.
 *
 * THE TRUNCATION CASE IS THE ONE THAT MATTERS MOST (WT-36). A datagram larger than the receive buffer
 * must not look like a small datagram: QUIC would parse the prefix of a packet as a whole packet, and
 * a truncated packet is a different packet. The test sends one datagram that is too large on purpose
 * and requires WT_ERR_TRUNCATED with no length reported, while the peer's address is still filled in,
 * because "who sent what I could not receive" is the useful half of the report.
 */

#include <string.h>

#include "wt_test.h"

#include "webtransport/runtime/udp.h"

/* The two loopback addresses as bytes: 127.0.0.1 and ::1. Written out rather than taken from the
 * platform, because INADDR_LOOPBACK is BSD and not POSIX and a test that needed it would be testing
 * the platform's header rather than this library's bytes. */
static const uint8_t k_loopback4[4] = {127U, 0U, 0U, 1U};
static const uint8_t k_loopback6[16] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};

/* Two sockets of one family, both on loopback, with the receiver's address. The sender is bound too,
 * on a port the kernel picks, so that the address a receive reports can be checked against a known
 * source rather than against "some port". */
static void open_pair(wt_udp_family_t family, wt_udp_socket_t *receiver, wt_udp_socket_t *sender,
                      wt_udp_address_t *receiver_address, wt_udp_address_t *sender_address) {
  uint16_t port = 0U;

  WT_EXPECT_OK("the receiver opens", wt_udp_socket_open(receiver, family));
  WT_EXPECT_OK("and binds a loopback port", wt_udp_bind_loopback(receiver, 0U, &port));
  WT_EXPECT_TRUE("which the kernel chose", port != 0U);
  wt_udp_address_loopback(family, receiver_address);
  receiver_address->port = port;
  WT_EXPECT_U64("the receiver reports its port", (uint64_t)port, (uint64_t)receiver->port);

  WT_EXPECT_OK("the sender opens", wt_udp_socket_open(sender, family));
  WT_EXPECT_OK("and binds a loopback port", wt_udp_bind_loopback(sender, 0U, &port));
  wt_udp_address_loopback(family, sender_address);
  sender_address->port = port;
  WT_EXPECT_TRUE("the two ports differ", receiver->port != sender->port);
}

static void test_addresses(void) {
  wt_udp_address_t address;
  wt_udp_address_t other;
  char text[80];

  /* IPv4. */
  WT_EXPECT_OK("an IPv4 address parses", wt_udp_address_parse("127.0.0.1", 443U, &address));
  WT_EXPECT_U64("as IPv4", (uint64_t)WT_UDP_IPV4, (uint64_t)address.family);
  WT_EXPECT_U64("with its port", 443U, (uint64_t)address.port);
  WT_EXPECT_BYTES("and its four bytes", k_loopback4, address.bytes, 4U);
  WT_EXPECT_U64("with no scope", 0U, (uint64_t)address.scope_id);

  /* IPv6, both spellings of the loopback. */
  WT_EXPECT_OK("an IPv6 address parses", wt_udp_address_parse("::1", 80U, &address));
  WT_EXPECT_U64("as IPv6", (uint64_t)WT_UDP_IPV6, (uint64_t)address.family);
  WT_EXPECT_BYTES("as fifteen zero bytes and a one", k_loopback6, address.bytes, 16U);
  WT_EXPECT_OK("and so does its long form",
               wt_udp_address_parse("0:0:0:0:0:0:0:1", 80U, &other));
  WT_EXPECT_INT("which is the same address", 1, wt_udp_address_equal(&address, &other));

  /* The scope id is part of a link-local address, and it is carried rather than dropped. */
  WT_EXPECT_OK("a scoped address parses", wt_udp_address_parse("fe80::1%4", 1234U, &address));
  WT_EXPECT_U64("with its scope", 4U, (uint64_t)address.scope_id);
  WT_EXPECT_U64("and its port", 1234U, (uint64_t)address.port);
  WT_EXPECT_OK("which formats back", wt_udp_address_parse("fe80::1%4", 1234U, &other));
  WT_EXPECT_U64("as text", 16U, (uint64_t)wt_udp_address_format(&other, text, sizeof(text)));
  WT_EXPECT_STR("with the scope written as a percent and a number", "[fe80::1%4]:1234", text);
  WT_EXPECT_OK("and parses back from that text",
               wt_udp_address_parse_host_port("[fe80::1%4]:1234", &other));
  WT_EXPECT_INT("to the same address", 1, wt_udp_address_equal(&address, &other));

  /* A scope on an address that is not per-interface is a mistake, not a decoration. */
  WT_EXPECT_STATUS("a scope on a global address is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse("2001:db8::1%4", 1U, &address));
  WT_EXPECT_STATUS("and an empty one", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse("fe80::1%", 1U, &address));

  /* Malformed text. */
  WT_EXPECT_STATUS("an empty address is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse("", 1U, &address));
  WT_EXPECT_STATUS("a name is refused, because there is no resolver here",
                   WT_ERR_INVALID_ARGUMENT, wt_udp_address_parse("localhost", 1U, &address));
  WT_EXPECT_STATUS("a truncated IPv4 address is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse("127.0.0", 1U, &address));
  WT_EXPECT_STATUS("an out-of-range octet is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse("127.0.0.256", 1U, &address));
  WT_EXPECT_STATUS("a truncated IPv6 address is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse("2001:db8", 1U, &address));
  WT_EXPECT_STATUS("and a null pointer is", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse(NULL, 1U, &address));

  /* host:port, with the brackets a colon in an IPv6 address forces. */
  WT_EXPECT_OK("a host and port parse", wt_udp_address_parse_host_port("127.0.0.1:8443", &address));
  WT_EXPECT_U64("with the port", 8443U, (uint64_t)address.port);
  WT_EXPECT_OK("an IPv6 host and port parse",
               wt_udp_address_parse_host_port("[2001:db8::1]:443", &address));
  WT_EXPECT_U64("with the port", 443U, (uint64_t)address.port);
  WT_EXPECT_U64("and the address", 1U, (uint64_t)(address.bytes[0] == 0x20U));
  WT_EXPECT_STATUS("a port is required", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse_host_port("127.0.0.1", &address));
  WT_EXPECT_STATUS("an empty port is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse_host_port("127.0.0.1:", &address));
  WT_EXPECT_STATUS("a port above the range is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse_host_port("127.0.0.1:65536", &address));
  WT_EXPECT_STATUS("a port that is not a number is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse_host_port("127.0.0.1:http", &address));
  WT_EXPECT_STATUS("an unbracketed IPv6 address with a port is refused as ambiguous",
                   WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse_host_port("2001:db8::1:443", &address));
  WT_EXPECT_STATUS("an unclosed bracket is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_address_parse_host_port("[2001:db8::1", &address));

  /* Formatting: the length is what the address needs, whether or not it fitted, and a truncated
   * buffer is still terminated. */
  WT_EXPECT_OK("an address formats", wt_udp_address_parse("192.0.2.7", 53U, &address));
  WT_EXPECT_U64("to its text", 12U, (uint64_t)wt_udp_address_format(&address, text, sizeof(text)));
  WT_EXPECT_STR("which is the address and the port", "192.0.2.7:53", text);
  WT_EXPECT_U64("and the length is reported even into a buffer too small",
                12U, (uint64_t)wt_udp_address_format(&address, text, 4U));
  WT_EXPECT_U64("where the text is cut", 3U, (uint64_t)strlen(text));
  WT_EXPECT_OK("an IPv6 address formats with brackets",
               wt_udp_address_parse("2001:db8::1", 443U, &address));
  WT_EXPECT_U64("to its text", 17U, (uint64_t)wt_udp_address_format(&address, text, sizeof(text)));
  WT_EXPECT_STR("with the port outside the brackets", "[2001:db8::1]:443", text);

  /* Equality is the whole address, not a prefix: a connection keyed on one that ignored the port or
   * the scope would be a different connection. */
  WT_EXPECT_OK("one address", wt_udp_address_parse("192.0.2.7", 53U, &address));
  WT_EXPECT_OK("the same one", wt_udp_address_parse("192.0.2.7", 53U, &other));
  WT_EXPECT_INT("are equal", 1, wt_udp_address_equal(&address, &other));
  WT_EXPECT_OK("a different port", wt_udp_address_parse("192.0.2.7", 54U, &other));
  WT_EXPECT_INT("is not", 0, wt_udp_address_equal(&address, &other));
  WT_EXPECT_OK("a different address", wt_udp_address_parse("192.0.2.8", 53U, &other));
  WT_EXPECT_INT("is not either", 0, wt_udp_address_equal(&address, &other));
  WT_EXPECT_OK("and so is the other family", wt_udp_address_parse("::1", 53U, &other));
  WT_EXPECT_INT("which is not equal", 0, wt_udp_address_equal(&address, &other));
  WT_EXPECT_INT("nor is a null", 0, wt_udp_address_equal(&address, NULL));

  /* The loopback helper, which is what a test or a local client binds. */
  wt_udp_address_loopback(WT_UDP_IPV4, &address);
  WT_EXPECT_BYTES("the IPv4 loopback is 127.0.0.1", k_loopback4, address.bytes, 4U);
  wt_udp_address_loopback(WT_UDP_IPV6, &address);
  WT_EXPECT_BYTES("and the IPv6 one is ::1", k_loopback6, address.bytes, 16U);
  WT_EXPECT_STR("the families are named", "ipv4", wt_udp_family_name(WT_UDP_IPV4));
  WT_EXPECT_STR("both of them", "ipv6", wt_udp_family_name(WT_UDP_IPV6));
  WT_EXPECT_STR("and a value that is not one is not", "unknown",
                wt_udp_family_name((wt_udp_family_t)9));
}

static void test_round_trip(wt_udp_family_t family) {
  wt_udp_socket_t receiver;
  wt_udp_socket_t sender;
  wt_udp_address_t receiver_address;
  wt_udp_address_t sender_address;
  wt_udp_address_t from;
  uint8_t buffer[64];
  uint8_t message[5] = {1U, 2U, 3U, 4U, 5U};
  size_t length = 0U;

  open_pair(family, &receiver, &sender, &receiver_address, &sender_address);

  /* Nothing has been sent, so there is nothing to read, and a non-blocking socket says so rather than
   * blocking the caller's loop. */
  memset(&from, 0, sizeof(from));
  WT_EXPECT_STATUS("an empty socket has nothing to receive", WT_ERR_AGAIN,
                   wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  WT_EXPECT_U64("and no length is reported", 0U, (uint64_t)length);

  /* A wait with a deadline returns the timeout rather than the datagram. */
  WT_EXPECT_STATUS("a wait with nothing to read times out", WT_ERR_TIMEOUT,
                   wt_udp_wait(&receiver, 2000U));

  WT_EXPECT_OK("a datagram is sent",
               wt_udp_send(&sender, &receiver_address, message, sizeof(message)));
  WT_EXPECT_OK("and the socket becomes readable", wt_udp_wait(&receiver, 2000000U));

  memset(&from, 0, sizeof(from));
  WT_EXPECT_OK("it is received",
               wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  WT_EXPECT_U64("whole", (uint64_t)sizeof(message), (uint64_t)length);
  WT_EXPECT_BYTES("with the bytes that were sent", message, buffer, sizeof(message));
  WT_EXPECT_INT("from the address it was sent from", 1,
                wt_udp_address_equal(&from, &sender_address));

  /* A zero-length datagram is legal in UDP, and it must not be confused with having received
   * nothing: the length is zero and the status is ok. */
  WT_EXPECT_OK("an empty datagram is sent", wt_udp_send(&sender, &receiver_address, NULL, 0U));
  WT_EXPECT_OK("and the socket becomes readable", wt_udp_wait(&receiver, 2000000U));
  length = 99U;
  memset(&from, 0, sizeof(from));
  WT_EXPECT_OK("it is received",
               wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  WT_EXPECT_U64("as an empty datagram", 0U, (uint64_t)length);

  /* Datagrams do not merge: two sends are two receives, in order on loopback. */
  WT_EXPECT_OK("two datagrams are sent",
               wt_udp_send(&sender, &receiver_address, message, 2U));
  WT_EXPECT_OK("one after the other",
               wt_udp_send(&sender, &receiver_address, message + 2U, 3U));
  WT_EXPECT_OK("the first is waiting", wt_udp_wait(&receiver, 2000000U));
  WT_EXPECT_OK("and read", wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  WT_EXPECT_U64("as two bytes", 2U, (uint64_t)length);
  WT_EXPECT_OK("the second is waiting", wt_udp_wait(&receiver, 2000000U));
  WT_EXPECT_OK("and read", wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  WT_EXPECT_U64("as three bytes", 3U, (uint64_t)length);

  wt_udp_close(&sender);
  wt_udp_close(&receiver);
}

/* The PEEK's contract, which is the part of this file that differs by platform and was therefore the part
 * nothing asserted: the Windows-only test measures the `_WIN32` branch, and on POSIX there was no peek test at
 * all, so a header promising "the datagram's own length" passed while macOS returned the copied count.
 *
 * What is asserted here is what holds on EVERY platform: a peek of a datagram larger than the buffer reports a
 * full buffer, never a length below what it copied, the bytes are the datagram's own prefix, the sender is
 * named -- and the datagram is still in the queue afterwards, which is the property a listener depends on.
 * Whether `out_length` is the datagram's own length (Linux) or the copied count (macOS, the BSDs) is documented
 * in `webtransport/runtime/udp.h` rather than asserted, because a test that pinned one of them would fail on
 * the other platform for being right. */
static void test_peek(wt_udp_family_t family) {
  wt_udp_socket_t receiver;
  wt_udp_socket_t sender;
  wt_udp_address_t receiver_address;
  wt_udp_address_t sender_address;
  wt_udp_address_t from;
  uint8_t large[2000];
  uint8_t small[16];
  uint8_t buffer[100];
  size_t length = 0U;
  size_t available = 0U;
  size_t i;

  for (i = 0U; i < sizeof(large); i++) large[i] = (uint8_t)(i & 0xffU);
  for (i = 0U; i < sizeof(small); i++) small[i] = (uint8_t)(0x80U + i);

  open_pair(family, &receiver, &sender, &receiver_address, &sender_address);

  /* A datagram that FITS: both lengths are its size, and it is still there afterwards. */
  WT_EXPECT_OK("a datagram that fits is sent", wt_udp_send(&sender, &receiver_address, small, sizeof(small)));
  WT_EXPECT_OK("and the socket becomes readable", wt_udp_wait(&receiver, 2000000U));
  length = 99U;
  available = 99U;
  memset(&from, 0, sizeof(from));
  WT_EXPECT_OK("a peek looks at it", wt_udp_peek(&receiver, buffer, sizeof(buffer), &length, &available, &from));
  WT_EXPECT_U64("reporting its length", (uint64_t)sizeof(small), (uint64_t)length);
  WT_EXPECT_U64("and all of it available", (uint64_t)sizeof(small), (uint64_t)available);
  WT_EXPECT_BYTES("with its bytes", small, buffer, sizeof(small));
  WT_EXPECT_INT("and the sender named", 1, wt_udp_address_equal(&from, &sender_address));
  length = 0U;
  WT_EXPECT_OK("and the peek did not consume it",
               wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  WT_EXPECT_U64("which the receive gets whole", (uint64_t)sizeof(small), (uint64_t)length);

  /* A datagram LARGER than the buffer: the invariants above hold, and the queue is untouched. */
  WT_EXPECT_OK("a datagram larger than the buffer is sent",
               wt_udp_send(&sender, &receiver_address, large, sizeof(large)));
  WT_EXPECT_OK("and the socket becomes readable", wt_udp_wait(&receiver, 2000000U));
  length = 99U;
  available = 99U;
  memset(&from, 0, sizeof(from));
  WT_EXPECT_OK("a peek looks at it too",
               wt_udp_peek(&receiver, buffer, sizeof(buffer), &length, &available, &from));
  WT_EXPECT_U64("a full buffer is reported", (uint64_t)sizeof(buffer), (uint64_t)available);
  WT_EXPECT_TRUE("and the datagram's length is never BELOW what was copied", length >= available);
  WT_EXPECT_BYTES("the bytes are the datagram's own prefix", large, buffer, sizeof(buffer));
  WT_EXPECT_INT("and the sender is named", 1, wt_udp_address_equal(&from, &sender_address));
  {
    uint8_t whole[2048];
    length = 0U;
    memset(&from, 0, sizeof(from));
    WT_EXPECT_OK("the oversized datagram is STILL in the queue",
                 wt_udp_receive(&receiver, whole, sizeof(whole), &length, &from));
    WT_EXPECT_U64("whole", (uint64_t)sizeof(large), (uint64_t)length);
    WT_EXPECT_BYTES("with its bytes", large, whole, sizeof(large));
  }

  wt_udp_close(&sender);
  wt_udp_close(&receiver);
}

/* A datagram larger than the buffer is refused as a truncation with nothing usable in it. */
static void test_truncation(wt_udp_family_t family) {
  wt_udp_socket_t receiver;
  wt_udp_socket_t sender;
  wt_udp_address_t receiver_address;
  wt_udp_address_t sender_address;
  wt_udp_address_t from;
  uint8_t large[2000];
  uint8_t buffer[100];
  size_t length = 0U;
  size_t i;

  for (i = 0U; i < sizeof(large); i++) large[i] = (uint8_t)(i & 0xffU);

  open_pair(family, &receiver, &sender, &receiver_address, &sender_address);
  WT_EXPECT_OK("a datagram larger than the buffer is sent",
               wt_udp_send(&sender, &receiver_address, large, sizeof(large)));
  WT_EXPECT_OK("and the socket becomes readable", wt_udp_wait(&receiver, 2000000U));

  length = 99U;
  memset(&from, 0, sizeof(from));
  WT_EXPECT_STATUS("receiving it into a small buffer is a truncation", WT_ERR_TRUNCATED,
                   wt_udp_receive(&receiver, buffer, sizeof(buffer), &length, &from));
  /* The length is zeroed rather than left standing: a caller that used a stale value would parse the
   * prefix of a datagram as one, and the truncation would become a parsing bug. */
  WT_EXPECT_U64("and no length is reported", 0U, (uint64_t)length);
  WT_EXPECT_INT("the sender is still named", 1, wt_udp_address_equal(&from, &sender_address));

  /* The same datagram into a buffer that can hold it is fine, which is what proves the refusal above
   * was the buffer and not the datagram. */
  {
    uint8_t big[2048];
    WT_EXPECT_OK("a second datagram of the same size is sent",
                 wt_udp_send(&sender, &receiver_address, large, sizeof(large)));
    WT_EXPECT_OK("and the socket becomes readable", wt_udp_wait(&receiver, 2000000U));
    length = 0U;
    WT_EXPECT_OK("it is received whole",
                 wt_udp_receive(&receiver, big, sizeof(big), &length, &from));
    WT_EXPECT_U64("with its whole length", (uint64_t)sizeof(large), (uint64_t)length);
    WT_EXPECT_BYTES("and its bytes", large, big, sizeof(large));
  }

  wt_udp_close(&sender);
  wt_udp_close(&receiver);
}

static void test_refusals(void) {
  wt_udp_socket_t socket;
  wt_udp_socket_t other;
  wt_udp_address_t address;
  wt_udp_address_t receiver_address;
  uint8_t buffer[8];
  size_t length = 0U;
  uint16_t port = 0U;

  wt_udp_address_loopback(WT_UDP_IPV4, &receiver_address);
  memset(&address, 0, sizeof(address));

  /* A family this layer does not carry, and a null output. */
  WT_EXPECT_STATUS("a third family is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_socket_open(&socket, (wt_udp_family_t)2));
  WT_EXPECT_STATUS("and no output is", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_socket_open(NULL, WT_UDP_IPV4));

  /* A socket that was never opened, and one that was closed, are both a state error rather than a
   * crash or a descriptor that another part of the process now owns. */
  memset(&socket, 0, sizeof(socket));
  socket.fd = -1;
  WT_EXPECT_STATUS("binding an unopened socket is a state error", WT_ERR_STATE,
                   wt_udp_bind_loopback(&socket, 0U, &port));
  WT_EXPECT_STATUS("sending on it is too", WT_ERR_STATE,
                   wt_udp_send(&socket, &receiver_address, buffer, 1U));
  WT_EXPECT_STATUS("and receiving on it", WT_ERR_STATE,
                   wt_udp_receive(&socket, buffer, sizeof(buffer), &length, &receiver_address));
  WT_EXPECT_STATUS("and waiting on it", WT_ERR_STATE, wt_udp_wait(&socket, 0U));

  WT_EXPECT_OK("an IPv4 socket opens", wt_udp_socket_open(&socket, WT_UDP_IPV4));
  WT_EXPECT_OK("and binds", wt_udp_bind_loopback(&socket, 0U, &port));

  /* An address of the other family cannot be used on this socket: the families are separate on
   * purpose, so this is a caller error rather than a dual-stack send. */
  WT_EXPECT_OK("an IPv6 address", wt_udp_address_parse("::1", 9U, &address));
  WT_EXPECT_STATUS("sent on an IPv4 socket is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_send(&socket, &address, buffer, 1U));
  WT_EXPECT_STATUS("and bound on it", WT_ERR_INVALID_ARGUMENT, wt_udp_bind(&socket, &address));

  /* A datagram larger than UDP can carry is refused before the syscall. */
  wt_udp_address_loopback(WT_UDP_IPV4, &address);
  address.port = port;
  WT_EXPECT_STATUS("a datagram above the UDP maximum is a limit", WT_ERR_LIMIT,
                   wt_udp_send(&socket, &address, buffer, (size_t)WT_UDP_MAX_DATAGRAM + 1U));

  /* Arguments. */
  WT_EXPECT_STATUS("a null socket is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_send(NULL, &address, buffer, 1U));
  WT_EXPECT_STATUS("a null address is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_send(&socket, NULL, buffer, 1U));
  WT_EXPECT_STATUS("a null payload with a length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_send(&socket, &address, NULL, 1U));
  WT_EXPECT_STATUS("a null buffer is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_receive(&socket, NULL, sizeof(buffer), &length, &receiver_address));
  WT_EXPECT_STATUS("a null length is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_receive(&socket, buffer, sizeof(buffer), NULL, &receiver_address));
  WT_EXPECT_STATUS("a null port is refused", WT_ERR_INVALID_ARGUMENT,
                   wt_udp_local_port(&socket, NULL));

  /* Closing twice is safe, and the second close must not close a descriptor that has been reused: the
   * field is cleared by the first. */
  wt_udp_close(&socket);
  /* The SENTINEL rather than -1: the field holds a platform handle, which is a small signed descriptor on POSIX
   * and a pointer-sized unsigned SOCKET on Windows whose invalid value is all ones. `WT_UDP_INVALID_FD` is both
   * of those, and the GCC cross-compile is what insisted on saying so. */
  WT_EXPECT_TRUE("the descriptor is cleared", socket.fd == WT_UDP_INVALID_FD);
  wt_udp_close(&socket);
  WT_EXPECT_TRUE("and closing again is harmless", socket.fd == WT_UDP_INVALID_FD);
  wt_udp_close(NULL);

  /* Two sockets of different families coexist, which is what the runtime will do when a client is
   * given an IPv6 address and a server is listening on both. */
  WT_EXPECT_OK("an IPv6 socket opens", wt_udp_socket_open(&other, WT_UDP_IPV6));
  WT_EXPECT_OK("and binds its own loopback", wt_udp_bind_loopback(&other, 0U, &port));
  wt_udp_address_loopback(WT_UDP_IPV6, &receiver_address);
  receiver_address.port = port;
  WT_EXPECT_OK("a datagram is sent to it",
               wt_udp_send(&other, &receiver_address, buffer, sizeof(buffer)));
  WT_EXPECT_OK("and read back", wt_udp_wait(&other, 2000000U));
  WT_EXPECT_OK("whole", wt_udp_receive(&other, buffer, sizeof(buffer), &length, &address));
  WT_EXPECT_U64("with its length", (uint64_t)sizeof(buffer), (uint64_t)length);
  WT_EXPECT_INT("from itself, on the loopback", 1,
                wt_udp_address_equal(&address, &receiver_address));
  wt_udp_close(&other);
}

int main(void) {
  test_addresses();
  test_round_trip(WT_UDP_IPV4);
  test_round_trip(WT_UDP_IPV6);
  test_truncation(WT_UDP_IPV4);
  test_truncation(WT_UDP_IPV6);
  test_peek(WT_UDP_IPV4);
  test_peek(WT_UDP_IPV6);
  test_refusals();

  WT_TEST_MAIN_END("wt_runtime_udp");
}
