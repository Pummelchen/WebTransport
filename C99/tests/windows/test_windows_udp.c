/* The Windows datagram layer's RECEIVE CONTRACT, run rather than compiled (WT-199).
 *
 * Every other test in this tree reaches the socket layer through the public API and is compilable on POSIX.
 * This one includes the PRIVATE platform header and drives its two receive paths directly, for two reasons:
 *
 *   - the contract they share -- a datagram's sender and its truncation, reported rather than guessed -- is
 *     what `wt_udp_receive` is built on, and a failure here is diagnosable in one line where a failure two
 *     layers up is not; and
 *   - one of the two paths is a FALLBACK that a working provider never takes. `test_runtime_udp` cannot reach
 *     it on a machine whose `WSARecvMsg` works, and a fallback no test runs is a fallback nobody has tested --
 *     which is how the six-parameter prototype this branch once declared survived a cross-compile, a link and
 *     a review (`WT-199`).
 *
 * It runs on the loopback interface only, opening two real sockets per case and choosing both ports from the
 * kernel, so it needs no network, no privileges and no fixed port. `scripts/check-windows-wine.sh` runs it
 * under Wine on a Linux or macOS host; a Windows runner runs it natively.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED: the datagram's own length past the caller's buffer. A Windows peek cannot
 * see past it, so `WT_UDP_PLATFORM_FULL_LENGTH` is not honoured there, and the portability document records
 * why a listener must hold the datagram it looked at instead. Asserting it would be asserting a POSIX
 * behaviour on a platform that does not have it.
 */

#include <string.h>

#include "wt_test.h"

#include "udp_platform.h"

/* 127.0.0.1 as bytes, written out rather than taken from the platform: the addresses this file builds are this
 * library's own type, and the port is the kernel's. */
static const uint8_t k_loopback4[4] = {127U, 0U, 0U, 1U};

/* The two receive paths, so that one body of expectations can be applied to both. They have the same signature
 * because they answer the same contract; the fallback is the one a provider without a usable `WSARecvMsg`
 * takes (and the one Wine's own `WSARecvMsg` used to force, before the prototype in the header was corrected). */
typedef int (*wt_receive_path_t)(wt_udp_handle_t, wt_udp_platform_message_t *);

/* Every check below is the same check for two paths, so the label has to say WHICH path failed: reusing one
 * buffer to prefix it keeps a failure attributable without twenty duplicated strings. Single-threaded, like
 * every test in this tree, so one buffer is enough. */
static char wt_test_label[160];

static const char *label_for(const char *path, const char *what) {
  (void)snprintf(wt_test_label, sizeof(wt_test_label), "%s: %s", path, what);
  return wt_test_label;
}

/* One bound loopback socket, with the port the kernel chose. The platform layer deliberately has no `open` --
 * `udp.c` owns the socket lifetime -- so the test opens the socket the way `udp.c` does and keeps using the
 * platform's own API for everything the contract is about. */
static SOCKET open_bound_socket(int family, uint16_t *out_port) {
  struct sockaddr_storage storage;
  struct sockaddr_in address;
  struct sockaddr_in6 address6;
  const struct sockaddr *bound;
  int bound_length;
  SOCKET handle;
  int length;

  memset(&storage, 0, sizeof(storage));
  memset(&address, 0, sizeof(address));
  memset(&address6, 0, sizeof(address6));
  if (family == AF_INET6) {
    address6.sin6_family = AF_INET6;
    address6.sin6_addr = in6addr_loopback;
    bound = (const struct sockaddr *)(const void *)&address6;
    bound_length = (int)sizeof(address6);
  } else {
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(0x7f000001UL);
    bound = (const struct sockaddr *)(const void *)&address;
    bound_length = (int)sizeof(address);
  }

  handle = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  WT_EXPECT_TRUE("a loopback socket opens", handle != INVALID_SOCKET);
  WT_EXPECT_INT("and binds", 0, bind(handle, bound, bound_length));
  length = (int)sizeof(storage);
  WT_EXPECT_INT("and reports its port", 0, getsockname(handle, (struct sockaddr *)(void *)&storage, &length));
  *out_port = (uint16_t)ntohs(((struct sockaddr_in *)(void *)&storage)->sin_port);
  WT_EXPECT_TRUE("which the kernel chose", *out_port != 0U);
  /* Non-blocking, with a bounded wait before every receive, so a datagram that never arrives fails a check
   * rather than hanging the runner: a hang is the one result a Wine run cannot attribute. */
  WT_EXPECT_INT("and is non-blocking", 0, wt_udp_platform_set_nonblocking(handle));
  return handle;
}

/* The socket's own address as this library's type, so that "the sender is named" is a comparison rather than a
 * port number that happens to look right. */
static void local_address(SOCKET handle, wt_udp_address_t *out) {
  struct sockaddr_storage storage;
  int length = (int)sizeof(storage);

  memset(&storage, 0, sizeof(storage));
  WT_EXPECT_INT("the socket names its own address", 0,
                getsockname(handle, (struct sockaddr *)(void *)&storage, &length));
  WT_EXPECT_OK("which converts", wt_udp_platform_address_from_storage(
                                     (const struct sockaddr *)(const void *)&storage, (wt_udp_socklen_t)length,
                                     out));
}

/* One receive, with the wait that makes its absence a failed check rather than a hang. */
static int receive_now(SOCKET handle, wt_receive_path_t receive, wt_udp_platform_message_t *message) {
  WT_EXPECT_TRUE("the socket becomes readable", wt_udp_platform_wait_readable(handle, 2000) > 0);
  return receive(handle, message);
}

/* The expectations every path must meet, against one datagram size at a time. */
static void test_path(const char *path, wt_receive_path_t receive) {
  uint8_t datagram[64];
  uint8_t small[8];
  uint8_t large[64];
  struct sockaddr_storage to;
  struct sockaddr_storage from;
  wt_udp_address_t expected;
  wt_udp_address_t reported;
  wt_udp_address_t receiver;
  wt_udp_platform_message_t message;
  wt_udp_socklen_t to_length = 0;
  uint16_t listener_port = 0U;
  uint16_t sender_port = 0U;
  SOCKET listener;
  SOCKET sender;
  int from_length;
  size_t i;

  for (i = 0U; i < sizeof(datagram); i++) datagram[i] = (uint8_t)(0x40U + i);

  listener = open_bound_socket(AF_INET, &listener_port);
  sender = open_bound_socket(AF_INET, &sender_port);
  local_address(sender, &expected);

  /* The listener's address, built from this library's own type rather than from a raw `sockaddr`. */
  wt_udp_address_loopback(WT_UDP_IPV4, &receiver);
  WT_EXPECT_BYTES("the listener's address is the loopback", k_loopback4, receiver.bytes, 4U);
  receiver.port = listener_port;
  WT_EXPECT_OK(label_for(path, "and converts for the send"),
               wt_udp_platform_address_to_storage(&receiver, &to, &to_length));

  /* 1. A datagram that EXACTLY fills the buffer. This is the case a "the buffer came back full, so it must
   * have been truncated" guess gets wrong, and the reason the truncation is reported rather than inferred. */
  WT_EXPECT_OK(label_for(path, "a fitting datagram is sent"),
               wt_udp_platform_send_message(sender, (const struct sockaddr *)(const void *)&to, (int)to_length,
                                            datagram, sizeof(small), NULL));
  memset(&from, 0, sizeof(from));
  memset(&message, 0, sizeof(message));
  from_length = (int)sizeof(from);
  message.bytes = small;
  message.capacity = sizeof(small);
  message.address = &from;
  message.address_length = &from_length;
  WT_EXPECT_INT(label_for(path, "a datagram that exactly fills the buffer is received"), 0,
                receive_now(listener, receive, &message));
  WT_EXPECT_U64(label_for(path, "with its whole length"), (uint64_t)sizeof(small),
                (uint64_t)message.bytes_out);
  WT_EXPECT_INT(label_for(path, "and is NOT called truncated"), 0,
                message.flags_out & WT_UDP_PLATFORM_TRUNCATED);
  WT_EXPECT_BYTES(label_for(path, "with its bytes"), datagram, small, sizeof(small));
  WT_EXPECT_OK(label_for(path, "and the sender converts"),
               wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&from,
                                                    (wt_udp_socklen_t)from_length, &reported));
  WT_EXPECT_INT(label_for(path, "which is the socket that sent it"), 1,
                wt_udp_address_equal(&reported, &expected));

  /* 2. A datagram LARGER than the buffer: the truncation is reported, the length is not, and the sender is
   * still named, because "who sent what I could not receive" is the useful half of the report (WT-36). */
  WT_EXPECT_OK(label_for(path, "an oversized datagram is sent"),
               wt_udp_platform_send_message(sender, (const struct sockaddr *)(const void *)&to, (int)to_length,
                                            large, sizeof(large), NULL));
  memset(&from, 0, sizeof(from));
  memset(&message, 0, sizeof(message));
  from_length = (int)sizeof(from);
  message.bytes = small;
  message.capacity = sizeof(small);
  message.address = &from;
  message.address_length = &from_length;
  WT_EXPECT_INT(label_for(path, "receiving it into a small buffer is a truncation"), 0,
                receive_now(listener, receive, &message));
  WT_EXPECT_INT(label_for(path, "which is flagged"), WT_UDP_PLATFORM_TRUNCATED,
                message.flags_out & WT_UDP_PLATFORM_TRUNCATED);
  WT_EXPECT_OK(label_for(path, "and the sender is still named"),
               wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&from,
                                                    (wt_udp_socklen_t)from_length, &reported));
  WT_EXPECT_INT(label_for(path, "byte for byte"), 1, wt_udp_address_equal(&reported, &expected));
  /* The buffer was filled, so the datagram was at least as long as it: the honest floor when the platform
   * cannot report past the buffer. */
  WT_EXPECT_TRUE(label_for(path, "and the reported length fills the buffer"),
                 message.bytes_out >= (size_t)sizeof(small));

  /* 3. A PEEK of a datagram that does not fit leaves it in the queue: the listener learns its peer from the
   * first datagram without consuming it, which is the whole reason `wt_udp_peek` exists. */
  WT_EXPECT_OK(label_for(path, "a datagram for the peek is sent"),
               wt_udp_platform_send_message(sender, (const struct sockaddr *)(const void *)&to, (int)to_length,
                                            large, sizeof(large), NULL));
  memset(&from, 0, sizeof(from));
  memset(&message, 0, sizeof(message));
  from_length = (int)sizeof(from);
  message.bytes = small;
  message.capacity = sizeof(small);
  message.address = &from;
  message.address_length = &from_length;
  message.flags_in = WT_UDP_PLATFORM_PEEK | WT_UDP_PLATFORM_FULL_LENGTH;
  WT_EXPECT_INT(label_for(path, "the peek reads it"), 0, receive_now(listener, receive, &message));
  WT_EXPECT_INT(label_for(path, "and reports the truncation"), WT_UDP_PLATFORM_TRUNCATED,
                message.flags_out & WT_UDP_PLATFORM_TRUNCATED);
  WT_EXPECT_OK(label_for(path, "naming the sender"),
               wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&from,
                                                    (wt_udp_socklen_t)from_length, &reported));
  WT_EXPECT_INT(label_for(path, "which is the sender"), 1, wt_udp_address_equal(&reported, &expected));

  /* The receive that follows proves the peek did not consume it, and gets the whole datagram this time. */
  memset(&message, 0, sizeof(message));
  from_length = (int)sizeof(from);
  message.bytes = large;
  message.capacity = sizeof(large);
  message.address = &from;
  message.address_length = &from_length;
  WT_EXPECT_INT(label_for(path, "and the datagram is still in the queue"), 0,
                receive_now(listener, receive, &message));
  WT_EXPECT_U64(label_for(path, "whole"), (uint64_t)sizeof(large), (uint64_t)message.bytes_out);
  WT_EXPECT_INT(label_for(path, "with no truncation"), 0,
                message.flags_out & WT_UDP_PLATFORM_TRUNCATED);
  WT_EXPECT_BYTES(label_for(path, "and its bytes"), large, (const uint8_t *)message.bytes, sizeof(large));

  /* 4. A PEEK of a datagram that FITS reports what it copied and names the sender, which is the case the
   * runtime listener actually runs for a 64-byte header prefix. */
  WT_EXPECT_OK(label_for(path, "a fitting datagram for the peek is sent"),
               wt_udp_platform_send_message(sender, (const struct sockaddr *)(const void *)&to, (int)to_length,
                                            datagram, sizeof(small), NULL));
  memset(&from, 0, sizeof(from));
  memset(&message, 0, sizeof(message));
  from_length = (int)sizeof(from);
  message.bytes = small;
  message.capacity = sizeof(small);
  message.address = &from;
  message.address_length = &from_length;
  message.flags_in = WT_UDP_PLATFORM_PEEK | WT_UDP_PLATFORM_FULL_LENGTH;
  WT_EXPECT_INT(label_for(path, "the peek reads it whole"), 0, receive_now(listener, receive, &message));
  WT_EXPECT_U64(label_for(path, "reporting every byte"), (uint64_t)sizeof(small),
                (uint64_t)message.bytes_out);
  WT_EXPECT_INT(label_for(path, "with no truncation"), 0,
                message.flags_out & WT_UDP_PLATFORM_TRUNCATED);
  WT_EXPECT_BYTES(label_for(path, "and its bytes"), datagram, small, sizeof(small));
  WT_EXPECT_OK(label_for(path, "and names the sender"),
               wt_udp_platform_address_from_storage((const struct sockaddr *)(const void *)&from,
                                                    (wt_udp_socklen_t)from_length, &reported));
  WT_EXPECT_INT(label_for(path, "byte for byte"), 1, wt_udp_address_equal(&reported, &expected));
  /* Consume it, so that each path starts and ends with an empty queue. */
  memset(&message, 0, sizeof(message));
  message.bytes = small;
  message.capacity = sizeof(small);
  WT_EXPECT_INT(label_for(path, "the peeked datagram is then consumed"), 0,
                receive_now(listener, receive, &message));

  wt_udp_platform_close(sender);
  wt_udp_platform_close(listener);
}

/* A closed handle must keep its OWN error rather than being read as "this provider has no extension". The
 * liveness probe that tells those two apart is one call, and this is the case it exists for. */
static void test_closed_handle(void) {
  struct sockaddr_storage from;
  wt_udp_platform_message_t message;
  uint8_t buffer[8];
  uint16_t port = 0U;
  SOCKET handle;
  int from_length = (int)sizeof(from);

  handle = open_bound_socket(AF_INET, &port);
  WT_EXPECT_INT("the handle closes", 0, wt_udp_platform_close(handle));

  memset(&from, 0, sizeof(from));
  memset(&message, 0, sizeof(message));
  message.bytes = buffer;
  message.capacity = sizeof(buffer);
  message.address = &from;
  message.address_length = &from_length;
  WT_EXPECT_INT("a receive on a closed handle fails", -1,
                wt_udp_platform_receive_message(handle, &message));
  WT_EXPECT_TRUE("with an error of its own", wt_udp_platform_last_error() != 0);
  WT_EXPECT_INT("and is not a socket", 0, wt_udp_platform_handle_is_socket(handle));
}

/* The REST of the branch's surface, named for a reason that is about compiling rather than about behaviour:
 * including the private header pulls in every helper it defines, and the tree's warnings-as-errors turn a
 * helper this translation unit does not call into `-Wunused-function`. `tests/windows/platform_probe.c` exists
 * for exactly that at COMPILE time; these calls assert on the same helpers, so the naming is not the only thing
 * they do -- and they are the Windows branch of the address and error conversions, which the POSIX suite
 * reaches through the public API instead. */
static void test_the_rest_of_the_surface(void) {
  uint8_t bytes[16];
  char text[64];
  SOCKET v6;

  WT_EXPECT_INT("IPv4 maps to its domain", AF_INET, wt_udp_platform_family_domain(WT_UDP_IPV4));
  WT_EXPECT_INT("and IPv6 to its own", AF_INET6, wt_udp_platform_family_domain(WT_UDP_IPV6));

  memset(bytes, 0, sizeof(bytes));
  WT_EXPECT_INT("a loopback literal parses", 1,
                wt_udp_platform_parse_address("127.0.0.1", AF_INET, bytes));
  WT_EXPECT_BYTES("to the four bytes it names", k_loopback4, bytes, 4U);
  WT_EXPECT_TRUE("a malformed one does not",
                 wt_udp_platform_parse_address("127.0.0.999", AF_INET, bytes) <= 0);

  WT_EXPECT_U64("and formats back", 9U,
                (uint64_t)wt_udp_platform_format_address(AF_INET, k_loopback4, text, sizeof(text)));
  WT_EXPECT_STR("as the literal it came from", "127.0.0.1", text);
  WT_EXPECT_U64("with no room for anything", 0U,
                (uint64_t)wt_udp_platform_format_address(AF_INET, k_loopback4, text, 0U));

  WT_EXPECT_INT("a would-block error is a retry", WT_ERR_AGAIN,
                wt_udp_platform_status_of_error(WSAEWOULDBLOCK));
  WT_EXPECT_INT("an oversized datagram is a limit", WT_ERR_LIMIT,
                wt_udp_platform_status_of_error(WSAEMSGSIZE));

  /* The option helper needs a socket of the family it is about, and a real one is the honest way to call it. */
  v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  WT_EXPECT_TRUE("an IPv6 socket opens", v6 != INVALID_SOCKET);
  WT_EXPECT_INT("and takes the v6-only option", 0, wt_udp_platform_set_v6_only(v6, 1));
  wt_udp_platform_close(v6);
}

int main(void) {
  WT_EXPECT_INT("the socket layer starts", 0, wt_udp_platform_acquire());

  /* BOTH paths, one body of expectations: the call a provider with the extension takes, and the fallback a
   * provider without it takes. */
  test_path("WSARecvMsg", wt_udp_platform_receive_message);
  test_path("recvfrom fallback", wt_udp_platform_recvfrom_message);
  test_closed_handle();
  test_the_rest_of_the_surface();

  wt_udp_platform_release();
  WT_TEST_MAIN_END("wt_windows_udp");
}
