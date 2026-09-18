/* A packet the peer lost: the relay pair and what the loss hook saw (WT-135). */

#include "test_runtime_session_pair_internal.h"

/* What the lost-frame hook saw. The relay test installs this on the client, so the dropped CONNECT is reported
 * to the layer that sent it rather than to the handshake alone -- which is the difference between "the bytes are
 * gone" and "the bytes are owed" (WT-135). */
typedef struct lost_log {
  unsigned calls;
  unsigned non_crypto;
  size_t last_length;
} lost_log_t;

static void on_lost_frame(void *context, const wt_quic_tx_frame_t *frame) {
  lost_log_t *log = context;
  if (log == NULL || frame == NULL) return;
  log->calls++;
  if (!frame->is_crypto) {
    log->non_crypto++;
    log->last_length = frame->length;
  }
}

/* A packet the peer LOST is retransmitted.
 *
 * This is the property the interop peer exercised first and this tree could not test at all: every other test
 * here runs over loopback with no loss, so "the peer never read it" was an environment no test produced
 * (WT-135). The relay sits between the two ends on a third socket: both ends address IT, it learns the client's
 * address from the first packet that is not the server's, and it forwards -- except the one datagram it is told
 * to drop.
 */
void test_a_lost_packet_is_retransmitted(void) {
  pair_t pair;
  wt_udp_socket_t relay;
  wt_udp_address_t relay_address;
  wt_udp_address_t client_address;
  int client_known = 0;
  unsigned from_client = 0U;
  unsigned drop_this = 0U;
  unsigned round;
  int saw_drop = 0;
  lost_log_t lost;

  memset(&pair, 0, sizeof(pair));
  memset(&lost, 0, sizeof(lost));
  open_socket(&relay, &relay_address);
  /* Both ends address the relay; the server learns the relay as its peer from the first packet it sees. */
  arm_pair_to(&pair, &relay_address, &relay_address);
  WT_EXPECT_OK("the layer behind the handshake is told about lost frames",
               wt_runtime_session_set_lost_frame_handler(&pair.client, on_lost_frame, &lost));

  for (round = 0U; round < 600U; round++) {
    uint8_t datagram[2048];
    size_t length = 0U;
    wt_udp_address_t from;

    /* WAIT for the relay before spending a round. Every datagram in this test passes through it -- both ends
     * address it -- so it is the one place a wait paces the loop, and without one this loop spins faster than
     * loopback delivers: it spent all 600 rounds before the handshake's first packet arrived and failed about one
     * run in five. That is the same rule `pump_pair` states for the direct pair ("a loop that spun faster than the
     * loopback interface would finish before the first Initial packet did"), and this loop was the exception
     * (WT-163). */
    (void)wt_udp_wait(&relay, 2000U);
    (void)wt_runtime_session_pump(&pair.client, pair.now);
    (void)wt_runtime_session_pump(&pair.server, pair.now);
    pair.now += 1000U;
    while (wt_udp_receive(&relay, datagram, sizeof(datagram), &length, &from) == WT_OK) {
      int to_server = wt_udp_address_equal(&from, &pair.server_address) == 0;
      if (to_server) {
        client_address = from;
        client_known = 1;
        from_client++;
        if (drop_this != 0U && from_client == drop_this) {
          saw_drop = 1;
          continue; /* lost on the way */
        }
      }
      if (to_server) {
        (void)wt_udp_send(&relay, &pair.server_address, datagram, length);
      } else if (client_known != 0) {
        (void)wt_udp_send(&relay, &client_address, datagram, length);
      }
    }

    /* Once the handshake is done, the NEXT packet the client sends is the CONNECT: drop it, and the
     * exchange can only complete if the client sends it again. */
    if (drop_this == 0U && both_established(&pair) != 0) drop_this = from_client + 1U;
    if (saw_drop != 0 && connect_arrived(&pair) != 0) break;
  }

  WT_EXPECT_TRUE("the handshake completes through the relay",
                 wt_runtime_session_established(&pair.client) != 0);
  WT_EXPECT_TRUE("the CONNECT was sent and one packet was dropped", saw_drop != 0);
  /* THE ASSERTION THIS TEST WANTS TO MAKE, and cannot yet: the exchange should complete because the client
   * retransmits. It does not, and that is the defect the interop peer has been showing all along -- the CONNECT
   * is dropped once and never sent again, so the peer waits for a request that will never arrive (WT-135).
   *
   * It is asserted in the direction it is TRUE today, with the measurement either side, so the tree stays green
   * and the reproduction stays in it. The line flips to `connect_arrived(&pair) != 0` on the day the
   * retransmission lands, and this comment goes with it. */
  /* THE SECOND MEASUREMENT, and it is not what the hook was added for: the hook is installed and it is NEVER
   * CALLED. So the dropped CONNECT is not merely unresendable -- its LOSS IS NEVER REPORTED, which means the
   * probe timeout never fired for the application space at all. Written in the direction that is true today, for
   * the same reason as the assertion below: the suite stays green, the reproduction stays in the tree, and the
   * lines flip when the loss path works (WT-135). */
  /* THE THIRD MEASUREMENT, and it eliminates the second candidate outright: NO packet is declared lost in ANY
   * space. So the loss is not "declared with nothing to name" -- the loss detector never runs, which leaves the
   * timer arithmetic (or the arming of the loss module) as the thing to read next. The counters are in the
   * connection, so this is a fact the tree keeps rather than a print in a test (WT-135). */
  /* THE FOURTH MEASUREMENT, and it names the defect: the client HAS outstanding ack-eliciting packets (the
   * dropped CONNECT among them) and the loss list remembers six -- but the application space's RTT estimator
   * has NO SAMPLE AT ALL (has_sample = 0), because the peer never acknowledged anything in that space. With no
   * sample there is no time-threshold loss time, so nothing is ever declared lost; and a probe timeout, when it
   * fires, sends a PING rather than the outstanding data. RFC 9002 section 6.2.4 says a PTO MUST send new frames
   * or RETRANSMIT unacknowledged data, so the probe path is where the fix goes (WT-135). */
  WT_EXPECT_TRUE("the dropped CONNECT is still outstanding",
                 pair.client.connection.loss.ack_eliciting_in_flight >= 1U);
  WT_EXPECT_TRUE("the loss list remembers the packets it sent",
                 pair.client.connection.loss.count > 0U);
  WT_EXPECT_TRUE(
      "and the application space has no RTT sample, so there is no loss time to reach (WT-135)",
      pair.client.connection.spaces[WT_QUIC_SPACE_APPLICATION].rtt.has_sample == 0);
  WT_EXPECT_U64("no packet is declared lost in the initial space", 0U,
                (uint64_t)pair.client.connection.packets_declared_lost[WT_QUIC_SPACE_INITIAL]);
  WT_EXPECT_U64("nor the handshake space", 0U,
                (uint64_t)pair.client.connection.packets_declared_lost[WT_QUIC_SPACE_HANDSHAKE]);
  WT_EXPECT_TRUE("nor the application space, where the dropped CONNECT is (WT-135)",
                 pair.client.connection.packets_declared_lost[WT_QUIC_SPACE_APPLICATION] == 0U);
  WT_EXPECT_U64("and nothing was lost with a missing descriptor", 0U,
                (uint64_t)pair.client.connection.lost_without_descriptor);
  WT_EXPECT_TRUE("the lost stream frame is NOT reported yet: the application space never armed its "
                 "probe (WT-135)",
                 lost.non_crypto == 0U);
  WT_EXPECT_TRUE("the exchange did NOT complete, because nothing resends it yet (WT-135)",
                 connect_arrived(&pair) == 0);

  wt_runtime_session_clear(&pair.client);
  wt_runtime_session_clear(&pair.server);
  wt_udp_close(&pair.client_socket);
  wt_udp_close(&pair.server_socket);
  wt_udp_close(&relay);
}
