"""The smallest aioquic peer that completes a handshake and writes a KEYLOG (WT-135).

The differential test needs the peer's OWN view of its traffic secrets, and pywebtransport's development server has
no configuration passthrough to ask for one. This is the same library (aioquic) with the two things that matter for
the test and nothing else: it completes the TLS handshake, and it writes an NSS keylog.

It does not serve WebTransport: the C99 client's request will go unanswered, and that is fine -- the question is the
handshake secret, which is settled long before a request.

Usage: python aioquic_peer.py <port> <cert-dir> <keylog-path>
"""

import asyncio
import os
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicFileLogger


class Quiet(QuicConnectionProtocol):
    """A protocol that does nothing: the handshake is aioquic's, and the point is the keylog."""

    def quic_event_received(self, event) -> None:  # noqa: D102 - aioquic's hook
        pass


async def main() -> None:
    port = int(sys.argv[1])
    cert_dir = sys.argv[2]
    keylog_path = sys.argv[3]

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(os.path.join(cert_dir, "cert.pem"), os.path.join(cert_dir, "key.pem"))
    # The whole reason this peer exists.
    configuration.secrets_log_file = open(keylog_path, "a")
    # And a qlog, which is the peer's own account of what it did with each packet -- including the ones it could
    # not read. It is the only artefact in this investigation that says WHY a packet was dropped rather than that
    # it was (WT-135).
    qlog_dir = os.path.join(os.path.dirname(keylog_path), "qlog")
    os.makedirs(qlog_dir, exist_ok=True)  # aioquic refuses a directory that does not exist, and says so
    configuration.quic_logger = QuicFileLogger(qlog_dir)

    await serve("0.0.0.0", port, configuration=configuration, create_protocol=Quiet)
    print(f"aioquic peer listening on {port}, keylog at {keylog_path}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
