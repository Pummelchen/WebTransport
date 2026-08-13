"""Minimal WebTransport echo server built on pywebtransport.

Stands in for the third-party pywebtransport/aioquic peer that the VPS interop
matrix normally provides, so the Swift client can be validated against an
independent implementation locally. It echoes bidirectional stream payloads and
datagrams back verbatim, which is what run-vps-third-party-interop.sh asserts.
"""

import asyncio
import logging
import os

from pywebtransport import create_development_server

PORT = int(os.environ.get("PORT", "54001"))
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("echo")

app = create_development_server(host="0.0.0.0", port=PORT, generate_certs=True)


@app.route("/")
async def echo(session) -> None:
    await session.ready()
    log.info("session ready path=%s", session.path)

    async def echo_datagrams() -> None:
        try:
            # `datagrams` is a property returning the duplex stream, not a coroutine.
            datagrams = session.datagrams
            if asyncio.iscoroutine(datagrams):
                datagrams = await datagrams
            while not session.is_closed:
                payload = await datagrams.receive()
                log.info("datagram in: %d bytes", len(payload))
                await datagrams.send(payload)
                log.info("datagram echoed")
        except Exception as error:  # noqa: BLE001 - diagnostic server
            log.info("datagram loop ended: %r", error)

    async def echo_streams() -> None:
        try:
            async for stream in session.incoming_streams():
                data = await stream.read_all()
                log.info("stream in: %d bytes", len(data))
                # Unidirectional streams have no send side; only echo on bidi.
                if hasattr(stream, "write"):
                    await stream.write(data, end_stream=True)
                    log.info("stream echoed")
        except Exception as error:  # noqa: BLE001 - diagnostic server
            log.info("stream loop ended: %r", error)

    await asyncio.gather(echo_datagrams(), echo_streams(), return_exceptions=True)


if __name__ == "__main__":
    log.info("pywebtransport echo server listening on 0.0.0.0:%d", PORT)
    app.run()
