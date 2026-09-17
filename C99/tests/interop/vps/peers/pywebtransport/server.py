"""pywebtransport echo peer for the VPS interop matrix.

Uses a real CA-issued certificate rather than a generated self-signed one, so
the Swift client can validate it with platform system trust over a routable
network path. That is the property this matrix exists to prove and the one the
loopback container matrix cannot cover.
"""
import asyncio, logging, os

from pywebtransport import ServerApp, ServerConfig

PORT = int(os.environ.get("PORT", "54001"))
CERTFILE = os.environ["CERTFILE"]
KEYFILE = os.environ["KEYFILE"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("echo")

app = ServerApp(config=ServerConfig(
    bind_host="0.0.0.0",
    bind_port=PORT,
    certfile=CERTFILE,
    keyfile=KEYFILE,
))


@app.route("/")
async def echo(session) -> None:
    await session.ready()
    log.info("session ready")

    async def echo_datagrams() -> None:
        try:
            datagrams = session.datagrams
            if asyncio.iscoroutine(datagrams):
                datagrams = await datagrams
            while not session.is_closed:
                payload = await datagrams.receive()
                log.info("datagram in: %d bytes", len(payload))
                await datagrams.send(payload)
        except Exception as error:  # noqa: BLE001 - diagnostic peer
            log.info("datagram loop ended: %r", error)

    async def echo_streams() -> None:
        try:
            async for stream in session.incoming_streams():
                data = await stream.read_all()
                log.info("stream in: %d bytes", len(data))
                if hasattr(stream, "write"):
                    await stream.write(data, end_stream=True)
        except Exception as error:  # noqa: BLE001 - diagnostic peer
            log.info("stream loop ended: %r", error)

    await asyncio.gather(echo_datagrams(), echo_streams(), return_exceptions=True)


if __name__ == "__main__":
    log.info("pywebtransport echo listening on 0.0.0.0:%d with %s", PORT, CERTFILE)
    app.run()
