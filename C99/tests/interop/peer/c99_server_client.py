"""A third-party WebTransport CLIENT against this tree's server (WT-153).

The other interop runner drives this tree's client against somebody else's server, and that direction found seven
real defects. Nothing has ever driven a third-party client against `wt-server-c99`, so every server-side defect --
including a server that accepted only its own connection ID and would therefore have refused any client that chose
its own -- was found by reading code rather than by talking to a peer. This is the mirror: pywebtransport's client
(aioquic underneath) opens a session with the C99 server, sends a message on a bidirectional stream, and reports
what the server sends back.

It says what it did on stdout as JSON, because the runner asserts on that rather than on a log line.

Usage:  c99_server_client.py --host 127.0.0.1 --port 54060 --path / --message hello-from-peer [--timeout 8]
"""

import argparse
import asyncio
import json
import sys

from pywebtransport import ClientConfig, WebTransportClient


async def collect_server_message(session, timeout):
    """The message the C99 server sends on a stream IT opens, or b"" when none arrives."""
    try:
        # A server-initiated bidirectional stream reaches the client through the session's incoming streams.
        incoming = await asyncio.wait_for(session.incoming_streams().__anext__(), timeout=timeout)
        return await asyncio.wait_for(incoming.read_all(), timeout=timeout)
    except (asyncio.TimeoutError, StopAsyncIteration):
        return b""


async def run(host, port, path, message, timeout):
    """Connect, send the message, and wait for the server's own message on a stream it opens."""
    report = {
        "role": "peer-client",
        "url": "https://%s:%d%s" % (host, port, path),
        "established": False,
        "sentBytes": 0,
        "receivedBytes": 0,
        "received": None,
        "error": None,
    }
    # The C99 server's certificate is the self-signed one `--listen` generates, so this is the development
    # configuration: verification off, which a pinned or system-trust client would replace.
    config = ClientConfig.create_for_development(verify_ssl=False)
    config.connect_timeout = timeout
    config.read_timeout = timeout
    # `create` is a plain factory; the async context is what starts the client's connection manager, so the
    # client is used with `async with` rather than awaited.
    client = WebTransportClient.create(config=config)
    async with client:
        try:
            session = await client.connect("https://%s:%d%s" % (host, port, path), timeout=timeout)
            report["established"] = True

            stream = await session.create_bidirectional_stream()
            await stream.write(message.encode(), end_stream=True)
            report["sentBytes"] = len(message)

            data = await collect_server_message(session, timeout)
            report["receivedBytes"] = len(data)
            report["received"] = data.decode("utf-8", "replace")

            await session.close(code=0, reason="")
        except Exception as error:  # noqa: BLE001 - a diagnostic client reports, it does not decide
            report["error"] = "%s: %s" % (type(error).__name__, error)
    return report


def main():
    parser = argparse.ArgumentParser(description="A third-party WebTransport client for wt-server-c99 (WT-153).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--message", default="hello-from-peer")
    parser.add_argument("--timeout", type=float, default=8.0)
    options = parser.parse_args()

    report = asyncio.run(run(options.host, options.port, options.path, options.message, options.timeout))
    print(json.dumps(report))
    return 0 if report["established"] and report["receivedBytes"] > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
