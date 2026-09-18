#!/usr/bin/env python3
"""Make the `web-transport-quinn` peer ADVERTISE datagram support, by vendoring the crate.

WHY
---
The Phase 11 matrix's quinn datagram proof fails with `status=timeout`, and the reason is in the peer
library rather than in the peer's configuration. `web-transport-quinn` 0.11.9's `ServerBuilder`
exposes only `new`, `with_addr`, `with_congestion_control` and `with_certificate`, and
`with_certificate` builds `quinn::ServerConfig::with_crypto(..)` and hands it straight to
`quinn::Endpoint::server` -- so the transport config is quinn's default and
`datagram_receive_buffer_size` is never set. There is no setter for it in that version.

A conforming client will not send a datagram to a peer that has not advertised one, which is the
correct behaviour and exactly what our client does. So the peer has to change, and the smallest
correct change is to set the transport parameter where the endpoint is built.

This vendors the crate and patches that one place, rather than bypassing `ServerBuilder` and
reimplementing the peer's endpoint setup, because the rest of the builder (rustls provider, ALPN,
the WebTransport handshake) should stay exactly as the library wrote it.

Run from the quinn peer's source directory (the one holding Cargo.toml and src/main.rs).
"""

import pathlib
import shutil
import subprocess
import sys

CRATE = "web-transport-quinn"
VERSION = "0.11.9"

OLD = """        let config: quinn::crypto::rustls::QuicServerConfig = config.try_into().unwrap();
        let config = quinn::ServerConfig::with_crypto(Arc::new(config));

        let server = quinn::Endpoint::server(config, self.addr)"""

NEW = """        let config: quinn::crypto::rustls::QuicServerConfig = config.try_into().unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(config));

        // A conforming WebTransport client will not send a datagram to a peer that has not
        // ADVERTISED support, and in quinn the advertisement is the transport parameter that
        // `datagram_receive_buffer_size(Some(..))` sets. This builder never set it, so the peer
        // accepted sessions and echoed streams while silently refusing datagrams -- which the interop
        // matrix reported as `status=timeout` for the quinn datagram proof (WT-198).
        //
        // Vendored rather than worked around: the rest of the setup (rustls provider, ALPN, the
        // WebTransport handshake) stays exactly as the library wrote it.
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(65536));
        transport.datagram_send_buffer_size(65536);
        config.transport_config(Arc::new(transport));

        let server = quinn::Endpoint::server(config, self.addr)"""

PATCH_SECTION = f"""
# WT-198: the vendored {CRATE} with datagram support advertised. See ../VENDORED.md.
[patch.crates-io]
{CRATE} = {{ path = "vendor/{CRATE}" }}
"""


def main() -> int:
    peer = pathlib.Path.cwd()
    manifest = peer / "Cargo.toml"
    if not manifest.exists():
        print("patch: no Cargo.toml here; run from the quinn peer's source directory", file=sys.stderr)
        return 2

    vendor = peer / "vendor" / CRATE
    if vendor.exists():
        print("patch: already vendored")
    else:
        # `cargo vendor` would pull the whole dependency graph; only this crate is patched, so fetch
        # its published source and keep it, letting every other dependency resolve normally.
        tmp = peer / "vendor" / f"{CRATE}-{VERSION}"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        archive = tmp.parent / f"{CRATE}-{VERSION}.crate"
        subprocess.run(
            [
                "curl",
                "-sL",
                "-A",
                "interop-vendor/1.0",
                f"https://static.crates.io/crates/{CRATE}/{CRATE}-{VERSION}.crate",
                "-o",
                str(archive),
            ],
            check=True,
        )
        subprocess.run(["tar", "xzf", str(archive), "-C", str(tmp.parent)], check=True)
        archive.unlink()
        shutil.move(str(tmp), str(vendor))
        print(f"patch: vendored {CRATE} {VERSION}")

    server_rs = vendor / "src" / "server.rs"
    text = server_rs.read_text()
    if "datagram_receive_buffer_size" in text:
        print("patch: crate source already patched")
    else:
        if OLD not in text:
            print("patch: the with_certificate anchor was not found -- the crate has changed", file=sys.stderr)
            return 2
        server_rs.write_text(text.replace(OLD, NEW, 1))
        print("patch: datagram support advertised in the vendored crate")

    manifest_text = manifest.read_text()
    if "[patch.crates-io]" in manifest_text:
        print("patch: Cargo.toml already carries the patch section")
    else:
        manifest.write_text(manifest_text.rstrip("\n") + "\n" + PATCH_SECTION)
        print("patch: Cargo.toml now points at the vendored crate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
