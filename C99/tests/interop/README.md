# C99 interop material

Everything the C99 interoperability work needs beyond the test suite itself. Three
environments live here, and they prove different things:

- **`client/` + `peer/`** — the *container* matrix (`../scripts/run-container-interop.sh`):
  both ends on one Docker network with a self-signed certificate. It proves the
  protocol and nothing about trust, and it needs no host.
- **the same containers, the other way round** (`../scripts/run-container-interop-server.sh`):
  a third-party **client** against `wt-server-c99`, which is the direction the
  Phase 11 proofs do not cover. Two independent clients run it — pywebtransport/
  aioquic (`peer/c99_server_client.py`) and quic-go/webtransport-go
  (`peer/go-client/`) — because one implementation is not a matrix, and the
  second is what found WT-258.
- **`vps/`** — the *public-host* matrix (`../scripts/run-vps-third-party-interop.sh`):
  five independent implementations on a routable host, each presenting a
  CA-issued certificate, driven with `--trust system`. That is the Phase 11
  criterion: the chain is validated against the platform trust store and the
  certificate's name is checked rather than bypassed.

Neither the peer setup nor an interop result is reproducible without what is in
here, which is why the third-party build contexts, the patches they need and the
host-side scripts are all committed.

## The container matrix

`peer/` keeps the two patches the public peers need — `patch-erlang-chain.py`
(WT-196: `erlang-webtransport` sends only the leaf certificate unless the chain
rides inside `quic_opts`) and `patch-quinn-datagram.py` (WT-198:
`web-transport-quinn` 0.11.9 never advertises QUIC DATAGRAM) — together with the
diagnostic peers the investigations used (`server.py`, `aioquic_peer.py`,
`decrypt_packet.py`) and the two server-side clients above.

Both container runners build the C99 tools from `client/Dockerfile`, whose context
is the **repository root**: CMake reads `../VERSION` and refuses to configure
without it, so the file has to be copied next to the tree. Building with `C99/` as
the context does not work, and did not — the configure failed before anything was
compiled, and both runners had been building that way.

## The public-host (VPS) matrix

The five endpoints the C99 suite talks to are ports **54001/54002/54003/54005/54007**,
one per implementation, all reading the same CA-issued certificate files. They are
rebuilt and started from this repository by `deploy-vps-peers.sh` (WT-255); nothing
about the arrangement has to be typed by hand on the host.

```
vps/
  caddy/webtransport-interop.caddy   the certificate's Caddy project file (WT-254)
  caddy/README.md                    where it goes and why
  peers/pywebtransport/              the five third-party build contexts
  peers/quinn/  peers/quiche/  peers/h3/  peers/erlang/
  cron.d/webtransport-interop-certificates   the renewal sync's cron entry
```

### The certificate

The port-80 Caddy owns `:80`/`:443` and obtains and auto-renews the certificate
for the interop name from `vps/caddy/webtransport-interop.caddy`; see
`vps/caddy/README.md`. The peers cannot read Caddy's store, so they read copies at

```
/etc/letsencrypt/live/<authority>/fullchain.pem   # the long-running wt-* set
/var/wt-c99-interop/certs/                        # the internal wt2-* set
```

`sync-vps-peer-certificates.sh` copies the renewed pair to both paths and restarts
the ten peers when the bytes change (WT-196b). It is a no-op when the certificate
is unchanged, which is what the cron entry relies on:

```
/usr/local/sbin/webtransport-interop-sync-certificates
```

### Standing it up (fresh clone or rebuilt host)

```sh
sudo WEBTRANSPORT_VPS_INTEROP_AUTHORITY=<name> C99/tests/interop/deploy-vps-peers.sh
```

That builds all five images from `vps/peers/` (applying the two patches), starts
them with the certificate paths and the published UDP ports, and installs the
host-side units: `/usr/local/sbin/webtransport-interop-sync-certificates`,
`/usr/local/sbin/webtransport-interop-reset-peers` and
`/etc/cron.d/webtransport-interop-certificates`. The one thing it does not do is
obtain the certificate — the Caddy project file above has to be in place and
Caddy reloaded first, or every peer exits at startup on a missing file.

Measured on the host on 17 September 2026, and this is the point of the script: from a **fresh clone**
(`main` at `3bf3a3e`) with **no peer images, no base images and no build cache** — the five `wt-*`
images and the `python:3.12-slim`, `rust:1-slim`, `debian:trixie-slim` and `erlang:26-alpine` bases
removed, `docker builder prune -af` run, and the work directory deleted — it built and started all five
in **7 m 38 s**, each reporting its listener: three Rust peers from a cold crates index and the erlang
one cloned at its pinned commit and patched. The interop suite then passed **7 of 7** against them,
every proof on its first attempt. Nothing is reused from a previous deployment and nothing is typed by
hand.

### Running the suite

```sh
WEBTRANSPORT_VPS_INTEROP_CLIENT=$PWD/C99/out/macos26/build/apps/wt-client-c99 \
WEBTRANSPORT_VPS_INTEROP_RESET='ssh -o BatchMode=yes root@<host> /usr/local/sbin/webtransport-interop-reset-peers' \
  sh C99/scripts/run-vps-third-party-interop.sh
```

`WEBTRANSPORT_VPS_INTEROP_RESET` is the command `run-vps-third-party-interop.sh`
runs before each proof with the proof key as its argument. `erlang-webtransport`
serves a bounded number of sessions and then stops accepting, so without the
reset the datagram proof passes alone and fails inside a full run. The committed
implementation is `reset-vps-peers.sh` (installed by `deploy-vps-peers.sh` as
`/usr/local/sbin/webtransport-interop-reset-peers`); it restarts the peer that
serves the named proof and waits until it reports a listener.

`deploy-vps-peers.sh` covers the five endpoints this suite talks to. The internal
`wt2-*` set on the static `wt-matrix` subnet (ports 55501-55505) is the Swift
interop matrix's, not this suite's; its own reset lives with that tree.
