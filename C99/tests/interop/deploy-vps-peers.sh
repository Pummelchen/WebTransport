#!/bin/sh
# Stand the VPS interop peers up from this repository (WT-255).
#
# `run-vps-third-party-interop.sh` talks to five endpoints on a routable host -- ports 54001/54002/
# 54003/54005/54007, each serving a CA-issued certificate for one name, driven with `--trust system`.
# They used to be started by hand: no script here or on the host started them, so a rebuilt host had
# no way back and the images, the certificate mount and the port map existed only in shell history.
#
# This builds every image from the contexts under `vps/peers/` (applying the two peer patches this
# repository already carries), starts the five with the certificate paths, and installs the host-side
# units the matrix needs. The certificate itself is NOT issued here: the port-80 Caddy does that from
# `vps/caddy/webtransport-interop.caddy` (WT-254) and the sync script copies the renewed pair into the
# mounted path (WT-196b). Stand the certificate up first, or every peer exits on a missing file.
#
# Run this FROM THE REPOSITORY, as root (or a user that can drive docker).
#
# Environment:
#   WEBTRANSPORT_VPS_INTEROP_AUTHORITY  the name on the certificate
#                                       (default pummelchen.91.99.176.243.nip.io)
#   WEBTRANSPORT_VPS_INTEROP_CERT_DIR   host directory bind-mounted read-only at the same path
#                                       (default /etc/letsencrypt)
#   WEBTRANSPORT_VPS_INTEROP_WORK       where the third-party sources are cloned/built
#                                       (default /var/wt-interop-vps)
#   WEBTRANSPORT_VPS_INTEROP_ERLANG_COMMIT  upstream erlang-webtransport commit to pin, because the
#                                       chain patch is written against its source
#                                       (default beb60942f8e8193f5c8f5882cc6885172bed887b)
#   WEBTRANSPORT_VPS_INSTALL_UNITS     1 to install the reset and certificate-sync scripts under
#                                       /usr/local/sbin and the cron.d entry (default 1)
#
# Usage:  deploy-vps-peers.sh [peer ...]      # default: all five
#         deploy-vps-peers.sh erlang           # rebuild and restart one, leaving the rest alone
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
caddy_store_name="acme-v02.api.letsencrypt.org-directory"

authority="${WEBTRANSPORT_VPS_INTEROP_AUTHORITY:-pummelchen.91.99.176.243.nip.io}"
cert_dir="${WEBTRANSPORT_VPS_INTEROP_CERT_DIR:-/etc/letsencrypt}"
work="${WEBTRANSPORT_VPS_INTEROP_WORK:-/var/wt-interop-vps}"
erlang_commit="${WEBTRANSPORT_VPS_INTEROP_ERLANG_COMMIT:-beb60942f8e8193f5c8f5882cc6885172bed887b}"
install_units="${WEBTRANSPORT_VPS_INSTALL_UNITS:-1}"

certfile="$cert_dir/live/$authority/fullchain.pem"
keyfile="$cert_dir/live/$authority/privkey.pem"
sync_install="/usr/local/sbin/webtransport-interop-sync-certificates"
reset_install="/usr/local/sbin/webtransport-interop-reset-peers"
cron_install="/etc/cron.d/webtransport-interop-certificates"

[ "$(id -u)" = "0" ] || echo "deploy-vps-peers: not root; docker may refuse" >&2
command -v docker >/dev/null 2>&1 || { echo "deploy-vps-peers: docker is not on PATH"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "deploy-vps-peers: python3 is not on PATH (the peer patches need it)"; exit 2; }
command -v git >/dev/null 2>&1 || { echo "deploy-vps-peers: git is not on PATH (the erlang peer is cloned)"; exit 2; }

# The five endpoints, in the order `run-vps-third-party-interop.sh` knows them. The port is the
# published UDP port; the container name is the `wt-*` name the reset and sync scripts restart.
port_of() {
  case "$1" in
    pywebtransport) printf 54001 ;;
    quinn)          printf 54002 ;;
    quiche)         printf 54003 ;;
    h3)             printf 54005 ;;
    erlang)         printf 54007 ;;
  esac
}

image_of() {
  case "$1" in
    pywebtransport) printf wt-py ;;
    quinn)          printf wt-quinn ;;
    quiche)         printf wt-quiche ;;
    h3)             printf wt-h3 ;;
    erlang)         printf wt-erlang ;;
  esac
}

# Build one image from the committed context. The two patches are repository files and are applied to
# the build context rather than being assumed: `quinn` vendors the published crate and flips the
# transport parameter that advertises DATAGRAM (WT-198); `erlang` clones upstream at a pinned commit
# and gives the h3 listener the certificate CHAIN, not just the leaf (WT-196).
build_peer() {
  peer="$1"
  case "$peer" in
    pywebtransport|quiche|h3)
      echo "deploy-vps-peers: building $(image_of "$peer") from vps/peers/$peer"
      docker build -t "$(image_of "$peer")" "$here/vps/peers/$peer"
      ;;
    quinn)
      echo "deploy-vps-peers: building $(image_of "$peer") with the DATAGRAM patch"
      rm -rf "$work/quinn"
      mkdir -p "$work"
      cp -R "$here/vps/peers/quinn" "$work/quinn"
      ( cd "$work/quinn" && python3 "$here/peer/patch-quinn-datagram.py" )
      docker build -t "$(image_of "$peer")" "$work/quinn"
      ;;
    erlang)
      echo "deploy-vps-peers: building $(image_of "$peer") with the certificate-chain patch"
      mkdir -p "$work"
      if [ ! -d "$work/erlang/.git" ]; then
        git clone --quiet https://github.com/benoitc/erlang-webtransport.git "$work/erlang"
      fi
      # A pinned commit, detached, so the patch and the build are the ones that were measured. The
      # source is a third-party clone in the work directory; this never touches this repository.
      git -C "$work/erlang" fetch --quiet origin
      git -C "$work/erlang" checkout --quiet --detach "$erlang_commit"
      git -C "$work/erlang" clean -qfdx
      cp "$here/vps/peers/erlang/Dockerfile.vps" "$work/erlang/Dockerfile.vps"
      mkdir -p "$work/erlang/examples"
      cp "$here/vps/peers/erlang/vps_echo.erl" "$work/erlang/examples/vps_echo.erl"
      ( cd "$work/erlang" && python3 "$here/peer/patch-erlang-chain.py" )
      docker build -t "$(image_of "$peer")" -f "$work/erlang/Dockerfile.vps" "$work/erlang"
      ;;
  esac
}

# Wait until the peer itself says it is listening. A fixed sleep either wastes time or lies; the
# peers all log the word when their listener is up.
wait_listening() {
  name="$1" tries=30
  while [ "$tries" -gt 0 ]; do
    if docker logs "$name" 2>&1 | grep -qi "listening"; then return 0; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || printf false)" != "true" ]; then
      echo "deploy-vps-peers: $name exited during startup:" >&2
      docker logs "$name" 2>&1 | tail -10 >&2
      return 1
    fi
    tries=$((tries - 1))
    sleep 1
  done
  echo "deploy-vps-peers: $name did not report a listener within 30s" >&2
  return 1
}

start_peer() {
  peer="$1" name="$(image_of "$peer")" port="$(port_of "$peer")"
  docker rm -f "$name" >/dev/null 2>&1 || true
  # The certificate directory is mounted at its own path so the container's CERTFILE/KEYFILE are the
  # same absolute paths the sync script writes; read-only, because a peer has no business writing it.
  docker run -d --name "$name" --restart unless-stopped \
    -p "$port:$port/udp" \
    -v "$cert_dir:$cert_dir:ro" \
    -e "PORT=$port" \
    -e "CERTFILE=$certfile" \
    -e "KEYFILE=$keyfile" \
    "$name" >/dev/null
  wait_listening "$name"
  echo "deploy-vps-peers: $name listening on 0.0.0.0:$port/udp"
}

install_units() {
  cp "$here/sync-vps-peer-certificates.sh" "$sync_install"
  cp "$here/reset-vps-peers.sh" "$reset_install"
  chmod 755 "$sync_install" "$reset_install"
  chown root:root "$sync_install" "$reset_install" 2>/dev/null || true
  cp "$here/vps/cron.d/webtransport-interop-certificates" "$cron_install"
  chmod 644 "$cron_install"
  chown root:root "$cron_install" 2>/dev/null || true
  echo "deploy-vps-peers: installed $sync_install, $reset_install and $cron_install"
}

peers="${*:-pywebtransport quinn quiche h3 erlang}"
for peer in $peers; do
  case "$peer" in
    pywebtransport|quinn|quiche|h3|erlang) ;;
    *) echo "deploy-vps-peers: unknown peer $peer"; exit 2 ;;
  esac
done

if [ "$install_units" = "1" ]; then
  install_units
fi

# The certificate has to exist before a peer starts. If the copies are missing but Caddy already holds
# the certificate, the just-installed sync script is the thing that materialises them.
if [ ! -f "$certfile" ] && [ -x "$sync_install" ]; then
  "$sync_install" || true
fi
if [ ! -f "$certfile" ] || [ ! -f "$keyfile" ]; then
  echo "deploy-vps-peers: no certificate at $certfile" >&2
  echo "  put vps/caddy/webtransport-interop.caddy at /var/caddy/projects/, reload Caddy, then re-run." >&2
  echo "  Caddy stores it under /var/caddy/data/caddy/certificates/$caddy_store_name/$authority/" >&2
  exit 1
fi

for peer in $peers; do
  build_peer "$peer"
  start_peer "$peer"
done

echo "deploy-vps-peers: done ($peers)"
