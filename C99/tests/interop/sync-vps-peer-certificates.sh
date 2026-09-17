#!/bin/sh
# Copy Caddy's auto-renewed interop certificate to the two paths the peers read (WT-196b).
#
# The port-80 Caddy obtains and renews the Let's Encrypt certificate automatically, but the ten peers
# read COPIES of it -- they cannot read Caddy's store, and a peer that loaded a certificate at startup
# has no other way to see a new one. Nothing copied on renewal, so the environment would go stale at
# the next renewal (about 60 days). This copies the renewed pair to both locations and restarts the
# ten peers when the bytes actually changed.
#
# It is a no-op when the certificate is unchanged, which is what makes it safe in cron. It is also
# safe to run by hand. `deploy-vps-peers.sh` installs it as
# `/usr/local/sbin/webtransport-interop-sync-certificates` and installs the cron.d entry that calls it.
#
# Environment:
#   WEBTRANSPORT_VPS_INTEROP_AUTHORITY       the name on the certificate
#                                            (default pummelchen.91.99.176.243.nip.io)
#   WEBTRANSPORT_VPS_INTEROP_CADDY_DATA      Caddy's data directory (default /var/caddy/data)
#   WEBTRANSPORT_VPS_INTEROP_CERT_DIR        first destination (default /etc/letsencrypt)
#   WEBTRANSPORT_VPS_INTEROP_MATRIX_CERT_DIR second destination (default /var/wt-c99-interop/certs)
#   WEBTRANSPORT_VPS_INTEROP_PEERS           the containers to restart when it changed
#                                            (default the ten wt-*/wt2-* peers)
set -eu

authority="${WEBTRANSPORT_VPS_INTEROP_AUTHORITY:-pummelchen.91.99.176.243.nip.io}"
caddy_data="${WEBTRANSPORT_VPS_INTEROP_CADDY_DATA:-/var/caddy/data}"
cert_dir="${WEBTRANSPORT_VPS_INTEROP_CERT_DIR:-/etc/letsencrypt}"
matrix_cert_dir="${WEBTRANSPORT_VPS_INTEROP_MATRIX_CERT_DIR:-/var/wt-c99-interop/certs}"
peers="${WEBTRANSPORT_VPS_INTEROP_PEERS:-wt-py wt-quinn wt-quiche wt-h3 wt-erlang wt2-py wt2-quinn wt2-quiche wt2-h3 wt2-erlang}"

# Caddy's store for one name. `.crt` is the full chain (the leaf first), `.key` the private key.
store="$caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$authority"
src_crt="$store/$authority.crt"
src_key="$store/$authority.key"

if [ ! -f "$src_crt" ] || [ ! -f "$src_key" ]; then
  echo "peer certificates: no certificate at $store for $authority" >&2
  echo "  is vps/caddy/webtransport-interop.caddy installed and Caddy reloaded?" >&2
  exit 1
fi

command -v openssl >/dev/null 2>&1 || { echo "peer certificates: openssl is not on PATH"; exit 2; }
command -v cmp >/dev/null 2>&1 || { echo "peer certificates: cmp is not on PATH"; exit 2; }

# The pair has to match, or a copy turn a working peer into a handshake failure. Comparing the public
# keys catches a half-written or mismatched store before anything is installed.
crt_pub="$(openssl x509 -in "$src_crt" -noout -pubkey | openssl sha256)"
key_pub="$(openssl pkey -in "$src_key" -pubout 2>/dev/null | openssl sha256)"
if [ "$crt_pub" != "$key_pub" ]; then
  echo "peer certificates: $src_crt and $src_key are not a pair; refusing to install them" >&2
  exit 1
fi

changed=0
for dir in "$cert_dir/live/$authority" "$matrix_cert_dir"; do
  mkdir -p "$dir"
  if cmp -s "$src_crt" "$dir/fullchain.pem" && cmp -s "$src_key" "$dir/privkey.pem"; then
    echo "peer certificates: $dir already current"
    continue
  fi
  # 0600 and root-owned: the private key is read by the containers as root through a read-only bind.
  install -m 600 "$src_crt" "$dir/fullchain.pem"
  install -m 600 "$src_key" "$dir/privkey.pem"
  echo "peer certificates: installed into $dir"
  changed=1
done

if [ "$changed" -eq 0 ]; then
  echo "peer certificates: unchanged ($(openssl x509 -in "$src_crt" -noout -fingerprint -sha256 | cut -d= -f2)); no peer restarted"
  exit 0
fi

command -v docker >/dev/null 2>&1 || { echo "peer certificates: changed, but docker is not on PATH; peers not restarted" >&2; exit 1; }

restarted=0
for name in $peers; do
  if docker inspect "$name" >/dev/null 2>&1; then
    # The echo peers ignore SIGTERM, so Docker otherwise waits its whole 10s stop timeout per peer and
    # ten peers make the cron run a minute long for nothing. They hold no state; 2s is generous.
    docker restart -t 2 "$name" >/dev/null
    restarted=$((restarted + 1))
  fi
done
echo "peer certificates: restarted $restarted peer(s) on the new certificate"
