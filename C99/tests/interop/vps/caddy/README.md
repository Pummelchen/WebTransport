# The interop certificate's Caddy project file (WT-254)

`webtransport-interop.caddy` is the **host-local** configuration that makes the
interop peers' Let's Encrypt certificate obtainable and renewable, and until now
it existed on `91.99.176.243` and nowhere else. It is committed here so a host
rebuild does not lose the certificate path.

## Where it goes

```
/var/caddy/projects/webtransport-interop.caddy      # this file, owned caddy:caddy
```

The master edge config `/var/caddy/Caddyfile` ends with `import projects/*.caddy`,
and its own header says a project's deploy must never rewrite another project's
entry — which is exactly why this file is kept with the interop material rather
than folded into the master config. The host needs `/var/caddy/Caddyfile` itself
for the import to happen (it is that master file's job to own `:80`/`:443`), but
that file is not interop-specific and is not carried here.

## Why it exists

The peers are QUIC servers, not HTTP services, so Caddy does not proxy them. The
site only answers a status line. The point of the file is the **side effect**: a
site block with a public hostname makes the port-80 Caddy run the ACME challenge
and store the certificate, and Caddy renews it automatically from then on.

The certificate lives under Caddy's data directory, which the peers do not read:

```
/var/caddy/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<name>/<name>.crt   # full chain
/var/caddy/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<name>/<name>.key   # ECDSA P-256 key
```

`sync-vps-peer-certificates.sh` copies that pair to the two paths the peers mount
(`/etc/letsencrypt/live/<name>/` and `/var/wt-c99-interop/certs/`) whenever the
bytes change, and restarts the peers. Renewal is Caddy's; propagation is the
script's, because a peer that reads a copy at startup has no other way to see a
renewed certificate.

## After editing

`/var/caddy/Caddyfile` imports this file, so the running Caddy must be reloaded
for a change to take effect:

```
caddy reload --config /var/caddy/Caddyfile --force
```
