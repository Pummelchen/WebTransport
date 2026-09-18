#!/usr/bin/env python3
"""Patch the `erlang-webtransport` peer so its h3 listener sends the whole certificate chain.

WHY THIS EXISTS
---------------
The Phase 11 interop matrix (WT-135) runs the C99 client against five independent implementations
with `--trust system`, so every peer must present a chain the platform trust store can build. Four of
them do. `erlang-webtransport` does not, and it is not a configuration mistake:

  * `read_cert_file/1` keeps only the FIRST certificate in a PEM (`[{_, CertDer, _} | _]`), and the h3
    listener passes `cert => CertDer` -- the leaf alone. Pointing `CERTFILE` at a multi-certificate
    fullchain therefore changes nothing, which was measured rather than assumed:
    `openssl s_client -quic -alpn h3` reported a single-entry chain and
    `Verify return code: 21 (unable to verify the first certificate)` for this peer, against
    `depth=0..3` and `Verify return code: 0 (ok)` for the h3 peer presenting the SAME leaf.

  * The QUIC layer already supports a chain (`quic_listener.erl` reads `cert_chain`), so the peer only
    has to supply it -- but `quic_h3:build_server_quic_opts/1` lifts ONLY `cert`, `key` and `cacerts`
    from the top level and merges the caller's `quic_opts` LAST:

        TlsOpts = maps:with([cert, key, cacerts], Opts),
        Merged  = maps:merge(maps:merge(BaseOpts, TlsOpts), QuicOpts),

    so `cert_chain` at the top level is dropped and must instead ride inside `quic_opts` -- which is
    also why this peer already routes `sni_callback` through it.

Measured end to end: before the patch the client reported `status=trust` for both erlang proofs;
after it, `openssl` reports `Verify return code: 0 (ok)` and the stream proof passes.

This patches a THIRD-PARTY peer, not this repository's code. It is kept here because the matrix
depends on it, and an interop result whose peer setup is not recorded is not reproducible. The
per-proof peer sources themselves live outside the repository (on the VPS under /opt/wt-interop),
which is where the plan puts them.

USAGE
    cd <erlang-webtransport source dir>          # the one holding src/webtransport.erl
    python3 patch-erlang-chain.py
    docker build -f Dockerfile.vps -t <tag> .    # then run it with CERTFILE=<fullchain>

Idempotent: a second run reports that it is already applied.
"""

import pathlib
import sys

CHAIN_HELPER = """read_cert_chain_file(CertFile) ->
    case file:read_file(CertFile) of
        {ok, PemData} ->
            case public_key:pem_decode(PemData) of
                [] -> {error, invalid_certificate};
                Entries -> {ok, [Der || {_, Der, _} <- Entries]}
            end;
        {error, Reason} ->
            {error, {cert_read_failed, Reason}}
    end.

"""

LISTENER_OLD = """        {ok, CertDer, PrivateKey} ->
            Claim = wt_stream_type_handler(),"""

LISTENER_NEW = """        {ok, CertDer, PrivateKey} ->
            %% The leaf alone is not a chain. A validator that does not already hold the issuer
            %% cannot build one, and a strict client reports exactly that -- "unable to get local
            %% issuer certificate" -- so the rest of the PEM file is sent too.
            CertChain = case read_cert_chain_file(CertFile) of
                {ok, [_Leaf | Rest]} -> Rest;
                _ -> []
            end,
            Claim = wt_stream_type_handler(),"""

QUIC_OPTS_OLD = """                quic_opts => maybe_put_sni(Opts, #{
                    max_datagram_frame_size => 65535,"""

QUIC_OPTS_NEW = """                quic_opts => maybe_put_sni(Opts, #{
                    %% The chain rides here rather than beside `cert': `quic_h3' lifts only
                    %% cert/key/cacerts from the top level and merges `quic_opts' last.
                    cert_chain => CertChain,
                    max_datagram_frame_size => 65535,"""


def main() -> int:
    path = pathlib.Path("src/webtransport.erl")
    if not path.exists():
        print(f"patch: {path} not found; run this from the peer's source directory", file=sys.stderr)
        return 2

    text = path.read_text()
    if "read_cert_chain_file(" in text and "cert_chain => CertChain," in text:
        print("patch: already applied")
        return 0

    for label, needle in (
        ("read_cert_file/1", "read_cert_file(CertFile) ->"),
        ("the h3 listener's cert branch", LISTENER_OLD),
        ("the h3 listener's quic_opts", QUIC_OPTS_OLD),
    ):
        if needle not in text:
            print(f"patch: {label} was not found -- the peer source has changed", file=sys.stderr)
            return 2

    text = text.replace("read_cert_file(CertFile) ->", CHAIN_HELPER + "read_cert_file(CertFile) ->", 1)
    text = text.replace(LISTENER_OLD, LISTENER_NEW, 1)
    text = text.replace(QUIC_OPTS_OLD, QUIC_OPTS_NEW, 1)
    path.write_text(text)
    print("patch: applied to src/webtransport.erl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
