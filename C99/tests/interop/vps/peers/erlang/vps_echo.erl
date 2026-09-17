%% Launcher for the VPS interop matrix.
%%
%% The bundled echo_server example hardcodes its port and certificate paths.
%% This reads them from the environment so the peer can be pointed at the real
%% Let's Encrypt certificate and the port the runner expects, matching how the
%% other peers on this host are configured.
-module(vps_echo).
-export([start/0]).

start() ->
    Port = list_to_integer(os:getenv("PORT", "54007")),
    CertFile = os:getenv("CERTFILE", "cert.pem"),
    KeyFile = os:getenv("KEYFILE", "key.pem"),
    %% The listener registers itself in an ETS table owned by the quic
    %% application's supervision tree, so the applications have to be up before
    %% start_listener is called or it fails on a missing table.
    {ok, _Started} = application:ensure_all_started(webtransport),
    io:format("erlang-webtransport echo listening on ~p with ~s~n", [Port, CertFile]),
    {ok, _} = webtransport:start_listener(vps_echo, #{
        transport => h3,
        port => Port,
        certfile => CertFile,
        keyfile => KeyFile,
        handler => echo_server
    }),
    receive stop -> ok end.
