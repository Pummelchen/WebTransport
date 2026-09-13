# The C99 client, in a container, so interop needs no NAT (WT-135).
#
# The host-to-container direction works: a published UDP port forwards the client's Initial in. The REPLY path
# does not -- Docker Desktop forwards inbound datagrams, and the container's answers do not come back to a
# host-initiated flow -- which looked exactly like a stalled handshake until the CLI's oracle reported that the
# client's socket had seen ZERO packets while the peer had sent six.
#
# Running the client where the server is removes the problem in both directions: two containers on one bridge
# network, addressing each other by service name. It is also how a Linux CI job would run interop, and this tree
# already builds on Debian, so this is a Dockerfile rather than a port.
FROM debian:stable-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The whole tree, because the client tool is built from apps/ against src/ and include/.
COPY . /src/c99

RUN cmake -S /src/c99 -B /build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DWEBTRANSPORT_C99_BUILD_TESTS=OFF \
        -DWEBTRANSPORT_C99_BUILD_APPS=ON \
    && cmake --build /build --target wt-client-c99 wt-server-c99 wt-conformance-c99

# The tools' output goes to stdout/stderr unbuffered enough for a container log; the entrypoint is the client so
# that `docker run <image> --connect peer:54001 ...` reads as the command line it is.
WORKDIR /src/c99
ENTRYPOINT ["/build/apps/wt-client-c99"]
