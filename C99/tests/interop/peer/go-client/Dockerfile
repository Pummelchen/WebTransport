# The Go server-side interop client (WT-153, WT-258).
#
# `webtransport-go` on top of `quic-go`: an implementation that shares no code with pywebtransport/aioquic
# (`c99_server_client.py`), which is the point -- a server that happened to suit one client's habits would look
# correct. Its client selects a ZERO-LENGTH connection ID for its first Initial, which is legal (RFC 9000 section
# 5.1) and which `wt-server-c99` refused until WT-258, so this image is also the regression test for that.
FROM golang:1.27 AS build
WORKDIR /src
# The sums are committed, so the build resolves the same modules every time and fails loudly if it cannot.
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
# GOTOOLCHAIN=local: the module names a Go version no newer than this image's toolchain -- which is why the image
# tracks it -- so nothing is fetched to build it. CGO off, so the binary needs nothing from the runtime image.
RUN CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -ldflags "-s -w" -o /out/wt-go-client .

FROM debian:trixie-slim
COPY --from=build /out/wt-go-client /usr/local/bin/wt-go-client
ENTRYPOINT ["/usr/local/bin/wt-go-client"]
