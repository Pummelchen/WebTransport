FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml .
# `deploy-vps-peers.sh` runs `patch-quinn-datagram.py` over this context before building, and that
# patch vendors `web-transport-quinn` here and points Cargo.toml at it. The directory must be copied
# too, or cargo fails on the patched path ("failed to read /src/vendor/web-transport-quinn/Cargo.toml").
COPY vendor ./vendor
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
COPY --from=build /src/target/release/wt-echo-quinn /usr/local/bin/
CMD ["wt-echo-quinn"]
