FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release 2>&1 | tail -40

FROM debian:trixie-slim
COPY --from=build /src/target/release/wt-echo-quinn /usr/local/bin/
CMD ["wt-echo-quinn"]
