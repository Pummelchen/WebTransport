FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
COPY --from=build /src/target/release/wt-echo-h3 /usr/local/bin/
CMD ["wt-echo-h3"]
