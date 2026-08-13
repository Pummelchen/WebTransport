FROM rust:1-slim AS build
# quiche vendors BoringSSL: needs cmake, a C++ toolchain, Go, and git (its
# build script applies patches with git, and libclang for its bindgen step).
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake perl build-essential golang pkg-config git clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml .
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
COPY --from=build /src/target/release/wt-echo-quiche /usr/local/bin/
CMD ["wt-echo-quiche"]
