FROM lukemathwalker/cargo-chef:latest-rust-bookworm AS chef
WORKDIR /app

COPY Cargo.toml Cargo.lock ./

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM ghcr.io/foundry-rs/foundry:latest AS foundry

FROM chef AS app-builder
COPY . .

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil

RUN apt-get update && \
    apt-get install -y protobuf-compiler clang

RUN cargo build --release --all

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && \
    apt-get install -y libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=app-builder /app/target/release/bls-blueprint-bin /usr/local/bin

LABEL org.opencontainers.image.authors="Webb Technologies Inc."
LABEL org.opencontainers.image.description="A BLS Blueprint that can run keygen and signing jobs on demand from the Tangle network"
LABEL org.opencontainers.image.source="https://github.com/tangle-network/bls-blueprint"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENV RUST_LOG="info"
ENV BIND_ADDR="0.0.0.0"
ENV BIND_PORT=9632
ENV BLUEPRINT_ID=0
ENV SERVICE_ID=0
ENV CHAIN="testnet"
ENV KEYSTORE_URI="./keystore"

ENTRYPOINT ["/usr/local/bin/bls-blueprint-bin", "run"]
