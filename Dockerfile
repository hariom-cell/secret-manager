# Build stage
FROM rust:1.75-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY fuzz/ ./fuzz/

# Build only the CLI binary (skip WASM and fuzz)
RUN cargo build --release --bin vault-cli --workspace --exclude vault-wasm --exclude vault-fuzz

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vault-cli /usr/local/bin/secret-manager

RUN vault-cli help > /dev/null

ENTRYPOINT ["secret-manager"]
CMD ["help"]
