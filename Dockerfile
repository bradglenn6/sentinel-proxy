# ==============================================================================
# Stage 1: Official Cargo-Chef with Latest Rust Compiler
# ==============================================================================
FROM lukemathwalker/cargo-chef:latest-rust-bookworm AS chef
WORKDIR /app

# ==============================================================================
# Stage 2: Cache & Pre-build Workspace Dependencies
# ==============================================================================
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build third-party dependencies first to cache in Docker layer
RUN cargo chef cook --release --recipe-path recipe.json

# Copy real source code and compile the production binary
COPY . .
RUN cargo build --release --bin sentinel-proxy

# ==============================================================================
# Stage 3: Minimal, Hardened Runtime Image
# ==============================================================================
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Install standard CA certificates for upstream TLS/HTTPS connections
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user for security best practices
RUN useradd -m -u 10001 -s /bin/bash sentinel
USER sentinel

# Copy the compiled binary and the configuration file
COPY --from=builder --chown=sentinel:sentinel /app/target/release/sentinel-proxy /app/sentinel-proxy
COPY --from=builder --chown=sentinel:sentinel /app/sentinel.toml /app/sentinel.toml

# Port configuration (Cloud Run standard: PORT=8080)
ENV PORT=8080
ENV RUST_LOG=info
EXPOSE 8080

CMD ["/app/sentinel-proxy"]
