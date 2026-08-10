# syntax=docker/dockerfile:1.7
#
# Container image for the Rust collateral provider.
#
# Build context is this directory (rs/), not the repo root:
#     docker build -t collateral-provider-rs rs/
#
# Signing keys are NOT baked in. On platforms that offer neither secret files
# nor volumes they arrive as encrypted env vars (SKEY_CONTENTS /
# VKEY_CONTENTS) which the entrypoint materializes under /run/keys. On
# runtimes that do provide a mount, point SKEY_PATH / VKEY_PATH at it. The
# startup identity check refuses to boot if they are missing or inconsistent.

# Must be >= the rust-version in Cargo.toml, which the dependency graph sets
# (currently 1.88, from `time` 0.3). Bump both together.
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Cache the dependency build across source-only changes: compile a stub main
# against the real manifest first, then drop it and build the actual sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Cargo skips a rebuild when mtimes look unchanged; touching the roots makes
# the real build unconditional.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked \
    && strip target/release/collateral-provider

FROM debian:bookworm-slim AS runtime

# TLS to Koios/Ogmios goes through rustls, which uses the system trust store
# via rustls-native-certs' fallback path; ca-certificates supplies it. curl
# stays for manual diagnosis from inside a container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user: a code-execution bug shouldn't have root inside the
# container.
RUN useradd --system --create-home --uid 10001 app

# In a container the default file-based log is wrong. Select the console
# handler explicitly so no file is opened; the platform captures stderr and
# retains it independently of the ephemeral container.
ENV LOG_TO_CONSOLE=True \
    LOG_FORMAT=json \
    BIND_ADDRESS=0.0.0.0:8080

WORKDIR /app

COPY --from=builder /build/target/release/collateral-provider /usr/local/bin/collateral-provider
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Pre-create /run/keys for the entrypoint's key materialization (the app user
# can't mkdir under /run, which is root-owned).
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p /run/keys \
    && chown app:app /run/keys \
    && chmod 700 /run/keys

USER app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["collateral-provider"]
