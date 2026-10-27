# syntax=docker/dockerfile:1
#
# Postal Pigeon: a static musl binary on Alpine, rustls only (no OpenSSL).
# Builds for linux/amd64 and linux/arm64.
#
#   docker build -t postal-pigeon:latest .
#
# Needs BuildKit (the default since Docker 23). The cargo registry and the
# target directory live in cache mounts, so rebuilds after a source change
# only recompile the relay itself.

ARG RUST_VERSION=1.99
ARG ALPINE_VERSION=3.22

# --- Builder -----------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine AS builder

# build-base: C toolchain for the bundled SQLite and aws-lc-rs (rustls crypto).
RUN apk add --no-cache build-base

WORKDIR /app

# Smaller binaries without touching Cargo.toml: no symbols, and link-time
# optimisation across all crates in one unit.
ENV CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_PROFILE_RELEASE_LTO=true \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_TERM_COLOR=never

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# BUILD_JOBS (build arg): cap parallel compile jobs on a shared machine.
ARG BUILD_JOBS=
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --locked ${BUILD_JOBS:+--jobs $BUILD_JOBS} \
    && cp target/release/postal-pigeon /usr/local/bin/

# --- Runtime -----------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS runtime

ARG VERSION=0.0.0
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Postal Pigeon" \
      org.opencontainers.image.description="The Hedgerow push relay: a content-free doorbell between self-hosted servers and iOS push" \
      org.opencontainers.image.url="https://github.com/Ferdinand99/Postal-Pigeon" \
      org.opencontainers.image.source="https://github.com/Ferdinand99/Postal-Pigeon" \
      org.opencontainers.image.documentation="https://github.com/Ferdinand99/Postal-Pigeon#readme" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# ca-certificates: TLS trust store for the connection to Apple.
# An unprivileged user (uid/gid 1000) owns /data and runs the relay; the
# container needs no root at all, so it can run with a read-only root
# filesystem and no capabilities.
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 1000 pigeon \
    && adduser -S -D -H -u 1000 -G pigeon -h /data -s /sbin/nologin pigeon \
    && mkdir -p /data \
    && chown pigeon:pigeon /data

COPY --from=builder /usr/local/bin/postal-pigeon /usr/local/bin/postal-pigeon

ENV PP_BIND=0.0.0.0:3010 \
    PP_DATA_DIR=/data

USER pigeon
WORKDIR /data
VOLUME ["/data"]
EXPOSE 3010

# The relay answers /healthz (busybox wget, no curl needed).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:3010/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/postal-pigeon"]
CMD ["serve"]
