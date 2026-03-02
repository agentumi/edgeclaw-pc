# EdgeClaw Desktop Agent — Multi-stage Docker build
# Target: <50MB image, minimal attack surface
# Expected size: ~15-20MB (Alpine ~5MB + stripped binary ~6MB + ca-certs ~1MB)

# Stage 1: Build (Rust on Alpine for musl static linking)
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev pkgconf openssl-dev openssl-libs-static

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY static/ static/

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || \
    cargo build --release && \
    strip target/*/release/edgeclaw-agent -o /build/edgeclaw-agent || \
    strip target/release/edgeclaw-agent -o /build/edgeclaw-agent

# Stage 2: Runtime (Alpine for minimal footprint — ~5MB base)
FROM alpine:3.19 AS runtime

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -s /sbin/nologin edgeclaw

COPY --from=builder /build/edgeclaw-agent /usr/local/bin/edgeclaw-agent
COPY config/default.toml /etc/edgeclaw/agent.toml
COPY static/ /usr/share/edgeclaw/static/

RUN chmod +x /usr/local/bin/edgeclaw-agent

USER edgeclaw

EXPOSE 9443 9444 9445 9446

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/edgeclaw-agent", "health"]

ENTRYPOINT ["/usr/local/bin/edgeclaw-agent"]
CMD ["start"]
