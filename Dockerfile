# EdgeClaw Desktop Agent — Multi-stage Docker build
# Target: <50MB image, minimal attack surface

# Stage 1: Build
FROM rust:1.75-slim AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY static/ static/

RUN cargo build --release && \
    strip target/release/edgeclaw-agent

# Stage 2: Runtime (distroless for minimal footprint)
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /bin/false edgeclaw

COPY --from=builder /build/target/release/edgeclaw-agent /usr/local/bin/edgeclaw-agent
COPY config/default.toml /etc/edgeclaw/agent.toml

USER edgeclaw

EXPOSE 9443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/edgeclaw-agent", "health"]

ENTRYPOINT ["/usr/local/bin/edgeclaw-agent"]
CMD ["start"]
