# Build stage
FROM rust:1-bookworm AS builder
WORKDIR /app

# Слой 1: только системные пакеты (инвалидируется при изменении списка пакетов)
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Слой 2: загрузка и сборка зависимостей (инвалидируется при изменении Cargo.toml / Cargo.lock)
# Without --locked, cargo can update Cargo.lock when new deps are in Cargo.toml (e.g. tokio-rustls).
# For reproducible builds, run `cargo update` locally and commit Cargo.lock.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'pub fn __dummy() {}' > src/lib.rs && \
    echo 'fn main() { ldap_load_balancer::__dummy(); }' > src/main.rs && \
    cargo fetch && \
    cargo build --release

# Слой 3: подстановка своего кода и сборка (инвалидируется при изменении src/)
COPY src ./src
RUN touch src/lib.rs src/main.rs && cargo build --release

# Run stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ldap-load-balancer /usr/local/bin/
EXPOSE 1389
ENTRYPOINT ["ldap-load-balancer"]
CMD ["--config", "/etc/ldap-lb/config.yaml"]
