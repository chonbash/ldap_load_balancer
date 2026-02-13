FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ldap-utils \
    python3 \
    python3-ldap \
    python3-pyasn1 \
    python3-pyasn1-modules \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

CMD ["/scripts/run-loop.sh"]
