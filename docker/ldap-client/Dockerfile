FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ldap-utils \
    python3 \
    python3-pip \
    python3-ldap \
    python3-pyasn1 \
    python3-pyasn1-modules \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

COPY tests/ /tests/
COPY pytest.ini requirements-test.txt /
RUN pip3 install --break-system-packages --no-cache-dir -r /requirements-test.txt

# Default: single pytest run with JUnit + HTML reports (for CI and local)
ENV PYTEST_ADDOPTS="--junitxml=/reports/junit.xml --html=/reports/report.html --self-contained-html"
RUN mkdir -p /reports
VOLUME ["/reports"]
CMD ["python3", "-m", "pytest", "/tests", "-v"]
