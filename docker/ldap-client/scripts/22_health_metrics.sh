#!/bin/bash
# Integration test: Health and metrics endpoints (curl to lb from host or sidecar).
# LB metrics listen is on 9090; from ldap-client we call ldap-load-balancer:9090.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

METRICS_HOST="${METRICS_HOST:-ldap-load-balancer}"
METRICS_PORT="${METRICS_PORT:-9090}"
METRICS_URL="http://${METRICS_HOST}:${METRICS_PORT}"

log_msg "GET /health"
curl -sS -o /dev/null -w "%{http_code}" "$METRICS_URL/health" | grep -q 200 && log_ok || log_fail "health not 200"

log_msg "GET /ready"
code=$(curl -sS -o /dev/null -w "%{http_code}" "$METRICS_URL/ready")
if [ "$code" = "200" ] || [ "$code" = "503" ]; then
  log_ok
else
  log_fail "ready returned $code"
fi

log_msg "GET /metrics (backend_up present)"
curl -sS "$METRICS_URL/metrics" | grep -q "ldap_lb_backend_up" && log_ok || log_fail "ldap_lb_backend_up not in metrics"
