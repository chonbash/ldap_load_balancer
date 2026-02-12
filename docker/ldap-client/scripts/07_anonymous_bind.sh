#!/bin/bash
# Сценарий: Anonymous bind (если разрешено на сервере). Часто отключено.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Anonymous bind + base search"
if ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -s base "(objectclass=*)" dn 2>/dev/null; then
  log_msg "OK (anonymous allowed)"
else
  log_msg "SKIP (anonymous bind disabled - expected)"
fi
