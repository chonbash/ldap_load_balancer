#!/bin/bash
# Сценарий: GPO-like — поиск в системном поддереве (cn=System / Policies).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Search policies (GPO-like: read base/system)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s base "(objectclass=*)" dn objectClass o
log_ok
