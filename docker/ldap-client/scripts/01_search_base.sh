#!/bin/bash
# Базовый search: объект по DN
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"
log_msg "Search base (object)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s base "(objectclass=*)" dn > /dev/null
log_ok