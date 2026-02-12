#!/bin/bash
# Search с фильтром по objectClass
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"
log_msg "Search filter (objectClass=organization)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" "(objectClass=organization)" dn o
log_ok