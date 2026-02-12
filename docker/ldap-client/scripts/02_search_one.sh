#!/bin/bash
# Search one level: direct children
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"
log_msg "Search one level (children)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s one "(objectclass=*)" dn
log_ok