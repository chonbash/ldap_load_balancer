#!/bin/bash
# Search subtree: все объекты в дереве
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"
log_msg "Search subtree (all)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s sub "(objectclass=*)" dn > /dev/null
log_ok