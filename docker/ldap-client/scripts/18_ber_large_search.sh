#!/bin/bash
# Integration test: Search with larger filter/attribute list (exercises BER length encoding).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "BER: search with long attribute list (many attrs)"
# Request many attributes to produce longer BER-encoded message
ATTRS="cn,mail,sn,givenName,objectClass,uid,userPassword,displayName,description,memberOf"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" \
  -LLL "(objectClass=*)" $ATTRS 2>/dev/null | head -50
log_ok

log_msg "BER: search with complex filter (nested AND/OR)"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" \
  -LLL "(&(objectClass=*)(|(cn=admin)(cn=*)))" cn 2>/dev/null | head -20
log_ok
