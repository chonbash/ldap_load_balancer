#!/bin/bash
# Integration test: Search with various filter types (exercises Filter parser).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Filter: (objectClass=*) base scope"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" -s base -LLL "(objectClass=*)" cn 2>/dev/null | head -5
log_ok

log_msg "Filter: (&(objectClass=*)(cn=admin))"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" -LLL "(&(objectClass=*)(cn=admin))" cn 2>/dev/null | head -5
log_ok

log_msg "Filter: (|(cn=admin)(cn=*)) one level"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" -s one -LLL "(|(cn=admin)(cn=*))" cn 2>/dev/null | head -10
log_ok

log_msg "Filter: subtree (cn=*)"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" -s sub -LLL "(cn=*)" cn 2>/dev/null | head -10
log_ok
