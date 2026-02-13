#!/bin/bash
# Integration test: Sticky session — Bind then Add then Search in one flow (same connection in proxy).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

STICKY_OU="ou=sticky-test"
STICKY_DN="cn=sticky-$(date +%s),${STICKY_OU},${BASE_DN}"

log_msg "Sticky: ensure OU exists (add if not)"
ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" 2>/dev/null <<EOF || true
dn: ${STICKY_OU},${BASE_DN}
objectClass: organizationalUnit
ou: sticky-test
EOF
log_ok

log_msg "Sticky: add entry then search (same backend in proxy)"
ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: ${STICKY_DN}
objectClass: person
cn: sticky-$(date +%s)
sn: test
EOF
log_ok

ldapsearch -x -H "$LDAP_URI" -b "$STICKY_DN" -D "$BIND_DN" -w "$BIND_PW" -s base -LLL "(objectClass=*)" cn 2>/dev/null | head -5
log_ok
