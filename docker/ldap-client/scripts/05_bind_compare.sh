#!/bin/bash
# Bind + compare (проверка bind через LB)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"
log_msg "Bind and compare"
# OpenLDAP ldapcompare exits 6 for compareTrue, 0 for success in some builds; with set -e, 6 would abort
ldapcompare -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  "$BASE_DN" "objectClass:organization" || { r=$?; [ "$r" -eq 6 ] && true || exit "$r"; }
log_ok