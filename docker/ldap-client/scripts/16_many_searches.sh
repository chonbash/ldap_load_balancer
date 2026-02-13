#!/bin/bash
# Сценарий: Интерактивный логин — серия коротких поисков (имитация всплеска запросов).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Many sequential searches (login burst)"
for i in 1 2 3 4 5 6 7 8 9 10; do
  ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
    -b "$BASE_DN" -s base "(objectclass=*)" dn >/dev/null > /dev/null
  ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
    -b "$BASE_DN" -s one "(objectclass=*)" dn >/dev/null > /dev/null
done
log_ok
