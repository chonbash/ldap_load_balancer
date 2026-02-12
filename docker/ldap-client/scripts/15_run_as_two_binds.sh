#!/bin/bash
# Сценарий: Run as — два пользователя подряд: bind admin → search, bind user → search.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Run as: admin bind + search, then user bind + search (user reads own entry)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s one "(objectclass=*)" dn
# Пользователь по умолчанию может читать только свою запись
ldapsearch -x -H "$LDAP_URI" -D "$TEST_USER_DN" -w "$TEST_USER_PW" \
  -b "$TEST_USER_DN" -s base "(objectclass=*)" dn
log_ok
