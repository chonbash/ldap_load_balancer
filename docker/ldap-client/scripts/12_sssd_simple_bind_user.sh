#!/bin/bash
# Сценарий: Linux SSSD (id_provider=ldap) — Simple bind пользователем + поиск.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "SSSD simple bind as user + search (read own entry)"
ldapwhoami -x -H "$LDAP_URI" -D "$TEST_USER_DN" -w "$TEST_USER_PW" > /dev/null
# Пользователь по умолчанию может читать только свою запись (by self read)
ldapsearch -x -H "$LDAP_URI" -D "$TEST_USER_DN" -w "$TEST_USER_PW" \
  -b "$TEST_USER_DN" -s base "(objectclass=*)" dn > /dev/null
log_ok
