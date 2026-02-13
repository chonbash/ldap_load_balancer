#!/bin/bash
# Сценарий: Смена пароля (passwd) — extended или modify. Проверяем и возвращаем пароль.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Password modify (set same password to verify operation)"
# Устанавливаем тот же пароль через ldappasswd (проверка что операция проходит через LB)
ldappasswd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -S "$TEST_USER_DN" -s "$TEST_USER_PW"
# Проверяем, что bind пользователем по-прежнему работает
ldapwhoami -x -H "$LDAP_URI" -D "$TEST_USER_DN" -w "$TEST_USER_PW" > /dev/null
log_ok
