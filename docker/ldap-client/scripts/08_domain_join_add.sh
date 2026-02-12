#!/bin/bash
# Сценарий: Domain join / realm join — Bind + Search + Add (создание OU и пользователя).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Domain join: add OU and test user (idempotent)"

# Проверяем, есть ли уже тестовый пользователь
if ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$TEST_USER_DN" -s base "(objectclass=*)" dn 2>/dev/null | grep -q "dn:"; then
  log_msg "Test user already exists, skip add"
  log_ok
  exit 0
fi

# Создаём OU users, если нет
OU_DN="${TEST_USER_OU},${BASE_DN}"
if ! ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$OU_DN" -s base "(objectclass=*)" dn 2>/dev/null | grep -q "dn:"; then
  ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $OU_DN
objectClass: organizationalUnit
ou: users
EOF
fi

# Добавляем тестового пользователя (аналог записи компьютера/пользователя при join)
ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $TEST_USER_DN
objectClass: inetOrgPerson
cn: $TEST_USER_CN
sn: Test
uid: $TEST_USER_CN
userPassword: $TEST_USER_PW
EOF

log_ok
