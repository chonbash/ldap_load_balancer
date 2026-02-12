#!/bin/bash
# Сценарий: Windows login / SSSD — поиск пользователя (getpwnam, поиск по uid/cn).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Search user (getpwnam-like)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s sub "(|(uid=${TEST_USER_CN})(cn=${TEST_USER_CN}))" dn uid cn sn
log_ok
