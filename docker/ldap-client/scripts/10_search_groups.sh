#!/bin/bash
# Сценарий: Поиск групп (memberOf / groupOfNames) — Windows login, SSSD getgrnam.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Search groups (groupOfNames / groupOfUniqueNames)"
ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" \
  -b "$BASE_DN" -s sub "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))" dn cn > /dev/null
log_ok
