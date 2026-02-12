#!/bin/bash
# Сценарий: Админ-скрипт / приложение — Modify атрибута (description).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Modify attribute (description)"
ldapmodify -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $TEST_USER_DN
changetype: modify
replace: description
description: Updated by scenario 13 at $(date -u +%Y%m%d%H%M%S)
EOF
log_ok
