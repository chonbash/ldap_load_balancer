#!/bin/bash
# Integration test: Search with paged results control (-E pr=page_size).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

log_msg "Paged results: search with page size 2"
ldapsearch -x -H "$LDAP_URI" -b "$BASE_DN" -D "$BIND_DN" -w "$BIND_PW" -LLL -E pr=2 "(objectClass=*)" cn 2>/dev/null | head -30
log_ok
