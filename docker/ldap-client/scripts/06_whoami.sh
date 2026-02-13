#!/bin/bash
# WhoAmI extended operation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"
log_msg "WhoAmI"
ldapwhoami -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" > /dev/null
log_ok