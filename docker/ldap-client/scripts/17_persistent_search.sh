#!/bin/bash
# Сценарий: Persistent Search (RFC 4533 refreshAndPersist).
# Запускаем persistent search в фоне, делаем два изменения по ldapmodify,
# проверяем, что оба изменения пришли в потоке поиска.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/env.sh"

log_msg "Persistent search: run in background, apply 2 modifies, expect both in stream"

# Тестовый пользователь должен существовать (создаётся в 08)
OUT_FILE="/tmp/ps_out.$$"
ERR_FILE="/tmp/ps_err.$$"
trap 'rm -f "$OUT_FILE" "$ERR_FILE"' EXIT

python3 "$SCRIPT_DIR/17_persistent_search.py" > "$OUT_FILE" 2>"$ERR_FILE" &
PS_PID=$!

# Ждём READY (конец refresh, начало persist) — макс 8 сек
READY_TIMEOUT=8
READY_SEC=0
while [ $READY_SEC -lt $READY_TIMEOUT ]; do
  if grep -q "READY" "$OUT_FILE" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$PS_PID" 2>/dev/null; then
    log_fail "persistent search process exited before READY"
    cat "$ERR_FILE" >&2
    exit 1
  fi
  sleep 1
  READY_SEC=$((READY_SEC + 1))
done

if ! grep -q "READY" "$OUT_FILE"; then
  kill "$PS_PID" 2>/dev/null
  wait "$PS_PID" 2>/dev/null
  log_fail "no READY (sync may be unsupported by backend?)"
  cat "$ERR_FILE" >&2
  exit 1
fi

# Два изменения — оба должны попасть в persistent search
log_msg "Applying first modify (description=persist-test-1)"
ldapmodify -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $TEST_USER_DN
changetype: modify
replace: description
description: persist-test-1
EOF

sleep 0.5

log_msg "Applying second modify (description=persist-test-2)"
ldapmodify -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $TEST_USER_DN
changetype: modify
replace: description
description: persist-test-2
EOF

# Ждём завершения Python (он выйдет 0 после двух ENTRY)
WAIT_TIMEOUT=15
WAIT_SEC=0
while [ $WAIT_SEC -lt $WAIT_TIMEOUT ]; do
  if ! kill -0 "$PS_PID" 2>/dev/null; then
    break
  fi
  sleep 0.5
  WAIT_SEC=$((WAIT_SEC + 1))
done

if kill -0 "$PS_PID" 2>/dev/null; then
  kill "$PS_PID" 2>/dev/null
  wait "$PS_PID" 2>/dev/null
  log_fail "persistent search did not receive 2 changes (timeout)"
  exit 1
fi

wait "$PS_PID"
EXIT=$?
if [ "$EXIT" -eq 0 ] && grep -q "DONE" "$OUT_FILE"; then
  log_ok
  exit 0
fi

log_fail "exit_code=$EXIT or DONE not seen"
cat "$ERR_FILE" >&2
exit 1
