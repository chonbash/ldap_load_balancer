# Общие переменные для сценариев (можно переопределить через env в docker-compose)
export LDAP_HOST="${LDAP_HOST:-ldap-lb}"
export LDAP_PORT="${LDAP_PORT:-1389}"
export LDAP_URI="ldap://${LDAP_HOST}:${LDAP_PORT}"
export BASE_DN="${BASE_DN:-dc=example,dc=com}"
export BIND_DN="${BIND_DN:-cn=admin,dc=example,dc=com}"
export BIND_PW="${BIND_PW:-secret}"
# Тестовый пользователь для сценариев SSSD / Run as / Modify
export TEST_USER_OU="${TEST_USER_OU:-ou=users}"
export TEST_USER_CN="${TEST_USER_CN:-testuser}"
export TEST_USER_DN="${TEST_USER_DN:-cn=${TEST_USER_CN},${TEST_USER_OU},${BASE_DN}}"
export TEST_USER_PW="${TEST_USER_PW:-testpass}"

# Единый формат логов для сценариев: [HH:MM:SS] script_name | сообщение
log_msg() {
  local ts
  ts=$(date +%H:%M:%S)
  echo "[$ts] $(basename "${BASH_SOURCE[1]}" .sh) | $*"
}
log_ok() { log_msg "OK"; }
log_fail() { log_msg "FAILED: $*" >&2; }
