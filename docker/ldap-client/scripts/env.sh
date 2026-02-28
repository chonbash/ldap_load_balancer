# Общие переменные для сценариев (можно переопределить через env в docker-compose)
export LDAP_HOST="${LDAP_HOST:-ldap-lb}"
export LDAP_PORT="${LDAP_PORT:-1389}"
export LDAP_SCHEME="${LDAP_SCHEME:-ldap}"
export LDAP_URI="${LDAP_SCHEME}://${LDAP_HOST}:${LDAP_PORT}"
export BASE_DN="${BASE_DN:-dc=example,dc=com}"
export BIND_DN="${BIND_DN:-cn=admin,dc=example,dc=com}"
export BIND_PW="${BIND_PW:-secret}"
# Тестовый пользователь для сценариев SSSD / Run as / Modify
export TEST_USER_OU="${TEST_USER_OU:-ou=users}"
export TEST_USER_CN="${TEST_USER_CN:-testuser}"
export TEST_USER_DN="${TEST_USER_DN:-cn=${TEST_USER_CN},${TEST_USER_OU},${BASE_DN}}"
export TEST_USER_PW="${TEST_USER_PW:-testpass}"

# TLS (LDAPS): проверка сертификата сервера (для ldap-utils)
# LDAP_TLS_REQCERT=never — отключить проверку (только для тестов); иначе — demand (по умолчанию)
# LDAP_TLS_CACERT — путь к CA-сертификату для проверки (если не задан, используются системные корни)
if [ -n "${LDAP_TLS_REQCERT:-}" ]; then
  export LDAPTLS_REQCERT="${LDAP_TLS_REQCERT}"
fi
if [ -n "${LDAP_TLS_CACERT:-}" ]; then
  export LDAPTLS_CACERT="${LDAP_TLS_CACERT}"
fi

# Единый формат логов для сценариев: [HH:MM:SS] script_name | сообщение
log_msg() {
  local ts
  ts=$(date +%H:%M:%S)
  echo "[$ts] $(basename "${BASH_SOURCE[1]}" .sh) | $*"
}
log_ok() { log_msg "OK"; }
log_fail() { log_msg "FAILED: $*" >&2; }
