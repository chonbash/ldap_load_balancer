#!/bin/bash
# Сценарий: Создание пользователя, группы и включение пользователя в группу.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
. "$SCRIPT_DIR/env.sh"

# Пользователь и группа, создаваемые этим скриптом (можно переопределить через env)
export SCRIPT_USER_OU="${SCRIPT_USER_OU:-ou=users}"
export SCRIPT_USER_CN="${SCRIPT_USER_CN:-demouser}"
export SCRIPT_USER_DN="${SCRIPT_USER_DN:-cn=${SCRIPT_USER_CN},${SCRIPT_USER_OU},${BASE_DN}}"
export SCRIPT_USER_PW="${SCRIPT_USER_PW:-demopass}"
export SCRIPT_GROUP_OU="${SCRIPT_GROUP_OU:-ou=groups}"
export SCRIPT_GROUP_CN="${SCRIPT_GROUP_CN:-demogroup}"
export SCRIPT_GROUP_DN="${SCRIPT_GROUP_DN:-cn=${SCRIPT_GROUP_CN},${SCRIPT_GROUP_OU},${BASE_DN}}"

log_msg "Create user, create group, add user to group (idempotent)"

# 1. OU groups — создать, если нет
GROUPS_OU_DN="${SCRIPT_GROUP_OU},${BASE_DN}"
if ! ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$GROUPS_OU_DN" -s base "(objectclass=*)" dn 2>/dev/null | grep -q "dn:"; then
  log_msg "Creating OU $GROUPS_OU_DN"
  ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $GROUPS_OU_DN
objectClass: organizationalUnit
ou: groups
EOF
fi

# 2. Пользователь — создать, если нет
if ! ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$SCRIPT_USER_DN" -s base "(objectclass=*)" dn 2>/dev/null | grep -q "dn:"; then
  log_msg "Creating user $SCRIPT_USER_DN"
  ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $SCRIPT_USER_DN
objectClass: inetOrgPerson
cn: $SCRIPT_USER_CN
sn: Demo
uid: $SCRIPT_USER_CN
userPassword: $SCRIPT_USER_PW
EOF
else
  log_msg "User $SCRIPT_USER_DN already exists"
fi

# 3. Группа — создать с пользователем как member (groupOfNames требует минимум одного member)
if ! ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$SCRIPT_GROUP_DN" -s base "(objectclass=*)" dn 2>/dev/null | grep -q "dn:"; then
  log_msg "Creating group $SCRIPT_GROUP_DN with user as member"
  ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $SCRIPT_GROUP_DN
objectClass: groupOfNames
cn: $SCRIPT_GROUP_CN
member: $SCRIPT_USER_DN
EOF
else
  # Группа уже есть — добавить пользователя в группу, если ещё не member
  if ! ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" -b "$SCRIPT_GROUP_DN" -s base "(member=$SCRIPT_USER_DN)" dn 2>/dev/null | grep -q "dn:"; then
    log_msg "Adding user to existing group $SCRIPT_GROUP_DN"
    ldapmodify -x -H "$LDAP_URI" -D "$BIND_DN" -w "$BIND_PW" <<EOF
dn: $SCRIPT_GROUP_DN
changetype: modify
add: member
member: $SCRIPT_USER_DN
EOF
  else
    log_msg "User already in group $SCRIPT_GROUP_DN"
  fi
fi

log_ok
