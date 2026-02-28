# OpenLDAP backend (ldap1, ldap2, ldap3)

Сертификаты в `certs/`. Остальная конфигурация — через переменные окружения в `docker-compose.yml`.

## Анонимное чтение (для test_07_anonymous_bind)

По умолчанию в osixia/openldap анонимный bind может быть разрешён, но чтение записей — нет. Чтобы тест `test_07_anonymous_bind` проходил (анонимный bind + чтение созданной записи), нужно один раз на каждом бэкенде добавить ACL:

```bash
# После старта контейнеров (docker compose up -d)
docker compose exec ldap1 ldapmodify -Y EXTERNAL -H ldapi:/// -f /opt/ldap1/acl-anonymous-read.ldif
docker compose exec ldap2 ldapmodify -Y EXTERNAL -H ldapi:/// -f /opt/ldap1/acl-anonymous-read.ldif
docker compose exec ldap3 ldapmodify -Y EXTERNAL -H ldapi:/// -f /opt/ldap1/acl-anonymous-read.ldif
```

Файл `acl-anonymous-read.ldif` добавляет правило `to * by * read` в конфиг базы (olcDatabase={1}mdb,cn=config), разрешая чтение каталога для всех, в том числе анонимных подключений.

**Внимание:** в продакшене анонимное чтение часто отключают; используйте только в тестовых/внутренних стендах.
