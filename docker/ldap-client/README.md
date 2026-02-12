# LDAP client для тестирования сценариев

Контейнер с `ldap-utils` запускает скрипты, эмулирующие клиентов из [матрицы сценариев](../../docs/client-scenarios-matrix.md).

## Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `LDAP_HOST` | `ldap-lb` | Хост балансировщика |
| `LDAP_PORT` | `1389` | Порт |
| `BASE_DN` | `dc=example,dc=com` | Базовый DN |
| `BIND_DN` | `cn=admin,dc=example,dc=com` | DN для bind |
| `BIND_PW` | `secret` | Пароль |
| `TEST_USER_OU` | `ou=users` | OU тестового пользователя |
| `TEST_USER_CN` | `testuser` | cn тестового пользователя |
| `TEST_USER_PW` | `testpass` | Пароль тестового пользователя |

В `docker-compose` можно задать их в `environment` сервиса `ldap-client`.

## Скрипты (порядок выполнения в run-loop)

| Скрипт | Сценарий из матрицы |
|--------|----------------------|
| `01_search_base.sh` | Search base (объект по DN) |
| `02_search_one.sh` | Search one level (дети) |
| `03_search_subtree.sh` | Search subtree |
| `04_search_filter.sh` | Search с фильтром по objectClass |
| `05_bind_compare.sh` | Bind + compare |
| `06_whoami.sh` | WhoAmI extended |
| `07_anonymous_bind.sh` | Anonymous bind (может быть SKIP, если отключено) |
| `08_domain_join_add.sh` | Domain join / realm join — Add OU и пользователя |
| `09_search_user.sh` | Поиск пользователя (getpwnam-like) |
| `10_search_groups.sh` | Поиск групп (groupOfNames) |
| `11_search_policies.sh` | GPO-like — чтение базы/системного поддерева |
| `12_sssd_simple_bind_user.sh` | SSSD ldap — Simple bind пользователем + search |
| `13_modify_attribute.sh` | Админ — Modify атрибута (description) |
| `14_password_modify.sh` | Смена пароля (ldappasswd) |
| `15_run_as_two_binds.sh` | Run as — два пользователя подряд (admin, user) |
| `16_many_searches.sh` | Серия поисков (имитация всплеска при логине) |
| `17_persistent_search.sh` | Persistent Search (RFC 4533): поиск в фоне, два ldapmodify, проверка что оба изменения пришли в потоке |

Скрипты 08–17 зависят от тестового пользователя, создаваемого в `08_domain_join_add.sh`; порядок запуска сохраняется (`run-loop.sh` выполняет `[0-9][0-9]_*.sh` по возрастанию номера).

Для сценария 17 (persistent search) бэкенд должен поддерживать RFC 4533 (контроль Sync Request, режим refreshAndPersist); в OpenLDAP для этого нужен overlay `syncprov` на провайдере.

## Запуск

```bash
docker compose up -d ldap-load-balancer ldap-client
docker compose logs -f ldap-client
```

Один проход всех сценариев выполняется в `run-loop.sh`; цикл повторяется с паузой 2 с.

### Несколько клиентов (как поды, без Kubernetes)

Запуск N экземпляров клиента для нагрузки на балансировщик:

```bash
docker compose up -d --scale ldap-client=5
```

Будут созданы контейнеры `ldap-client-1`, `ldap-client-2`, … Все идут на один и тот же `ldap-load-balancer`. Логи по одному клиенту:

```bash
docker compose logs -f ldap-client-1
```

Вернуть один клиент:

```bash
docker compose up -d --scale ldap-client=1
```
