# LDAP client для тестирования сценариев

Контейнер `ldap-client` запускает интеграционные тесты против LDAP Load Balancer, эмулируя клиентов из [матрицы сценариев](../../docs/client-scenarios-matrix.md).

**По умолчанию** контейнер выполняет один прогон **pytest** (сценарии 01–23) с генерацией отчётов JUnit XML и HTML. Раньше использовался бесконечный цикл shell-скриптов (`run-loop.sh`); его можно запустить вручную (см. ниже).

## Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `LDAP_SCHEME` | `ldap` | Схема: `ldap` или `ldaps` (URI = `${LDAP_SCHEME}://${LDAP_HOST}:${LDAP_PORT}`) |
| `LDAP_HOST` | `ldap-load-balancer` | Хост балансировщика |
| `LDAP_PORT` | `1389` | Порт LDAP (для LDAPS обычно `636`) |
| `BASE_DN` | `dc=example,dc=com` | Базовый DN |
| `BIND_DN` | `cn=admin,dc=example,dc=com` | DN для bind |
| `BIND_PW` | `secret` | Пароль |
| `TEST_USER_OU` | `ou=users` | OU тестового пользователя |
| `TEST_USER_CN` | `testuser` | cn тестового пользователя |
| `TEST_USER_PW` | `testpass` | Пароль тестового пользователя |
| `METRICS_HOST` | `ldap-load-balancer` | Хост для /health, /ready, /metrics |
| `METRICS_PORT` | `9090` | Порт метрик |
| `LDAP_TLS_REQCERT` | — | Для LDAPS: `never` — не проверять сертификат сервера (только для тестов); иначе проверка по умолчанию |
| `LDAP_TLS_CACERT` | — | Путь к CA-сертификату для проверки сервера (если не задан — системные корни) |

В `docker-compose` задавайте их в `environment` сервиса `ldap-client` или `ldap-client-ldaps`.

**TLS (LDAPS):** для проверки сертификата сервера задайте `LDAP_TLS_CACERT` (путь к CA). Для тестовой среды с самоподписными сертификатами можно использовать `LDAP_TLS_REQCERT=never` (только не для продакшена).

## Запуск интеграционных тестов (pytest)

1. Поднять балансировщик и бэкенды (и при необходимости etcd с конфигом):

   ```bash
   docker compose up -d etcd ldap1 ldap2 ldap3 ldap-load-balancer
   # При необходимости: записать конфиг в etcd
   ```

2. Запустить тесты (один прогон). Отчёты пишутся в каталог `./reports` на хосте:

   ```bash
   mkdir -p reports
   docker compose run --rm -v "$(pwd)/reports:/reports" ldap-client
   ```

### Запуск тестов по LDAPS

Сервис `ldap-load-balancer-ldaps` слушает порт **636** (LDAPS) с TLS; конфиг — `config.docker.ldaps.yaml`, сертификаты — из `docker/ldap1/certs`. Клиентский сервис `ldap-client-ldaps` использует тот же образ, что и `ldap-client`, с переменными `LDAP_SCHEME=ldaps`, `LDAP_HOST=ldap-load-balancer-ldaps`, `LDAP_PORT=636` и `LDAP_TLS_REQCERT=never` (для тестовой среды с самоподписными сертификатами).

1. Поднять бэкенды и LDAPS-балансировщик:

   ```bash
   docker compose up -d etcd ldap1 ldap2 ldap3 ldap-load-balancer-ldaps
   ```

2. Запустить тесты клиента по LDAPS:

   ```bash
   mkdir -p reports
   docker compose run --rm -v "$(pwd)/reports:/reports" ldap-client-ldaps
   ```

Поведение сценариев (поиск, bind, whoami и т.д.) совпадает с обычным `ldap-client`; отличие лишь в транспорте (LDAPS).

   В `reports/` появятся:
   - **`junit.xml`** — для CI (GitHub Actions, GitLab CI и т.д.);
   - **`report.html`** — HTML-отчёт для просмотра в браузере (имя теста, статус, время, трассировка при падении).

3. Только JUnit (без HTML):

   ```bash
   docker compose run --rm -e PYTEST_ADDOPTS="--junitxml=/reports/junit.xml" \
     -v "$(pwd)/reports:/reports" ldap-client
   ```

4. JUnit + HTML (явно):

   ```bash
   docker compose run --rm -e PYTEST_ADDOPTS="--junitxml=/reports/junit.xml --html=/reports/report.html --self-contained-html" \
     -v "$(pwd)/reports:/reports" ldap-client
   ```

По умолчанию `PYTEST_ADDOPTS` уже задан в образе так, что генерируются оба отчёта в `/reports`; достаточно смонтировать том в `./reports`.

## Где смотреть отчёты

- **JUnit XML** (`reports/junit.xml`) — загружается в CI для отображения результатов и истории.
- **HTML** (`reports/report.html`) — откройте в браузере: список тестов, passed/failed, время, при падении — сообщение и трассировка.

## Подключение к CI (GitHub Actions / GitLab CI)

1. Поднять стек: etcd, ldap1/ldap2/ldap3, ldap-load-balancer (и при необходимости записать конфиг в etcd).
2. Запустить контейнер `ldap-client` с монтированием каталога для отчётов.
3. Сохранить артефакты `junit.xml` и `report.html` (например, `actions/upload-artifact` в GitHub Actions).

Пример (GitHub Actions):

```yaml
- name: Run integration tests
  run: |
    docker compose up -d etcd ldap1 ldap2 ldap3 ldap-load-balancer
    sleep 5
    mkdir -p reports
    docker compose run --rm -v "$(pwd)/reports:/reports" ldap-client
- name: Upload test reports
  uses: actions/upload-artifact@v4
  with:
    name: test-reports
    path: reports/
```

После прогона публикуйте `junit.xml` в качестве test results (например, через `pytest-reporting` или встроенную поддержку JUnit в GitLab/GitHub).

## Структура тестов (pytest)

- **`tests/conftest.py`** — фикстуры: `ldap_scheme`, `ldap_uri` (собирается как `${LDAP_SCHEME}://${LDAP_HOST}:${LDAP_PORT}`), `bind_dn`, `base_dn`, `ldap_conn`, `ensure_test_user` (создание OU и тестового пользователя для сценариев 09–17). Для LDAPS применяются опции TLS из `LDAP_TLS_REQCERT` / `LDAP_TLS_CACERT`.
- **`tests/test_01_search_base.py` … `test_23_create_user_group.py`** — один файл на сценарий (01–23), те же проверки, что и в прежних скриптах `scripts/NN_*.sh`.
- Порядок выполнения задаётся маркером `@pytest.mark.order(N)`; зависимости (тестовый пользователь) — через фикстуру `ensure_test_user`.

Сценарий 17 (Persistent Search) вызывает существующий `scripts/17_persistent_search.py` через subprocess.

## Запуск в режиме loop (shell-скрипты)

Для ручной проверки или нагрузки можно снова запускать все shell-скрипты по кругу:

```bash
docker compose run --rm ldap-client /scripts/run-loop.sh
```

Цикл будет повторяться с паузой 2 с; в stdout — OK/FAIL и время по каждому скрипту.

## Несколько клиентов (нагрузка)

Запуск нескольких экземпляров клиента на один балансировщик:

```bash
docker compose up -d --scale ldap-client=5
```

По умолчанию каждый контейнер выполняет один прогон pytest и завершается. Для непрерывной нагрузки используйте переопределение команды на `run-loop.sh` (см. выше).

## Соответствие сценариям (01–23)

| № | Файл теста | Сценарий |
|---|------------|----------|
| 01 | test_01_search_base.py | Search base (объект по DN) |
| 02 | test_02_search_one.py | Search one level (дети) |
| 03 | test_03_search_subtree.py | Search subtree |
| 04 | test_04_search_filter.py | Search с фильтром objectClass |
| 05 | test_05_bind_compare.py | Bind + compare |
| 06 | test_06_whoami.py | WhoAmI extended |
| 07 | test_07_anonymous_bind.py | Anonymous bind + чтение тестовой записи (см. docker/ldap1/README.md) |
| 08 | test_08_domain_join_add.py | Domain join — Add OU и пользователя |
| 09–17 | test_09_… — test_17_… | Поиск пользователя/групп, SSSD bind, modify, passwd, run-as, много поисков, persistent search |
| 18–19 | test_18_ber_…, test_19_filter_… | BER/фильтры |
| 20 | test_20_paged_results.py | Paged results |
| 21 | test_21_sticky_… | Sticky: add + search |
| 22 | test_22_health_metrics.py | /health, /ready, /metrics |
| 23 | test_23_create_user_group.py | Создание пользователя, группы, member |

Сценарий 07 для прохождения требует разрешённого анонимного чтения на бэкенде OpenLDAP: один раз применить `acl-anonymous-read.ldif` (см. `docker/ldap1/README.md`).

Сценарий 17 требует поддержки RFC 4533 (Sync Request, refreshAndPersist) на бэкенде (например, overlay `syncprov` в OpenLDAP).
