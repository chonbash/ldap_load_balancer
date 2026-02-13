# LDAP Load Balancer

LDAP v3 load balancer на Rust, реализующий функциональность OpenLDAP lloadd для распределения LDAP запросов между несколькими backend серверами.

## Возможности

- ✅ Распределение нагрузки между несколькими LDAP серверами
- ✅ Поддержка всех основных LDAP операций (Bind, Search, Add, Modify, Delete, ModifyDN, Compare, Extended)
- ✅ Connection pooling к backend серверам
- ✅ Поддержка TLS/STARTTLS
- ✅ Конфигурируемые таймауты и параметры подключения
- ✅ Стратегии балансировки: random, round_robin, ring_hash (consistent hashing по ключу клиента)
- ✅ Асинхронная обработка запросов на базе Tokio

## Установка

```bash
# Клонировать репозиторий
git clone <repository-url>
cd ldap_load_balancer

# Собрать проект
cargo build --release

# Запустить
cargo run --release -- --config config.yaml
```

## Конфигурация

Создайте файл конфигурации `config.yaml`:

```yaml
listen:
  url: "ldap://:1389"  # URL для прослушивания

backend:
  # Стратегия выбора backend: random (по умолчанию), round_robin, ring_hash
  # ring_hash — consistent hashing по адресу клиента (все запросы с одного клиента на один backend)
  strategy: random  # или round_robin, ring_hash
  # sticky_writes: true  # по умолчанию true — после Bind операции записи (Add/Modify/Delete/ModifyDN) идут на тот же backend; в proxy-режиме одно соединение на клиента уже даёт sticky
  # Для ring_hash: число виртуальных узлов на сервер (по умолчанию 100)
  # ring_hash_vnodes: 100
  # Повтор подключения к backend при proxy: число попыток (default 3), задержка между попытками в ms (default 50)
  # connect_attempts: 3
  # connect_retry_delay_ms: 50

  bind:
    method: "simple"
    binddn: "cn=admin,dc=example,dc=com"
    credentials: "secret"
    network_timeout: 5
    tls_cacert: "/path/to/ca.crt"
    tls_cert: "/path/to/cert.crt"
    tls_key: "/path/to/key.pem"

  servers:
    - uri: "ldap://ldaphost01:389"
      starttls: "critical"
      retry: 5
      max_pending_ops: 50
      conn_max_pending: 10
      numconns: 10
      bindconns: 5
    
    - uri: "ldap://ldaphost02:389"
      starttls: "critical"
      retry: 5
      max_pending_ops: 50
      conn_max_pending: 10
      numconns: 10
      bindconns: 5
    
    - uri: "ldap://ldaphost03:389"
      starttls: "critical"
      retry: 5
      max_pending_ops: 50
      conn_max_pending: 10
      numconns: 10
      bindconns: 5

tls:
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
  ca_file: "/path/to/ca.pem"
  share_slapd_ctx: true

io_threads: 2
proxyauthz: false

# Опционально: HTTP-сервер для метрик (Prometheus). Если задан, GET /metrics возвращает метрики.
# metrics_listen: "0.0.0.0:9090"
```

### Метрики мониторинга (Prometheus)

Если в конфиге указан `metrics_listen` (например, `"0.0.0.0:9090"`), балансировщик поднимает отдельный HTTP-сервер. Эндпоинт **GET /metrics** отдаёт метрики в [текстовом формате Prometheus](https://prometheus.io/docs/instrumenting/exposition_formats/):

Метрики соответствуют схеме **RED** (Rate, Errors, Duration):

| Метрика | Тип | Описание |
|--------|-----|----------|
| `ldap_lb_connections_total` | counter | Число принятых клиентских подключений |
| `ldap_lb_requests_total{op="bind\|search\|add\|modify\|delete\|extended"}` | counter | Успешные запросы по типу операции (Rate) |
| `ldap_lb_errors_total{op="..."}` | counter | Ошибки по типу операции (Errors) |
| `ldap_lb_request_duration_seconds` | histogram | Длительность обработки запросов по операциям (Duration): `_bucket`, `_sum`, `_count` |
| `ldap_lb_backend_servers` | gauge | Текущее число backend-серверов (из конфига) |
| `ldap_lb_backend_up{uri="..."}` | gauge | Состояние узла: 1 = up, 0 = down, -1 = unknown (health check отключён) |
| `ldap_lb_backend_requests_total{uri="...", op="..."}` | counter | Запросы, пересланные на каждый backend по типу операции (proxy-режим) |

Пример конфигурации и запроса:

```yaml
metrics_listen: "0.0.0.0:9090"
```

```bash
curl http://localhost:9090/metrics
```

### Конфигурация через etcd (обновление на лету)

Конфигурацию можно хранить в etcd и обновлять без перезапуска процесса. Формат значения ключа — тот же YAML, что и в файле.

```bash
# Записать конфиг в etcd (пример)
etcdctl put /ldap-load-balancer/config "$(cat config.yaml)"

# Запуск с загрузкой и watch ключа в etcd
./target/release/ldap-load-balancer \
  --etcd-endpoints http://127.0.0.1:2379 \
  --etcd-config-key /ldap-load-balancer/config

# С fallback-файлом, если ключ пуст или etcd недоступен при старте
./target/release/ldap-load-balancer \
  --etcd-endpoints http://127.0.0.1:2379 \
  --etcd-config-key /ldap-load-balancer/config \
  --etcd-fallback-file config.yaml
```

При изменении значения ключа в etcd конфигурация (в т.ч. список backend-серверов и `proxyauthz`) подхватывается автоматически; перезапуск не требуется. Адрес прослушивания (`listen.url`) задаётся при старте и по умолчанию не меняется (можно переопределить через `--listen`).

### Сертификаты и бандл CA в etcd

Значения в etcd — обычные строки (UTF-8). Для сертификатов и ключей кладут **PEM как есть** (включая строки `-----BEGIN ...-----` / `-----END ...-----`). Бандл доверенных CA — это один ключ с **несколькими PEM-сертификатами подряд** (конкатенация блоков).

**Пример (etcdctl v3):**

```bash
# Один сертификат
etcdctl put /ldap-load-balancer/tls/ca.pem "$(cat /path/to/ca.pem)"

# Бандл из нескольких CA (файл уже содержит несколько блоков)
etcdctl put /ldap-load-balancer/tls/ca-bundle.pem "$(cat /path/to/ca-bundle.pem)"

# Сертификат и ключ сервера (для LDAPS листенера)
etcdctl put /ldap-load-balancer/tls/cert.pem "$(cat /path/to/cert.pem)"
etcdctl put /ldap-load-balancer/tls/key.pem "$(cat /path/to/key.pem)"
```

**Загрузить CA из docker/ldap1/certs в etcd** (из корня проекта; через stdin, чтобы PEM не трактовался как флаги):

```bash
cat docker/ldap1/certs/ca.crt | docker compose exec -T etcd etcdctl put /ldap-load-balancer/backend-tls/ca-bundle.pem
```

В YAML указываются только **ключи** etcd (пути), не сами данные:

- **Листенер (LDAPS/StartTLS):** в секции `tls` — `cert_etcd_key`, `key_etcd_key`, при необходимости `ca_etcd_key` (один ключ с одним или несколькими PEM CA).
- **Бэкенды (ldaps://):** в секции `backend` — опционально `tls_ca_etcd_key` (ключ с PEM одного CA или бандла). Если задан, при подключении к ldaps-бэкендам используется этот бандл (плюс системные корни). Иначе — только системные CA или `tls_skip_verify: true`.

Пример конфига с etcd-ключами для TLS:

```yaml
tls:
  cert_etcd_key: "/ldap-load-balancer/tls/cert.pem"
  key_etcd_key: "/ldap-load-balancer/tls/key.pem"
  ca_etcd_key: "/ldap-load-balancer/tls/ca-bundle.pem"

backend:
  tls_ca_etcd_key: "/ldap-load-balancer/backend-tls/ca-bundle.pem"  # CA для проверки ldaps:// бэкендов
  # ...
```

## Docker

Окружение для запуска балансировщика с двумя Samba backend, etcd и LDAP-клиентом:

```bash
# Собрать и запустить все сервисы
docker compose up -d

# Проверить, что все контейнеры запущены
docker compose ps

# LDAP search через балансировщик (с клиентского контейнера; бэкенды — OpenLDAP, admin DN ниже)
docker compose exec ldap-client ldapsearch -x -H ldap://ldap-load-balancer:1389 -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w secret

# WhoAmI через балансировщик
docker compose exec ldap-client ldapwhoami -x -H ldap://ldap-load-balancer:1389 -D "cn=admin,dc=example,dc=com" -w secret

# С хоста (если установлен ldap-utils): порт 1389 проброшен на хост
ldapsearch -x -H ldap://127.0.0.1:1389 -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w secret

# Остановить
docker compose down
```

Сервисы:
- **etcd** — порт 12379 на хосте (в сети контейнеров: etcd:2379)
- **ldap1**, **ldap2**, **ldap3** — backend LDAP (OpenLDAP; для реального Samba AD нужен другой образ)
- **ldap-load-balancer** — порт 1389
- **ldap-client** — контейнер с `ldapsearch`/`ldapwhoami` для проверки запросов

Конфиг балансировщика для Docker: `config.docker.yaml`.

### Быстрая пересборка и режим разработки

- **Обычная пересборка** (`docker compose build` / `docker compose up --build`): в Dockerfile закеширован слой с зависимостями Rust. При изменении только кода в `src/` пересобирается только ваш крейт, а не все зависимости — пересборка заметно быстрее.

- **Без пересборки образа**: код монтируется в контейнер, `target` хранится в volume — после правки перезапускаете контейнер, пересборка только через `cargo` (инкрементальная). Запуск:
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.dev.yml up ldap-load-balancer
  ```
  Первый раз соберётся образ (stage `builder`), далее достаточно перезапускать сервис.

## Использование

### Командная строка

```bash
# Запуск с конфигурационным файлом
./target/release/ldap-load-balancer --config config.yaml

# Запуск с конфигурацией из etcd (live reload)
./target/release/ldap-load-balancer --etcd-endpoints http://127.0.0.1:2379

# Переопределение URL прослушивания
./target/release/ldap-load-balancer --config config.yaml --listen ldap://:1389

# Включить debug логирование
./target/release/ldap-load-balancer --config config.yaml --debug
```

### Параметры командной строки

- `--config, -c`: Путь к файлу конфигурации (YAML). Обязателен, если не задан etcd.
- `--etcd-endpoints`: Список etcd endpoints (например, `http://127.0.0.1:2379`). При указании конфиг загружается и обновляется из etcd «на лету».
- `--etcd-config-key`: Ключ в etcd с YAML-конфигом (по умолчанию `/ldap-load-balancer/config`).
- `--etcd-fallback-file`: Файл конфигурации при пустом ключе или недоступном etcd при старте.
- `--listen, -h`: URL для прослушивания (переопределяет значение из конфига).
- `--debug, -d`: Включить debug логирование

## Архитектура

Проект состоит из следующих модулей:

- **config.rs**: Управление конфигурацией (загрузка из YAML)
- **backend.rs**: Управление backend серверами и connection pooling
- **ldap_handler.rs**: Обработка LDAP операций и маршрутизация к backend серверам
- **ldap_protocol.rs**: Структуры для LDAP протокола (заглушка для полной реализации)
- **server.rs**: TCP сервер для приема LDAP соединений
- **main.rs**: Точка входа и CLI

## Текущие ограничения
\

Для production использования рекомендуется:

1. Добавить полную реализацию BER encoding/decoding
2. Реализовать полный LDAP протокол парсер
3. Добавить поддержку LDAP controls
4. Реализовать sticky sessions для операций записи
5. Добавить health checks для backend серверов
6. Реализовать мониторинг и метрики

## Разработка

```bash
# Запустить тесты
cargo test

# Проверить код
cargo clippy

# Форматировать код
cargo fmt
```

## Лицензия

MIT

## Ссылки

- [OpenLDAP Load Balancer Documentation](https://www.openldap.org/doc/admin25/loadbalancer.html)
- [LDAP v3 Protocol Specification](https://www.rfc-editor.org/rfc/rfc4511)

