# TODO: Готовность к промышленной эксплуатации

Список задач и ограничений для вывода LDAP Load Balancer в production.

---

### 1. TLS/SSL на клиентском листенере
- **Проблема**: Конфиг поддерживает `listen.url: ldaps://:636` и `tls: { cert_file, key_file, ca_file }`, но сервер использует только `TcpListener::bind()` — **TLS не применяется**.
- **Следствие**: Клиенты подключаются по незашифрованному LDAP, что неприемлемо для production (пароли в открытом виде).
- **Решение**: Реализовать TLS wrapper (rustls или native-tls) для входящих соединений при `ldaps://` или при наличии `tls` в конфиге.

### 2. Graceful shutdown
- **Проблема**: Нет обработки SIGTERM/SIGINT. При `docker stop` или `kill` процесс обрывается без завершения активных соединений.
- **Решение**: 
  - Подписаться на `tokio::signal::ctrl_c()` / SIGTERM
  - Остановить приём новых соединений
  - Дождаться завершения текущих запросов (с таймаутом)

### 3. Health check endpoint
- **Проблема**: Нет отдельного HTTP-эндпоинта для liveness/readiness (Kubernetes, Docker healthcheck). Сейчас только `/metrics`.
- **Решение**: Добавить `GET /health` и/или `GET /ready`:
  - Liveness: процесс жив
  - Readiness: есть хотя бы один здоровый backend

### 4. Handler-режим не подключён / Proxyauthz не реализован
- **Проблема**: Функция `process_ldap_message` (handler-режим: парсинг запросов → вызов ldap_handler → кодирование ответов) **никогда не вызывается**. Сервер работает только в proxy-режиме (пересылка байтов). `proxyauthz` читается из конфига, но не используется.
- **Контекст**: Proxy Authorization (RFC 4370) нужен, когда балансировщик делает bind от своего имени, а затем должен передать identity клиента на backend через control.
- **Решение**: Либо реализовать добавление ProxyAuth control при `proxyauthz: true` (в handler-режиме), либо убрать опцию из конфига и документации.

### 5. SASL в handler-режиме не поддерживается
- **Проблема**: В `process_ldap_message` (сейчас не используется) при SASL Bind возвращается `authMethodNotSupported`.
- **Контекст**: В текущем **proxy-режиме** SASL проходит транзитом (байты пересылаются без изменений) — GSSAPI/NTLM работают. Ограничение актуально только при включении handler-режима.
- **GSSAPI и «Invalid credentials (49)”**: Балансировщик не формирует ответы на bind — только проксирует запросы/ответы. Если при GSSAPI через балансер приходит 49, это ответ **backend** (AD/LDAP). Частая причина — несовпадение SPN: клиент получает билет на имя, к которому подключается (например `ldap/ldap-balancer`), а backend ожидает свой SPN (например `ldap/dc1.elles.lan`). Решение — настройка Kerberos/AD: зарегистрировать SPN для имени балансера на учётной записи backend или использовать имя backend в подключении клиента.

### 6. StartTLS на входящем (клиентском) соединении
- **Проблема**: Клиент может подключиться по `ldap://:389` и инициировать StartTLS. Балансировщик должен уметь «апгрейдить» TCP до TLS.
- **Решение**: Обработка ExtendedRequest (StartTLS OID) и переключение стрима на TLS.

### 7. Роль `io_threads` в конфиге
- **Проблема**: `io_threads` читается из конфига, но не передаётся в `tokio::runtime`. Tokio по умолчанию использует количество CPU.
- **Решение**: Либо применять `io_threads` при создании runtime, либо убрать из конфига.

### 8. Тестирование
- **Есть**: Unit-тесты в `config.rs`, `ldap_handler.rs`, частично в `server.rs`. Интеграционные тесты в `docker/ldap-client/tests/` (pytest), покрывающие сценарии 01–23; отчёты JUnit XML и HTML.
- **Нет**: 
  - CI (GitHub Actions / GitLab CI) с прогоном интеграционных тестов и сохранением артефактов отчётов.
- **Решение**: Добавить CI pipeline (поднять стек, запустить `docker compose run ldap-client`, сохранить `reports/junit.xml` и `reports/report.html`). См. `docker/ldap-client/README.md` — раздел «Подключение к CI».

### 9. Sticky sessions / affinity для операций записи
- **Проблема**: При `strategy: random` или `round_robin` bind и последующие modify/add могут попасть на разные DC. До репликации — «пользователь не найден» / «неверный пароль» (см. `client-scenarios-matrix.md`, раздел 4).
- **Решение**: Можно использовать ring-hash. Надо подумать над другими вариантами

### 10. Rate limiting и защита от DoS
- **Проблема**: Нет ограничения числа соединений/запросов от одного клиента.
- **Решение**: Настраиваемые лимиты (max connections per IP, max requests/sec).

### 11. Structured logging
- **Проблема**: Логи через `tracing` в текстовом виде. Для production полезен JSON (elk, Loki).
- **Решение**: Опция `--log-format json` и/или настройка через конфиг.

### 12. Метрика `ldap_lb_backend_up` при health_check_interval_sec: 0
- **Проблема**: При отключённом health check все узлы считаются up (NODE_UP по умолчанию). Метрика может вводить в заблуждение.
- **Решение**: Явно помечать состояние «unknown» или учитывать отсутствие проверок.

### 13. Документация
- **Добавить**:
  - Описание режимов: proxy vs handler (сейчас используется в основном proxy)
  - Архитектурная диаграмма
  - Рекомендации по развёртыванию (K8s, systemd)
  - Security considerations (secrets в etcd, минимальные права)

### 14. Конфигурация etcd без TLS
- **Проблема**: Подключение к etcd по HTTP. В production etcd обычно с TLS.
- **Решение**: Поддержать `etcd-ca`, `etcd-cert`, `etcd-key` (или аналоги) в конфиге/CLI.

---

## Уже реализовано (готово к использованию)

- Балансировка: random, round_robin, ring_hash
- Connection pooling к backend
- Health checks backend-серверов
- Prometheus-метрики (RED)
- Конфигурация из etcd с live reload
- Proxy-режим (forward LDAP bytes unchanged)
- Persistent Search (Sync Request control)
- Поддержка Bind, Search, Add, Modify, Delete, ModifyDN, Compare, Extended (WhoAmI)
- Docker Compose окружение с etcd, Prometheus, Grafana

