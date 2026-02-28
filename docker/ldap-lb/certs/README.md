# Сертификаты LDAP Load Balancer (LDAPS)

Эта директория предназначена для TLS-сертификатов балансировщика при приёме клиентских подключений по **LDAPS** (порт 636, TLS с первого байта).

## Варианты размещения сертификатов

1. **Сертификаты бэкенда (быстрый старт)**  
   В `docker-compose.yml` сервис `ldap-load-balancer-ldaps` по умолчанию монтирует `./docker/ldap1/certs` в `/etc/ldap-lb/certs`. В конфиге `config.docker.ldaps.yaml` указаны пути к `ldap1.crt` и `ldap1.key`. Это позволяет поднять LDAPS без дополнительной генерации — используется тот же CA, что и у бэкендов ldap1/2/3.

2. **Отдельные сертификаты для балансировщика (рекомендуется для production)**  
   Сгенерируйте сертификат с CN/SAN для имени сервиса в Docker-сети (например, `ldap-load-balancer`, `ldap-lb`), чтобы клиенты по имени хоста проходили проверку. Результат — файлы `cert.pem` и `key.pem` в этой директории.

3. **Сертификаты из etcd**  
   Конфиг с `tls.cert_etcd_key` и `tls.key_etcd_key` — сертификат и ключ подгружаются из etcd (hot reload при смене значения ключей). Пример конфига: `config.docker.ldaps.etcd.yaml` в корне репозитория. Загрузите конфиг в ключ `/ldap-load-balancer/ldaps-config`, затем PEM сертификата и ключа в указанные ключи (например, `/ldap-load-balancer/ldaps-tls/cert.pem` и `.../key.pem`). Volume с файлами сертификатов не нужен.

## Генерация сертификатов (вариант 2)

Требуется наличие сертификатов ldap1 (CA). Из корня репозитория:

```bash
./docker/ldap-lb/certs/gen-certs.sh
```

Скрипт:
- копирует CA из `docker/ldap1/certs` (ca.crt, ca.key);
- создаёт ключ и сертификат с SAN: `ldap-load-balancer`, `ldap-lb`, `ldap-lb-ldaps`, `localhost`;
- записывает `cert.pem` и `key.pem` в `docker/ldap-lb/certs/`.

Для использования этих файлов в Docker:
- в `config.docker.ldaps.yaml` задайте `tls.cert_file: "/etc/ldap-lb/certs/cert.pem"` и `tls.key_file: "/etc/ldap-lb/certs/key.pem"`;
- в `docker-compose.yml` для сервиса `ldap-load-balancer-ldaps` замените volume на:  
  `./docker/ldap-lb/certs:/etc/ldap-lb/certs:ro`.

## Production

В production используйте сертификаты от доверенного CA или внутренней PKI. Самоподписные сертификаты допустимы только в тестовой среде.

Не храните приватные ключи в репозитории. Файлы `key.pem` и `*.key` добавлены в `.gitignore` этой директории.
