# Матрица сценариев клиентов LDAP

Сеть: один контроллер **Microsoft AD**, один **Samba DC**. Клиенты: **Windows** и **Linux + SSSD**.  
Документ описывает все возможные сценарии от лица клиентов (эмулятор реальной сети).

---

## 1. Сводная матрица: клиент → операции

| Клиент | Bind | Search (read) | Modify/Add | Типичные объекты/атрибуты |
|--------|------|---------------|------------|---------------------------|
| Windows (domain join, GPO, ADUC) | IWA / Simple | Массовые (user, group, computer, GPO) | Редко (при join) | sAMAccountName, memberOf, objectClass, cn, distinguishedName |
| Windows (приложение) | Simple / IWA | По пользователю и группам | Почти нет | То же + кастомные атрибуты |
| Linux SSSD (ad) | GSSAPI / реже simple | user, group, memberOf | passwd (extended) | uid, sAMAccountName, userPrincipalName, memberOf, objectSid |
| Linux SSSD (ldap) | Simple при каждом логине | user (для DN), group | passwd | uid, memberOf (или group по member) |
| Скрипты / админка | Simple (service account) | Любые | Да (создание пользователя, смена пароля) | Всё дерево |

---

## 2. Матрица по типу операции и протоколу

| Сценарий | Клиент | Операция | 389 | 636 | StartTLS |
|----------|--------|----------|-----|-----|----------|
| Domain join | Windows | Bind + Search + Add | ✓ | ✓ | ✓ |
| Интерактивный логин | Windows | Search (user/group) | ✓ | ✓ | ✓ |
| Сетевой логин (RDP, share) | Windows | Search | ✓ | ✓ | ✓ |
| Run as (другой пользователь) | Windows | Bind + Search | ✓ | ✓ | ✓ |
| GPO при старте сессии | Windows | Search (Policies) | ✓ | ✓ | ✓ |
| ADUC / MMC поиск | Windows | Search | ✓ | ✓ | ✓ |
| PowerShell / .NET | Windows | Bind + Search | ✓ | ✓ | ✓ |
| realm join | Linux SSSD | Bind + Search + Add | ✓ | ✓ | ✓ |
| Логин (id_provider=ad) | Linux SSSD | Search (user/group) | ✓ | ✓ | ✓ |
| getpwnam / getgrnam | Linux SSSD | Search | ✓ | ✓ | ✓ |
| Смена пароля (passwd) | Linux SSSD | Extended (modify) | ✓ | ✓ | ✓ |
| Логин (id_provider=ldap) | Linux SSSD | Bind + Search | ✓ | ✓ | ✓ |
| Приложение (портал, почта) | Любой | Bind + Search | ✓ | ✓ | ✓ |
| Админ-скрипт | Любой | Bind + Search + Modify | ✓ | ✓ | ✓ |

---

## 3. Матрица по механизму аутентификации

| Механизм | Windows | Linux SSSD (ad) | Linux SSSD (ldap) | Приложения |
|----------|---------|-----------------|-------------------|------------|
| Anonymous | — | — | — | Редко (если разрешено) |
| Simple bind (DN + пароль) | Да (приложения) | Редко | Да (каждый логин) | Да |
| SASL GSSAPI (Kerberos) | Да (IWA) | Да | — | Да (интеграция с AD) |
| SASL NTLM | Возможно | — | — | Редко |

---

## 4. Сценарии по контроллерам (AD vs Samba)

| № | Сценарий | Риск / примечание |
|---|----------|-------------------|
| 1 | Запрос на AD, следующий на Samba | Различия схемы/атрибутов, лаг репликации |
| 2 | Bind на DC#1, Search на DC#2 | Stateful: ошибка; stateless: возможны неожиданности |
| 3 | Referral с AD/Samba на другой DC | Клиент может уйти мимо балансировщика |
| 4 | Запись (пароль, атрибуты) | Желательно один DC, репликация на второй |
| 5 | Создание пользователя на AD → логин с Linux | Запрос на Samba до репликации → «пользователь не найден» |
| 6 | Смена пароля на одном DC | Вход через второй DC до репликации → «неверный пароль» |

---

## 5. Детализация по клиентам

### 5.1 Windows

| № | Сценарий | LDAP-операции | Особенности |
|---|----------|---------------|-------------|
| 1 | Присоединение к домену | Поиск DC, чтение OU, запись в cn=Computers | Один выбранный DC по DNS |
| 2 | Интерактивный вход | Поиск user/group после Kerberos | Много коротких поисков |
| 3 | Сетевой вход (RDP, share) | Поиск учётки/групп | Тот же пользователь с разных машин |
| 4 | Run as | Bind + поиск | Один хост, разные пользователи |
| 5 | Групповые политики (GPO) | Поиск cn=Policies, cn=System | Массовые чтения при старте |
| 6 | ADUC / MMC | Разные base DN, scope, фильтры | Поиск пользователей/компьютеров |
| 7 | PowerShell / .NET | Bind + Search по атрибутам | Скрипты, приложения |

### 5.2 Linux + SSSD (id_provider = ad)

| № | Сценарий | LDAP-операции | Особенности |
|---|----------|---------------|-------------|
| 8 | realm join | Поиск домена/DC, запись компьютера | Аналог Windows domain join |
| 9 | Вход пользователя | Поиск user по sAMAccountName/UPN, группы | Критичный путь входа |
| 10 | getpwnam / getgrnam | Поиск user/group по имени | При cache miss — LDAP |
| 11 | Перечисление user/group | Scope onelevel/subtree | Нагрузка по объёму |
| 12 | Смена пароля (passwd) | Extended (password modify) | Зависит от настроек DC |

### 5.3 Linux + SSSD (id_provider = ldap)

| № | Сценарий | LDAP-операции | Особенности |
|---|----------|---------------|-------------|
| 13 | Simple bind при логине | Bind с DN пользователя + пароль | Каждый логин = bind; балансировка может развести bind и поиски |
| 14 | Поиск user по логину (для DN) | Фильтр (uid=user) или (sAMAccountName=user) | До bind, если DN неизвестен |
| 15 | Поиск групп | memberOf или поиск по member | Зависит от ldap_id_use_tokengroups |

### 5.4 Надёжность и протокол

| № | Сценарий | Детали |
|---|----------|--------|
| 16 | LDAP vs LDAPS | 389 vs 636, StartTLS на 389 |
| 17 | Офлайн-логин (SSSD cache) | После успешного LDAP — кэш; при недоступности LDAP вход по кэшу |
| 18 | Failover в ldap_uri | Несколько адресов в SSSD; балансировщик может быть одним из них |

---

## 6. Эмулятор: матрица для тестов

Использование: строки = тип клиента, столбцы = тип операции; ячейка = ожидаемое поведение (OK / ошибка / зависит от репликации).

| | Bind Simple | Bind GSSAPI | Search User | Search Group | Search GPO | Modify Passwd | Add (join) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Windows join | — | ✓ | ✓ | — | — | — | ✓ |
| Windows login | — | ✓ | ✓ | ✓ | ✓ | — | — |
| Windows ADUC | ✓/IWA | ✓ | ✓ | ✓ | — | — | — |
| App (service) | ✓ | ✓ | ✓ | ✓ | — | — | — |
| Linux SSSD (ad) | редко | ✓ | ✓ | ✓ | — | ✓ | при join |
| Linux SSSD (ldap) | ✓ | — | ✓ | ✓ | — | ✓ | — |
| Админ-скрипт | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ |

---

---

## 7. Скрипты ldap-client

Сценарии выше можно гнать автоматически скриптами в [docker/ldap-client](../docker/ldap-client/): см. [README ldap-client](../docker/ldap-client/README.md). Нумерация скриптов `01_*` … `16_*` соответствует типам операций и клиентам из матрицы.

*Документ можно расширять конкретными тест-кейсами и результатами прогонов под балансировщиком.*
