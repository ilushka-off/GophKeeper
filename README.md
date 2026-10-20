# GophKeeper

Клиент-серверный менеджер паролей на Go. Сервер хранит зашифрованные данные пользователя
и синхронизирует их между его устройствами, CLI-клиент работает на Linux, macOS и Windows.

- **Сквозное шифрование.** Данные шифруются на клиенте (Argon2id + AES-256-GCM). Сервер хранит
  только шифротекст и не знает ни мастер-пароля, ни ключа шифрования.
- **Четыре типа записей:** логин/пароль, произвольный текст, бинарные данные (файлы), банковские карты.
  У каждой записи есть имя и произвольная метаинформация.
- **Работа офлайн и синхронизация.** Клиент держит локальную копию в SQLite и синхронизирует её
  с сервером после входа, после каждого изменения и по команде `sync`. Конфликты решаются по версиям.
- **gRPC + TLS**, PostgreSQL на сервере, клиент собирается без CGO.

## Быстрый старт

```bash
make cert          # самоподписанный сертификат для разработки в ./certs
make docker-up     # PostgreSQL + сервер на :3200
make client        # клиент в ./bin/gophkeeper
```

Без Docker сервер можно запустить и так (без `-d` данные хранятся в памяти):

```bash
make server
./bin/gophkeeper-server -d "postgres://user:pass@localhost:5432/gophkeeper?sslmode=disable" \
  -jwt-secret "$(openssl rand -hex 32)"
```

## Клиент

```bash
export GOPHKEEPER_SERVER=localhost:3200
export GOPHKEEPER_CA_CERT=certs/server.crt   # не нужен, если сертификат выпущен публичным CA

gophkeeper register -l ilya                   # новый пользователь
gophkeeper add credentials -n github --login ilya -m "https://github.com"   # пароль спросит без эха
gophkeeper add text -n wifi --text "пароль от wifi: ..."
gophkeeper add card -n visa --number "4111 1111 1111 1111" --holder "ILYA" --expiry 12/30 --cvv 123
gophkeeper add binary -n passport --file ./passport.pdf
gophkeeper list
gophkeeper get 3f2a91c0                       # можно указать начало id
gophkeeper get 9b1e -o passport.pdf           # выгрузить файл
gophkeeper edit 3f2a91c0 --password new-pass
gophkeeper delete 3f2a91c0
gophkeeper sync
gophkeeper status
gophkeeper logout
gophkeeper version
```

На втором устройстве достаточно `gophkeeper login -l ilya`: клиент скачает и расшифрует все записи.

| Флаг | Переменная окружения | По умолчанию |
|------|----------------------|--------------|
| `--server` | `GOPHKEEPER_SERVER` | `localhost:3200` |
| `--ca-cert` | `GOPHKEEPER_CA_CERT` | системные корневые сертификаты |
| `--data-dir` | `GOPHKEEPER_DATA_DIR` | `<UserConfigDir>/gophkeeper` |
| — | `GOPHKEEPER_MASTER_PASSWORD` | мастер-пароль для скриптов; интерактивно лучше вводить по запросу |

### TUI

`gophkeeper tui` открывает интерактивный интерфейс в терминале (bubbletea): список записей
с фильтром по типу и поиском, просмотр записи с живым OTP-кодом и формы добавления
учётных данных, текста, карт и OTP. Пароли, номер карты и CVV скрыты, пока не нажать `r`.

| Клавиша | Действие |
|---------|----------|
| `↑`/`k`, `↓`/`j`, `enter` | выбор и открытие записи |
| `tab` / `shift+tab` | фильтр по типу |
| `/` | поиск по имени |
| `a` | добавить запись (в форме `tab` — следующее поле, `ctrl+s` — сохранить) |
| `d` | удалить запись (с подтверждением) |
| `s` | синхронизировать |
| `esc`, `q`, `?` | назад, выход, справка |

Бинарные файлы добавляются и выгружаются командами `add binary` и `get -o`.

## Сервер

| Флаг | Переменная окружения | По умолчанию |
|------|----------------------|--------------|
| `-a` | `ADDRESS` | `:3200` |
| `-http-address` | `HTTP_ADDRESS` | пусто: REST-шлюз выключен |
| `-d` | `DATABASE_DSN` | пусто: хранилище в памяти |
| `-tls-cert`, `-tls-key` | `TLS_CERT`, `TLS_KEY` | `certs/server.crt`, `certs/server.key` |
| `-jwt-secret` | `JWT_SECRET` | случайный при каждом запуске |
| `-access-ttl`, `-refresh-ttl` | `ACCESS_TTL`, `REFRESH_TTL` | `15m`, `720h` |
| `-max-blob-size` | `MAX_BLOB_SIZE` | 100 MB |
| `-shutdown-timeout` | `SHUTDOWN_TIMEOUT` | `10s` |
| `-log-level` | `LOG_LEVEL` | `info` |

Переменные окружения важнее флагов. Сервер применяет миграции при старте и корректно
завершается по SIGTERM/SIGINT.

## Как это устроено

```mermaid
flowchart LR
    U[Пользователь] --> C[CLI-клиент]
    C --> L[(SQLite: локальная копия)]
    C -->|gRPC + TLS| S[server]
    S --> DB[(PostgreSQL)]
```

**Ключи.** Из мастер-пароля и случайной соли через Argon2id выводится мастер-ключ, из него через
HKDF два независимых значения: пароль входа (уходит на сервер и хранится там как хеш Argon2id)
и ключ шифрования (никогда не покидает клиент). Перед входом клиент получает соль через
`AuthService.GetSalt`; для несуществующего логина сервер отдаёт детерминированную фиктивную соль,
чтобы не раскрывать, какие логины заняты.

**Записи.** Полезная нагрузка (имя, метаинформация, данные) сериализуется в JSON и шифруется
AES-256-GCM с привязкой к id и типу записи. Файлы шифруются чанками по 1 MB, каждый чанк
привязан к id блоба, своему номеру и признаку последнего чанка, поэтому их нельзя переставить
или обрезать. Блобы неизменяемы: при замене файла загружается новый, а старый удаляется после
синхронизации, если на него больше не ссылается ни одна запись.

**Синхронизация.** У записи есть `version`, у пользователя счётчик `revision`. `Push` принимает
изменения с версией, от которой отталкивался клиент; если на сервере версия новее, это конфликт.
Побеждает серверная версия, а локальная сохраняется отдельной записью с пометкой
`(conflict <дата>)`, так что правки не теряются. `Pull(since)` отдаёт все изменения после
последней полученной ревизии, включая удаления (tombstones).

**Протокол** описан в [`api/proto/gophkeeper/v1`](api/proto/gophkeeper/v1): `AuthService`,
`VaultService`, `SyncService`.

## REST и Swagger

Кроме gRPC сервер умеет отдавать тот же API как REST/JSON через
[grpc-gateway](https://github.com/grpc-ecosystem/grpc-gateway). Шлюз включается флагом
`-http-address` (или `HTTP_ADDRESS`), работает по HTTPS с тем же сертификатом и вызывает
сервисы через внутренний gRPC-сервер, поэтому авторизация, логирование и коды ошибок те же.

```bash
./bin/gophkeeper-server -http-address :8443
curl --cacert certs/server.crt https://localhost:8443/swagger.json
curl --cacert certs/server.crt https://localhost:8443/api/v1/auth/salt/ilya
curl --cacert certs/server.crt -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/records
```

- `GET /swagger.json` отдаёт спецификацию OpenAPI 2.0, её можно открыть в Swagger UI или
  [editor.swagger.io](https://editor.swagger.io). Сгенерированный файл лежит в
  [`api/openapi/gophkeeper.swagger.json`](api/openapi/gophkeeper.swagger.json).
- Методы доступны под `/api/v1/...`; токен передаётся заголовком `Authorization: Bearer <token>`.
- Поля `bytes` (зашифрованные данные, соль) в JSON кодируются в base64. Данные по-прежнему
  шифруются на клиенте, сервер их не видит.
- `UploadBlob` (клиентский стрим) есть только в gRPC; `DownloadBlob` по REST отдаёт чанки
  как JSON-объекты, по одному на строку.

## Разработка

```bash
make tools    # установить protoc-gen-go, protoc-gen-go-grpc, protoc-gen-grpc-gateway, protoc-gen-openapiv2
make gen      # buf generate: Go-код, gRPC, grpc-gateway и api/openapi/gophkeeper.swagger.json
make lint     # golangci-lint + buf lint
make test     # go test -race ./...
make cover    # покрытие, не меньше 70%
make test-integration  # end-to-end: сервер по TLS + PostgreSQL + два клиента
make clients  # клиент под linux/darwin/windows × amd64/arm64 в ./dist
```

Тесты PostgreSQL-хранилища запускаются, если задан `TEST_DATABASE_DSN`, иначе пропускаются.

Интеграционные тесты (`test/integration`, build tag `integration`) поднимают настоящий сервер
с TLS-сертификатом, сгенерированным в тесте, и гоняют через CLI два устройства одного пользователя:
регистрация, вход, все типы записей, синхронизация, конфликт, файлы больше 1 МБ, удаление и сборка
мусорных блобов. PostgreSQL берётся из `TEST_DATABASE_DSN`, а если он не задан, запускается в Docker
через testcontainers. Тесты удаляют таблицы в этой базе, поэтому указывайте только тестовую.
Релиз собирается goreleaser по тегу `v*`.

## Структура

```
api/proto/gophkeeper/v1   protobuf-контракт
api/proto/google, api/proto/protoc-gen-openapiv2
                          сторонние proto для аннотаций grpc-gateway (вендорены)
api/gen                   сгенерированный код
api/openapi               спецификация OpenAPI (Swagger)
cmd/server, cmd/client    точки входа
internal/model            доменные типы и сериализация записей
internal/crypto           KDF, AES-GCM, шифрование потоков, хеш паролей
internal/server/...       конфиг, сервисы, gRPC, REST-шлюз, хранилища (PostgreSQL, память)
internal/client/...       CLI, TUI, бизнес-логика клиента, SQLite, gRPC-клиент
test/integration          end-to-end тесты (build tag integration)
```
