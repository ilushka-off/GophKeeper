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

## Сервер

| Флаг | Переменная окружения | По умолчанию |
|------|----------------------|--------------|
| `-a` | `ADDRESS` | `:3200` |
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

## Разработка

```bash
make gen      # buf generate (нужны buf, protoc-gen-go, protoc-gen-go-grpc)
make lint     # golangci-lint + buf lint
make test     # go test -race ./...
make cover    # покрытие, не меньше 70%
make clients  # клиент под linux/darwin/windows × amd64/arm64 в ./dist
```

Тесты PostgreSQL-хранилища запускаются, если задан `TEST_DATABASE_DSN`, иначе пропускаются.
Релиз собирается goreleaser по тегу `v*`.

## Структура

```
api/proto/gophkeeper/v1   protobuf-контракт
api/gen                   сгенерированный код
cmd/server, cmd/client    точки входа
internal/model            доменные типы и сериализация записей
internal/crypto           KDF, AES-GCM, шифрование потоков, хеш паролей
internal/server/...       конфиг, сервисы, gRPC, хранилища (PostgreSQL, память)
internal/client/...       CLI, бизнес-логика клиента, SQLite, gRPC-клиент
```
