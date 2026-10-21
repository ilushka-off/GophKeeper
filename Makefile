MODULE    := github.com/ilushka-off/GophKeeper
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS   := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Date=$(DATE) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
COVER_MIN := 70

.PHONY: all tools gen lint test test-integration cover build server client clients cert docker-up docker-down clean

all: lint test build

## tools: install the protoc plugins used by buf generate
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.27.2
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.27.2

## gen: regenerate protobuf, gRPC, grpc-gateway code and the OpenAPI spec with buf
gen:
	buf lint
	buf generate

## lint: run golangci-lint and buf lint
lint:
	golangci-lint run ./...
	buf lint

## test: run unit tests with the race detector
test:
	go test -race -count=1 ./...

## test-integration: run end-to-end tests with PostgreSQL (TEST_DATABASE_DSN or a testcontainers container)
test-integration:
	go test -tags integration -count=1 -v ./test/integration/...

## cover: run tests and check total coverage without generated code
cover:
	go test -count=1 -coverpkg=./internal/... -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print int($$3)}'); \
	if [ $$total -lt $(COVER_MIN) ]; then echo "coverage $$total% < $(COVER_MIN)%"; exit 1; fi

build: server client

## server: build the server binary
server:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper-server ./cmd/server

## client: build the client for the current platform
client:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/gophkeeper ./cmd/client

## clients: cross-compile the client for Windows, Linux and macOS
clients:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o dist/gophkeeper_$${os}_$${arch}$$ext ./cmd/client || exit 1; \
	done

## cert: generate a self-signed TLS certificate for development
cert:
	mkdir -p certs
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
		-keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,DNS:server,IP:127.0.0.1"
	# the server container runs as a non-root user and must be able to read the dev key
	chmod 644 certs/server.key

## docker-up: start PostgreSQL and the server
docker-up: cert
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf bin dist coverage.out
