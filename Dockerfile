FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X github.com/ilushka-off/GophKeeper/internal/buildinfo.Version=${VERSION} -X github.com/ilushka-off/GophKeeper/internal/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /out/gophkeeper-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gophkeeper-server /gophkeeper-server
EXPOSE 3200 8443
ENTRYPOINT ["/gophkeeper-server"]
