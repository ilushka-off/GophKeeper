package testutil

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/server/app"
	"github.com/ilushka-off/GophKeeper/internal/server/config"
	"github.com/ilushka-off/GophKeeper/internal/server/grpcapi"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
)

// FastKDF are cheap Argon2id parameters that keep tests fast. Never use them in production.
var FastKDF = crypto.KDFParams{Time: 1, Memory: 1024, Threads: 1}

// Server is an in-process GophKeeper server on an in-memory listener and in-memory storage.
type Server struct {
	Storage  *memory.Storage
	Services grpcapi.Services
	lis      *bufconn.Listener
}

// ServerConfig returns a server configuration suitable for tests.
func ServerConfig() config.Config {
	return config.Config{
		Address:         "bufconn",
		TLSCert:         "unused",
		TLSKey:          "unused",
		AccessTTL:       time.Minute,
		RefreshTTL:      time.Hour,
		MaxBlobSize:     16 << 20,
		ShutdownTimeout: time.Second,
	}
}

// StartServer starts a server and stops it when the test ends.
func StartServer(t testing.TB) *Server {
	t.Helper()
	st := memory.New()
	services, err := app.NewServices(st, []byte("test-secret"), ServerConfig(), FastKDF)
	if err != nil {
		t.Fatalf("new services: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpcapi.NewServer(services, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return &Server{Storage: st, Services: services, lis: lis}
}

// Dial returns a client connection to the server. It is closed when the test ends.
func (s *Server) Dial(t testing.TB) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return s.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
