// Package gateway exposes the gRPC API as REST/JSON through grpc-gateway and serves
// its OpenAPI specification. The gateway calls the services through an in-process
// gRPC server, so REST requests go through the same interceptors (auth, logging,
// recovery) and error mapping as native gRPC calls.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/api/openapi"
	"github.com/ilushka-off/GophKeeper/internal/server/grpcapi"
)

// SpecPath is the URL path of the OpenAPI specification.
const SpecPath = "/swagger.json"

// APIPrefix is the URL prefix of the REST API.
const APIPrefix = "/api/"

const bufSize = 1 << 20

// Gateway is an HTTP handler that translates REST calls into gRPC calls.
type Gateway struct {
	handler http.Handler
	srv     *grpc.Server
	conn    *grpc.ClientConn
}

// New starts an in-process gRPC server for services and returns a gateway in front of it.
// Close must be called to release it.
func New(ctx context.Context, services grpcapi.Services, log *slog.Logger) (*Gateway, error) {
	lis := bufconn.Listen(bufSize)
	srv := grpcapi.NewServer(services, log)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///gateway",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		return nil, fmt.Errorf("gateway: dial: %w", err)
	}
	g := &Gateway{srv: srv, conn: conn}

	gw := runtime.NewServeMux()
	for _, register := range []func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error{
		pb.RegisterAuthServiceHandler,
		pb.RegisterVaultServiceHandler,
		pb.RegisterSyncServiceHandler,
	} {
		if err := register(ctx, gw, conn); err != nil {
			g.Close()
			return nil, fmt.Errorf("gateway: register: %w", err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle(APIPrefix, gw)
	mux.HandleFunc("GET "+SpecPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(openapi.Spec)
	})
	g.handler = mux
	return g, nil
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.handler.ServeHTTP(w, r)
}

// Close stops the in-process gRPC server and closes the connection to it.
func (g *Gateway) Close() {
	_ = g.conn.Close()
	g.srv.GracefulStop()
}
