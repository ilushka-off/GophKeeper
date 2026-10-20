// Package app wires the server together: storage, services, the TLS gRPC server,
// the optional REST gateway and graceful shutdown.
package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/server/config"
	"github.com/ilushka-off/GophKeeper/internal/server/gateway"
	"github.com/ilushka-off/GophKeeper/internal/server/grpcapi"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/postgres"
	"github.com/ilushka-off/GophKeeper/internal/server/token"
)

// Storage is everything the services need from a storage backend.
type Storage interface {
	service.UserRepository
	service.TokenRepository
	service.RecordRepository
	service.BlobRepository
}

// NewServices builds the business services on top of a storage.
func NewServices(st Storage, jwtSecret []byte, cfg config.Config, hashParams crypto.KDFParams) (grpcapi.Services, error) {
	tm, err := token.NewManager(jwtSecret, cfg.AccessTTL)
	if err != nil {
		return grpcapi.Services{}, err
	}
	saltSecret := sha256.Sum256(append([]byte("gophkeeper/salt/"), jwtSecret...))
	return grpcapi.Services{
		Auth: service.NewAuth(st, st, tm, service.AuthConfig{
			RefreshTTL: cfg.RefreshTTL,
			HashParams: hashParams,
			SaltSecret: saltSecret[:],
		}),
		Vault: service.NewVault(st, st, cfg.MaxBlobSize),
		Sync:  service.NewSync(st),
	}, nil
}

// Run starts the server and blocks until ctx is cancelled, then stops gracefully.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	secret := []byte(cfg.JWTSecret)
	if len(secret) == 0 {
		log.Warn("JWT_SECRET is not set, using a random secret: tokens will not survive a restart")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("generate jwt secret: %w", err)
		}
	}

	var st Storage
	if cfg.DatabaseDSN == "" {
		log.Warn("DATABASE_DSN is not set, using in-memory storage: data will be lost on exit")
		st = memory.New()
	} else {
		pg, err := postgres.New(ctx, cfg.DatabaseDSN)
		if err != nil {
			return err
		}
		defer pg.Close()
		st = pg
	}

	services, err := NewServices(st, secret, cfg, crypto.DefaultKDFParams)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	srv := grpcapi.NewServer(services, log, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))

	lc := &net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Address, err)
	}
	if cfg.HTTPAddress == "" {
		return Serve(ctx, srv, lis, cfg.ShutdownTimeout, log)
	}

	gw, err := gateway.New(ctx, services, log)
	if err != nil {
		_ = lis.Close()
		return err
	}
	defer gw.Close()
	httpLis, err := lc.Listen(ctx, "tcp", cfg.HTTPAddress)
	if err != nil {
		_ = lis.Close()
		return fmt.Errorf("listen %s: %w", cfg.HTTPAddress, err)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	httpSrv := &http.Server{Handler: gw, ReadHeaderTimeout: 10 * time.Second}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return Serve(gctx, srv, lis, cfg.ShutdownTimeout, log) })
	g.Go(func() error {
		return ServeHTTP(gctx, httpSrv, tls.NewListener(httpLis, tlsConf), cfg.ShutdownTimeout, log)
	})
	return g.Wait()
}

// ServeHTTP runs srv on lis until ctx is cancelled, then shuts it down, waiting up to
// timeout for in-flight requests.
func ServeHTTP(ctx context.Context, srv *http.Server, lis net.Listener, timeout time.Duration, log *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		log.Info("REST gateway started", "address", lis.Addr().String())
		errCh <- srv.Serve(lis)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve http: %w", err)
	case <-ctx.Done():
	}

	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("REST gateway shutdown timed out, closing", "error", err)
		_ = srv.Close()
	}
	<-errCh
	log.Info("REST gateway stopped")
	return nil
}

// Serve runs srv on lis until ctx is cancelled. On cancellation it waits up to timeout
// for in-flight calls to finish and then stops the server forcibly.
func Serve(ctx context.Context, srv *grpc.Server, lis net.Listener, timeout time.Duration, log *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		log.Info("server started", "address", lis.Addr().String())
		errCh <- srv.Serve(lis)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	log.Info("shutting down")
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(timeout):
		log.Warn("graceful shutdown timed out, stopping")
		srv.Stop()
	}
	<-errCh
	log.Info("server stopped")
	return nil
}
