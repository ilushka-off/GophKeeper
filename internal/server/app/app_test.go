package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/ilushka-off/GophKeeper/api/gen/gophkeeper/v1"
	"github.com/ilushka-off/GophKeeper/internal/server/app"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// writeCert writes a self-signed certificate for 127.0.0.1 and returns the cert and key paths.
func writeCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestNewServices(t *testing.T) {
	st := memory.New()
	_, err := app.NewServices(st, nil, testutil.ServerConfig(), testutil.FastKDF)
	assert.Error(t, err, "empty secret")
	s, err := app.NewServices(st, []byte("secret"), testutil.ServerConfig(), testutil.FastKDF)
	require.NoError(t, err)
	assert.NotNil(t, s.Auth)
	assert.NotNil(t, s.Vault)
	assert.NotNil(t, s.Sync)
}

func TestServeGracefulShutdown(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, srv, lis, time.Second, discard()) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServeListenerError(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, lis.Close())
	err = app.Serve(context.Background(), grpc.NewServer(), lis, time.Second, discard())
	assert.Error(t, err)
}

func TestRun(t *testing.T) {
	certPath, keyPath := writeCert(t)
	cfg := testutil.ServerConfig()
	cfg.Address = freeAddr(t)
	cfg.TLSCert, cfg.TLSKey = certPath, keyPath

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, cfg, discard()) }()

	creds, err := credentials.NewClientTLSFromFile(certPath, "")
	require.NoError(t, err)
	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	auth := pb.NewAuthServiceClient(conn)
	require.Eventually(t, func() bool {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Second)
		defer ccancel()
		_, err := auth.GetSalt(cctx, &pb.GetSaltRequest{Login: "ilya"})
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "server answers over TLS")

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRunErrors(t *testing.T) {
	certPath, keyPath := writeCert(t)

	cfg := testutil.ServerConfig()
	cfg.Address = freeAddr(t)
	cfg.TLSCert, cfg.TLSKey = "missing.crt", "missing.key"
	assert.Error(t, app.Run(context.Background(), cfg, discard()), "bad TLS files")

	cfg.TLSCert, cfg.TLSKey = certPath, keyPath
	cfg.DatabaseDSN = "postgres://nobody:wrong@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	assert.Error(t, app.Run(ctx, cfg, discard()), "bad DSN")

	cfg.DatabaseDSN = ""
	cfg.Address = "256.0.0.1:99999"
	assert.Error(t, app.Run(context.Background(), cfg, discard()), "bad address")
}

func TestRunWithGateway(t *testing.T) {
	certPath, keyPath := writeCert(t)
	cfg := testutil.ServerConfig()
	cfg.Address, cfg.HTTPAddress = freeAddr(t), freeAddr(t)
	cfg.TLSCert, cfg.TLSKey = certPath, keyPath

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, cfg, discard()) }()

	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	require.Eventually(t, func() bool {
		resp, err := client.Get("https://" + cfg.HTTPAddress + "/api/v1/auth/salt/ilya")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "gateway answers over TLS")

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRunGatewayListenError(t *testing.T) {
	certPath, keyPath := writeCert(t)
	cfg := testutil.ServerConfig()
	cfg.Address, cfg.HTTPAddress = freeAddr(t), "256.0.0.1:99999"
	cfg.TLSCert, cfg.TLSKey = certPath, keyPath
	assert.Error(t, app.Run(context.Background(), cfg, discard()))
}

func TestServeHTTPError(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, lis.Close())
	err = app.ServeHTTP(context.Background(), &http.Server{ReadHeaderTimeout: time.Second}, lis, time.Second, discard())
	assert.Error(t, err)
}
