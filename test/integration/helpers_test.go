//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/client/cli"
	"github.com/ilushka-off/GophKeeper/internal/server/app"
	"github.com/ilushka-off/GophKeeper/internal/server/config"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

// server is the real GophKeeper server listening on a random localhost port with TLS.
type server struct {
	addr   string
	caFile string
	stop   func() error
}

// startServer runs app.Run with PostgreSQL storage and a fresh self-signed certificate.
func startServer(t *testing.T, accessTTL time.Duration) *server {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.Addr().String()
	require.NoError(t, lis.Close())

	cfg := config.Config{
		Address:         addr,
		DatabaseDSN:     dsn,
		TLSCert:         certFile,
		TLSKey:          keyFile,
		JWTSecret:       "integration-secret",
		AccessTTL:       accessTTL,
		RefreshTTL:      time.Hour,
		MaxBlobSize:     32 << 20,
		ShutdownTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	var stopped bool
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("server did not stop")
			return nil
		}
	}
	t.Cleanup(func() { _ = stop() })

	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("server exited: %v", err)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server is not listening on %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return &server{addr: addr, caFile: certFile, stop: stop}
}

// writeCert generates a self-signed certificate for localhost and 127.0.0.1.
// The certificate is also the CA the clients trust.
func writeCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

// device is one installation of the command-line client with its own local vault.
type device struct {
	t       *testing.T
	srv     *server
	dataDir string
	master  string
	// serverAddr overrides the server address, e.g. to simulate being offline.
	serverAddr string
}

func newDevice(t *testing.T, srv *server, master string) *device {
	t.Helper()
	return &device{t: t, srv: srv, dataDir: t.TempDir(), master: master}
}

// offline returns the same device configured with an unreachable server.
func (d *device) offline() *device {
	c := *d
	c.serverAddr = "127.0.0.1:1"
	return &c
}

// withMaster returns the same device that enters another master password.
func (d *device) withMaster(master string) *device {
	c := *d
	c.master = master
	return &c
}

func (d *device) run(args ...string) (string, string, int) {
	d.t.Helper()
	addr := d.srv.addr
	if d.serverAddr != "" {
		addr = d.serverAddr
	}
	envVars := map[string]string{
		cli.EnvServer:         addr,
		cli.EnvCACert:         d.srv.caFile,
		cli.EnvDataDir:        d.dataDir,
		cli.EnvMasterPassword: d.master,
	}
	var stdout, stderr bytes.Buffer
	env := cli.Env{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Getenv: func(k string) string { return envVars[k] },
		KDF:    testutil.FastKDF,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	code := cli.Execute(ctx, env, args)
	return stdout.String(), stderr.String(), code
}

// ok runs a command that must succeed and returns its stdout.
func (d *device) ok(args ...string) string {
	d.t.Helper()
	out, errOut, code := d.run(args...)
	require.Equal(d.t, 0, code, "%v: %s", args, errOut)
	return out
}

// fail runs a command that must fail and returns its stderr.
func (d *device) fail(args ...string) string {
	d.t.Helper()
	out, errOut, code := d.run(args...)
	require.Equal(d.t, 1, code, "%v: %s", args, out)
	return errOut
}

var addedRe = regexp.MustCompile(`Added ([0-9a-f-]{36})`)

// add runs "add" and returns the id of the new record.
func (d *device) add(args ...string) string {
	d.t.Helper()
	out := d.ok(append([]string{"add"}, args...)...)
	m := addedRe.FindStringSubmatch(out)
	require.NotNil(d.t, m, out)
	return m[1]
}

// db runs fn on a direct connection to the server database.
func db(t *testing.T, fn func(ctx context.Context, conn *pgx.Conn)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	fn(ctx, conn)
}

// count returns the result of a COUNT(*) query.
func count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	db(t, func(ctx context.Context, conn *pgx.Conn) {
		require.NoError(t, conn.QueryRow(ctx, query, args...).Scan(&n))
	})
	return n
}

// uniqueLogin returns a login that is not used by other tests or runs.
func uniqueLogin(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + strings.ToLower(new(big.Int).SetBytes(b).Text(36))
}

func randomFile(t *testing.T, name string, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	_, err := rand.Read(data)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path, data
}
