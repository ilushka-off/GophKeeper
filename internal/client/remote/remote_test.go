package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

type memTokens struct {
	mu   sync.Mutex
	t    model.Tokens
	err  error
	sets int
}

func (m *memTokens) Tokens(context.Context) (model.Tokens, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t, m.err
}

func (m *memTokens) SetTokens(_ context.Context, t model.Tokens) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = t
	m.sets++
	return nil
}

func (m *memTokens) get() model.Tokens {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t
}

// newClient registers a fresh user and returns a client with its session.
func newClient(t *testing.T) (*Client, *memTokens) {
	t.Helper()
	srv := testutil.StartServer(t)
	c := New(srv.Dial(t))
	salt, err := crypto.NewSalt()
	require.NoError(t, err)
	tok, err := c.Register(context.Background(), "ilya", "password", salt)
	require.NoError(t, err)
	ts := &memTokens{t: tok}
	c.SetTokenStore(ts)
	return c, ts
}

func TestAuthFlow(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	c := New(srv.Dial(t))

	salt := bytes.Repeat([]byte{7}, crypto.SaltSize)
	tok, err := c.Register(ctx, "ilya", "secret", salt)
	require.NoError(t, err)
	assert.NotEmpty(t, tok.AccessToken)
	assert.NotEmpty(t, tok.RefreshToken)
	assert.True(t, tok.AccessExpiresAt.After(time.Now()))

	_, err = c.Register(ctx, "ilya", "secret", salt)
	require.ErrorIs(t, err, model.ErrAlreadyExists)

	_, err = c.Register(ctx, "x", "secret", salt)
	require.ErrorIs(t, err, model.ErrInvalidArgument)

	got, err := c.GetSalt(ctx, "ilya")
	require.NoError(t, err)
	assert.Equal(t, salt, got)

	tok2, gotSalt, err := c.Login(ctx, "ilya", "secret")
	require.NoError(t, err)
	assert.Equal(t, salt, gotSalt)
	assert.NotEqual(t, tok.RefreshToken, tok2.RefreshToken)

	_, _, err = c.Login(ctx, "ilya", "wrong")
	require.ErrorIs(t, err, model.ErrUnauthenticated)

	require.NoError(t, c.Logout(ctx, tok2.RefreshToken))
	require.NoError(t, c.Close())
}

func TestRecordsAndSync(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)

	id := uuid.New()
	res, err := c.Push(ctx, []model.Change{{ID: id, Type: model.TypeText, Payload: []byte("cipher")}})
	require.NoError(t, err)
	require.Len(t, res.Accepted, 1)
	assert.Equal(t, id, res.Accepted[0].ID)
	assert.Equal(t, int64(1), res.Accepted[0].Version)
	assert.Equal(t, int64(1), res.Revision)

	res, err = c.Push(ctx, []model.Change{{ID: id, Type: model.TypeText, Payload: []byte("stale"), BaseVersion: 0}})
	require.NoError(t, err)
	assert.Empty(t, res.Accepted)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, []byte("cipher"), res.Conflicts[0].Payload)

	_, err = c.Push(ctx, []model.Change{{ID: id, Type: "bogus", Payload: []byte("x")}})
	require.ErrorIs(t, err, model.ErrInvalidArgument)

	rec, err := c.GetRecord(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, model.TypeText, rec.Type)
	assert.Equal(t, int64(1), rec.Version)

	_, err = c.GetRecord(ctx, uuid.New())
	require.ErrorIs(t, err, model.ErrNotFound)

	recs, rev, err := c.Pull(ctx, 0)
	require.NoError(t, err)
	assert.Len(t, recs, 1)
	assert.Equal(t, int64(1), rev)

	recs, rev, err = c.Pull(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, recs)
	assert.Equal(t, int64(1), rev)

	_, _, err = c.Pull(ctx, -1)
	require.ErrorIs(t, err, model.ErrInvalidArgument)
}

func TestBlobs(t *testing.T) {
	ctx := context.Background()
	c, _ := newClient(t)
	blobID := uuid.New()
	chunks := [][]byte{[]byte("one"), []byte("two"), []byte("three")}

	size, err := c.UploadBlob(ctx, blobID, func(send func([]byte) error) error {
		for _, ch := range chunks {
			if err := send(ch); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, int64(11), size)

	var got [][]byte
	require.NoError(t, c.DownloadBlob(ctx, blobID, func(b []byte) error {
		got = append(got, bytes.Clone(b))
		return nil
	}))
	assert.Equal(t, chunks, got)

	stop := errors.New("stop")
	err = c.DownloadBlob(ctx, blobID, func([]byte) error { return stop })
	require.ErrorIs(t, err, stop)

	// The same blob id cannot be uploaded twice.
	_, err = c.UploadBlob(ctx, blobID, func(send func([]byte) error) error { return send([]byte("x")) })
	require.ErrorIs(t, err, model.ErrAlreadyExists)

	// Producer errors are returned as is.
	_, err = c.UploadBlob(ctx, uuid.New(), func(func([]byte) error) error { return stop })
	require.ErrorIs(t, err, stop)

	require.NoError(t, c.DeleteBlob(ctx, blobID))
	err = c.DownloadBlob(ctx, blobID, func([]byte) error { return nil })
	require.ErrorIs(t, err, model.ErrNotFound)
}

func TestUploadTooLargeChunk(t *testing.T) {
	c, _ := newClient(t)
	big := make([]byte, crypto.ChunkSize+crypto.Overhead+1)
	_, err := c.UploadBlob(context.Background(), uuid.New(), func(send func([]byte) error) error {
		for range 3 {
			if err := send(big); err != nil {
				return err
			}
		}
		return nil
	})
	require.ErrorIs(t, err, model.ErrInvalidArgument)
}

func TestProactiveRefresh(t *testing.T) {
	ctx := context.Background()
	c, ts := newClient(t)
	old := ts.get()
	// Pretend the access token is about to expire.
	c.now = func() time.Time { return old.AccessExpiresAt.Add(-time.Second) }

	_, _, err := c.Pull(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, ts.sets)
	assert.NotEqual(t, old.RefreshToken, ts.get().RefreshToken)
}

func TestRetryAfterUnauthenticated(t *testing.T) {
	ctx := context.Background()
	c, ts := newClient(t)
	tok := ts.get()
	tok.AccessToken = "forged"
	ts.t = tok

	_, _, err := c.Pull(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, ts.sets)
	assert.NotEqual(t, "forged", ts.get().AccessToken)
}

func TestRefreshFailure(t *testing.T) {
	ctx := context.Background()
	c, ts := newClient(t)
	ts.t = model.Tokens{AccessToken: "forged", RefreshToken: "revoked", AccessExpiresAt: time.Now().Add(time.Hour)}

	_, _, err := c.Pull(ctx, 0)
	require.ErrorIs(t, err, ErrNotLoggedIn)

	ts.t.AccessExpiresAt = time.Now()
	err = c.DownloadBlob(ctx, uuid.New(), func([]byte) error { return nil })
	require.ErrorIs(t, err, ErrNotLoggedIn)
	_, err = c.UploadBlob(ctx, uuid.New(), func(func([]byte) error) error { return nil })
	require.ErrorIs(t, err, ErrNotLoggedIn)
}

func TestNoTokenStore(t *testing.T) {
	srv := testutil.StartServer(t)
	c := New(srv.Dial(t))
	_, _, err := c.Pull(context.Background(), 0)
	require.ErrorIs(t, err, ErrNotLoggedIn)

	storeErr := errors.New("locked")
	c.SetTokenStore(&memTokens{err: storeErr})
	err = c.DeleteBlob(context.Background(), uuid.New())
	require.ErrorIs(t, err, storeErr)
}

func TestMapErr(t *testing.T) {
	require.NoError(t, mapErr(nil))
	plain := errors.New("plain")
	assert.Equal(t, plain, mapErr(plain))

	cases := map[codes.Code]error{
		codes.Unavailable:      ErrUnavailable,
		codes.Unauthenticated:  model.ErrUnauthenticated,
		codes.NotFound:         model.ErrNotFound,
		codes.AlreadyExists:    model.ErrAlreadyExists,
		codes.InvalidArgument:  model.ErrInvalidArgument,
		codes.PermissionDenied: model.ErrPermissionDenied,
	}
	for code, want := range cases {
		assert.ErrorIs(t, mapErr(status.Error(code, "msg")), want, code.String())
	}
	err := mapErr(status.Error(codes.Internal, "boom"))
	assert.Contains(t, err.Error(), "Internal")
}

func TestUnavailable(t *testing.T) {
	creds, err := TLSCredentials("")
	require.NoError(t, err)
	c, err := Dial("127.0.0.1:1", creds)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.GetSalt(ctx, "ilya")
	require.Error(t, err)
}

func writeCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestTLSCredentials(t *testing.T) {
	dir := t.TempDir()

	creds, err := TLSCredentials("")
	require.NoError(t, err)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)

	_, err = TLSCredentials(filepath.Join(dir, "missing.crt"))
	require.Error(t, err)

	bad := filepath.Join(dir, "bad.crt")
	require.NoError(t, os.WriteFile(bad, []byte("not a cert"), 0o600))
	_, err = TLSCredentials(bad)
	require.Error(t, err)

	creds, err = TLSCredentials(writeCA(t, dir))
	require.NoError(t, err)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
}
