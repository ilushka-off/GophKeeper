package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var fastKDF = KDFParams{Time: 1, Memory: 1024, Threads: 1}

func newTestCipher(t *testing.T) *Cipher {
	t.Helper()
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	c, err := NewCipher(key)
	require.NoError(t, err)
	return c
}

func TestNewSalt(t *testing.T) {
	a, err := NewSalt()
	require.NoError(t, err)
	b, err := NewSalt()
	require.NoError(t, err)
	assert.Len(t, a, SaltSize)
	assert.NotEqual(t, a, b)
}

func TestDeriveKeys(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltSize)
	k1, err := DeriveKeys("master", salt, fastKDF)
	require.NoError(t, err)
	k2, err := DeriveKeys("master", salt, fastKDF)
	require.NoError(t, err)
	assert.Equal(t, k1, k2, "derivation is deterministic")
	assert.Len(t, k1.Auth, KeySize)
	assert.Len(t, k1.Enc, KeySize)
	assert.NotEqual(t, k1.Auth, k1.Enc, "auth and encryption keys are separated")
	assert.NotEmpty(t, k1.AuthPassword())
	assert.NotContains(t, k1.AuthPassword(), "=")

	other, err := DeriveKeys("other", salt, fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, k1.Enc, other.Enc)

	otherSalt, err := DeriveKeys("master", bytes.Repeat([]byte{2}, SaltSize), fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, k1.Enc, otherSalt.Enc)

	_, err = DeriveKeys("master", []byte("short"), fastKDF)
	require.ErrorIs(t, err, ErrInvalidSalt)
}

func TestNewCipherBadKey(t *testing.T) {
	_, err := NewCipher(make([]byte, 16))
	require.Error(t, err)
	_, err = NewCipher(nil)
	require.Error(t, err)
}

func TestSealOpen(t *testing.T) {
	c := newTestCipher(t)
	aad := []byte("aad")
	plain := []byte("secret data")

	sealed, err := c.Seal(plain, aad)
	require.NoError(t, err)
	assert.Len(t, sealed, len(plain)+Overhead)
	assert.False(t, bytes.Contains(sealed, plain))

	again, err := c.Seal(plain, aad)
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again, "random nonce")

	got, err := c.Open(sealed, aad)
	require.NoError(t, err)
	assert.Equal(t, plain, got)

	empty, err := c.Seal(nil, nil)
	require.NoError(t, err)
	got, err = c.Open(empty, nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestOpenFailures(t *testing.T) {
	c := newTestCipher(t)
	sealed, err := c.Seal([]byte("secret"), []byte("aad"))
	require.NoError(t, err)

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1

	tests := map[string]struct {
		c      *Cipher
		sealed []byte
		aad    []byte
	}{
		"wrong key": {newTestCipher(t), sealed, []byte("aad")},
		"wrong aad": {c, sealed, []byte("other")},
		"tampered":  {c, tampered, []byte("aad")},
		"short":     {c, sealed[:Overhead-1], []byte("aad")},
		"empty":     {c, nil, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tt.c.Open(tt.sealed, tt.aad)
			require.ErrorIs(t, err, ErrDecrypt)
		})
	}
}

func encryptAll(t *testing.T, c *Cipher, data, blobID []byte) [][]byte {
	t.Helper()
	var chunks [][]byte
	n, err := c.EncryptStream(bytes.NewReader(data), blobID, func(ch []byte) error {
		chunks = append(chunks, bytes.Clone(ch))
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, int64(len(data)), n)
	return chunks
}

func iter(chunks [][]byte) func() ([]byte, error) {
	i := 0
	return func() ([]byte, error) {
		if i >= len(chunks) {
			return nil, io.EOF
		}
		i++
		return chunks[i-1], nil
	}
}

func TestStreamRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	blobID := []byte("blob-1")
	tests := map[string]struct {
		size   int
		chunks int
	}{
		"empty":          {0, 1},
		"small":          {100, 1},
		"exact chunk":    {ChunkSize, 1},
		"two exact":      {2 * ChunkSize, 2},
		"with remainder": {2*ChunkSize + 17, 3},
		"one byte over":  {ChunkSize + 1, 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := make([]byte, tt.size)
			_, _ = rand.Read(data)
			chunks := encryptAll(t, c, data, blobID)
			assert.Len(t, chunks, tt.chunks)
			for _, ch := range chunks {
				assert.LessOrEqual(t, len(ch), ChunkSize+Overhead)
			}
			var out bytes.Buffer
			n, err := c.DecryptStream(iter(chunks), blobID, &out)
			require.NoError(t, err)
			assert.Equal(t, int64(tt.size), n)
			assert.True(t, bytes.Equal(data, out.Bytes()))
		})
	}
}

func TestDecryptStreamAttacks(t *testing.T) {
	c := newTestCipher(t)
	blobID := []byte("blob-1")
	data := make([]byte, 2*ChunkSize+5)
	_, _ = rand.Read(data)
	chunks := encryptAll(t, c, data, blobID)
	require.Len(t, chunks, 3)

	tests := map[string]struct {
		chunks [][]byte
		blobID []byte
	}{
		"truncated":   {chunks[:2], blobID},
		"reordered":   {[][]byte{chunks[1], chunks[0], chunks[2]}, blobID},
		"wrong blob":  {chunks, []byte("blob-2")},
		"duplicated":  {[][]byte{chunks[0], chunks[0], chunks[1], chunks[2]}, blobID},
		"extra chunk": {append(append([][]byte{}, chunks...), chunks[2]), blobID},
		"empty":       {nil, blobID},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := c.DecryptStream(iter(tt.chunks), tt.blobID, io.Discard)
			require.ErrorIs(t, err, ErrDecrypt)
		})
	}
}

type errReader struct{ after int }

func (r *errReader) Read(p []byte) (int, error) {
	if r.after > 0 {
		n := min(len(p), r.after)
		r.after -= n
		return n, nil
	}
	return 0, errors.New("read failed")
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestStreamIOErrors(t *testing.T) {
	c := newTestCipher(t)
	blobID := []byte("b")
	emit := func([]byte) error { return nil }

	_, err := c.EncryptStream(&errReader{}, blobID, emit)
	require.ErrorContains(t, err, "read failed")

	_, err = c.EncryptStream(&errReader{after: ChunkSize}, blobID, emit)
	require.ErrorContains(t, err, "read failed")

	emitErr := errors.New("emit failed")
	_, err = c.EncryptStream(strings.NewReader("data"), blobID, func([]byte) error { return emitErr })
	require.ErrorIs(t, err, emitErr)

	chunks := encryptAll(t, c, []byte("data"), blobID)
	_, err = c.DecryptStream(iter(chunks), blobID, errWriter{})
	require.ErrorContains(t, err, "write failed")

	nextErr := errors.New("next failed")
	_, err = c.DecryptStream(func() ([]byte, error) { return nil, nextErr }, blobID, io.Discard)
	require.ErrorIs(t, err, nextErr)

	calls := 0
	_, err = c.DecryptStream(func() ([]byte, error) {
		calls++
		if calls == 1 {
			return chunks[0], nil
		}
		return nil, nextErr
	}, blobID, io.Discard)
	require.ErrorIs(t, err, nextErr)
}

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("pass", fastKDF)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(h, "$argon2id$v=19$m=1024,t=1,p=1$"))

	h2, err := HashPassword("pass", fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, h, h2, "random salt")

	ok, err := VerifyPassword("pass", h)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = VerifyPassword("wrong", h)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyPasswordMalformed(t *testing.T) {
	h, err := HashPassword("pass", fastKDF)
	require.NoError(t, err)
	parts := strings.Split(h, "$")

	replace := func(i int, v string) string {
		p := append([]string{}, parts...)
		p[i] = v
		return strings.Join(p, "$")
	}
	tests := map[string]string{
		"empty":        "",
		"wrong algo":   replace(1, "argon2i"),
		"few parts":    "$argon2id$v=19$m=1,t=1,p=1$salt",
		"bad version":  replace(2, "v=18"),
		"version text": replace(2, "x"),
		"bad params":   replace(3, "m=x"),
		"bad salt":     replace(4, "!!!"),
		"bad hash":     replace(5, "!!!"),
		"short hash":   replace(5, "YWJj"),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyPassword("pass", in)
			require.ErrorIs(t, err, ErrInvalidHash)
		})
	}
}
