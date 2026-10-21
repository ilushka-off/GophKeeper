package token

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManagerErrors(t *testing.T) {
	_, err := NewManager(nil, time.Minute)
	require.Error(t, err)
	_, err = NewManager([]byte("s"), 0)
	require.Error(t, err)
}

func TestIssueParse(t *testing.T) {
	// The bubble's fake clock lets the token expire without waiting or a clock stub.
	synctest.Test(t, func(t *testing.T) {
		m, err := NewManager([]byte("secret"), time.Minute)
		require.NoError(t, err)

		id := uuid.New()
		tok, exp, err := m.IssueAccess(id)
		require.NoError(t, err)
		assert.Equal(t, time.Now().Add(time.Minute), exp)

		got, err := m.ParseAccess(tok)
		require.NoError(t, err)
		assert.Equal(t, id, got)

		time.Sleep(2 * time.Minute)
		_, err = m.ParseAccess(tok)
		require.ErrorIs(t, err, ErrInvalidToken, "expired")
	})
}

func TestParseInvalid(t *testing.T) {
	m, err := NewManager([]byte("secret"), time.Minute)
	require.NoError(t, err)
	other, err := NewManager([]byte("other"), time.Minute)
	require.NoError(t, err)

	foreign, _, err := other.IssueAccess(uuid.New())
	require.NoError(t, err)

	sign := func(method jwt.SigningMethod, key any, claims jwt.RegisteredClaims) string {
		s, err := jwt.NewWithClaims(method, claims).SignedString(key)
		require.NoError(t, err)
		return s
	}
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	tests := map[string]string{
		"garbage":       "not-a-token",
		"wrong secret":  foreign,
		"none alg":      sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, jwt.RegisteredClaims{Issuer: issuer, Subject: uuid.NewString(), ExpiresAt: future}),
		"hs512":         sign(jwt.SigningMethodHS512, []byte("secret"), jwt.RegisteredClaims{Issuer: issuer, Subject: uuid.NewString(), ExpiresAt: future}),
		"bad subject":   sign(jwt.SigningMethodHS256, []byte("secret"), jwt.RegisteredClaims{Issuer: issuer, Subject: "not-uuid", ExpiresAt: future}),
		"wrong issuer":  sign(jwt.SigningMethodHS256, []byte("secret"), jwt.RegisteredClaims{Issuer: "x", Subject: uuid.NewString(), ExpiresAt: future}),
		"no expiration": sign(jwt.SigningMethodHS256, []byte("secret"), jwt.RegisteredClaims{Issuer: issuer, Subject: uuid.NewString()}),
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := m.ParseAccess(tok)
			require.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

func TestRefresh(t *testing.T) {
	a, ha, err := NewRefresh()
	require.NoError(t, err)
	b, hb, err := NewRefresh()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, ha, hb)
	assert.Equal(t, ha, HashRefresh(a))
	assert.Len(t, ha, 32)
}
