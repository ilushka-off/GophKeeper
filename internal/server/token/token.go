// Package token issues and verifies access JWTs and generates opaque refresh tokens.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalidToken is returned for a malformed, forged or expired token.
var ErrInvalidToken = errors.New("invalid token")

const issuer = "gophkeeper"

// Manager signs access tokens with HMAC-SHA256.
type Manager struct {
	secret    []byte
	accessTTL time.Duration
	now       func() time.Time
}

// NewManager creates a token manager. The secret must not be empty.
func NewManager(secret []byte, accessTTL time.Duration) (*Manager, error) {
	if len(secret) == 0 {
		return nil, errors.New("token: empty secret")
	}
	if accessTTL <= 0 {
		return nil, errors.New("token: access ttl must be positive")
	}
	return &Manager{secret: secret, accessTTL: accessTTL, now: time.Now}, nil
}

// IssueAccess returns a signed access token for the user and its expiry time.
func (m *Manager) IssueAccess(userID uuid.UUID) (string, time.Time, error) {
	now := m.now()
	exp := now.Add(m.accessTTL)
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token: sign: %w", err)
	}
	return signed, exp, nil
}

// ParseAccess verifies an access token and returns the user id from it.
func (m *Manager) ParseAccess(tokenString string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (any, error) {
		return m.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	return id, nil
}

// NewRefresh returns a random refresh token and its hash for storage.
func NewRefresh() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("token: generate refresh: %w", err)
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	return t, HashRefresh(t), nil
}

// HashRefresh returns the SHA-256 hash under which a refresh token is stored.
func HashRefresh(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}
