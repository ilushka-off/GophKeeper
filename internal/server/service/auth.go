package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/token"
)

// Login and password limits.
const (
	MinLoginLen    = 3
	MaxLoginLen    = 255
	MaxPasswordLen = 1024
)

// TokenIssuer issues and verifies access tokens.
type TokenIssuer interface {
	IssueAccess(userID uuid.UUID) (string, time.Time, error)
	ParseAccess(token string) (uuid.UUID, error)
}

// Auth registers users and manages their sessions.
type Auth struct {
	users      UserRepository
	tokens     TokenRepository
	issuer     TokenIssuer
	hashParams crypto.KDFParams
	refreshTTL time.Duration
	saltSecret []byte
	now        func() time.Time
}

// AuthConfig configures Auth.
type AuthConfig struct {
	// RefreshTTL is the lifetime of refresh tokens.
	RefreshTTL time.Duration
	// HashParams are Argon2id parameters for login password hashes.
	HashParams crypto.KDFParams
	// SaltSecret is used to answer GetSalt for unknown logins with a stable fake salt,
	// so the call does not reveal which logins exist.
	SaltSecret []byte
}

// NewAuth creates the auth service.
func NewAuth(users UserRepository, tokens TokenRepository, issuer TokenIssuer, cfg AuthConfig) *Auth {
	return &Auth{
		users:      users,
		tokens:     tokens,
		issuer:     issuer,
		hashParams: cfg.HashParams,
		refreshTTL: cfg.RefreshTTL,
		saltSecret: cfg.SaltSecret,
		now:        time.Now,
	}
}

func validateCredentials(login, password string) error {
	n := utf8.RuneCountInString(login)
	if n < MinLoginLen || n > MaxLoginLen || strings.TrimSpace(login) != login {
		return fmt.Errorf("%w: login must be %d..%d characters without surrounding spaces",
			model.ErrInvalidArgument, MinLoginLen, MaxLoginLen)
	}
	if password == "" || len(password) > MaxPasswordLen {
		return fmt.Errorf("%w: password is empty or too long", model.ErrInvalidArgument)
	}
	return nil
}

// Register creates a user and returns a token pair.
func (a *Auth) Register(ctx context.Context, login, password string, kdfSalt []byte) (model.Tokens, error) {
	if err := validateCredentials(login, password); err != nil {
		return model.Tokens{}, err
	}
	if len(kdfSalt) < crypto.SaltSize || len(kdfSalt) > 64 {
		return model.Tokens{}, fmt.Errorf("%w: kdf salt must be %d..64 bytes", model.ErrInvalidArgument, crypto.SaltSize)
	}
	hash, err := crypto.HashPassword(password, a.hashParams)
	if err != nil {
		return model.Tokens{}, err
	}
	u, err := a.users.CreateUser(ctx, model.User{
		ID:           uuid.New(),
		Login:        login,
		PasswordHash: hash,
		KDFSalt:      kdfSalt,
	})
	if err != nil {
		return model.Tokens{}, fmt.Errorf("create user: %w", err)
	}
	return a.issue(ctx, u.ID)
}

// GetSalt returns the KDF salt of a login. For an unknown login it returns
// a deterministic fake salt so the response does not reveal whether the login exists.
func (a *Auth) GetSalt(ctx context.Context, login string) ([]byte, error) {
	u, err := a.users.UserByLogin(ctx, login)
	if errors.Is(err, model.ErrNotFound) {
		mac := hmac.New(sha256.New, a.saltSecret)
		mac.Write([]byte(login))
		return mac.Sum(nil)[:crypto.SaltSize], nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return u.KDFSalt, nil
}

// Login checks the login password and returns a token pair with the KDF salt.
func (a *Auth) Login(ctx context.Context, login, password string) (model.Tokens, []byte, error) {
	if err := validateCredentials(login, password); err != nil {
		return model.Tokens{}, nil, model.ErrUnauthenticated
	}
	u, err := a.users.UserByLogin(ctx, login)
	if errors.Is(err, model.ErrNotFound) {
		return model.Tokens{}, nil, model.ErrUnauthenticated
	}
	if err != nil {
		return model.Tokens{}, nil, fmt.Errorf("get user: %w", err)
	}
	ok, err := crypto.VerifyPassword(password, u.PasswordHash)
	if err != nil {
		return model.Tokens{}, nil, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return model.Tokens{}, nil, model.ErrUnauthenticated
	}
	t, err := a.issue(ctx, u.ID)
	if err != nil {
		return model.Tokens{}, nil, err
	}
	return t, u.KDFSalt, nil
}

// Refresh exchanges a refresh token for a new pair. The old refresh token stops working.
func (a *Auth) Refresh(ctx context.Context, refreshToken string) (model.Tokens, error) {
	if refreshToken == "" {
		return model.Tokens{}, model.ErrUnauthenticated
	}
	rt, err := a.tokens.ConsumeRefreshToken(ctx, token.HashRefresh(refreshToken))
	if errors.Is(err, model.ErrNotFound) {
		return model.Tokens{}, model.ErrUnauthenticated
	}
	if err != nil {
		return model.Tokens{}, fmt.Errorf("consume refresh token: %w", err)
	}
	if !a.now().Before(rt.ExpiresAt) {
		return model.Tokens{}, model.ErrUnauthenticated
	}
	return a.issue(ctx, rt.UserID)
}

// Logout revokes a refresh token. Revoking an unknown token is not an error.
func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	_, err := a.tokens.ConsumeRefreshToken(ctx, token.HashRefresh(refreshToken))
	if err != nil && !errors.Is(err, model.ErrNotFound) {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

// Authenticate verifies an access token and returns the user id.
func (a *Auth) Authenticate(accessToken string) (uuid.UUID, error) {
	id, err := a.issuer.ParseAccess(accessToken)
	if err != nil {
		return uuid.Nil, model.ErrUnauthenticated
	}
	return id, nil
}

func (a *Auth) issue(ctx context.Context, userID uuid.UUID) (model.Tokens, error) {
	access, exp, err := a.issuer.IssueAccess(userID)
	if err != nil {
		return model.Tokens{}, err
	}
	refresh, hash, err := token.NewRefresh()
	if err != nil {
		return model.Tokens{}, err
	}
	err = a.tokens.SaveRefreshToken(ctx, model.RefreshToken{
		Hash:      hash,
		UserID:    userID,
		ExpiresAt: a.now().Add(a.refreshTTL),
	})
	if err != nil {
		return model.Tokens{}, fmt.Errorf("save refresh token: %w", err)
	}
	return model.Tokens{AccessToken: access, RefreshToken: refresh, AccessExpiresAt: exp}, nil
}
