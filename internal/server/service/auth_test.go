package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
	"github.com/ilushka-off/GophKeeper/internal/server/service/mocks"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
	"github.com/ilushka-off/GophKeeper/internal/server/token"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

var errDB = errors.New("db is down")

func newTokenManager(t *testing.T) *token.Manager {
	t.Helper()
	tm, err := token.NewManager([]byte("secret"), time.Minute)
	require.NoError(t, err)
	return tm
}

func authConfig() service.AuthConfig {
	return service.AuthConfig{RefreshTTL: time.Hour, HashParams: testutil.FastKDF, SaltSecret: []byte("salt-secret")}
}

func newAuth(t *testing.T) (*service.Auth, *memory.Storage) {
	t.Helper()
	st := memory.New()
	return service.NewAuth(st, st, newTokenManager(t), authConfig()), st
}

func salt() []byte { return []byte("0123456789abcdef") }

func TestAuth_RegisterAndLogin(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)

	tokens, err := a.Register(ctx, "ilya", "secret-password", salt())
	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.True(t, tokens.AccessExpiresAt.After(time.Now()))

	uid, err := a.Authenticate(tokens.AccessToken)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, uid)

	t2, gotSalt, err := a.Login(ctx, "ilya", "secret-password")
	require.NoError(t, err)
	assert.Equal(t, salt(), gotSalt)
	uid2, err := a.Authenticate(t2.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, uid, uid2)
}

func TestAuth_RegisterValidation(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	tests := []struct {
		name, login, password string
		salt                  []byte
	}{
		{"short login", "ab", "pw", salt()},
		{"long login", strings.Repeat("a", service.MaxLoginLen+1), "pw", salt()},
		{"spaces around login", " ilya ", "pw", salt()},
		{"empty password", "ilya", "", salt()},
		{"long password", "ilya", strings.Repeat("p", service.MaxPasswordLen+1), salt()},
		{"short salt", "ilya", "pw", []byte("short")},
		{"long salt", "ilya", "pw", make([]byte, 65)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.Register(ctx, tt.login, tt.password, tt.salt)
			assert.ErrorIs(t, err, model.ErrInvalidArgument)
		})
	}
}

func TestAuth_RegisterDuplicate(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	_, err := a.Register(ctx, "ilya", "pw", salt())
	require.NoError(t, err)
	_, err = a.Register(ctx, "ilya", "pw2", salt())
	assert.ErrorIs(t, err, model.ErrAlreadyExists)
}

func TestAuth_GetSalt(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	_, err := a.Register(ctx, "ilya", "pw", salt())
	require.NoError(t, err)

	got, err := a.GetSalt(ctx, "ilya")
	require.NoError(t, err)
	assert.Equal(t, salt(), got)

	fake1, err := a.GetSalt(ctx, "nobody")
	require.NoError(t, err)
	fake2, err := a.GetSalt(ctx, "nobody")
	require.NoError(t, err)
	other, err := a.GetSalt(ctx, "someone-else")
	require.NoError(t, err)
	assert.Len(t, fake1, crypto.SaltSize)
	assert.Equal(t, fake1, fake2, "fake salt must be stable")
	assert.NotEqual(t, fake1, other)
}

func TestAuth_LoginFailures(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	_, err := a.Register(ctx, "ilya", "pw", salt())
	require.NoError(t, err)

	_, _, err = a.Login(ctx, "ilya", "wrong")
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
	_, _, err = a.Login(ctx, "nobody", "pw")
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
	_, _, err = a.Login(ctx, "ilya", "")
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
}

func TestAuth_RefreshIsSingleUse(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	tokens, err := a.Register(ctx, "ilya", "pw", salt())
	require.NoError(t, err)

	next, err := a.Refresh(ctx, tokens.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, tokens.RefreshToken, next.RefreshToken)

	_, err = a.Refresh(ctx, tokens.RefreshToken)
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
	_, err = a.Refresh(ctx, "")
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
	_, err = a.Refresh(ctx, next.RefreshToken)
	assert.NoError(t, err)
}

func TestAuth_RefreshExpired(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	tokens, err := a.Register(ctx, "ilya", "pw", salt())
	require.NoError(t, err)
	service.SetAuthNow(a, func() time.Time { return time.Now().Add(2 * time.Hour) })
	_, err = a.Refresh(ctx, tokens.RefreshToken)
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
}

func TestAuth_Logout(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	tokens, err := a.Register(ctx, "ilya", "pw", salt())
	require.NoError(t, err)

	require.NoError(t, a.Logout(ctx, tokens.RefreshToken))
	_, err = a.Refresh(ctx, tokens.RefreshToken)
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
	assert.NoError(t, a.Logout(ctx, tokens.RefreshToken), "second logout is not an error")
	assert.NoError(t, a.Logout(ctx, ""))
}

func TestAuth_Authenticate(t *testing.T) {
	a, _ := newAuth(t)
	_, err := a.Authenticate("garbage")
	assert.ErrorIs(t, err, model.ErrUnauthenticated)
}

func TestAuth_RepositoryErrors(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	a := service.NewAuth(users, tokens, newTokenManager(t), authConfig())

	users.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(model.User{}, errDB)
	_, err := a.Register(ctx, "ilya", "pw", salt())
	assert.ErrorIs(t, err, errDB)

	users.EXPECT().UserByLogin(gomock.Any(), "ilya").Return(model.User{}, errDB)
	_, err = a.GetSalt(ctx, "ilya")
	assert.ErrorIs(t, err, errDB)

	users.EXPECT().UserByLogin(gomock.Any(), "ilya").Return(model.User{}, errDB)
	_, _, err = a.Login(ctx, "ilya", "pw")
	assert.ErrorIs(t, err, errDB)

	users.EXPECT().UserByLogin(gomock.Any(), "ilya").Return(model.User{PasswordHash: "broken"}, nil)
	_, _, err = a.Login(ctx, "ilya", "pw")
	assert.ErrorIs(t, err, crypto.ErrInvalidHash)

	users.EXPECT().CreateUser(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, u model.User) (model.User, error) { return u, nil })
	tokens.EXPECT().SaveRefreshToken(gomock.Any(), gomock.Any()).Return(errDB)
	_, err = a.Register(ctx, "ilya", "pw", salt())
	assert.ErrorIs(t, err, errDB)

	tokens.EXPECT().ConsumeRefreshToken(gomock.Any(), gomock.Any()).Return(model.RefreshToken{}, errDB)
	_, err = a.Refresh(ctx, "token")
	assert.ErrorIs(t, err, errDB)

	tokens.EXPECT().ConsumeRefreshToken(gomock.Any(), gomock.Any()).Return(model.RefreshToken{}, errDB)
	assert.ErrorIs(t, a.Logout(ctx, "token"), errDB)
}

type failingIssuer struct{}

func (failingIssuer) IssueAccess(uuid.UUID) (string, time.Time, error) {
	return "", time.Time{}, errDB
}

func (failingIssuer) ParseAccess(string) (uuid.UUID, error) { return uuid.Nil, errDB }

func TestAuth_IssuerError(t *testing.T) {
	st := memory.New()
	a := service.NewAuth(st, st, failingIssuer{}, authConfig())
	_, err := a.Register(context.Background(), "ilya", "pw", salt())
	assert.ErrorIs(t, err, errDB)
}
