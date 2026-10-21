package memory_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
)

var errBoom = errors.New("boom")

func newUser(t *testing.T, s *memory.Storage, login string) model.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), model.User{ID: uuid.New(), Login: login, KDFSalt: []byte("salt")})
	require.NoError(t, err)
	return u
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	u := newUser(t, s, "ilya")
	assert.False(t, u.CreatedAt.IsZero())

	_, err := s.CreateUser(ctx, model.User{ID: uuid.New(), Login: "ilya"})
	assert.ErrorIs(t, err, model.ErrAlreadyExists)

	got, err := s.UserByLogin(ctx, "ilya")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	_, err = s.UserByLogin(ctx, "nobody")
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func TestRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	tok := model.RefreshToken{Hash: []byte("h"), UserID: uuid.New(), ExpiresAt: time.Now()}
	require.NoError(t, s.SaveRefreshToken(ctx, tok))
	got, err := s.ConsumeRefreshToken(ctx, []byte("h"))
	require.NoError(t, err)
	assert.Equal(t, tok.UserID, got.UserID)
	_, err = s.ConsumeRefreshToken(ctx, []byte("h"))
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func TestRecordsAndTx(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	u := newUser(t, s, "ilya")
	other := newUser(t, s, "other")
	a, b := uuid.New(), uuid.New()

	err := s.InUserTx(ctx, u.ID, func(tx service.SyncTx) error {
		for i, id := range []uuid.UUID{a, b} {
			rev, err := tx.NextRevision(ctx)
			require.NoError(t, err)
			require.NoError(t, tx.SaveRecord(ctx, model.Record{
				ID: id, UserID: u.ID, Type: model.TypeText, Payload: []byte{byte(i)}, Version: 1, Revision: rev,
				Deleted: id == b,
			}))
		}
		staged, err := tx.RecordForUpdate(ctx, a)
		require.NoError(t, err)
		assert.Equal(t, int64(1), staged.Revision, "staged records are visible inside the tx")
		assert.Equal(t, int64(2), tx.Revision())
		return nil
	})
	require.NoError(t, err)

	r, err := s.GetRecord(ctx, u.ID, a)
	require.NoError(t, err)
	assert.Equal(t, []byte{0}, r.Payload)
	_, err = s.GetRecord(ctx, other.ID, a)
	assert.ErrorIs(t, err, model.ErrNotFound)
	_, err = s.GetRecord(ctx, u.ID, uuid.New())
	assert.ErrorIs(t, err, model.ErrNotFound)

	live, err := s.ListRecords(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, live, 1, "tombstones are not listed")

	changes, rev, err := s.ChangesSince(ctx, u.ID, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), rev)
	require.Len(t, changes, 2)
	assert.Equal(t, a, changes[0].ID)
	changes, _, err = s.ChangesSince(ctx, u.ID, 1)
	require.NoError(t, err)
	assert.Len(t, changes, 1)
	_, _, err = s.ChangesSince(ctx, uuid.New(), 0)
	assert.ErrorIs(t, err, model.ErrNotFound)

	// Committed records are visible to later transactions.
	err = s.InUserTx(ctx, u.ID, func(tx service.SyncTx) error {
		got, err := tx.RecordForUpdate(ctx, a)
		require.NoError(t, err)
		assert.Equal(t, a, got.ID)
		_, err = tx.RecordForUpdate(ctx, uuid.New())
		assert.ErrorIs(t, err, model.ErrNotFound)
		return nil
	})
	require.NoError(t, err)
}

func TestTxRollback(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	u := newUser(t, s, "ilya")
	id := uuid.New()
	err := s.InUserTx(ctx, u.ID, func(tx service.SyncTx) error {
		_, _ = tx.NextRevision(ctx)
		require.NoError(t, tx.SaveRecord(ctx, model.Record{ID: id, UserID: u.ID, Payload: []byte("x")}))
		return errBoom
	})
	assert.ErrorIs(t, err, errBoom)
	_, err = s.GetRecord(ctx, u.ID, id)
	assert.ErrorIs(t, err, model.ErrNotFound)
	_, rev, err := s.ChangesSince(ctx, u.ID, 0)
	require.NoError(t, err)
	assert.Zero(t, rev)

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	err = s.InUserTx(cctx, u.ID, func(service.SyncTx) error { return nil })
	assert.ErrorIs(t, err, context.Canceled)

	err = s.InUserTx(ctx, uuid.New(), func(service.SyncTx) error { return nil })
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func feed(cs ...[]byte) func() ([]byte, error) {
	return func() ([]byte, error) {
		if len(cs) == 0 {
			return nil, io.EOF
		}
		c := cs[0]
		cs = cs[1:]
		return c, nil
	}
}

func TestBlobs(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	uid, blobID := uuid.New(), uuid.New()

	size, err := s.SaveBlob(ctx, uid, blobID, feed([]byte("ab"), []byte("cde")))
	require.NoError(t, err)
	assert.Equal(t, int64(5), size)
	_, err = s.SaveBlob(ctx, uid, blobID, feed())
	assert.ErrorIs(t, err, model.ErrAlreadyExists)
	_, err = s.SaveBlob(ctx, uid, uuid.New(), func() ([]byte, error) { return nil, errBoom })
	assert.ErrorIs(t, err, errBoom)

	var got []byte
	require.NoError(t, s.ReadBlob(ctx, uid, blobID, func(c []byte) error {
		got = append(got, c...)
		return nil
	}))
	assert.Equal(t, "abcde", string(got))
	assert.ErrorIs(t, s.ReadBlob(ctx, uid, blobID, func([]byte) error { return errBoom }), errBoom)
	assert.ErrorIs(t, s.ReadBlob(ctx, uuid.New(), blobID, func([]byte) error { return nil }), model.ErrNotFound)

	require.NoError(t, s.DeleteBlob(ctx, uuid.New(), blobID), "other user cannot delete, no error")
	require.NoError(t, s.ReadBlob(ctx, uid, blobID, func([]byte) error { return nil }))
	require.NoError(t, s.DeleteBlob(ctx, uid, blobID))
	assert.ErrorIs(t, s.ReadBlob(ctx, uid, blobID, func([]byte) error { return nil }), model.ErrNotFound)
}
