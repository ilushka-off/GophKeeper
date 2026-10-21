package postgres

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
)

var errBoom = errors.New("boom")

// newStorage connects to TEST_DATABASE_DSN and empties all tables.
func newStorage(t *testing.T) *Storage {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	ctx := context.Background()
	s, err := New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(s.Close)
	_, err = s.pool.Exec(ctx, `TRUNCATE users, refresh_tokens, records, blobs, blob_chunks CASCADE`)
	require.NoError(t, err)
	return s
}

func newUser(t *testing.T, s *Storage, login string) model.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), model.User{
		ID: uuid.New(), Login: login, PasswordHash: "hash", KDFSalt: []byte("0123456789abcdef"),
	})
	require.NoError(t, err)
	return u
}

func TestNew_BadDSN(t *testing.T) {
	if os.Getenv("TEST_DATABASE_DSN") == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := New(ctx, "postgres://nobody:wrong@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	assert.Error(t, err)
	_, err = New(ctx, "::not a dsn::")
	assert.Error(t, err)
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := newStorage(t)
	require.NoError(t, Migrate(context.Background(), s.pool))
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	assert.False(t, u.CreatedAt.IsZero())
	assert.Zero(t, u.Revision)

	_, err := s.CreateUser(ctx, model.User{ID: uuid.New(), Login: "ilya", PasswordHash: "h", KDFSalt: []byte("s")})
	assert.ErrorIs(t, err, model.ErrAlreadyExists)

	got, err := s.UserByLogin(ctx, "ilya")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	assert.Equal(t, u.KDFSalt, got.KDFSalt)
	assert.Equal(t, "hash", got.PasswordHash)
	_, err = s.UserByLogin(ctx, "nobody")
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func TestRefreshTokens(t *testing.T) {
	ctx := context.Background()
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	exp := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	require.NoError(t, s.SaveRefreshToken(ctx, model.RefreshToken{Hash: []byte("hash"), UserID: u.ID, ExpiresAt: exp}))
	assert.Error(t, s.SaveRefreshToken(ctx, model.RefreshToken{Hash: []byte("hash"), UserID: u.ID, ExpiresAt: exp}),
		"duplicate hash")

	got, err := s.ConsumeRefreshToken(ctx, []byte("hash"))
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.UserID)
	assert.True(t, exp.Equal(got.ExpiresAt))
	_, err = s.ConsumeRefreshToken(ctx, []byte("hash"))
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func save(t *testing.T, s *Storage, userID uuid.UUID, recs ...model.Record) {
	t.Helper()
	ctx := context.Background()
	err := s.InUserTx(ctx, userID, func(tx service.SyncTx) error {
		for _, r := range recs {
			rev, err := tx.NextRevision(ctx)
			if err != nil {
				return err
			}
			r.UserID = userID
			r.Revision = rev
			r.UpdatedAt = time.Now()
			if err := tx.SaveRecord(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
}

func TestRecords(t *testing.T) {
	ctx := context.Background()
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	other := newUser(t, s, "other")
	a, b := uuid.New(), uuid.New()

	save(t, s, u.ID,
		model.Record{ID: a, Type: model.TypeText, Payload: []byte("a"), Version: 1},
		model.Record{ID: b, Type: model.TypeCard, Payload: nil, Version: 1, Deleted: true},
	)

	r, err := s.GetRecord(ctx, u.ID, a)
	require.NoError(t, err)
	assert.Equal(t, model.TypeText, r.Type)
	assert.Equal(t, []byte("a"), r.Payload)
	assert.Equal(t, int64(1), r.Revision)
	_, err = s.GetRecord(ctx, other.ID, a)
	assert.ErrorIs(t, err, model.ErrNotFound)

	live, err := s.ListRecords(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, live, 1)
	assert.Equal(t, a, live[0].ID)

	changes, rev, err := s.ChangesSince(ctx, u.ID, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), rev)
	require.Len(t, changes, 2)
	assert.True(t, changes[1].Deleted)
	assert.Empty(t, changes[1].Payload)

	changes, _, err = s.ChangesSince(ctx, u.ID, 1)
	require.NoError(t, err)
	assert.Len(t, changes, 1)
	_, _, err = s.ChangesSince(ctx, uuid.New(), 0)
	assert.ErrorIs(t, err, model.ErrNotFound)

	// Update a in a new transaction.
	err = s.InUserTx(ctx, u.ID, func(tx service.SyncTx) error {
		cur, err := tx.RecordForUpdate(ctx, a)
		require.NoError(t, err)
		_, err = tx.RecordForUpdate(ctx, uuid.New())
		assert.ErrorIs(t, err, model.ErrNotFound)
		assert.Equal(t, int64(2), tx.Revision())
		rev, _ := tx.NextRevision(ctx)
		cur.Payload = []byte("a2")
		cur.Version++
		cur.Revision = rev
		return tx.SaveRecord(ctx, cur)
	})
	require.NoError(t, err)
	r, err = s.GetRecord(ctx, u.ID, a)
	require.NoError(t, err)
	assert.Equal(t, []byte("a2"), r.Payload)
	assert.Equal(t, int64(2), r.Version)
	assert.Equal(t, int64(3), r.Revision)

	// The upsert never moves a record to another owner.
	save(t, s, other.ID, model.Record{ID: a, Type: model.TypeText, Payload: []byte("stolen"), Version: 9})
	r, err = s.GetRecord(ctx, u.ID, a)
	require.NoError(t, err)
	assert.Equal(t, []byte("a2"), r.Payload)
}

func TestTxRollback(t *testing.T) {
	ctx := context.Background()
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	id := uuid.New()
	err := s.InUserTx(ctx, u.ID, func(tx service.SyncTx) error {
		rev, _ := tx.NextRevision(ctx)
		require.NoError(t, tx.SaveRecord(ctx, model.Record{
			ID: id, UserID: u.ID, Type: model.TypeText, Payload: []byte("x"), Version: 1, Revision: rev,
		}))
		return errBoom
	})
	assert.ErrorIs(t, err, errBoom)
	_, err = s.GetRecord(ctx, u.ID, id)
	assert.ErrorIs(t, err, model.ErrNotFound)
	_, rev, err := s.ChangesSince(ctx, u.ID, 0)
	require.NoError(t, err)
	assert.Zero(t, rev)

	err = s.InUserTx(ctx, uuid.New(), func(service.SyncTx) error { return nil })
	assert.ErrorIs(t, err, model.ErrNotFound)

	// A transaction without changes commits without touching the revision.
	require.NoError(t, s.InUserTx(ctx, u.ID, func(service.SyncTx) error { return nil }))
}

func TestTxSerializesPushes(t *testing.T) {
	ctx := context.Background()
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			errs <- s.InUserTx(ctx, u.ID, func(tx service.SyncTx) error {
				rev, _ := tx.NextRevision(ctx)
				return tx.SaveRecord(ctx, model.Record{
					ID: uuid.New(), UserID: u.ID, Type: model.TypeText, Payload: []byte("x"), Version: 1, Revision: rev,
				})
			})
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
	recs, rev, err := s.ChangesSince(ctx, u.ID, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(n), rev)
	seen := map[int64]bool{}
	for _, r := range recs {
		assert.False(t, seen[r.Revision], "revisions are unique")
		seen[r.Revision] = true
	}
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
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	other := newUser(t, s, "other")
	blobID := uuid.New()

	size, err := s.SaveBlob(ctx, u.ID, blobID, feed([]byte("ab"), []byte("cde"), []byte("f")))
	require.NoError(t, err)
	assert.Equal(t, int64(6), size)
	_, err = s.SaveBlob(ctx, u.ID, blobID, feed())
	assert.ErrorIs(t, err, model.ErrAlreadyExists)

	failed := uuid.New()
	_, err = s.SaveBlob(ctx, u.ID, failed, func() ([]byte, error) { return nil, errBoom })
	assert.ErrorIs(t, err, errBoom)
	assert.ErrorIs(t, s.ReadBlob(ctx, u.ID, failed, func([]byte) error { return nil }), model.ErrNotFound,
		"failed upload is rolled back")

	var got []byte
	require.NoError(t, s.ReadBlob(ctx, u.ID, blobID, func(c []byte) error {
		got = append(got, c...)
		return nil
	}))
	assert.Equal(t, "abcdef", string(got))
	assert.ErrorIs(t, s.ReadBlob(ctx, u.ID, blobID, func([]byte) error { return errBoom }), errBoom)
	assert.ErrorIs(t, s.ReadBlob(ctx, other.ID, blobID, func([]byte) error { return nil }), model.ErrNotFound)

	require.NoError(t, s.DeleteBlob(ctx, other.ID, blobID))
	require.NoError(t, s.ReadBlob(ctx, u.ID, blobID, func([]byte) error { return nil }), "other user cannot delete")
	require.NoError(t, s.DeleteBlob(ctx, u.ID, blobID))
	assert.ErrorIs(t, s.ReadBlob(ctx, u.ID, blobID, func([]byte) error { return nil }), model.ErrNotFound)
}

func TestClosedPoolErrors(t *testing.T) {
	ctx := context.Background()
	s := newStorage(t)
	u := newUser(t, s, "ilya")
	s.pool.Close()

	_, err := s.CreateUser(ctx, model.User{ID: uuid.New(), Login: "x"})
	assert.Error(t, err)
	_, err = s.UserByLogin(ctx, "ilya")
	assert.Error(t, err)
	assert.Error(t, s.SaveRefreshToken(ctx, model.RefreshToken{Hash: []byte("h"), UserID: u.ID}))
	_, err = s.ConsumeRefreshToken(ctx, []byte("h"))
	assert.Error(t, err)
	_, err = s.GetRecord(ctx, u.ID, uuid.New())
	assert.Error(t, err)
	_, err = s.ListRecords(ctx, u.ID)
	assert.Error(t, err)
	_, _, err = s.ChangesSince(ctx, u.ID, 0)
	assert.Error(t, err)
	assert.Error(t, s.InUserTx(ctx, u.ID, func(service.SyncTx) error { return nil }))
	_, err = s.SaveBlob(ctx, u.ID, uuid.New(), feed())
	assert.Error(t, err)
	assert.Error(t, s.ReadBlob(ctx, u.ID, uuid.New(), func([]byte) error { return nil }))
	assert.Error(t, s.DeleteBlob(ctx, u.ID, uuid.New()))
}
