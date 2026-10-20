package storage

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/model"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "vault.db")
	s, err := Open(context.Background(), path)
	require.NoError(t, err)
	require.NoError(t, s.SetMeta(context.Background(), MetaLogin, []byte("ilya")))
	require.NoError(t, s.Close())

	fi, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}

	s, err = Open(context.Background(), path)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	v, err := s.Meta(context.Background(), MetaLogin)
	require.NoError(t, err)
	assert.Equal(t, "ilya", string(v))
}

func TestOpenBadDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	_, err := Open(context.Background(), filepath.Join(file, "sub", "vault.db"))
	require.Error(t, err)
}

func TestMeta(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	_, err := s.Meta(ctx, "missing")
	require.ErrorIs(t, err, model.ErrNotFound)

	require.NoError(t, s.SetMeta(ctx, "k", []byte("v1")))
	require.NoError(t, s.SetMeta(ctx, "k", []byte("v2")))
	v, err := s.Meta(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), v)

	require.NoError(t, s.SetMeta(ctx, "empty", nil))
	v, err = s.Meta(ctx, "empty")
	require.NoError(t, err)
	assert.Empty(t, v)

	require.NoError(t, s.DeleteMeta(ctx, "k"))
	_, err = s.Meta(ctx, "k")
	require.ErrorIs(t, err, model.ErrNotFound)
}

func TestRecords(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	_, err := s.Record(ctx, uuid.New())
	require.ErrorIs(t, err, model.ErrNotFound)

	now := time.Now().Truncate(time.Millisecond)
	a := Record{ID: uuid.New(), Type: model.TypeText, Payload: []byte("a"), Dirty: true, UpdatedAt: now}
	b := Record{ID: uuid.New(), Type: model.TypeCard, Payload: []byte("b"), Version: 3, UpdatedAt: now.Add(time.Second)}
	c := Record{ID: uuid.New(), Type: model.TypeText, Deleted: true, Dirty: true, Version: 2}
	for _, r := range []Record{a, b, c} {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	got, err := s.Record(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a.ID, got.ID)
	assert.Equal(t, a.Type, got.Type)
	assert.Equal(t, a.Payload, got.Payload)
	assert.True(t, got.Dirty)
	assert.True(t, got.UpdatedAt.Equal(now))

	gotC, err := s.Record(ctx, c.ID)
	require.NoError(t, err)
	assert.Empty(t, gotC.Payload)
	assert.False(t, gotC.UpdatedAt.IsZero())

	live, err := s.Records(ctx)
	require.NoError(t, err)
	require.Len(t, live, 2)
	assert.Equal(t, a.ID, live[0].ID)
	assert.Equal(t, b.ID, live[1].ID)

	dirty, err := s.DirtyRecords(ctx)
	require.NoError(t, err)
	assert.Len(t, dirty, 2)

	b.Payload = []byte("b2")
	b.Dirty = true
	require.NoError(t, s.PutRecord(ctx, b))
	got, err = s.Record(ctx, b.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("b2"), got.Payload)
	assert.Equal(t, int64(3), got.Version)

	require.NoError(t, s.DeleteRecord(ctx, a.ID))
	_, err = s.Record(ctx, a.ID)
	require.ErrorIs(t, err, model.ErrNotFound)
}

func TestFindByPrefix(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id1 := uuid.MustParse("aaaa1111-0000-0000-0000-000000000001")
	id2 := uuid.MustParse("aaaa2222-0000-0000-0000-000000000002")
	id3 := uuid.MustParse("bbbb1111-0000-0000-0000-000000000003")
	for _, id := range []uuid.UUID{id1, id2, id3} {
		require.NoError(t, s.PutRecord(ctx, Record{ID: id, Type: model.TypeText, Payload: []byte("x")}))
	}
	require.NoError(t, s.PutRecord(ctx, Record{
		ID: uuid.MustParse("aaaa3333-0000-0000-0000-000000000004"), Type: model.TypeText, Deleted: true,
	}))

	got, err := s.FindByPrefix(ctx, "AAAA")
	require.NoError(t, err)
	assert.Len(t, got, 2)

	got, err = s.FindByPrefix(ctx, "aaaa1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, id1, got[0].ID)

	for _, wildcard := range []string{"%", "_", "aaa_", `\`} {
		got, err = s.FindByPrefix(ctx, wildcard)
		require.NoError(t, err)
		assert.Empty(t, got, wildcard)
	}
}

func TestOrphanBlobsAndReset(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	require.NoError(t, s.AddOrphanBlob(ctx, "b2"))
	require.NoError(t, s.AddOrphanBlob(ctx, "b1"))
	require.NoError(t, s.AddOrphanBlob(ctx, "b1"))
	got, err := s.OrphanBlobs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"b1", "b2"}, got)

	require.NoError(t, s.RemoveOrphanBlob(ctx, "b1"))
	got, err = s.OrphanBlobs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"b2"}, got)

	require.NoError(t, s.SetMeta(ctx, MetaLogin, []byte("x")))
	require.NoError(t, s.PutRecord(ctx, Record{ID: uuid.New(), Type: model.TypeText, Payload: []byte("p")}))
	require.NoError(t, s.Reset(ctx))

	got, err = s.OrphanBlobs(ctx)
	require.NoError(t, err)
	assert.Empty(t, got)
	recs, err := s.Records(ctx)
	require.NoError(t, err)
	assert.Empty(t, recs)
	_, err = s.Meta(ctx, MetaLogin)
	require.ErrorIs(t, err, model.ErrNotFound)
}

func TestClosedStoreErrors(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	require.NoError(t, err)
	require.NoError(t, s.Close())

	_, err = s.Meta(ctx, "k")
	require.Error(t, err)
	require.Error(t, s.SetMeta(ctx, "k", nil))
	require.Error(t, s.DeleteMeta(ctx, "k"))
	require.Error(t, s.Reset(ctx))
	require.Error(t, s.PutRecord(ctx, Record{ID: uuid.New()}))
	_, err = s.Record(ctx, uuid.New())
	require.Error(t, err)
	_, err = s.Records(ctx)
	require.Error(t, err)
	require.Error(t, s.DeleteRecord(ctx, uuid.New()))
	require.Error(t, s.AddOrphanBlob(ctx, "b"))
	_, err = s.OrphanBlobs(ctx)
	require.Error(t, err)
	require.Error(t, s.RemoveOrphanBlob(ctx, "b"))
}
