package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
	"github.com/ilushka-off/GophKeeper/internal/server/service/mocks"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
)

func createUser(t *testing.T, st *memory.Storage) uuid.UUID {
	t.Helper()
	u, err := st.CreateUser(context.Background(), model.User{ID: uuid.New(), Login: uuid.NewString(), KDFSalt: salt()})
	require.NoError(t, err)
	return u.ID
}

func TestSync_PushAndPull(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	uid := createUser(t, st)
	s := service.NewSync(st)
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	service.SetSyncNow(s, func() time.Time { return fixed })

	a, b := uuid.New(), uuid.New()
	res, err := s.Push(ctx, uid, []model.Change{
		{ID: a, Type: model.TypeText, Payload: []byte("a1")},
		{ID: b, Type: model.TypeCard, Payload: []byte("b1")},
	})
	require.NoError(t, err)
	assert.Empty(t, res.Conflicts)
	require.Len(t, res.Accepted, 2)
	assert.Equal(t, model.Accepted{ID: a, Version: 1, Revision: 1}, res.Accepted[0])
	assert.Equal(t, model.Accepted{ID: b, Version: 1, Revision: 2}, res.Accepted[1])
	assert.Equal(t, int64(2), res.Revision)

	// Update a with the right base version, conflict on b with a stale one.
	res, err = s.Push(ctx, uid, []model.Change{
		{ID: a, Type: model.TypeText, Payload: []byte("a2"), BaseVersion: 1},
		{ID: b, Type: model.TypeCard, Payload: []byte("b-stale"), BaseVersion: 0},
	})
	require.NoError(t, err)
	require.Len(t, res.Accepted, 1)
	assert.Equal(t, int64(2), res.Accepted[0].Version)
	require.Len(t, res.Conflicts, 1)
	assert.Equal(t, []byte("b1"), res.Conflicts[0].Payload)
	assert.Equal(t, int64(3), res.Revision)

	recs, rev, err := s.Pull(ctx, uid, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(3), rev)
	require.Len(t, recs, 1)
	assert.Equal(t, a, recs[0].ID)
	assert.Equal(t, fixed, recs[0].UpdatedAt)

	all, _, err := s.Pull(ctx, uid, 0)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	// Delete a: tombstone with empty payload and a new revision.
	res, err = s.Push(ctx, uid, []model.Change{{ID: a, Type: model.TypeText, Deleted: true, BaseVersion: 2}})
	require.NoError(t, err)
	require.Len(t, res.Accepted, 1)
	recs, _, err = s.Pull(ctx, uid, 3)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.True(t, recs[0].Deleted)
	assert.Empty(t, recs[0].Payload)
	assert.Equal(t, int64(3), recs[0].Version)
}

func TestSync_DeleteUnseenAndStaleUnknown(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	uid := createUser(t, st)
	s := service.NewSync(st)

	id := uuid.New()
	res, err := s.Push(ctx, uid, []model.Change{{ID: id, Type: model.TypeText, Deleted: true}})
	require.NoError(t, err)
	require.Len(t, res.Accepted, 1)
	assert.Equal(t, int64(0), res.Accepted[0].Version)
	assert.Equal(t, int64(0), res.Revision)

	// The server lost the record (e.g. restored backup): accept the client copy as new.
	res, err = s.Push(ctx, uid, []model.Change{{ID: id, Type: model.TypeText, Payload: []byte("x"), BaseVersion: 7}})
	require.NoError(t, err)
	require.Len(t, res.Accepted, 1)
	assert.Equal(t, int64(1), res.Accepted[0].Version)
}

func TestSync_Validation(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	uid := createUser(t, st)
	s := service.NewSync(st)
	id := uuid.New()
	tests := []struct {
		name    string
		changes []model.Change
	}{
		{"nil id", []model.Change{{Type: model.TypeText, Payload: []byte("x")}}},
		{"bad type", []model.Change{{ID: id, Type: "pet", Payload: []byte("x")}}},
		{"negative base", []model.Change{{ID: id, Type: model.TypeText, Payload: []byte("x"), BaseVersion: -1}}},
		{"empty payload", []model.Change{{ID: id, Type: model.TypeText}}},
		{"huge payload", []model.Change{{ID: id, Type: model.TypeText, Payload: make([]byte, service.MaxPayloadSize+1)}}},
		{"duplicate", []model.Change{
			{ID: id, Type: model.TypeText, Payload: []byte("x")},
			{ID: id, Type: model.TypeText, Payload: []byte("y")},
		}},
		{"too many", make([]model.Change, service.MaxChangesPerPush+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Push(ctx, uid, tt.changes)
			assert.ErrorIs(t, err, model.ErrInvalidArgument)
		})
	}

	_, _, err := s.Pull(ctx, uid, -1)
	assert.ErrorIs(t, err, model.ErrInvalidArgument)
}

func TestSync_OtherUsersRecord(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	alice, bob := createUser(t, st), createUser(t, st)
	s := service.NewSync(st)

	shared := uuid.New()
	_, err := s.Push(ctx, alice, []model.Change{{ID: shared, Type: model.TypeText, Payload: []byte("alice")}})
	require.NoError(t, err)

	mine := uuid.New()
	_, err = s.Push(ctx, bob, []model.Change{
		{ID: mine, Type: model.TypeText, Payload: []byte("bob")},
		{ID: shared, Type: model.TypeText, Payload: []byte("hijack"), BaseVersion: 1},
	})
	assert.ErrorIs(t, err, model.ErrPermissionDenied)

	recs, rev, err := s.Pull(ctx, bob, 0)
	require.NoError(t, err)
	assert.Empty(t, recs, "no partial writes")
	assert.Zero(t, rev)

	r, err := st.GetRecord(ctx, alice, shared)
	require.NoError(t, err)
	assert.Equal(t, []byte("alice"), r.Payload)
}

func TestSync_UnknownUser(t *testing.T) {
	s := service.NewSync(memory.New())
	_, err := s.Push(context.Background(), uuid.New(), []model.Change{{ID: uuid.New(), Type: model.TypeText, Payload: []byte("x")}})
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func TestSync_TxErrors(t *testing.T) {
	ctx := context.Background()
	uid := uuid.New()
	change := []model.Change{{ID: uuid.New(), Type: model.TypeText, Payload: []byte("x")}}

	run := func(t *testing.T, setup func(tx *mocks.MockSyncTx)) error {
		ctrl := gomock.NewController(t)
		repo := mocks.NewMockRecordRepository(ctrl)
		tx := mocks.NewMockSyncTx(ctrl)
		setup(tx)
		repo.EXPECT().InUserTx(gomock.Any(), uid, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ uuid.UUID, fn func(service.SyncTx) error) error { return fn(tx) })
		_, err := service.NewSync(repo).Push(ctx, uid, change)
		return err
	}

	t.Run("load", func(t *testing.T) {
		err := run(t, func(tx *mocks.MockSyncTx) {
			tx.EXPECT().RecordForUpdate(gomock.Any(), gomock.Any()).Return(model.Record{}, errDB)
		})
		assert.ErrorIs(t, err, errDB)
	})
	t.Run("revision", func(t *testing.T) {
		err := run(t, func(tx *mocks.MockSyncTx) {
			tx.EXPECT().RecordForUpdate(gomock.Any(), gomock.Any()).Return(model.Record{}, model.ErrNotFound)
			tx.EXPECT().NextRevision(gomock.Any()).Return(int64(0), errDB)
		})
		assert.ErrorIs(t, err, errDB)
	})
	t.Run("save", func(t *testing.T) {
		err := run(t, func(tx *mocks.MockSyncTx) {
			tx.EXPECT().RecordForUpdate(gomock.Any(), gomock.Any()).Return(model.Record{}, model.ErrNotFound)
			tx.EXPECT().NextRevision(gomock.Any()).Return(int64(1), nil)
			tx.EXPECT().SaveRecord(gomock.Any(), gomock.Any()).Return(errDB)
		})
		assert.ErrorIs(t, err, errDB)
	})
}
