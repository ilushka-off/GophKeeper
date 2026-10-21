package service_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
	"github.com/ilushka-off/GophKeeper/internal/server/storage/memory"
)

func chunks(cs ...[]byte) func() ([]byte, error) {
	i := 0
	return func() ([]byte, error) {
		if i >= len(cs) {
			return nil, io.EOF
		}
		i++
		return cs[i-1], nil
	}
}

func TestVault_Blobs(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	v := service.NewVault(st, st, 100)
	uid, blobID := uuid.New(), uuid.New()

	size, err := v.UploadBlob(ctx, uid, blobID, chunks([]byte("hello "), []byte("world")))
	require.NoError(t, err)
	assert.Equal(t, int64(11), size)

	var buf bytes.Buffer
	require.NoError(t, v.DownloadBlob(ctx, uid, blobID, func(c []byte) error {
		buf.Write(c)
		return nil
	}))
	assert.Equal(t, "hello world", buf.String())

	err = v.DownloadBlob(ctx, uuid.New(), blobID, func([]byte) error { return nil })
	assert.ErrorIs(t, err, model.ErrNotFound, "other users cannot read the blob")

	require.NoError(t, v.DeleteBlob(ctx, uid, blobID))
	err = v.DownloadBlob(ctx, uid, blobID, func([]byte) error { return nil })
	assert.ErrorIs(t, err, model.ErrNotFound)
}

func TestVault_UploadLimits(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	v := service.NewVault(st, st, 10)

	_, err := v.UploadBlob(ctx, uuid.New(), uuid.New(), chunks(make([]byte, service.MaxChunkSize+1)))
	assert.ErrorIs(t, err, model.ErrInvalidArgument)

	_, err = v.UploadBlob(ctx, uuid.New(), uuid.New(), chunks(make([]byte, 6), make([]byte, 6)))
	assert.ErrorIs(t, err, model.ErrInvalidArgument)

	_, err = v.UploadBlob(ctx, uuid.New(), uuid.New(), func() ([]byte, error) { return nil, errDB })
	assert.ErrorIs(t, err, errDB)
}

func TestVault_Records(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	uid := createUser(t, st)
	s := service.NewSync(st)
	v := service.NewVault(st, st, 100)
	id := uuid.New()
	_, err := s.Push(ctx, uid, []model.Change{{ID: id, Type: model.TypeText, Payload: []byte("x")}})
	require.NoError(t, err)

	r, err := v.GetRecord(ctx, uid, id)
	require.NoError(t, err)
	assert.Equal(t, []byte("x"), r.Payload)
	list, err := v.ListRecords(ctx, uid)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}
