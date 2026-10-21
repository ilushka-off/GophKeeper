package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

// MaxChunkSize is the largest encrypted chunk the server accepts.
const MaxChunkSize = crypto.ChunkSize + crypto.Overhead

// Vault gives the owner access to records and blobs.
type Vault struct {
	records     RecordRepository
	blobs       BlobRepository
	maxBlobSize int64
}

// NewVault creates the vault service. maxBlobSize limits the stored size of one blob in bytes.
func NewVault(records RecordRepository, blobs BlobRepository, maxBlobSize int64) *Vault {
	return &Vault{records: records, blobs: blobs, maxBlobSize: maxBlobSize}
}

// GetRecord returns a record of the user.
func (v *Vault) GetRecord(ctx context.Context, userID, id uuid.UUID) (model.Record, error) {
	return v.records.GetRecord(ctx, userID, id)
}

// ListRecords returns live records of the user.
func (v *Vault) ListRecords(ctx context.Context, userID uuid.UUID) ([]model.Record, error) {
	return v.records.ListRecords(ctx, userID)
}

// UploadBlob stores a blob read chunk by chunk from next, which must return io.EOF at the end.
// It enforces the chunk size and the total size limit.
func (v *Vault) UploadBlob(ctx context.Context, userID, blobID uuid.UUID, next func() ([]byte, error)) (int64, error) {
	var total int64
	limited := func() ([]byte, error) {
		chunk, err := next()
		if err != nil {
			return nil, err
		}
		if len(chunk) > MaxChunkSize {
			return nil, fmt.Errorf("%w: chunk is larger than %d bytes", model.ErrInvalidArgument, MaxChunkSize)
		}
		total += int64(len(chunk))
		if v.maxBlobSize > 0 && total > v.maxBlobSize {
			return nil, fmt.Errorf("%w: blob is larger than %d bytes", model.ErrInvalidArgument, v.maxBlobSize)
		}
		return chunk, nil
	}
	return v.blobs.SaveBlob(ctx, userID, blobID, limited)
}

// DownloadBlob passes the chunks of the user's blob to fn.
func (v *Vault) DownloadBlob(ctx context.Context, userID, blobID uuid.UUID, fn func([]byte) error) error {
	return v.blobs.ReadBlob(ctx, userID, blobID, fn)
}

// DeleteBlob removes the user's blob.
func (v *Vault) DeleteBlob(ctx context.Context, userID, blobID uuid.UUID) error {
	return v.blobs.DeleteBlob(ctx, userID, blobID)
}
