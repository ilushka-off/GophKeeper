// Package service implements the server business logic: registration and authentication,
// access to records and blobs, and synchronization with version checks.
// Storage is abstracted behind the interfaces in this file.
package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/model"
)

//go:generate mockgen -source=storage.go -destination=mocks/storage_mock.go -package=mocks

// UserRepository stores users.
type UserRepository interface {
	// CreateUser stores a new user. It returns model.ErrAlreadyExists if the login is taken.
	CreateUser(ctx context.Context, u model.User) (model.User, error)
	// UserByLogin returns a user by login or model.ErrNotFound.
	UserByLogin(ctx context.Context, login string) (model.User, error)
}

// TokenRepository stores refresh tokens.
type TokenRepository interface {
	// SaveRefreshToken stores a refresh token hash.
	SaveRefreshToken(ctx context.Context, t model.RefreshToken) error
	// ConsumeRefreshToken deletes the token and returns it, or returns model.ErrNotFound.
	// Deleting on use makes every refresh token single-use.
	ConsumeRefreshToken(ctx context.Context, hash []byte) (model.RefreshToken, error)
}

// RecordRepository reads records and runs sync transactions.
type RecordRepository interface {
	// GetRecord returns a record of the user or model.ErrNotFound.
	GetRecord(ctx context.Context, userID, id uuid.UUID) (model.Record, error)
	// ListRecords returns live (not deleted) records of the user.
	ListRecords(ctx context.Context, userID uuid.UUID) ([]model.Record, error)
	// ChangesSince returns records with revision > since ordered by revision,
	// and the current revision of the user.
	ChangesSince(ctx context.Context, userID uuid.UUID, since int64) ([]model.Record, int64, error)
	// InUserTx runs fn in a transaction that holds an exclusive lock on the user's revision counter.
	// Changes made through tx are committed only if fn returns nil.
	InUserTx(ctx context.Context, userID uuid.UUID, fn func(tx SyncTx) error) error
}

// SyncTx is a transaction opened by RecordRepository.InUserTx.
type SyncTx interface {
	// RecordForUpdate locks and returns a record by id regardless of its owner, or model.ErrNotFound.
	RecordForUpdate(ctx context.Context, id uuid.UUID) (model.Record, error)
	// NextRevision increments the user's revision counter and returns the new value.
	NextRevision(ctx context.Context) (int64, error)
	// SaveRecord inserts or updates a record.
	SaveRecord(ctx context.Context, r model.Record) error
	// Revision returns the current revision of the user inside the transaction.
	Revision() int64
}

// BlobRepository stores encrypted binary data in chunks.
type BlobRepository interface {
	// SaveBlob stores chunks returned by next until it returns io.EOF.
	// It returns model.ErrAlreadyExists if a blob with this id exists.
	SaveBlob(ctx context.Context, userID, blobID uuid.UUID, next func() ([]byte, error)) (int64, error)
	// ReadBlob calls fn for every chunk of the user's blob in order, or returns model.ErrNotFound.
	ReadBlob(ctx context.Context, userID, blobID uuid.UUID, fn func(chunk []byte) error) error
	// DeleteBlob removes the user's blob. Deleting a missing blob is not an error.
	DeleteBlob(ctx context.Context, userID, blobID uuid.UUID) error
}
