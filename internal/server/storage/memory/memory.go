// Package memory is an in-memory implementation of the server storage interfaces.
// It is used in tests and for running the server without PostgreSQL during development.
package memory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
)

type blob struct {
	userID uuid.UUID
	chunks [][]byte
}

// Storage keeps users, tokens, records and blobs in memory. It is safe for concurrent use.
type Storage struct {
	mu      sync.Mutex
	users   map[uuid.UUID]model.User
	logins  map[string]uuid.UUID
	tokens  map[string]model.RefreshToken
	records map[uuid.UUID]model.Record
	blobs   map[uuid.UUID]blob
}

var (
	_ service.UserRepository   = (*Storage)(nil)
	_ service.TokenRepository  = (*Storage)(nil)
	_ service.RecordRepository = (*Storage)(nil)
	_ service.BlobRepository   = (*Storage)(nil)
)

// New returns an empty storage.
func New() *Storage {
	return &Storage{
		users:   make(map[uuid.UUID]model.User),
		logins:  make(map[string]uuid.UUID),
		tokens:  make(map[string]model.RefreshToken),
		records: make(map[uuid.UUID]model.Record),
		blobs:   make(map[uuid.UUID]blob),
	}
}

// CreateUser implements service.UserRepository.
func (s *Storage) CreateUser(_ context.Context, u model.User) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.logins[u.Login]; ok {
		return model.User{}, model.ErrAlreadyExists
	}
	u.CreatedAt = time.Now()
	u.KDFSalt = bytes.Clone(u.KDFSalt)
	s.users[u.ID] = u
	s.logins[u.Login] = u.ID
	return u, nil
}

// UserByLogin implements service.UserRepository.
func (s *Storage) UserByLogin(_ context.Context, login string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.logins[login]
	if !ok {
		return model.User{}, model.ErrNotFound
	}
	return s.users[id], nil
}

// SaveRefreshToken implements service.TokenRepository.
func (s *Storage) SaveRefreshToken(_ context.Context, t model.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[string(t.Hash)] = t
	return nil
}

// ConsumeRefreshToken implements service.TokenRepository.
func (s *Storage) ConsumeRefreshToken(_ context.Context, hash []byte) (model.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[string(hash)]
	if !ok {
		return model.RefreshToken{}, model.ErrNotFound
	}
	delete(s.tokens, string(hash))
	return t, nil
}

// GetRecord implements service.RecordRepository.
func (s *Storage) GetRecord(_ context.Context, userID, id uuid.UUID) (model.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok || r.UserID != userID {
		return model.Record{}, model.ErrNotFound
	}
	return r, nil
}

// ListRecords implements service.RecordRepository.
func (s *Storage) ListRecords(_ context.Context, userID uuid.UUID) ([]model.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Record
	for _, r := range s.records {
		if r.UserID == userID && !r.Deleted {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b model.Record) int { return int(a.Revision - b.Revision) })
	return out, nil
}

// ChangesSince implements service.RecordRepository.
func (s *Storage) ChangesSince(_ context.Context, userID uuid.UUID, since int64) ([]model.Record, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return nil, 0, model.ErrNotFound
	}
	var out []model.Record
	for _, r := range s.records {
		if r.UserID == userID && r.Revision > since {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b model.Record) int { return int(a.Revision - b.Revision) })
	return out, u.Revision, nil
}

type tx struct {
	s        *Storage
	revision int64
	staged   map[uuid.UUID]model.Record
}

// InUserTx implements service.RecordRepository. Writes are staged and applied only on success.
func (s *Storage) InUserTx(ctx context.Context, userID uuid.UUID, fn func(service.SyncTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return model.ErrNotFound
	}
	t := &tx{s: s, revision: u.Revision, staged: make(map[uuid.UUID]model.Record)}
	if err := fn(t); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for id, r := range t.staged {
		s.records[id] = r
	}
	u.Revision = t.revision
	s.users[userID] = u
	return nil
}

// RecordForUpdate implements service.SyncTx. Staged writes are visible inside the transaction.
func (t *tx) RecordForUpdate(_ context.Context, id uuid.UUID) (model.Record, error) {
	if r, ok := t.staged[id]; ok {
		return r, nil
	}
	r, ok := t.s.records[id]
	if !ok {
		return model.Record{}, model.ErrNotFound
	}
	return r, nil
}

// NextRevision implements service.SyncTx.
func (t *tx) NextRevision(context.Context) (int64, error) {
	t.revision++
	return t.revision, nil
}

// SaveRecord implements service.SyncTx. The record is applied on commit.
func (t *tx) SaveRecord(_ context.Context, r model.Record) error {
	r.Payload = bytes.Clone(r.Payload)
	t.staged[r.ID] = r
	return nil
}

// Revision implements service.SyncTx.
func (t *tx) Revision() int64 { return t.revision }

// SaveBlob implements service.BlobRepository.
func (s *Storage) SaveBlob(_ context.Context, userID, blobID uuid.UUID, next func() ([]byte, error)) (int64, error) {
	var (
		chunks [][]byte
		size   int64
	)
	for {
		c, err := next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		chunks = append(chunks, bytes.Clone(c))
		size += int64(len(c))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blobs[blobID]; ok {
		return 0, fmt.Errorf("blob %s: %w", blobID, model.ErrAlreadyExists)
	}
	s.blobs[blobID] = blob{userID: userID, chunks: chunks}
	return size, nil
}

// ReadBlob implements service.BlobRepository.
func (s *Storage) ReadBlob(_ context.Context, userID, blobID uuid.UUID, fn func([]byte) error) error {
	s.mu.Lock()
	b, ok := s.blobs[blobID]
	s.mu.Unlock()
	if !ok || b.userID != userID {
		return model.ErrNotFound
	}
	for _, c := range b.chunks {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

// DeleteBlob implements service.BlobRepository.
func (s *Storage) DeleteBlob(_ context.Context, userID, blobID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.blobs[blobID]; ok && b.userID == userID {
		delete(s.blobs, blobID)
	}
	return nil
}
