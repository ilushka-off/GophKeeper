// Package storage is the client's local copy of the vault in SQLite (modernc.org/sqlite,
// no CGO). It keeps encrypted records with their sync state and a key-value table for
// the session: login, KDF salt, encrypted tokens and the last synced revision.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // registers the sqlite driver

	"github.com/ilushka-off/GophKeeper/internal/model"
)

// Meta keys used by the client.
const (
	MetaLogin        = "login"
	MetaKDFSalt      = "kdf_salt"
	MetaKeyCheck     = "key_check"
	MetaTokens       = "tokens"
	MetaLastRevision = "last_revision"
)

// Record is a locally stored encrypted record with its sync state.
type Record struct {
	ID      uuid.UUID
	Type    model.RecordType
	Payload []byte
	// Version is the server version the local copy is based on, 0 if never synced.
	Version int64
	// Deleted marks a local tombstone waiting to be pushed.
	Deleted bool
	// Dirty means the record has local changes not yet accepted by the server.
	Dirty     bool
	UpdatedAt time.Time
}

// Store is the local SQLite storage.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    payload BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0,
    dirty INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orphan_blobs (
    blob_id TEXT PRIMARY KEY
);
`

// Open opens (and creates if needed) the database at path. Use ":memory:" for tests.
func Open(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("storage: create dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	// SQLite allows one writer; a single connection also keeps ":memory:" databases shared.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: pragma: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: schema: %w", err)
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0o600)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Meta returns a meta value or model.ErrNotFound.
func (s *Store) Meta(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get meta %s: %w", key, err)
	}
	return v, nil
}

// SetMeta stores a meta value.
func (s *Store) SetMeta(ctx context.Context, key string, value []byte) error {
	if value == nil {
		value = []byte{}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		key, value)
	if err != nil {
		return fmt.Errorf("storage: set meta %s: %w", key, err)
	}
	return nil
}

// DeleteMeta removes a meta value.
func (s *Store) DeleteMeta(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, key); err != nil {
		return fmt.Errorf("storage: delete meta %s: %w", key, err)
	}
	return nil
}

// Reset removes all records, orphan blobs and meta values.
func (s *Store) Reset(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM records; DELETE FROM meta; DELETE FROM orphan_blobs;`); err != nil {
		return fmt.Errorf("storage: reset: %w", err)
	}
	return nil
}

// PutRecord inserts or replaces a record.
func (s *Store) PutRecord(ctx context.Context, r Record) error {
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = time.Now()
	}
	payload := r.Payload
	if payload == nil {
		payload = []byte{}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO records (id, type, payload, version, deleted, dirty, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET type = excluded.type, payload = excluded.payload,
		   version = excluded.version, deleted = excluded.deleted, dirty = excluded.dirty,
		   updated_at = excluded.updated_at`,
		r.ID.String(), string(r.Type), payload, r.Version, r.Deleted, r.Dirty, r.UpdatedAt.UnixMilli())
	if err != nil {
		return fmt.Errorf("storage: put record: %w", err)
	}
	return nil
}

const recordColumns = `id, type, payload, version, deleted, dirty, updated_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(sc scanner) (Record, error) {
	var (
		r       Record
		id, typ string
		updated int64
	)
	if err := sc.Scan(&id, &typ, &r.Payload, &r.Version, &r.Deleted, &r.Dirty, &updated); err != nil {
		return Record{}, err
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		return Record{}, fmt.Errorf("storage: bad record id %q: %w", id, err)
	}
	r.ID = parsed
	r.Type = model.RecordType(typ)
	r.UpdatedAt = time.UnixMilli(updated)
	return r, nil
}

func (s *Store) queryRecords(ctx context.Context, where string, args ...any) ([]Record, error) {
	// where is always a constant from this file, values are passed as arguments.
	rows, err := s.db.QueryContext(ctx, `SELECT `+recordColumns+` FROM records `+where, args...) //nolint:gosec // see above
	if err != nil {
		return nil, fmt.Errorf("storage: query records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: scan record: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: read records: %w", err)
	}
	return out, nil
}

// Record returns a record by id or model.ErrNotFound.
func (s *Store) Record(ctx context.Context, id uuid.UUID) (Record, error) {
	r, err := scanRecord(s.db.QueryRowContext(ctx, `SELECT `+recordColumns+` FROM records WHERE id = ?`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, model.ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("storage: get record: %w", err)
	}
	return r, nil
}

// Records returns live (not deleted) records ordered by update time.
func (s *Store) Records(ctx context.Context) ([]Record, error) {
	return s.queryRecords(ctx, `WHERE deleted = 0 ORDER BY updated_at, id`)
}

// DirtyRecords returns records with changes not yet accepted by the server, tombstones included.
func (s *Store) DirtyRecords(ctx context.Context) ([]Record, error) {
	return s.queryRecords(ctx, `WHERE dirty = 1 ORDER BY updated_at, id`)
}

// FindByPrefix returns live records whose id starts with prefix.
func (s *Store) FindByPrefix(ctx context.Context, prefix string) ([]Record, error) {
	prefix = strings.ToLower(prefix)
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix)
	return s.queryRecords(ctx, `WHERE deleted = 0 AND id LIKE ? ESCAPE '\' ORDER BY id`, escaped+"%")
}

// DeleteRecord removes a record from the local copy.
func (s *Store) DeleteRecord(ctx context.Context, id uuid.UUID) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM records WHERE id = ?`, id.String()); err != nil {
		return fmt.Errorf("storage: delete record: %w", err)
	}
	return nil
}

// AddOrphanBlob remembers a blob that may no longer be referenced and should be removed from the server.
func (s *Store) AddOrphanBlob(ctx context.Context, blobID string) error {
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO orphan_blobs (blob_id) VALUES (?)`, blobID); err != nil {
		return fmt.Errorf("storage: add orphan blob: %w", err)
	}
	return nil
}

// OrphanBlobs returns remembered orphan blob ids.
func (s *Store) OrphanBlobs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT blob_id FROM orphan_blobs ORDER BY blob_id`)
	if err != nil {
		return nil, fmt.Errorf("storage: query orphan blobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("storage: scan orphan blob: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RemoveOrphanBlob forgets an orphan blob.
func (s *Store) RemoveOrphanBlob(ctx context.Context, blobID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM orphan_blobs WHERE blob_id = ?`, blobID); err != nil {
		return fmt.Errorf("storage: remove orphan blob: %w", err)
	}
	return nil
}
