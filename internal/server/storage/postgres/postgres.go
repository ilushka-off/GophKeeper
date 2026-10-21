// Package postgres implements the server storage interfaces on PostgreSQL with pgx.
// Migrations are embedded and applied with goose on start.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/server/service"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Storage implements the service repositories on a pgx pool.
type Storage struct {
	pool *pgxpool.Pool
}

var (
	_ service.UserRepository   = (*Storage)(nil)
	_ service.TokenRepository  = (*Storage)(nil)
	_ service.RecordRepository = (*Storage)(nil)
	_ service.BlobRepository   = (*Storage)(nil)
)

// New connects to PostgreSQL, applies migrations and returns the storage.
func New(ctx context.Context, dsn string) (*Storage, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Storage{pool: pool}, nil
}

// Migrate applies the embedded migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, mustSub(migrations, "migrations"))
	if err != nil {
		return fmt.Errorf("postgres: migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	return nil
}

// Close closes the connection pool.
func (s *Storage) Close() {
	s.pool.Close()
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateUser implements service.UserRepository.
func (s *Storage) CreateUser(ctx context.Context, u model.User) (model.User, error) {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (id, login, password_hash, kdf_salt) VALUES ($1, $2, $3, $4)
		 RETURNING revision, created_at`,
		u.ID, u.Login, u.PasswordHash, u.KDFSalt,
	).Scan(&u.Revision, &u.CreatedAt)
	if isUniqueViolation(err) {
		return model.User{}, model.ErrAlreadyExists
	}
	if err != nil {
		return model.User{}, fmt.Errorf("postgres: insert user: %w", err)
	}
	return u, nil
}

// UserByLogin implements service.UserRepository.
func (s *Storage) UserByLogin(ctx context.Context, login string) (model.User, error) {
	var u model.User
	err := s.pool.QueryRow(ctx,
		`SELECT id, login, password_hash, kdf_salt, revision, created_at FROM users WHERE login = $1`, login,
	).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.KDFSalt, &u.Revision, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.User{}, model.ErrNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("postgres: select user: %w", err)
	}
	return u, nil
}

// SaveRefreshToken implements service.TokenRepository.
func (s *Storage) SaveRefreshToken(ctx context.Context, t model.RefreshToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		t.Hash, t.UserID, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("postgres: insert refresh token: %w", err)
	}
	return nil
}

// ConsumeRefreshToken implements service.TokenRepository.
func (s *Storage) ConsumeRefreshToken(ctx context.Context, hash []byte) (model.RefreshToken, error) {
	t := model.RefreshToken{Hash: hash}
	err := s.pool.QueryRow(ctx,
		`DELETE FROM refresh_tokens WHERE token_hash = $1 RETURNING user_id, expires_at`, hash,
	).Scan(&t.UserID, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RefreshToken{}, model.ErrNotFound
	}
	if err != nil {
		return model.RefreshToken{}, fmt.Errorf("postgres: delete refresh token: %w", err)
	}
	return t, nil
}

const recordColumns = `id, user_id, type, payload, version, revision, deleted, updated_at`

func scanRecord(row pgx.Row) (model.Record, error) {
	var (
		r   model.Record
		typ string
	)
	err := row.Scan(&r.ID, &r.UserID, &typ, &r.Payload, &r.Version, &r.Revision, &r.Deleted, &r.UpdatedAt)
	r.Type = model.RecordType(typ)
	return r, err
}

func collectRecords(rows pgx.Rows) ([]model.Record, error) {
	defer rows.Close()
	var out []model.Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan record: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: read records: %w", err)
	}
	return out, nil
}

// GetRecord implements service.RecordRepository.
func (s *Storage) GetRecord(ctx context.Context, userID, id uuid.UUID) (model.Record, error) {
	r, err := scanRecord(s.pool.QueryRow(ctx,
		`SELECT `+recordColumns+` FROM records WHERE id = $1 AND user_id = $2`, id, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Record{}, model.ErrNotFound
	}
	if err != nil {
		return model.Record{}, fmt.Errorf("postgres: select record: %w", err)
	}
	return r, nil
}

// ListRecords implements service.RecordRepository.
func (s *Storage) ListRecords(ctx context.Context, userID uuid.UUID) ([]model.Record, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+recordColumns+` FROM records WHERE user_id = $1 AND NOT deleted ORDER BY revision`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: select records: %w", err)
	}
	return collectRecords(rows)
}

// ChangesSince implements service.RecordRepository.
func (s *Storage) ChangesSince(ctx context.Context, userID uuid.UUID, since int64) ([]model.Record, int64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, 0, fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revision int64
	err = tx.QueryRow(ctx, `SELECT revision FROM users WHERE id = $1`, userID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, model.ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("postgres: select revision: %w", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT `+recordColumns+` FROM records WHERE user_id = $1 AND revision > $2 ORDER BY revision`,
		userID, since)
	if err != nil {
		return nil, 0, fmt.Errorf("postgres: select changes: %w", err)
	}
	recs, err := collectRecords(rows)
	if err != nil {
		return nil, 0, err
	}
	return recs, revision, tx.Commit(ctx)
}

type syncTx struct {
	tx       pgx.Tx
	userID   uuid.UUID
	revision int64
}

// InUserTx implements service.RecordRepository. The user row is locked with
// SELECT ... FOR UPDATE, so pushes of one user are serialized.
func (s *Storage) InUserTx(ctx context.Context, userID uuid.UUID, fn func(service.SyncTx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	st := &syncTx{tx: tx, userID: userID}
	err = tx.QueryRow(ctx, `SELECT revision FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&st.revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("postgres: lock user: %w", err)
	}
	start := st.revision
	if err := fn(st); err != nil {
		return err
	}
	if st.revision != start {
		if _, err := tx.Exec(ctx, `UPDATE users SET revision = $2 WHERE id = $1`, userID, st.revision); err != nil {
			return fmt.Errorf("postgres: update revision: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// RecordForUpdate implements service.SyncTx with SELECT ... FOR UPDATE.
func (t *syncTx) RecordForUpdate(ctx context.Context, id uuid.UUID) (model.Record, error) {
	r, err := scanRecord(t.tx.QueryRow(ctx, `SELECT `+recordColumns+` FROM records WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Record{}, model.ErrNotFound
	}
	if err != nil {
		return model.Record{}, fmt.Errorf("postgres: select record: %w", err)
	}
	return r, nil
}

// NextRevision implements service.SyncTx. The counter is written to users on commit.
func (t *syncTx) NextRevision(context.Context) (int64, error) {
	t.revision++
	return t.revision, nil
}

// Revision implements service.SyncTx.
func (t *syncTx) Revision() int64 { return t.revision }

// SaveRecord implements service.SyncTx with an upsert that never changes the owner.
func (t *syncTx) SaveRecord(ctx context.Context, r model.Record) error {
	payload := r.Payload
	if payload == nil {
		payload = []byte{}
	}
	_, err := t.tx.Exec(ctx,
		`INSERT INTO records (`+recordColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (id) DO UPDATE SET type = EXCLUDED.type, payload = EXCLUDED.payload,
		   version = EXCLUDED.version, revision = EXCLUDED.revision,
		   deleted = EXCLUDED.deleted, updated_at = EXCLUDED.updated_at
		 WHERE records.user_id = EXCLUDED.user_id`,
		r.ID, r.UserID, string(r.Type), payload, r.Version, r.Revision, r.Deleted, r.UpdatedAt)
	if err != nil {
		return fmt.Errorf("postgres: upsert record: %w", err)
	}
	return nil
}

// SaveBlob implements service.BlobRepository. The blob and its chunks are written in one transaction.
func (s *Storage) SaveBlob(ctx context.Context, userID, blobID uuid.UUID, next func() ([]byte, error)) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `INSERT INTO blobs (id, user_id, created_at) VALUES ($1, $2, $3)`, blobID, userID, time.Now())
	if isUniqueViolation(err) {
		return 0, fmt.Errorf("blob %s: %w", blobID, model.ErrAlreadyExists)
	}
	if err != nil {
		return 0, fmt.Errorf("postgres: insert blob: %w", err)
	}
	var size int64
	for seq := 0; ; seq++ {
		chunk, err := next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO blob_chunks (blob_id, seq, data) VALUES ($1, $2, $3)`,
			blobID, seq, chunk); err != nil {
			return 0, fmt.Errorf("postgres: insert chunk: %w", err)
		}
		size += int64(len(chunk))
	}
	if _, err := tx.Exec(ctx, `UPDATE blobs SET size = $2 WHERE id = $1`, blobID, size); err != nil {
		return 0, fmt.Errorf("postgres: update blob size: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("postgres: commit: %w", err)
	}
	return size, nil
}

// ReadBlob implements service.BlobRepository. Chunks are read one by one to keep memory flat.
func (s *Storage) ReadBlob(ctx context.Context, userID, blobID uuid.UUID, fn func([]byte) error) error {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM blobs WHERE id = $1 AND user_id = $2)`,
		blobID, userID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("postgres: select blob: %w", err)
	}
	if !exists {
		return model.ErrNotFound
	}
	for seq := 0; ; seq++ {
		var data []byte
		err := s.pool.QueryRow(ctx, `SELECT data FROM blob_chunks WHERE blob_id = $1 AND seq = $2`,
			blobID, seq).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("postgres: select chunk: %w", err)
		}
		if err := fn(data); err != nil {
			return err
		}
	}
}

// DeleteBlob implements service.BlobRepository.
func (s *Storage) DeleteBlob(ctx context.Context, userID, blobID uuid.UUID) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM blobs WHERE id = $1 AND user_id = $2`, blobID, userID); err != nil {
		return fmt.Errorf("postgres: delete blob: %w", err)
	}
	return nil
}
