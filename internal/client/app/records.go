package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/client/storage"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

// Entry is a decrypted record.
type Entry struct {
	ID        uuid.UUID
	Payload   model.Payload
	Version   int64
	Dirty     bool
	UpdatedAt time.Time
}

// recordAAD binds the ciphertext to the record id and type,
// so the server cannot swap payloads between records.
func recordAAD(id uuid.UUID, t model.RecordType) []byte {
	return append(id[:], []byte(t)...)
}

func (a *App) seal(id uuid.UUID, p model.Payload) ([]byte, error) {
	if a.cipher == nil {
		return nil, ErrLocked
	}
	plain, err := model.MarshalPayload(p)
	if err != nil {
		return nil, err
	}
	return a.cipher.Seal(plain, recordAAD(id, p.Type()))
}

func (a *App) open(r storage.Record) (Entry, error) {
	if a.cipher == nil {
		return Entry{}, ErrLocked
	}
	plain, err := a.cipher.Open(r.Payload, recordAAD(r.ID, r.Type))
	if err != nil {
		return Entry{}, fmt.Errorf("record %s: %w", r.ID, err)
	}
	p, err := model.UnmarshalPayload(plain)
	if err != nil {
		return Entry{}, fmt.Errorf("record %s: %w", r.ID, err)
	}
	if p.Type() != r.Type {
		return Entry{}, fmt.Errorf("record %s: type mismatch", r.ID)
	}
	return Entry{ID: r.ID, Payload: p, Version: r.Version, Dirty: r.Dirty, UpdatedAt: r.UpdatedAt}, nil
}

// Add stores a new record locally and marks it for sync. Binary data must be added with AddFile.
func (a *App) Add(ctx context.Context, p model.Payload) (uuid.UUID, error) {
	if p.Type() == model.TypeBinary {
		return uuid.Nil, fmt.Errorf("%w: use AddFile for binary data", model.ErrInvalidArgument)
	}
	return a.add(ctx, p)
}

func (a *App) add(ctx context.Context, p model.Payload) (uuid.UUID, error) {
	if err := p.Validate(); err != nil {
		return uuid.Nil, err
	}
	id := uuid.New()
	sealed, err := a.seal(id, p)
	if err != nil {
		return uuid.Nil, err
	}
	err = a.store.PutRecord(ctx, storage.Record{
		ID: id, Type: p.Type(), Payload: sealed, Dirty: true, UpdatedAt: a.now(),
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// AddFile encrypts the file at path, uploads it to the server and stores a binary record for it.
func (a *App) AddFile(ctx context.Context, name, meta, path string) (uuid.UUID, error) {
	bin, err := a.uploadFile(ctx, path)
	if err != nil {
		return uuid.Nil, err
	}
	return a.add(ctx, model.Payload{Name: name, Meta: meta, Data: bin})
}

func (a *App) uploadFile(ctx context.Context, path string) (model.Binary, error) {
	if a.cipher == nil {
		return model.Binary{}, ErrLocked
	}
	f, err := os.Open(path)
	if err != nil {
		return model.Binary{}, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()
	blobID := uuid.New()
	var size int64
	_, err = a.remote.UploadBlob(ctx, blobID, func(send func([]byte) error) error {
		n, err := a.cipher.EncryptStream(f, blobID[:], send)
		size = n
		return err
	})
	if err != nil {
		return model.Binary{}, fmt.Errorf("upload file: %w", err)
	}
	return model.Binary{FileName: filepath.Base(path), Size: size, BlobID: blobID.String()}, nil
}

// Edit changes a record with fn and marks it for sync.
func (a *App) Edit(ctx context.Context, id uuid.UUID, fn func(p *model.Payload) error) error {
	r, err := a.store.Record(ctx, id)
	if err != nil {
		return err
	}
	if r.Deleted {
		return model.ErrNotFound
	}
	e, err := a.open(r)
	if err != nil {
		return err
	}
	p := e.Payload
	if err := fn(&p); err != nil {
		return err
	}
	if p.Type() != r.Type {
		return fmt.Errorf("%w: record type cannot be changed", model.ErrInvalidArgument)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	sealed, err := a.seal(id, p)
	if err != nil {
		return err
	}
	r.Payload = sealed
	r.Dirty = true
	r.UpdatedAt = a.now()
	return a.store.PutRecord(ctx, r)
}

// ReplaceFile uploads a new file for a binary record. The old blob is removed after the change is synced.
func (a *App) ReplaceFile(ctx context.Context, id uuid.UUID, path string) error {
	e, err := a.Get(ctx, id)
	if err != nil {
		return err
	}
	old, ok := e.Payload.Data.(model.Binary)
	if !ok {
		return fmt.Errorf("%w: record is not binary", model.ErrInvalidArgument)
	}
	bin, err := a.uploadFile(ctx, path)
	if err != nil {
		return err
	}
	if err := a.Edit(ctx, id, func(p *model.Payload) error {
		p.Data = bin
		return nil
	}); err != nil {
		return err
	}
	return a.store.AddOrphanBlob(ctx, old.BlobID)
}

// Delete marks a record as deleted. The tombstone is pushed on the next sync.
func (a *App) Delete(ctx context.Context, id uuid.UUID) error {
	r, err := a.store.Record(ctx, id)
	if err != nil {
		return err
	}
	if r.Deleted {
		return model.ErrNotFound
	}
	if r.Type == model.TypeBinary {
		// The tombstone drops the payload, so the blob id must be saved for GC now:
		// a record that cannot be read is not deleted, otherwise its blob would leak on the server.
		e, err := a.open(r)
		if err != nil {
			return fmt.Errorf("read binary record before delete: %w", err)
		}
		bin, ok := e.Payload.Data.(model.Binary)
		if !ok {
			return fmt.Errorf("%w: binary record has %s payload", model.ErrInvalidArgument, e.Payload.Type())
		}
		if err := a.store.AddOrphanBlob(ctx, bin.BlobID); err != nil {
			return err
		}
	}
	if r.Version == 0 {
		// Never reached the server: forget it locally.
		return a.store.DeleteRecord(ctx, id)
	}
	r.Deleted = true
	r.Dirty = true
	r.UpdatedAt = a.now()
	return a.store.PutRecord(ctx, r)
}

// Get returns a decrypted record. If the record is missing locally it is fetched from the server.
func (a *App) Get(ctx context.Context, id uuid.UUID) (Entry, error) {
	r, err := a.store.Record(ctx, id)
	if errors.Is(err, model.ErrNotFound) && a.remote != nil {
		rec, rerr := a.remote.GetRecord(ctx, id)
		if rerr != nil {
			return Entry{}, rerr
		}
		r = storage.Record{ID: rec.ID, Type: rec.Type, Payload: rec.Payload, Version: rec.Version,
			Deleted: rec.Deleted, UpdatedAt: rec.UpdatedAt}
		err = nil
	}
	if err != nil {
		return Entry{}, err
	}
	if r.Deleted {
		return Entry{}, model.ErrNotFound
	}
	return a.open(r)
}

// List returns decrypted live records, optionally filtered by type, sorted by name.
func (a *App) List(ctx context.Context, filter model.RecordType) ([]Entry, error) {
	recs, err := a.store.Records(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(recs))
	for _, r := range recs {
		if filter != "" && r.Type != filter {
			continue
		}
		e, err := a.open(r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	slices.SortStableFunc(out, func(x, y Entry) int {
		return strings.Compare(strings.ToLower(x.Payload.Name), strings.ToLower(y.Payload.Name))
	})
	return out, nil
}

// Resolve finds a record by a full id or a unique id prefix.
func (a *App) Resolve(ctx context.Context, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	if len(ref) < 4 {
		return uuid.Nil, fmt.Errorf("%w: id prefix must be at least 4 characters", model.ErrInvalidArgument)
	}
	recs, err := a.store.FindByPrefix(ctx, ref)
	if err != nil {
		return uuid.Nil, err
	}
	switch len(recs) {
	case 0:
		return uuid.Nil, model.ErrNotFound
	case 1:
		return recs[0].ID, nil
	}
	return uuid.Nil, ErrAmbiguousID
}

// SaveFile downloads, decrypts and writes the content of a binary record to w.
func (a *App) SaveFile(ctx context.Context, id uuid.UUID, w io.Writer) (int64, error) {
	e, err := a.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	bin, ok := e.Payload.Data.(model.Binary)
	if !ok {
		return 0, fmt.Errorf("%w: record is not binary", model.ErrInvalidArgument)
	}
	blobID, err := uuid.Parse(bin.BlobID)
	if err != nil {
		return 0, fmt.Errorf("bad blob id: %w", err)
	}

	next, stop := iter.Pull2(a.blobChunks(ctx, blobID))
	defer stop()
	return a.cipher.DecryptStream(func() ([]byte, error) {
		c, err, ok := next()
		switch {
		case !ok:
			return nil, io.EOF
		case err != nil:
			return nil, err
		}
		return c, nil
	}, blobID[:], w)
}

// errStopDownload aborts a download when the consumer of blobChunks stops early.
var errStopDownload = errors.New("download stopped")

// blobChunks streams the encrypted chunks of a blob from the server.
// A download error is yielded as the last element.
func (a *App) blobChunks(ctx context.Context, blobID uuid.UUID) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		err := a.remote.DownloadBlob(ctx, blobID, func(c []byte) error {
			if !yield(c, nil) {
				return errStopDownload
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStopDownload) {
			yield(nil, err)
		}
	}
}
