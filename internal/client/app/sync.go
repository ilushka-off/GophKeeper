package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/client/storage"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

// maxSyncRounds bounds push/pull rounds: conflict copies created in one round are pushed in the next.
const maxSyncRounds = 3

// SyncReport summarizes a synchronization.
type SyncReport struct {
	Pushed    int
	Pulled    int
	Conflicts int
	Revision  int64
}

// Sync pushes local changes and pulls remote ones.
//
// Conflicts are resolved in favour of the server: the server version replaces the local
// record, and the local version, unless it was a deletion, is kept as a new record with
// a "(conflict ...)" suffix in its name, so no edit is lost.
func (a *App) Sync(ctx context.Context) (SyncReport, error) {
	if a.cipher == nil {
		return SyncReport{}, ErrLocked
	}
	var rep SyncReport
	for round := 0; round < maxSyncRounds; round++ {
		if err := a.push(ctx, &rep); err != nil {
			return rep, err
		}
		if err := a.pull(ctx, &rep); err != nil {
			return rep, err
		}
		dirty, err := a.store.DirtyRecords(ctx)
		if err != nil {
			return rep, err
		}
		if len(dirty) == 0 {
			break
		}
	}
	a.collectBlobs(ctx)
	return rep, nil
}

func (a *App) push(ctx context.Context, rep *SyncReport) error {
	dirty, err := a.store.DirtyRecords(ctx)
	if err != nil || len(dirty) == 0 {
		return err
	}
	byID := make(map[uuid.UUID]storage.Record, len(dirty))
	changes := make([]model.Change, 0, len(dirty))
	for _, r := range dirty {
		byID[r.ID] = r
		changes = append(changes, model.Change{
			ID: r.ID, Type: r.Type, Payload: r.Payload, Deleted: r.Deleted, BaseVersion: r.Version,
		})
	}
	res, err := a.remote.Push(ctx, changes)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	for _, acc := range res.Accepted {
		r, ok := byID[acc.ID]
		if !ok {
			continue
		}
		rep.Pushed++
		if r.Deleted {
			if err := a.store.DeleteRecord(ctx, r.ID); err != nil {
				return err
			}
			continue
		}
		// The record may have been edited again while the push was in flight.
		cur, err := a.store.Record(ctx, r.ID)
		if err != nil {
			return err
		}
		cur.Version = acc.Version
		cur.Dirty = string(cur.Payload) != string(r.Payload) || cur.Deleted != r.Deleted
		if err := a.store.PutRecord(ctx, cur); err != nil {
			return err
		}
	}
	for _, srv := range res.Conflicts {
		local, ok := byID[srv.ID]
		if !ok {
			continue
		}
		if err := a.resolveConflict(ctx, local, srv); err != nil {
			return err
		}
		rep.Conflicts++
	}
	return nil
}

func (a *App) pull(ctx context.Context, rep *SyncReport) error {
	since, err := a.lastRevision(ctx)
	if err != nil {
		return err
	}
	recs, rev, err := a.remote.Pull(ctx, since)
	if err != nil {
		return fmt.Errorf("pull: %w", err)
	}
	for _, srv := range recs {
		local, err := a.store.Record(ctx, srv.ID)
		switch {
		case errors.Is(err, model.ErrNotFound):
			if err := a.applyServer(ctx, srv); err != nil {
				return err
			}
		case err != nil:
			return err
		case local.Dirty && srv.Version > local.Version:
			if err := a.resolveConflict(ctx, local, srv); err != nil {
				return err
			}
			rep.Conflicts++
		case local.Dirty:
			// Our own change echoed back or older than the local base: keep the local edit.
			continue
		default:
			if err := a.applyServer(ctx, srv); err != nil {
				return err
			}
		}
		rep.Pulled++
	}
	rep.Revision = rev
	return a.setLastRevision(ctx, rev)
}

// applyServer replaces the local copy with the server record.
func (a *App) applyServer(ctx context.Context, srv model.Record) error {
	if srv.Deleted {
		return a.store.DeleteRecord(ctx, srv.ID)
	}
	return a.store.PutRecord(ctx, storage.Record{
		ID: srv.ID, Type: srv.Type, Payload: srv.Payload, Version: srv.Version, UpdatedAt: srv.UpdatedAt,
	})
}

// resolveConflict keeps the server version and saves the local edit as a conflict copy.
func (a *App) resolveConflict(ctx context.Context, local storage.Record, srv model.Record) error {
	if !local.Deleted {
		e, err := a.open(local)
		if err != nil {
			return err
		}
		p := e.Payload
		p.Name = fmt.Sprintf("%s (conflict %s)", p.Name, a.now().Format("2006-01-02 15:04"))
		if _, err := a.add(ctx, p); err != nil {
			return fmt.Errorf("save conflict copy: %w", err)
		}
	}
	return a.applyServer(ctx, srv)
}

// collectBlobs deletes blobs that no local record references any more. Failures are
// ignored: the blob stays in the list and is retried on the next sync.
func (a *App) collectBlobs(ctx context.Context) {
	orphans, err := a.store.OrphanBlobs(ctx)
	if err != nil || len(orphans) == 0 {
		return
	}
	dirty, err := a.store.DirtyRecords(ctx)
	if err != nil || len(dirty) > 0 {
		return
	}
	used := make(map[string]bool)
	entries, err := a.List(ctx, model.TypeBinary)
	if err != nil {
		return
	}
	for _, e := range entries {
		if bin, ok := e.Payload.Data.(model.Binary); ok {
			used[bin.BlobID] = true
		}
	}
	for _, id := range orphans {
		if !used[id] {
			blobID, err := uuid.Parse(id)
			if err == nil && a.remote.DeleteBlob(ctx, blobID) != nil {
				continue
			}
		}
		_ = a.store.RemoveOrphanBlob(ctx, id)
	}
}
