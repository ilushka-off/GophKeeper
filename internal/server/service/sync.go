package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/model"
)

// MaxPayloadSize limits the encrypted payload of one record.
const MaxPayloadSize = 1 << 20

// MaxChangesPerPush limits the number of changes in one push.
const MaxChangesPerPush = 1000

// Sync implements record synchronization based on versions and revisions.
type Sync struct {
	records RecordRepository
	now     func() time.Time
}

// NewSync creates the sync service.
func NewSync(records RecordRepository) *Sync {
	return &Sync{records: records, now: time.Now}
}

// Pull returns all changes of the user after revision since and the current revision.
func (s *Sync) Pull(ctx context.Context, userID uuid.UUID, since int64) ([]model.Record, int64, error) {
	if since < 0 {
		return nil, 0, fmt.Errorf("%w: since must not be negative", model.ErrInvalidArgument)
	}
	return s.records.ChangesSince(ctx, userID, since)
}

func validateChange(c model.Change) error {
	if c.ID == uuid.Nil {
		return fmt.Errorf("%w: record id is required", model.ErrInvalidArgument)
	}
	if !c.Type.Valid() {
		return fmt.Errorf("%w: record %s: unknown type %q", model.ErrInvalidArgument, c.ID, c.Type)
	}
	if c.BaseVersion < 0 {
		return fmt.Errorf("%w: record %s: negative base version", model.ErrInvalidArgument, c.ID)
	}
	if !c.Deleted && len(c.Payload) == 0 {
		return fmt.Errorf("%w: record %s: payload is required", model.ErrInvalidArgument, c.ID)
	}
	if len(c.Payload) > MaxPayloadSize {
		return fmt.Errorf("%w: record %s: payload is larger than %d bytes", model.ErrInvalidArgument, c.ID, MaxPayloadSize)
	}
	return nil
}

// Push applies the user's changes in one transaction.
//
// A change is accepted when its base version equals the server version of the record
// (0 for a record the server has never seen). Otherwise the change is skipped and
// the current server record is returned as a conflict; the client resolves it.
// A change to a record of another user fails the whole push with model.ErrPermissionDenied.
func (s *Sync) Push(ctx context.Context, userID uuid.UUID, changes []model.Change) (model.PushResult, error) {
	if len(changes) > MaxChangesPerPush {
		return model.PushResult{}, fmt.Errorf("%w: more than %d changes", model.ErrInvalidArgument, MaxChangesPerPush)
	}
	seen := make(map[uuid.UUID]struct{}, len(changes))
	for _, c := range changes {
		if err := validateChange(c); err != nil {
			return model.PushResult{}, err
		}
		if _, dup := seen[c.ID]; dup {
			return model.PushResult{}, fmt.Errorf("%w: record %s is changed twice", model.ErrInvalidArgument, c.ID)
		}
		seen[c.ID] = struct{}{}
	}

	var res model.PushResult
	err := s.records.InUserTx(ctx, userID, func(tx SyncTx) error {
		res = model.PushResult{}
		for _, c := range changes {
			cur, err := tx.RecordForUpdate(ctx, c.ID)
			exists := err == nil
			if err != nil && !errors.Is(err, model.ErrNotFound) {
				return fmt.Errorf("load record %s: %w", c.ID, err)
			}
			if exists && cur.UserID != userID {
				return fmt.Errorf("%w: record %s", model.ErrPermissionDenied, c.ID)
			}
			var curVersion int64
			if exists {
				curVersion = cur.Version
			}
			// A record the server has never seen is accepted whatever base version the client
			// reports: there is no server state to lose.
			if exists && c.BaseVersion != curVersion {
				res.Conflicts = append(res.Conflicts, cur)
				continue
			}
			if !exists && c.Deleted {
				// Deleting a record the server has never seen: nothing to store.
				res.Accepted = append(res.Accepted, model.Accepted{ID: c.ID, Version: 0, Revision: tx.Revision()})
				continue
			}
			rev, err := tx.NextRevision(ctx)
			if err != nil {
				return fmt.Errorf("next revision: %w", err)
			}
			rec := model.Record{
				ID:        c.ID,
				UserID:    userID,
				Type:      c.Type,
				Payload:   c.Payload,
				Version:   curVersion + 1,
				Revision:  rev,
				Deleted:   c.Deleted,
				UpdatedAt: s.now(),
			}
			if c.Deleted {
				rec.Payload = []byte{}
			}
			if err := tx.SaveRecord(ctx, rec); err != nil {
				return fmt.Errorf("save record %s: %w", c.ID, err)
			}
			res.Accepted = append(res.Accepted, model.Accepted{ID: rec.ID, Version: rec.Version, Revision: rec.Revision})
		}
		res.Revision = tx.Revision()
		return nil
	})
	if err != nil {
		return model.PushResult{}, err
	}
	return res, nil
}
