package service

import "time"

// SetSyncNow replaces the clock of a Sync service in tests.
func SetSyncNow(s *Sync, now func() time.Time) { s.now = now }
