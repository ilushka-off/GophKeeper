package service

import "time"

// SetAuthNow replaces the clock of an Auth service in tests.
func SetAuthNow(a *Auth, now func() time.Time) { a.now = now }

// SetSyncNow replaces the clock of a Sync service in tests.
func SetSyncNow(s *Sync, now func() time.Time) { s.now = now }
