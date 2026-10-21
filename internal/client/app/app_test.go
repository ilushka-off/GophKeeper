package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ilushka-off/GophKeeper/internal/client/remote"
	"github.com/ilushka-off/GophKeeper/internal/client/storage"
	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/model"
	"github.com/ilushka-off/GophKeeper/internal/testutil"
)

const master = "correct horse battery"

// newApp creates an app on a fresh in-memory store connected to srv.
func newApp(t *testing.T, srv *testutil.Server) (*App, *storage.Store) {
	t.Helper()
	st, err := storage.Open(context.Background(), ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	rc := remote.New(srv.Dial(t))
	a := New(st, rc, testutil.FastKDF)
	rc.SetTokenStore(a)
	return a, st
}

// pair registers a user on the first app and logs the second app in to the same account.
func pair(t *testing.T) (*App, *App, *testutil.Server) {
	t.Helper()
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a1, _ := newApp(t, srv)
	a2, _ := newApp(t, srv)
	require.NoError(t, a1.SignUp(ctx, "ilya", master))
	require.NoError(t, a2.SignIn(ctx, "ilya", master))
	return a1, a2, srv
}

func mustSync(t *testing.T, a *App) SyncReport {
	t.Helper()
	rep, err := a.Sync(context.Background())
	require.NoError(t, err)
	return rep
}

func names(t *testing.T, a *App) []string {
	t.Helper()
	es, err := a.List(context.Background(), "")
	require.NoError(t, err)
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Payload.Name)
	}
	return out
}

func text(name, content string) model.Payload {
	return model.Payload{Name: name, Data: model.Text{Content: content}}
}

func TestSignUpUnlock(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, st := newApp(t, srv)

	_, err := a.Login(ctx)
	require.ErrorIs(t, err, ErrNoAccount)
	require.ErrorIs(t, a.Unlock(ctx, master), ErrNoAccount)
	assert.False(t, a.Unlocked())

	require.NoError(t, a.SignUp(ctx, "ilya", master))
	assert.True(t, a.Unlocked())
	login, err := a.Login(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ilya", login)

	// A fresh app on the same store must be unlocked with the right password.
	b := New(st, a.remote, testutil.FastKDF)
	require.ErrorIs(t, b.Unlock(ctx, "wrong"), ErrWrongMasterPassword)
	assert.False(t, b.Unlocked())
	require.NoError(t, b.Unlock(ctx, master))
	tok, err := b.Tokens(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, tok.AccessToken)

	// The server must not know the master password: login with it fails.
	_, _, err = remote.New(srv.Dial(t)).Login(ctx, "ilya", master)
	require.ErrorIs(t, err, model.ErrUnauthenticated)

	// Second registration of the same login fails on the server.
	c, _ := newApp(t, srv)
	require.ErrorIs(t, c.SignUp(ctx, "ilya", master), model.ErrAlreadyExists)
}

func TestSignIn(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, _ := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))

	b, _ := newApp(t, srv)
	require.ErrorIs(t, b.SignIn(ctx, "ilya", "wrong password"), model.ErrUnauthenticated)
	require.ErrorIs(t, b.SignIn(ctx, "nobody", master), model.ErrUnauthenticated)
	require.NoError(t, b.SignIn(ctx, "ilya", master))
	assert.True(t, b.Unlocked())
}

func TestLockedVault(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, st := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))
	id, err := a.Add(ctx, text("n", "c"))
	require.NoError(t, err)

	locked := New(st, a.remote, testutil.FastKDF)
	_, err = locked.Add(ctx, text("n", "c"))
	require.ErrorIs(t, err, ErrLocked)
	_, err = locked.Get(ctx, id)
	require.ErrorIs(t, err, ErrLocked)
	_, err = locked.List(ctx, "")
	require.ErrorIs(t, err, ErrLocked)
	_, err = locked.Sync(ctx)
	require.ErrorIs(t, err, ErrLocked)
	_, err = locked.Tokens(ctx)
	require.ErrorIs(t, err, ErrLocked)
	require.ErrorIs(t, locked.SetTokens(ctx, model.Tokens{}), ErrLocked)
	_, err = locked.AddFile(ctx, "f", "", "/nonexistent")
	require.ErrorIs(t, err, ErrLocked)
}

func TestSignOut(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, _ := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))
	_, err := a.Add(ctx, text("n", "c"))
	require.NoError(t, err)

	require.NoError(t, a.SignOut(ctx))
	_, err = a.Tokens(ctx)
	require.ErrorIs(t, err, ErrNotLoggedIn)
	_, err = a.Sync(ctx)
	require.ErrorIs(t, err, ErrNotLoggedIn)

	// Local data survives logout.
	assert.Equal(t, []string{"n"}, names(t, a))
	require.NoError(t, a.SignIn(ctx, "ilya", master))
	mustSync(t, a)
}

func TestAccountSwitch(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	other, _ := newApp(t, srv)
	require.NoError(t, other.SignUp(ctx, "anna", master))

	a, _ := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))
	_, err := a.Add(ctx, text("unsynced", "c"))
	require.NoError(t, err)

	err = a.SignIn(ctx, "anna", master)
	require.ErrorIs(t, err, ErrUnsyncedChanges)

	mustSync(t, a)
	require.NoError(t, a.SignIn(ctx, "anna", master))
	assert.Empty(t, names(t, a))
	login, err := a.Login(ctx)
	require.NoError(t, err)
	assert.Equal(t, "anna", login)

	// Logging in as the same account keeps local data.
	_, err = a.Add(ctx, text("mine", "c"))
	require.NoError(t, err)
	require.NoError(t, a.SignIn(ctx, "anna", master))
	assert.Equal(t, []string{"mine"}, names(t, a))
}

func TestRecordsCRUD(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, _ := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))

	_, err := a.Add(ctx, model.Payload{Name: "", Data: model.Text{Content: "x"}})
	require.ErrorIs(t, err, model.ErrInvalidArgument)
	_, err = a.Add(ctx, model.Payload{Name: "bin", Data: model.Binary{BlobID: "x"}})
	require.ErrorIs(t, err, model.ErrInvalidArgument)

	cred, err := a.Add(ctx, model.Payload{Name: "GitHub", Meta: "site", Data: model.Credentials{Login: "l", Password: "p"}})
	require.NoError(t, err)
	card, err := a.Add(ctx, model.Payload{Name: "card", Data: model.Card{Number: "4111111111111111", Expiry: "12/30", CVV: "123"}})
	require.NoError(t, err)
	_, err = a.Add(ctx, text("alpha", "t"))
	require.NoError(t, err)

	assert.Equal(t, []string{"alpha", "card", "GitHub"}, names(t, a))
	cards, err := a.List(ctx, model.TypeCard)
	require.NoError(t, err)
	require.Len(t, cards, 1)
	assert.Equal(t, card, cards[0].ID)
	assert.True(t, cards[0].Dirty)

	e, err := a.Get(ctx, cred)
	require.NoError(t, err)
	assert.Equal(t, "site", e.Payload.Meta)
	assert.Equal(t, model.Credentials{Login: "l", Password: "p"}, e.Payload.Data)

	require.NoError(t, a.Edit(ctx, cred, func(p *model.Payload) error {
		p.Name = "GitHub work"
		p.Data = model.Credentials{Login: "l2", Password: "p2"}
		return nil
	}))
	e, err = a.Get(ctx, cred)
	require.NoError(t, err)
	assert.Equal(t, "GitHub work", e.Payload.Name)

	err = a.Edit(ctx, cred, func(p *model.Payload) error {
		p.Data = model.Text{Content: "x"}
		return nil
	})
	require.ErrorIs(t, err, model.ErrInvalidArgument)
	err = a.Edit(ctx, cred, func(p *model.Payload) error {
		p.Name = " "
		return nil
	})
	require.ErrorIs(t, err, model.ErrInvalidArgument)
	stop := assert.AnError
	require.ErrorIs(t, a.Edit(ctx, cred, func(*model.Payload) error { return stop }), stop)
	require.ErrorIs(t, a.Edit(ctx, uuid.New(), func(*model.Payload) error { return nil }), model.ErrNotFound)

	// A record that never reached the server is removed right away.
	require.NoError(t, a.Delete(ctx, card))
	_, err = a.Get(ctx, card)
	require.ErrorIs(t, err, model.ErrNotFound)
	require.ErrorIs(t, a.Delete(ctx, uuid.New()), model.ErrNotFound)

	// A synced record becomes a tombstone until the next sync.
	mustSync(t, a)
	require.NoError(t, a.Delete(ctx, cred))
	_, err = a.Get(ctx, cred)
	require.ErrorIs(t, err, model.ErrNotFound)
	require.ErrorIs(t, a.Delete(ctx, cred), model.ErrNotFound)
	require.ErrorIs(t, a.Edit(ctx, cred, func(*model.Payload) error { return nil }), model.ErrNotFound)
	rep := mustSync(t, a)
	assert.Equal(t, 1, rep.Pushed)
	assert.Equal(t, []string{"alpha"}, names(t, a))
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, st := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))

	id1 := uuid.MustParse("abcd1111-0000-4000-8000-000000000001")
	id2 := uuid.MustParse("abcd2222-0000-4000-8000-000000000002")
	for _, id := range []uuid.UUID{id1, id2} {
		sealed, err := a.seal(id, text("n", "c"))
		require.NoError(t, err)
		require.NoError(t, st.PutRecord(ctx, storage.Record{ID: id, Type: model.TypeText, Payload: sealed}))
	}

	got, err := a.Resolve(ctx, id1.String())
	require.NoError(t, err)
	assert.Equal(t, id1, got)
	got, err = a.Resolve(ctx, "abcd1")
	require.NoError(t, err)
	assert.Equal(t, id1, got)
	_, err = a.Resolve(ctx, "abcd")
	require.ErrorIs(t, err, ErrAmbiguousID)
	_, err = a.Resolve(ctx, "ffff")
	require.ErrorIs(t, err, model.ErrNotFound)
	_, err = a.Resolve(ctx, "ab")
	require.ErrorIs(t, err, model.ErrInvalidArgument)
}

func TestTamperedRecord(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, st := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))
	id, err := a.Add(ctx, text("n", "c"))
	require.NoError(t, err)

	r, err := st.Record(ctx, id)
	require.NoError(t, err)
	// Moving the payload to another record id must break decryption (AAD binding).
	r.ID = uuid.New()
	require.NoError(t, st.PutRecord(ctx, r))
	_, err = a.Get(ctx, r.ID)
	require.ErrorIs(t, err, crypto.ErrDecrypt)
	_, err = a.List(ctx, "")
	require.Error(t, err)
}

func writeRandomFile(t *testing.T, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	_, err := rand.Read(data)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "data.bin")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path, data
}

func TestFiles(t *testing.T) {
	ctx := context.Background()
	a1, a2, srv := pair(t)

	path, data := writeRandomFile(t, crypto.ChunkSize*2+123)
	id, err := a1.AddFile(ctx, "photo", "meta", path)
	require.NoError(t, err)
	e, err := a1.Get(ctx, id)
	require.NoError(t, err)
	bin := e.Payload.Data.(model.Binary)
	assert.Equal(t, "data.bin", bin.FileName)
	assert.Equal(t, int64(len(data)), bin.Size)
	mustSync(t, a1)

	mustSync(t, a2)
	var out bytes.Buffer
	n, err := a2.SaveFile(ctx, id, &out)
	require.NoError(t, err)
	assert.Equal(t, int64(len(data)), n)
	assert.Equal(t, data, out.Bytes())

	// Replace the content: the old blob is collected after the change is synced.
	path2, data2 := writeRandomFile(t, 10)
	require.NoError(t, a2.ReplaceFile(ctx, id, path2))
	mustSync(t, a2)
	mustSync(t, a1)
	out.Reset()
	_, err = a1.SaveFile(ctx, id, &out)
	require.NoError(t, err)
	assert.Equal(t, data2, out.Bytes())
	err = srv.Storage.ReadBlob(ctx, mustUserID(t, srv), uuid.MustParse(bin.BlobID), func([]byte) error { return nil })
	require.ErrorIs(t, err, model.ErrNotFound)

	// Errors.
	_, err = a1.AddFile(ctx, "x", "", filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	tid, err := a1.Add(ctx, text("t", "c"))
	require.NoError(t, err)
	_, err = a1.SaveFile(ctx, tid, &out)
	require.ErrorIs(t, err, model.ErrInvalidArgument)
	require.ErrorIs(t, a1.ReplaceFile(ctx, tid, path2), model.ErrInvalidArgument)
	require.ErrorIs(t, a1.ReplaceFile(ctx, uuid.New(), path2), model.ErrNotFound)

	// Deleting the record removes its blob from the server.
	e, err = a1.Get(ctx, id)
	require.NoError(t, err)
	blob2 := uuid.MustParse(e.Payload.Data.(model.Binary).BlobID)
	require.NoError(t, a1.Delete(ctx, id))
	mustSync(t, a1)
	err = srv.Storage.ReadBlob(ctx, mustUserID(t, srv), blob2, func([]byte) error { return nil })
	require.ErrorIs(t, err, model.ErrNotFound)
}

func mustUserID(t *testing.T, srv *testutil.Server) uuid.UUID {
	t.Helper()
	u, err := srv.Storage.UserByLogin(context.Background(), "ilya")
	require.NoError(t, err)
	return u.ID
}

func TestSyncPropagation(t *testing.T) {
	ctx := context.Background()
	a1, a2, _ := pair(t)

	id, err := a1.Add(ctx, text("note", "v1"))
	require.NoError(t, err)
	rep := mustSync(t, a1)
	assert.Equal(t, 1, rep.Pushed)

	rep = mustSync(t, a2)
	assert.Equal(t, 1, rep.Pulled)
	e, err := a2.Get(ctx, id)
	require.NoError(t, err)
	assert.False(t, e.Dirty)
	assert.Equal(t, int64(1), e.Version)

	require.NoError(t, a2.Edit(ctx, id, func(p *model.Payload) error {
		p.Data = model.Text{Content: "v2"}
		return nil
	}))
	mustSync(t, a2)
	mustSync(t, a1)
	e, err = a1.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, model.Text{Content: "v2"}, e.Payload.Data)
	assert.Equal(t, int64(2), e.Version)

	require.NoError(t, a1.Delete(ctx, id))
	mustSync(t, a1)
	mustSync(t, a2)
	assert.Empty(t, names(t, a2))

	rep = mustSync(t, a2)
	assert.Zero(t, rep.Pulled)
	assert.Zero(t, rep.Pushed)
}

func TestSyncConflictEditEdit(t *testing.T) {
	ctx := context.Background()
	a1, a2, _ := pair(t)
	id, err := a1.Add(ctx, text("note", "base"))
	require.NoError(t, err)
	mustSync(t, a1)
	mustSync(t, a2)

	edit := func(a *App, content string) {
		require.NoError(t, a.Edit(ctx, id, func(p *model.Payload) error {
			p.Data = model.Text{Content: content}
			return nil
		}))
	}
	edit(a1, "from a1")
	edit(a2, "from a2")
	mustSync(t, a1)
	rep := mustSync(t, a2)
	assert.Equal(t, 1, rep.Conflicts)

	// Server version wins, the local edit is kept as a copy.
	e, err := a2.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, model.Text{Content: "from a1"}, e.Payload.Data)
	got := names(t, a2)
	require.Len(t, got, 2)
	assert.True(t, strings.HasPrefix(got[1], "note (conflict "), got[1])

	mustSync(t, a1)
	assert.Equal(t, got, names(t, a1))
}

func TestSyncConflictDeleteVsEdit(t *testing.T) {
	ctx := context.Background()
	a1, a2, _ := pair(t)
	id, err := a1.Add(ctx, text("note", "base"))
	require.NoError(t, err)
	mustSync(t, a1)
	mustSync(t, a2)

	// a1 edits, a2 deletes: the server edit wins and the deletion is dropped.
	require.NoError(t, a1.Edit(ctx, id, func(p *model.Payload) error {
		p.Data = model.Text{Content: "edited"}
		return nil
	}))
	mustSync(t, a1)
	require.NoError(t, a2.Delete(ctx, id))
	rep := mustSync(t, a2)
	assert.Equal(t, 1, rep.Conflicts)
	e, err := a2.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, model.Text{Content: "edited"}, e.Payload.Data)
	assert.Equal(t, []string{"note"}, names(t, a2))
}

func TestSyncConflictEditVsDelete(t *testing.T) {
	ctx := context.Background()
	a1, a2, _ := pair(t)
	id, err := a1.Add(ctx, text("note", "base"))
	require.NoError(t, err)
	mustSync(t, a1)
	mustSync(t, a2)

	// a1 deletes, a2 edits: the record is gone, the edit survives as a copy.
	require.NoError(t, a1.Delete(ctx, id))
	mustSync(t, a1)
	require.NoError(t, a2.Edit(ctx, id, func(p *model.Payload) error {
		p.Data = model.Text{Content: "edited"}
		return nil
	}))
	rep := mustSync(t, a2)
	assert.Equal(t, 1, rep.Conflicts)
	_, err = a2.Get(ctx, id)
	require.ErrorIs(t, err, model.ErrNotFound)
	es, err := a2.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, es, 1)
	assert.Equal(t, model.Text{Content: "edited"}, es[0].Payload.Data)
	assert.False(t, es[0].Dirty)

	mustSync(t, a1)
	assert.Equal(t, names(t, a2), names(t, a1))
}

func TestPullConflictWithDirtyRecord(t *testing.T) {
	ctx := context.Background()
	a1, a2, _ := pair(t)
	id, err := a1.Add(ctx, text("note", "base"))
	require.NoError(t, err)
	mustSync(t, a1)
	mustSync(t, a2)

	require.NoError(t, a1.Edit(ctx, id, func(p *model.Payload) error {
		p.Data = model.Text{Content: "server"}
		return nil
	}))
	mustSync(t, a1)
	require.NoError(t, a2.Edit(ctx, id, func(p *model.Payload) error {
		p.Data = model.Text{Content: "local"}
		return nil
	}))
	// Pull only: the server change meets a dirty local record.
	var rep SyncReport
	require.NoError(t, a2.pull(ctx, &rep))
	assert.Equal(t, 1, rep.Conflicts)
	e, err := a2.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, model.Text{Content: "server"}, e.Payload.Data)
	assert.Len(t, names(t, a2), 2)
}

func TestGetFallsBackToServer(t *testing.T) {
	ctx := context.Background()
	a1, a2, _ := pair(t)
	id, err := a1.Add(ctx, text("remote only", "c"))
	require.NoError(t, err)
	mustSync(t, a1)

	e, err := a2.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "remote only", e.Payload.Name)

	_, err = a2.Get(ctx, uuid.New())
	require.ErrorIs(t, err, model.ErrNotFound)

	require.NoError(t, a1.Delete(ctx, id))
	mustSync(t, a1)
	_, err = a2.Get(ctx, id)
	require.ErrorIs(t, err, model.ErrNotFound)
}

func TestSyncServerError(t *testing.T) {
	ctx := context.Background()
	srv := testutil.StartServer(t)
	a, st := newApp(t, srv)
	require.NoError(t, a.SignUp(ctx, "ilya", master))
	// A record with an invalid type is rejected by the server.
	require.NoError(t, st.PutRecord(ctx, storage.Record{ID: uuid.New(), Type: "bogus", Payload: []byte("x"), Dirty: true}))
	_, err := a.Sync(ctx)
	require.ErrorIs(t, err, model.ErrInvalidArgument)

	require.NoError(t, st.SetMeta(ctx, storage.MetaLastRevision, []byte("nan")))
	require.NoError(t, st.Reset(ctx))
	_, err = a.lastRevision(ctx)
	require.NoError(t, err)
	require.NoError(t, st.SetMeta(ctx, storage.MetaLastRevision, []byte("nan")))
	_, err = a.lastRevision(ctx)
	require.Error(t, err)
}
