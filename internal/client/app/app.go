// Package app implements the client use cases on top of the local storage and the
// server API: registration and login, unlocking the vault with the master password,
// managing records of all types, binary data transfer and synchronization.
//
// All data is encrypted here before it reaches the local database or the network.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ilushka-off/GophKeeper/internal/client/storage"
	"github.com/ilushka-off/GophKeeper/internal/crypto"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

// Errors returned by the client.
var (
	// ErrLocked means the vault is not unlocked with the master password yet.
	ErrLocked = errors.New("vault is locked")
	// ErrWrongMasterPassword means the master password does not match the local vault.
	ErrWrongMasterPassword = errors.New("wrong master password")
	// ErrNoAccount means there is no account on this device: run register or login.
	ErrNoAccount = errors.New("no account on this device: run register or login")
	// ErrUnsyncedChanges means switching accounts would lose local changes.
	ErrUnsyncedChanges = errors.New("local vault has unsynced changes of another account")
	// ErrAmbiguousID means an id prefix matches several records.
	ErrAmbiguousID = errors.New("id prefix matches several records")
	// ErrNotLoggedIn means there are no session tokens on this device.
	ErrNotLoggedIn = errors.New("not logged in: run login")
)

const keyCheckPlaintext = "gophkeeper key check v1"

// Remote is the server API used by the client.
type Remote interface {
	GetSalt(ctx context.Context, login string) ([]byte, error)
	Register(ctx context.Context, login, password string, salt []byte) (model.Tokens, error)
	Login(ctx context.Context, login, password string) (model.Tokens, []byte, error)
	Logout(ctx context.Context, refreshToken string) error
	GetRecord(ctx context.Context, id uuid.UUID) (model.Record, error)
	Pull(ctx context.Context, since int64) ([]model.Record, int64, error)
	Push(ctx context.Context, changes []model.Change) (model.PushResult, error)
	UploadBlob(ctx context.Context, blobID uuid.UUID, produce func(send func([]byte) error) error) (int64, error)
	DownloadBlob(ctx context.Context, blobID uuid.UUID, fn func([]byte) error) error
	DeleteBlob(ctx context.Context, blobID uuid.UUID) error
}

// App is the client application.
type App struct {
	store  *storage.Store
	remote Remote
	kdf    crypto.KDFParams
	cipher *crypto.Cipher
	now    func() time.Time
}

// New creates the application. kdf sets the cost of deriving keys from the master password.
func New(store *storage.Store, remote Remote, kdf crypto.KDFParams) *App {
	return &App{store: store, remote: remote, kdf: kdf, now: time.Now}
}

// SetRemote replaces the server API client.
func (a *App) SetRemote(r Remote) {
	a.remote = r
}

// Login returns the login of the account stored on this device, or ErrNoAccount.
func (a *App) Login(ctx context.Context) (string, error) {
	v, err := a.store.Meta(ctx, storage.MetaLogin)
	if errors.Is(err, model.ErrNotFound) {
		return "", ErrNoAccount
	}
	if err != nil {
		return "", err
	}
	return string(v), nil
}

// Unlock derives the encryption key from the master password and checks it against the local vault.
func (a *App) Unlock(ctx context.Context, master string) error {
	salt, err := a.store.Meta(ctx, storage.MetaKDFSalt)
	if errors.Is(err, model.ErrNotFound) {
		return ErrNoAccount
	}
	if err != nil {
		return err
	}
	keys, err := crypto.DeriveKeys(master, salt, a.kdf)
	if err != nil {
		return err
	}
	c, err := crypto.NewCipher(keys.Enc)
	if err != nil {
		return err
	}
	check, err := a.store.Meta(ctx, storage.MetaKeyCheck)
	if err != nil {
		return fmt.Errorf("read key check: %w", err)
	}
	if _, err := c.Open(check, []byte(storage.MetaKeyCheck)); err != nil {
		return ErrWrongMasterPassword
	}
	a.cipher = c
	return nil
}

// Unlocked reports whether the vault is unlocked.
func (a *App) Unlocked() bool {
	return a.cipher != nil
}

// SignUp creates an account on the server and initializes the local vault for it.
func (a *App) SignUp(ctx context.Context, login, master string) error {
	if err := a.prepareAccount(ctx, login); err != nil {
		return err
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	keys, err := crypto.DeriveKeys(master, salt, a.kdf)
	if err != nil {
		return err
	}
	tokens, err := a.remote.Register(ctx, login, keys.AuthPassword(), salt)
	if err != nil {
		return err
	}
	return a.saveSession(ctx, login, salt, keys, tokens)
}

// SignIn logs in to an existing account and initializes the local vault for it.
// Records are fetched by the next Sync.
func (a *App) SignIn(ctx context.Context, login, master string) error {
	if err := a.prepareAccount(ctx, login); err != nil {
		return err
	}
	salt, err := a.remote.GetSalt(ctx, login)
	if err != nil {
		return err
	}
	keys, err := crypto.DeriveKeys(master, salt, a.kdf)
	if err != nil {
		return err
	}
	tokens, serverSalt, err := a.remote.Login(ctx, login, keys.AuthPassword())
	if err != nil {
		return err
	}
	if len(serverSalt) > 0 && string(serverSalt) != string(salt) {
		return errors.New("server returned a different KDF salt")
	}
	return a.saveSession(ctx, login, salt, keys, tokens)
}

// prepareAccount wipes the local vault if it belongs to another account.
func (a *App) prepareAccount(ctx context.Context, login string) error {
	current, err := a.Login(ctx)
	if errors.Is(err, ErrNoAccount) || current == login {
		return nil
	}
	if err != nil {
		return err
	}
	dirty, err := a.store.DirtyRecords(ctx)
	if err != nil {
		return err
	}
	if len(dirty) > 0 {
		return fmt.Errorf("%w (%s): log in as %s and sync first", ErrUnsyncedChanges, current, current)
	}
	return a.store.Reset(ctx)
}

func (a *App) saveSession(ctx context.Context, login string, salt []byte, keys crypto.Keys, t model.Tokens) error {
	c, err := crypto.NewCipher(keys.Enc)
	if err != nil {
		return err
	}
	check, err := c.Seal([]byte(keyCheckPlaintext), []byte(storage.MetaKeyCheck))
	if err != nil {
		return err
	}
	if err := a.store.SetMeta(ctx, storage.MetaLogin, []byte(login)); err != nil {
		return err
	}
	if err := a.store.SetMeta(ctx, storage.MetaKDFSalt, salt); err != nil {
		return err
	}
	if err := a.store.SetMeta(ctx, storage.MetaKeyCheck, check); err != nil {
		return err
	}
	a.cipher = c
	return a.SetTokens(ctx, t)
}

// Tokens returns the decrypted session tokens. It implements remote.TokenStore.
func (a *App) Tokens(ctx context.Context) (model.Tokens, error) {
	if a.cipher == nil {
		return model.Tokens{}, ErrLocked
	}
	sealed, err := a.store.Meta(ctx, storage.MetaTokens)
	if errors.Is(err, model.ErrNotFound) {
		return model.Tokens{}, ErrNotLoggedIn
	}
	if err != nil {
		return model.Tokens{}, err
	}
	plain, err := a.cipher.Open(sealed, []byte(storage.MetaTokens))
	if err != nil {
		return model.Tokens{}, fmt.Errorf("decrypt tokens: %w", err)
	}
	var t model.Tokens
	if err := json.Unmarshal(plain, &t); err != nil {
		return model.Tokens{}, fmt.Errorf("decode tokens: %w", err)
	}
	return t, nil
}

// SetTokens encrypts and stores the session tokens. It implements remote.TokenStore.
func (a *App) SetTokens(ctx context.Context, t model.Tokens) error {
	if a.cipher == nil {
		return ErrLocked
	}
	plain, err := json.Marshal(t)
	if err != nil {
		return err
	}
	sealed, err := a.cipher.Seal(plain, []byte(storage.MetaTokens))
	if err != nil {
		return err
	}
	return a.store.SetMeta(ctx, storage.MetaTokens, sealed)
}

// SignOut revokes the refresh token on the server (best effort) and forgets the tokens.
// Local encrypted records are kept, so a later login does not need a full download.
func (a *App) SignOut(ctx context.Context) error {
	if a.cipher != nil {
		if t, err := a.Tokens(ctx); err == nil && t.RefreshToken != "" {
			_ = a.remote.Logout(ctx, t.RefreshToken)
		}
	}
	return a.store.DeleteMeta(ctx, storage.MetaTokens)
}

func (a *App) lastRevision(ctx context.Context) (int64, error) {
	v, err := a.store.Meta(ctx, storage.MetaLastRevision)
	if errors.Is(err, model.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(string(v), 10, 64)
}

func (a *App) setLastRevision(ctx context.Context, rev int64) error {
	return a.store.SetMeta(ctx, storage.MetaLastRevision, []byte(strconv.FormatInt(rev, 10)))
}
