// Package cli implements the gophkeeper command-line client on cobra.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ilushka-off/GophKeeper/internal/client/app"
	"github.com/ilushka-off/GophKeeper/internal/client/remote"
	"github.com/ilushka-off/GophKeeper/internal/client/storage"
	"github.com/ilushka-off/GophKeeper/internal/crypto"
)

// Environment variables read by the client.
const (
	EnvServer         = "GOPHKEEPER_SERVER"
	EnvCACert         = "GOPHKEEPER_CA_CERT"
	EnvDataDir        = "GOPHKEEPER_DATA_DIR"
	EnvMasterPassword = "GOPHKEEPER_MASTER_PASSWORD"
)

// DefaultServer is the server address used when none is configured.
const DefaultServer = "localhost:3200"

// Options are the connection settings of the client.
type Options struct {
	Server  string
	CACert  string
	DataDir string
}

// Remote is the server client used by commands.
type Remote interface {
	app.Remote
	SetTokenStore(ts remote.TokenStore)
	Close() error
}

// Env holds the dependencies of the CLI so it can be tested without a terminal or network.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// Prompter asks for passwords. Defaults to a terminal prompter on Stdin.
	Prompter Prompter
	// NewRemote creates the server client. Defaults to a TLS gRPC client.
	NewRemote func(o Options) (Remote, error)
	// KDF are the Argon2id parameters for the master password.
	KDF crypto.KDFParams
}

func (e *Env) setDefaults() {
	if e.Stdin == nil {
		e.Stdin = os.Stdin
	}
	if e.Stdout == nil {
		e.Stdout = os.Stdout
	}
	if e.Stderr == nil {
		e.Stderr = os.Stderr
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.Prompter == nil {
		e.Prompter = NewTerminalPrompter(e.Stdin, e.Stderr)
	}
	if e.NewRemote == nil {
		e.NewRemote = dialRemote
	}
	if e.KDF == (crypto.KDFParams{}) {
		e.KDF = crypto.DefaultKDFParams
	}
}

func dialRemote(o Options) (Remote, error) {
	creds, err := remote.TLSCredentials(o.CACert)
	if err != nil {
		return nil, err
	}
	return remote.Dial(o.Server, creds)
}

// runtime is created for every command run.
type runtime struct {
	env    *Env
	opts   Options
	store  *storage.Store
	remote Remote
	app    *app.App
}

func (r *runtime) close() {
	if r.remote != nil {
		_ = r.remote.Close()
	}
	if r.store != nil {
		_ = r.store.Close()
	}
}

// open opens the local vault and creates the server client. With unlock it also asks
// for the master password and unlocks the vault.
func (r *runtime) open(ctx context.Context, unlock bool) error {
	path := filepath.Join(r.opts.DataDir, "vault.db")
	st, err := storage.Open(ctx, path)
	if err != nil {
		return err
	}
	r.store = st
	rc, err := r.env.NewRemote(r.opts)
	if err != nil {
		return err
	}
	r.remote = rc
	r.app = app.New(st, rc, r.env.KDF)
	rc.SetTokenStore(r.app)
	if !unlock {
		return nil
	}
	if _, err := r.app.Login(ctx); err != nil {
		return err
	}
	master, err := r.masterPassword("Master password: ")
	if err != nil {
		return err
	}
	return r.app.Unlock(ctx, master)
}

func (r *runtime) masterPassword(prompt string) (string, error) {
	if v := r.env.Getenv(EnvMasterPassword); v != "" {
		return v, nil
	}
	return r.env.Prompter.Password(prompt)
}

// syncAfterChange synchronizes after a local change. A failure is reported as a warning:
// the change is kept locally and pushed by the next successful sync.
func (r *runtime) syncAfterChange(ctx context.Context) {
	if _, err := r.app.Sync(ctx); err != nil {
		_, _ = fmt.Fprintf(r.env.Stderr, "warning: saved locally, sync failed: %v\n", err)
	}
}

func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ".gophkeeper"
	}
	return filepath.Join(dir, "gophkeeper")
}

// NewRootCommand builds the gophkeeper command tree.
func NewRootCommand(env Env) *cobra.Command {
	env.setDefaults()
	rt := &runtime{env: &env}

	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper is a password manager with end-to-end encryption",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			flags := cmd.Flags()
			pick := func(flag, envKey string, def string) string {
				if flags.Changed(flag) {
					v, _ := flags.GetString(flag)
					return v
				}
				if v := env.Getenv(envKey); v != "" {
					return v
				}
				return def
			}
			rt.opts = Options{
				Server:  pick("server", EnvServer, DefaultServer),
				CACert:  pick("ca-cert", EnvCACert, ""),
				DataDir: pick("data-dir", EnvDataDir, defaultDataDir()),
			}
			return nil
		},
	}
	root.SetIn(env.Stdin)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	pf := root.PersistentFlags()
	pf.String("server", DefaultServer, "server address host:port (env "+EnvServer+")")
	pf.String("ca-cert", "", "CA certificate to verify the server, system roots if empty (env "+EnvCACert+")")
	pf.String("data-dir", defaultDataDir(), "directory of the local vault (env "+EnvDataDir+")")

	root.AddCommand(
		newVersionCmd(),
		newRegisterCmd(rt),
		newLoginCmd(rt),
		newLogoutCmd(rt),
		newAddCmd(rt),
		newEditCmd(rt),
		newDeleteCmd(rt),
		newListCmd(rt),
		newGetCmd(rt),
		newSyncCmd(rt),
		newStatusCmd(rt),
	)
	return root
}

// Execute runs the CLI with args and returns the process exit code.
func Execute(ctx context.Context, env Env, args []string) int {
	cmd := NewRootCommand(env)
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		w := env.Stderr
		if w == nil {
			w = os.Stderr
		}
		_, _ = fmt.Fprintln(w, "error:", userMessage(err))
		return 1
	}
	return 0
}

func userMessage(err error) error {
	switch {
	case errors.Is(err, remote.ErrUnavailable):
		return fmt.Errorf("cannot reach the server: %w", err)
	}
	return err
}
