package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/ilushka-off/GophKeeper/internal/buildinfo"
	"github.com/ilushka-off/GophKeeper/internal/client/app"
	"github.com/ilushka-off/GophKeeper/internal/model"
)

// MinMasterPasswordLen is the minimal length of a new master password.
const MinMasterPasswordLen = 8

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, build date and commit",
		Args:  cobra.NoArgs,
		PersistentPreRun: func(*cobra.Command, []string) {
			// version needs no configuration
		},
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
		},
	}
}

func newRegisterCmd(rt *runtime) *cobra.Command {
	var login string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create an account on the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, false); err != nil {
				return err
			}
			defer rt.close()
			master, err := rt.masterPassword("New master password: ")
			if err != nil {
				return err
			}
			if utf8.RuneCountInString(master) < MinMasterPasswordLen {
				return fmt.Errorf("master password must be at least %d characters", MinMasterPasswordLen)
			}
			if rt.env.Getenv(EnvMasterPassword) == "" {
				again, err := rt.env.Prompter.Password("Repeat master password: ")
				if err != nil {
					return err
				}
				if again != master {
					return errors.New("passwords do not match")
				}
			}
			if err := rt.app.SignUp(ctx, login, master); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Registered as %s.\n", login)
			_, _ = fmt.Fprintln(cmd.OutOrStdout(),
				"Keep the master password safe: it encrypts your data and cannot be recovered.")
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "account login")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func newLoginCmd(rt *runtime) *cobra.Command {
	var login string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to an existing account and download its data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, false); err != nil {
				return err
			}
			defer rt.close()
			master, err := rt.masterPassword("Master password: ")
			if err != nil {
				return err
			}
			if err := rt.app.SignIn(ctx, login, master); err != nil {
				return err
			}
			rep, err := rt.app.Sync(ctx)
			if err != nil {
				return fmt.Errorf("logged in, but sync failed: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Logged in as %s. Synced %d change(s).\n", login, rep.Pulled)
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "account login")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func newLogoutCmd(rt *runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "End the session on this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, true); err != nil {
				return err
			}
			defer rt.close()
			if err := rt.app.SignOut(ctx); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
			return nil
		},
	}
}

func newSyncCmd(rt *runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Synchronize the local vault with the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, true); err != nil {
				return err
			}
			defer rt.close()
			rep, err := rt.app.Sync(ctx)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Synced: pushed %d, pulled %d, conflicts %d, revision %d.\n",
				rep.Pushed, rep.Pulled, rep.Conflicts, rep.Revision)
			return nil
		},
	}
}

func newStatusCmd(rt *runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the account and unsynced changes on this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, false); err != nil {
				return err
			}
			defer rt.close()
			login, err := rt.app.Login(ctx)
			if err != nil {
				return err
			}
			dirty, err := rt.store.DirtyRecords(ctx)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Login:   %s\nServer:  %s\nVault:   %s\nPending: %d change(s)\n",
				login, rt.opts.Server, rt.opts.DataDir, len(dirty))
			return nil
		},
	}
}

func newListCmd(rt *runtime) *cobra.Command {
	var typ string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			filter := model.RecordType(typ)
			if typ != "" && !filter.Valid() {
				return fmt.Errorf("unknown type %q", typ)
			}
			ctx := cmd.Context()
			if err := rt.open(ctx, true); err != nil {
				return err
			}
			defer rt.close()
			entries, err := rt.app.List(ctx, filter)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(entries) == 0 {
				_, _ = fmt.Fprintln(out, "No records.")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ID\tTYPE\tNAME\tMETA\tSYNCED")
			for _, e := range entries {
				synced := "yes"
				if e.Dirty {
					synced = "no"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					e.ID.String()[:8], e.Payload.Type(), e.Payload.Name, shorten(e.Payload.Meta, 40), synced)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&typ, "type", "t", "", "show only records of this type: credentials, text, binary, card, otp")
	return cmd
}

func shorten(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func newGetCmd(rt *runtime) *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Show a record; for binary data save the file with --out",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, true); err != nil {
				return err
			}
			defer rt.close()
			id, err := rt.app.Resolve(ctx, args[0])
			if err != nil {
				return err
			}
			e, err := rt.app.Get(ctx, id)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			printEntry(out, e)
			if outPath == "" {
				if e.Payload.Type() == model.TypeBinary {
					_, _ = fmt.Fprintln(out, "Use --out <path> to save the file.")
				}
				return nil
			}
			if e.Payload.Type() != model.TypeBinary {
				return errors.New("--out is only supported for binary records")
			}
			return saveToFile(ctx, rt.app, e, outPath, out)
		},
	}
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "write binary data to this file")
	return cmd
}

func saveToFile(ctx context.Context, a *app.App, e app.Entry, path string, out io.Writer) error {
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	n, err := a.SaveFile(ctx, e.ID, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("save file: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Saved %d bytes to %s\n", n, path)
	return nil
}

func printEntry(w io.Writer, e app.Entry) {
	tw := tabwriter.NewWriter(w, 0, 4, 1, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			_, _ = fmt.Fprintf(tw, "%s:\t%s\n", k, v)
		}
	}
	row("ID", e.ID.String())
	row("Type", string(e.Payload.Type()))
	row("Name", e.Payload.Name)
	switch d := e.Payload.Data.(type) {
	case model.Credentials:
		row("Login", d.Login)
		row("Password", d.Password)
	case model.Text:
		row("Text", d.Content)
	case model.Binary:
		row("File", d.FileName)
		row("Size", fmt.Sprintf("%d bytes", d.Size))
	case model.Card:
		row("Number", d.Number)
		row("Holder", d.Holder)
		row("Expiry", d.Expiry)
		row("CVV", d.CVV)
	case model.OTP:
		row("Issuer", d.Issuer)
		row("Account", d.Account)
		if code, left, err := d.Code(time.Now()); err == nil {
			row("Code", fmt.Sprintf("%s (valid %ds)", code, int(left.Seconds())))
		}
	}
	row("Meta", e.Payload.Meta)
	row("Updated", e.UpdatedAt.Local().Format("2006-01-02 15:04:05"))
	if e.Dirty {
		row("Synced", "no")
	}
	_ = tw.Flush()
}

func newDeleteCmd(rt *runtime) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"rm"},
		Short:   "Delete a record",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, true); err != nil {
				return err
			}
			defer rt.close()
			id, err := rt.app.Resolve(ctx, args[0])
			if err != nil {
				return err
			}
			if err := rt.app.Delete(ctx, id); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s.\n", id)
			rt.syncAfterChange(ctx)
			return nil
		},
	}
}
