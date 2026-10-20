package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ilushka-off/GophKeeper/internal/model"
)

type contextLike = context.Context

// recordFlags are the flags shared by add and edit.
type recordFlags struct {
	name, meta             string
	login, password        string
	text, file             string
	number, holder, expiry string
	cvv                    string
}

func (f *recordFlags) registerCommon(fs *pflag.FlagSet) {
	fs.StringVarP(&f.name, "name", "n", "", "record name")
	fs.StringVarP(&f.meta, "meta", "m", "", "free-form metadata: site, bank, notes")
}

func (f *recordFlags) registerCredentials(fs *pflag.FlagSet) {
	fs.StringVar(&f.login, "login", "", "login")
	fs.StringVar(&f.password, "password", "", "password; asked interactively if omitted")
}

func (f *recordFlags) registerText(fs *pflag.FlagSet, fileHelp string) {
	fs.StringVar(&f.text, "text", "", "text content")
	fs.StringVar(&f.file, "file", "", fileHelp)
}

func (f *recordFlags) registerCard(fs *pflag.FlagSet) {
	fs.StringVar(&f.number, "number", "", "card number")
	fs.StringVar(&f.holder, "holder", "", "card holder")
	fs.StringVar(&f.expiry, "expiry", "", "expiry date MM/YY")
	fs.StringVar(&f.cvv, "cvv", "", "CVV/CVC code")
}

func readTextFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read text file: %w", err)
	}
	return string(b), nil
}

func newAddCmd(rt *runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a record: credentials, text, binary or card",
	}
	cmd.AddCommand(
		newAddCredentialsCmd(rt),
		newAddTextCmd(rt),
		newAddBinaryCmd(rt),
		newAddCardCmd(rt),
	)
	return cmd
}

// addRun opens the vault, builds the payload with build and stores it.
func addRun(rt *runtime, build func(ctx context.Context) (string, error)) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		if err := rt.open(ctx, true); err != nil {
			return err
		}
		defer rt.close()
		id, err := build(ctx)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added %s.\n", id)
		rt.syncAfterChange(ctx)
		return nil
	}
}

func newAddCredentialsCmd(rt *runtime) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:     "credentials",
		Aliases: []string{"login", "password"},
		Short:   "Add a login/password pair",
		Args:    cobra.NoArgs,
	}
	cmd.RunE = addRun(rt, func(ctx context.Context) (string, error) {
		if !cmd.Flags().Changed("password") {
			p, err := rt.env.Prompter.Password("Password to store: ")
			if err != nil {
				return "", err
			}
			f.password = p
		}
		id, err := rt.app.Add(ctx, model.Payload{
			Name: f.name, Meta: f.meta,
			Data: model.Credentials{Login: f.login, Password: f.password},
		})
		return id.String(), err
	})
	f.registerCommon(cmd.Flags())
	f.registerCredentials(cmd.Flags())
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newAddTextCmd(rt *runtime) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:   "text",
		Short: "Add arbitrary text",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = addRun(rt, func(ctx context.Context) (string, error) {
		content := f.text
		if f.file != "" {
			var err error
			if content, err = readTextFile(f.file); err != nil {
				return "", err
			}
		}
		id, err := rt.app.Add(ctx, model.Payload{Name: f.name, Meta: f.meta, Data: model.Text{Content: content}})
		return id.String(), err
	})
	f.registerCommon(cmd.Flags())
	f.registerText(cmd.Flags(), "read the text from this file")
	cmd.MarkFlagsMutuallyExclusive("text", "file")
	cmd.MarkFlagsOneRequired("text", "file")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newAddBinaryCmd(rt *runtime) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:     "binary",
		Aliases: []string{"file"},
		Short:   "Add a file (encrypted and uploaded in chunks)",
		Args:    cobra.NoArgs,
	}
	cmd.RunE = addRun(rt, func(ctx context.Context) (string, error) {
		id, err := rt.app.AddFile(ctx, f.name, f.meta, f.file)
		return id.String(), err
	})
	f.registerCommon(cmd.Flags())
	cmd.Flags().StringVar(&f.file, "file", "", "path to the file")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newAddCardCmd(rt *runtime) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:   "card",
		Short: "Add a bank card",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = addRun(rt, func(ctx context.Context) (string, error) {
		id, err := rt.app.Add(ctx, model.Payload{
			Name: f.name, Meta: f.meta,
			Data: model.Card{
				Number: model.NormalizeCardNumber(f.number),
				Holder: f.holder, Expiry: f.expiry, CVV: f.cvv,
			},
		})
		return id.String(), err
	})
	f.registerCommon(cmd.Flags())
	f.registerCard(cmd.Flags())
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("number")
	return cmd
}

func newEditCmd(rt *runtime) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:   "edit <id>",
		Short: "Change fields of a record; only the given flags are changed",
		Args:  cobra.ExactArgs(1),
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		flags := cmd.Flags()
		if flags.NFlag() == 0 {
			return fmt.Errorf("nothing to change: pass at least one flag")
		}
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
		if e.Payload.Type() == model.TypeBinary && flags.Changed("file") {
			if err := rt.app.ReplaceFile(ctx, id, f.file); err != nil {
				return err
			}
		}
		err = rt.app.Edit(ctx, id, func(p *model.Payload) error {
			return applyEdit(flags, &f, p)
		})
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Updated %s.\n", id)
		rt.syncAfterChange(ctx)
		return nil
	}
	f.registerCommon(cmd.Flags())
	f.registerCredentials(cmd.Flags())
	f.registerText(cmd.Flags(), "text: read new text from this file; binary: replace the file")
	f.registerCard(cmd.Flags())
	return cmd
}

// typeFlags lists flags that apply to each record type.
var typeFlags = map[model.RecordType][]string{
	model.TypeCredentials: {"login", "password"},
	model.TypeText:        {"text", "file"},
	model.TypeBinary:      {"file"},
	model.TypeCard:        {"number", "holder", "expiry", "cvv"},
}

func applyEdit(flags *pflag.FlagSet, f *recordFlags, p *model.Payload) error {
	allowed := map[string]bool{"name": true, "meta": true}
	for _, n := range typeFlags[p.Type()] {
		allowed[n] = true
	}
	var bad error
	flags.Visit(func(fl *pflag.Flag) {
		if fl.Name == "server" || fl.Name == "ca-cert" || fl.Name == "data-dir" {
			return
		}
		if !allowed[fl.Name] && bad == nil {
			bad = fmt.Errorf("--%s does not apply to a %s record", fl.Name, p.Type())
		}
	})
	if bad != nil {
		return bad
	}
	if flags.Changed("name") {
		p.Name = f.name
	}
	if flags.Changed("meta") {
		p.Meta = f.meta
	}
	switch d := p.Data.(type) {
	case model.Credentials:
		if flags.Changed("login") {
			d.Login = f.login
		}
		if flags.Changed("password") {
			d.Password = f.password
		}
		p.Data = d
	case model.Text:
		if flags.Changed("text") {
			d.Content = f.text
		}
		if flags.Changed("file") {
			content, err := readTextFile(f.file)
			if err != nil {
				return err
			}
			d.Content = content
		}
		p.Data = d
	case model.Card:
		if flags.Changed("number") {
			d.Number = model.NormalizeCardNumber(f.number)
		}
		if flags.Changed("holder") {
			d.Holder = f.holder
		}
		if flags.Changed("expiry") {
			d.Expiry = f.expiry
		}
		if flags.Changed("cvv") {
			d.CVV = f.cvv
		}
		p.Data = d
	}
	return nil
}
