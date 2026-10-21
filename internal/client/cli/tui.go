package cli

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/ilushka-off/GophKeeper/internal/client/tui"
)

func newTUICmd(rt *runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal interface",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if err := rt.open(ctx, true); err != nil {
				return err
			}
			defer rt.close()
			p := tea.NewProgram(tui.New(ctx, rt.app),
				tea.WithAltScreen(),
				tea.WithContext(ctx),
				tea.WithInput(cmd.InOrStdin()),
				tea.WithOutput(cmd.OutOrStdout()),
			)
			_, err := p.Run()
			return err
		},
	}
}
