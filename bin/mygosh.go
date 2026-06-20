package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mikadore/mygosh/app/client"
	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/app/server"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/rotisserie/eris"
	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	command, rootRef := newRootCommand(ctx)
	err := command.Execute()
	if appRoot := rootRef(); appRoot != nil {
		err = errors.Join(err, appRoot.Shutdown(context.Background()))
	}
	if err != nil {
		exitCode := 1
		var coder interface{ ExitCode() int }
		if errors.As(err, &coder) {
			exitCode = coder.ExitCode()
		}
		var silent interface{ Silent() bool }
		if !errors.As(err, &silent) || !silent.Silent() {
			fmt.Fprintln(os.Stderr, eris.ToString(err, false))
		}
		os.Exit(exitCode)
	}
}

func newRootCommand(ctx context.Context) (*cobra.Command, func() *root.Root) {
	var verbosity int
	var cfg settings.Settings
	var appRoot *root.Root

	cmdRoot := &cobra.Command{
		Use:           "mygosh",
		Short:         "minimal SSH-like terminal transport experiment",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			loaded, err := settings.Load(verbosity)
			if err != nil {
				return err
			}
			cfg = loaded
			createdRoot, err := root.New(cfg)
			if err != nil {
				return err
			}
			appRoot = createdRoot
			return nil
		},
	}
	cmdRoot.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "increase log verbosity (-v INFO, -vv DEBUG)")

	cmdRoot.AddCommand(&cobra.Command{
		Use:     "server",
		Aliases: []string{"serve"},
		Short:   "run the mygosh server",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.RunServer(ctx, appRoot)
		},
	})

	var forcePTY bool
	var disablePTY bool
	var environment []string
	connectCommand := &cobra.Command{
		Use:   "connect [user@]address[:port] [command [args...]]",
		Short: "connect to a mygosh server",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return client.RunClient(ctx, appRoot, client.ConnectArgs{
				Target:      args[0],
				Command:     append([]string(nil), args[1:]...),
				ForcePTY:    forcePTY,
				DisablePTY:  disablePTY,
				Environment: append([]string(nil), environment...),
			})
		},
	}
	connectCommand.Flags().BoolVarP(&forcePTY, "tty", "t", false, "force pseudo-terminal allocation")
	connectCommand.Flags().BoolVarP(&disablePTY, "no-tty", "T", false, "disable pseudo-terminal allocation")
	connectCommand.Flags().StringArrayVar(&environment, "env", nil, "forward NAME or NAME=value (repeatable)")
	connectCommand.MarkFlagsMutuallyExclusive("tty", "no-tty")
	cmdRoot.AddCommand(connectCommand)

	return cmdRoot, func() *root.Root { return appRoot }
}
