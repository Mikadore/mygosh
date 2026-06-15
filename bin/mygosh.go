package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
		fmt.Fprintln(os.Stderr, eris.ToString(err, false))
		os.Exit(1)
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
			appRoot = root.New(cfg)
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

	cmdRoot.AddCommand(&cobra.Command{
		Use:   "connect [address] [command]",
		Short: "connect to a mygosh server",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			connectArgs := client.ConnectArgs{Address: args[0]}
			if len(args) > 1 {
				connectArgs.Command = strings.Join(args[1:], " ")
			}
			return client.RunClient(ctx, appRoot, connectArgs)
		},
	})

	return cmdRoot, func() *root.Root { return appRoot }
}
