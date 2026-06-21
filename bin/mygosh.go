package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mikadore/mygosh/app/client"
	"github.com/Mikadore/mygosh/app/config"
	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/app/server"
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
	var appRoot *root.Root

	cmdRoot := &cobra.Command{
		Use:           "mygosh",
		Short:         "minimal SSH-like terminal transport experiment",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmdRoot.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "increase log verbosity (-v INFO, -vv DEBUG)")

	var serverConfigPath string
	serverCommand := &cobra.Command{
		Use:     "server",
		Aliases: []string{"serve"},
		Short:   "run the mygosh server",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadServer(serverConfigPath, verbosity)
			if err != nil {
				return err
			}
			appRoot, err = root.New(cfg.Log)
			if err != nil {
				return err
			}
			return server.RunServer(ctx, appRoot, cfg)
		},
	}
	serverCommand.Flags().StringVar(&serverConfigPath, "config", config.DefaultServerFile, "server configuration file")
	cmdRoot.AddCommand(serverCommand)

	var forcePTY bool
	var disablePTY bool
	var environment []string
	var clientConfigPath string
	connectCommand := &cobra.Command{
		Use:   "connect [user@]address[:port] [command [args...]]",
		Short: "connect to a mygosh server",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadClient(clientConfigPath, verbosity)
			if err != nil {
				return err
			}
			appRoot, err = root.New(cfg.Log)
			if err != nil {
				return err
			}
			return client.RunClient(ctx, appRoot, cfg, client.ConnectArgs{
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
	connectCommand.Flags().StringVar(&clientConfigPath, "config", config.DefaultClientFile, "client configuration file")
	connectCommand.MarkFlagsMutuallyExclusive("tty", "no-tty")
	cmdRoot.AddCommand(connectCommand)

	return cmdRoot, func() *root.Root { return appRoot }
}
