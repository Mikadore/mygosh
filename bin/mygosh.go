package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/app/client"
	"github.com/Mikadore/mygosh/app/server"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/settings"
	"github.com/rotisserie/eris"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, eris.ToString(err, false))
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var verbosity int
	var cfg settings.Settings

	root := &cobra.Command{
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
			logging.Configure(cfg.Log)
			return nil
		},
	}
	root.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "increase log verbosity (-v INFO, -vv DEBUG)")

	root.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "run the mygosh server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.RunServer(cfg)
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "connect [address] [command]",
		Short: "connect to a mygosh server",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			connectArgs := client.ConnectArgs{Address: args[0]}
			if len(args) > 1 {
				connectArgs.Command = strings.Join(args[1:], " ")
			}
			return client.RunClient(cfg, connectArgs)
		},
	})

	return root
}
