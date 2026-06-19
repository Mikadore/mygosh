package client

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/establish"
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

type ConnectArgs struct {
	Target  string
	Command string
}

func RunClient(ctx context.Context, appRoot *root.Root, args ConnectArgs) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if appRoot == nil {
		return eris.New("project root is required")
	}
	if args.Target == "" {
		return eris.New("connect target is required")
	}
	logger := appRoot.Logger.With("command", "client")
	cfg := appRoot.Settings

	target, err := parseConnectTarget(args.Target)
	if err != nil {
		return err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target.dialAddress(cfg.Core.Port))
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return eris.Wrapf(err, "connect to %s", args.Target)
	}
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer conn.Close()
	logger.Info("connected", "addr", conn.RemoteAddr())

	clientIdentity, err := trust.LookupClientIdentityWithLogger(trust.DefaultClientIdentityPath, logger)
	if err != nil {
		return err
	}

	established, err := establish.Connect(ctx, conn, establish.ClientConfig{
		ReferenceIdentity:      target.referenceIdentity(),
		Username:               target.resolvedUsername(),
		ClientIdentityProvider: auth.StaticClientIdentityProvider(auth.NewKeypairSigner(clientIdentity)),
		VerifyServerHostKey:    trust.KnownHostsHostKeyVerifierWithLogger(trust.DefaultKnownHostsPath, logger),
		Logger:                 logger,
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	logger.Info("server identity", "fingerprint", established.Auth.ServerHostKey.FingerprintSHA256())
	logger.Info("authenticated session established", "session_protocol", "terminal-demo")

	command := args.Command
	if strings.TrimSpace(command) == "" {
		command = cfg.Core.Shell
	}
	return NewTerminalDemo(established.Session, command, os.Stdin, os.Stdout, appRoot.Logging).Run(ctx)
}

func localUsername() string {
	user := strings.TrimSpace(os.Getenv("USER"))
	if user == "" {
		return "unknown"
	}
	return user
}
