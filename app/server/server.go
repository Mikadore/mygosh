package server

import (
	"context"
	"net"

	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/establish"
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

var defaultAuthorizedKeysPaths = []string{
	"~/.mygosh/authorized_keys",
	"~/.ssh/authorized_keys",
}

func RunServer(ctx context.Context, appRoot *root.Root) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if appRoot == nil {
		return eris.New("project root is required")
	}
	logger := appRoot.Logger.With("command", "server")
	cfg := appRoot.Settings
	addr := cfg.ListenAddress()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return eris.Wrapf(err, "listen on %s", addr)
	}
	stopClosingListener := context.AfterFunc(ctx, func() {
		_ = listener.Close()
	})
	defer stopClosingListener()
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer listener.Close()
	logger.Info("listening", "addr", listener.Addr(), "shell", cfg.Core.Shell)

	conn, err := listener.Accept()
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return eris.Wrap(err, "accept connection")
	}
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer conn.Close()
	logger.Info("accepted connection", "remote", conn.RemoteAddr())

	serverHostKey, err := trust.LookupHostKeyWithLogger(trust.DefaultHostKeyPath, logger)
	if err != nil {
		return err
	}

	established, err := establish.Accept(ctx, conn, establish.ServerConfig{
		HostKeyProvider:    auth.StaticHostKeyProvider(auth.NewKeypairSigner(serverHostKey)),
		AuthorizeClientKey: trust.AuthorizedKeysClientKeyAuthorizerWithLogger(defaultAuthorizedKeysPaths, logger),
		Logger:             logger,
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	defer established.Close()

	logger.Info(
		"authenticated client",
		"requested_username", established.Auth.ClientIdentity.Username,
		"local_username", established.Auth.ClientKeyAuthorization.Account.Username,
		"uid", established.Auth.ClientKeyAuthorization.Account.UID(),
		"gid", established.Auth.ClientKeyAuthorization.Account.GID(),
		"source", established.Auth.ClientKeyAuthorization.Source,
		"fingerprint", established.Auth.ClientIdentity.PublicKey.FingerprintSHA256(),
	)
	logger.Info("authenticated session established", "session_protocol", "terminal-demo")
	return NewShellDemo(
		established.Session,
		cfg.Core.Shell,
		established.Auth.ClientKeyAuthorization.Account,
		logger,
	).Run(ctx)
}
