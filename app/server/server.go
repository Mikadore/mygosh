package server

import (
	"context"
	"net"

	"github.com/Mikadore/mygosh/app/root"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/connection"
	"github.com/Mikadore/mygosh/lib/trust"
	"github.com/rotisserie/eris"
)

var defaultAuthorizedKeysPaths = []string{
	"~/.mygosh/authorized_keys",
	"~/.ssh/authorized_keys",
}

func RunServer(ctx context.Context, appRoot *root.Root) error {
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
	//TODO: implement comprehensive connection lifecycle
	// and integrate connection closing/termination with
	// logging and application error handling
	//nolint:errcheck
	defer listener.Close()
	logger.Info("listening", "addr", listener.Addr(), "shell", cfg.Core.Shell)

	conn, err := listener.Accept()
	if err != nil {
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

	established, err := connection.Accept(ctx, conn, connection.ServerConfig{
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
		"uid", established.Auth.ClientKeyAuthorization.Account.UID,
		"gid", established.Auth.ClientKeyAuthorization.Account.GID,
		"source", established.Auth.ClientKeyAuthorization.Source,
		"fingerprint", established.Auth.ClientIdentity.PublicKey.FingerprintSHA256(),
	)
	logger.Info("authenticated session established", "session_protocol", "disabled")
	return nil
}
