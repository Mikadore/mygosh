package server

import (
	"context"
	"errors"
	"net"

	"github.com/Mikadore/mygosh/app/root"
	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/establish"
	usermodel "github.com/Mikadore/mygosh/lib/user"
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

	serverHostKey, err := loadHostKey(defaultHostKeyPath, logger)
	if err != nil {
		return err
	}
	authorization, err := serverauthz.New(serverauthz.Config{
		Resolver:            usermodel.OSResolver{},
		AuthorizedKeysPaths: defaultAuthorizedKeysPaths,
		Logger:              logger,
	})
	if err != nil {
		return eris.Wrap(err, "configure server authorization")
	}

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
	connectionOwned := true
	defer func() {
		if connectionOwned {
			_ = conn.Close()
		}
	}()
	logger.Info("accepted connection", "remote", conn.RemoteAddr())

	pending, err := establish.BeginAccept(ctx, conn, establish.ServerConfig{
		HostKeyProvider: auth.StaticHostKeyProvider(serverHostKey),
		Logger:          logger,
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
	connectionOwned = false
	defer pending.Close()

	credentials, err := authorization.AuthorizeConnection(pending.Context(), serverauthz.ConnectionRequest{
		VerifiedClient: pending.VerifiedClient(),
		PeerAddress:    conn.RemoteAddr().String(),
	})
	if err != nil {
		logger.Error("connection authorization failed", "err", err)
		rejectErr := pending.Reject()
		return errors.Join(eris.Wrap(err, "authorize connection"), rejectErr)
	}

	established, err := pending.Accept()
	if err != nil {
		return eris.Wrap(err, "accept authenticated connection")
	}

	account := credentials.Account()
	logger.Info(
		"authenticated client",
		"requested_username", credentials.RequestedUsername(),
		"local_username", account.Username,
		"uid", account.UID(),
		"gid", account.GID(),
		"source", credentials.MatchedSource(),
		"fingerprint", credentials.KeyFingerprint(),
	)
	logger.Info("authenticated session established", "session_protocol", "terminal-demo")
	return NewShellDemo(
		established.Session,
		cfg.Core.Shell,
		credentials,
		authorization,
		logger,
	).Run(ctx)
}
