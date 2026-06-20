package server

import (
	"context"
	"errors"
	"net"

	"github.com/Mikadore/mygosh/app/root"
	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	servercommand "github.com/Mikadore/mygosh/app/server/command"
	serverprocess "github.com/Mikadore/mygosh/app/server/process"
	serverservices "github.com/Mikadore/mygosh/app/server/services"
	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/Mikadore/mygosh/lib/establish"
	"github.com/Mikadore/mygosh/lib/session"
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
		PermissionPolicy: serverauthz.PermissionPolicyFunc(func(
			context.Context,
			serverauthz.ConnectionRequest,
			usermodel.Account,
			string,
		) (serverauthz.PermissionDecision, error) {
			return serverauthz.PermissionDecision{
				AllowCommand: true,
				AllowShell:   true,
				AllowExec:    true,
				AllowPTY:     true,
				AllowedEnvironment: []string{
					"TERM",
					"COLORTERM",
					"LANG",
					"LC_ALL",
					"LC_CTYPE",
				},
			}, nil
		}),
		Logger: logger,
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
	logger.Info("listening", "addr", listener.Addr())

	conn, err := listener.Accept()
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return eris.Wrap(err, "accept connection")
	}
	logger.Info("accepted connection", "remote", conn.RemoteAddr())

	pending, err := establish.BeginAccept(ctx, conn, establish.ServerConfig{
		HostKey: serverHostKey,
		Logger:  logger,
	})
	if err != nil {
		return eris.Wrap(err, "establish session")
	}
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

	commandService, err := servercommand.NewService(authorization, serverprocess.Runner{}, logger)
	if err != nil {
		_ = pending.Reject()
		return eris.Wrap(err, "configure command service")
	}
	registry, err := serverservices.NewRegistry(credentials, authorization, commandService)
	if err != nil {
		_ = pending.Reject()
		return eris.Wrap(err, "configure connection services")
	}
	prepared, err := session.Prepare(session.Config{}, registry, session.Options{Logger: logger})
	if err != nil {
		_ = pending.Reject()
		return eris.Wrap(err, "prepare post-auth session")
	}

	established, err := pending.Accept(prepared)
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
	logger.Info("authenticated session established", "post_auth_mode", "command")
	return established.Wait()
}
