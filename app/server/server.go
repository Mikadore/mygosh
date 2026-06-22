package server

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/Mikadore/mygosh/app/config"
	"github.com/Mikadore/mygosh/app/root"
	serverauthz "github.com/Mikadore/mygosh/app/server/authz"
	servercommand "github.com/Mikadore/mygosh/app/server/command"
	serverprocess "github.com/Mikadore/mygosh/app/server/process"
	serverservices "github.com/Mikadore/mygosh/app/server/services"
	usermodel "github.com/Mikadore/mygosh/lib/account"
	"github.com/Mikadore/mygosh/lib/establish"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/rotisserie/eris"
)

func RunServer(ctx context.Context, appRoot *root.Root, cfg config.Server) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if appRoot == nil {
		return eris.New("project root is required")
	}
	if err := cfg.Validate(); err != nil {
		return eris.Wrap(err, "validate server config")
	}
	logger := appRoot.Audit.With("command", "server")
	addr := cfg.Listen.Address

	serverHostKey, err := loadHostKey(cfg.Identity.HostKey)
	if err != nil {
		return err
	}
	authorization, err := serverauthz.New(serverauthz.Config{
		Resolver:            usermodel.OSResolver{},
		AuthorizedKeysPaths: cfg.Authorization.AuthorizedKeys,
		PermissionPolicy: serverauthz.PermissionPolicyFunc(func(
			context.Context,
			serverauthz.ConnectionRequest,
			usermodel.Account,
			string,
		) (serverauthz.PermissionDecision, error) {
			permissions := cfg.Authorization.Permissions
			return serverauthz.PermissionDecision{
				AllowCommand:       permissions.AllowShell || permissions.AllowExec,
				AllowShell:         permissions.AllowShell,
				AllowExec:          permissions.AllowExec,
				AllowPTY:           permissions.AllowPTY,
				ForcedCommand:      permissions.ForcedCommand,
				AllowedEnvironment: append([]string(nil), permissions.AllowedEnvironment...),
			}, nil
		}),
		AuditLogger: logger,
	})
	if err != nil {
		return eris.Wrap(err, "configure server authorization")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return eris.Wrapf(err, "listen on %s", addr)
	}
	logger.Info("listening", "addr", listener.Addr())

	commandService, err := servercommand.NewService(authorization, serverprocess.Runner{})
	if err != nil {
		return eris.Wrap(err, "configure command service")
	}

	return runDaemon(ctx, listener, cfg.Daemon, logger, func(connectionCtx context.Context, conn net.Conn, connectionID string) error {
		return serveConnection(connectionCtx, conn, connectionID, serverHostKey, authorization, commandService, logger)
	})
}

func serveConnection(
	ctx context.Context,
	conn net.Conn,
	connectionID string,
	hostKey keys.Keypair,
	authorization *serverauthz.Authz,
	commandService *servercommand.Service,
	logger *slog.Logger,
) error {
	connectionLogger := logger.With(
		"connection_id", connectionID,
		"remote", conn.RemoteAddr(),
	)

	pending, err := establish.BeginAccept(ctx, conn, establish.ServerConfig{
		HostKey: hostKey,
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
		connectionLogger.Error("connection authorization failed", "err", err)
		rejectErr := pending.Reject()
		return errors.Join(eris.Wrap(err, "authorize connection"), rejectErr)
	}

	registry, err := serverservices.NewRegistry(credentials, authorization, commandService)
	if err != nil {
		_ = pending.Reject()
		return eris.Wrap(err, "configure connection services")
	}
	prepared, err := session.Prepare(session.Config{}, registry)
	if err != nil {
		_ = pending.Reject()
		return eris.Wrap(err, "prepare post-auth session")
	}

	established, err := pending.Accept(prepared)
	if err != nil {
		return eris.Wrap(err, "accept authenticated connection")
	}
	defer established.Close() //nolint:errcheck

	account := credentials.Account()
	connectionLogger.Info(
		"authenticated client",
		"requested_username", credentials.RequestedUsername(),
		"local_username", account.Username,
		"uid", account.UID(),
		"gid", account.GID(),
		"source", credentials.MatchedSource(),
		"fingerprint", credentials.KeyFingerprint(),
	)
	connectionLogger.Info("authenticated session established", "post_auth_mode", "command")
	return established.Wait()
}
