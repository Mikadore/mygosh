package establish

import (
	"context"
	"net"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/transport"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

type ServerConfig struct {
	HostKeyProvider    auth.HostKeyProvider
	AuthorizeClientKey auth.ClientKeyAuthorizer
	HandshakeTimeout   time.Duration
	AuthTimeout        time.Duration
	SessionConfig      session.Config
	Logger             *charmlog.Logger
}

type Server struct {
	*session.Session
	Auth auth.ServerResult
}

// Accept is the server-side establishment path. It intentionally keeps local
// trust and key providers outside the generic session multiplexer.
func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Server, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate server connection config")
	}
	if err := cfg.SessionConfig.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate server session mux config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting server connection", "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := session.NewRuntime(ctx, conn, logger)

	var secureConn *transport.Transport
	err := runtime.RunWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		secureConn, err = transport.HandshakeServerWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.SetTarget(secureConn)
	logger.Debug("server noise transport established", "remote", remoteAddrString(conn))

	var result auth.ServerResult
	err = runtime.RunWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.RunServer(runtime.Context(), secureConn, auth.ServerConfig{
			HostKeyProvider:    cfg.HostKeyProvider,
			AuthorizeClientKey: cfg.AuthorizeClientKey,
			Logger:             logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "authenticate server")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("server authenticated client", "reference_identity", result.ReferenceIdentity, "username", result.ClientIdentity.Username, "client_fingerprint", result.ClientIdentity.PublicKey.FingerprintSHA256())

	sess, err := session.New(secureConn, cfg.SessionConfig, session.Options{
		Runtime: runtime,
		Logger:  logger,
	})
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	return &Server{Session: sess, Auth: result}, nil
}
