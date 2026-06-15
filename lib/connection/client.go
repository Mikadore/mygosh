package connection

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

type ClientConfig struct {
	ReferenceIdentity      string
	Username               string
	ClientIdentityProvider auth.ClientIdentityProvider
	VerifyServerHostKey    auth.HostKeyVerifier
	HandshakeTimeout       time.Duration
	AuthTimeout            time.Duration
	SessionConfig          session.Config
	Logger                 *charmlog.Logger
}

type Client struct {
	*session.Session
	Auth auth.ClientResult
}

// Connect is the client-side composition point: TCP ownership stays in app
// code, auth stays role-specific, and the returned Session is role agnostic.
func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Client, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate client connection config")
	}
	if err := cfg.SessionConfig.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate client session mux config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting client connection", "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := session.NewRuntime(ctx, conn, logger)

	var secureConn *transport.Transport
	err := runtime.RunWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		secureConn, err = transport.HandshakeClientWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.SetTarget(secureConn)
	logger.Debug("client noise transport established", "remote", remoteAddrString(conn))

	var result auth.ClientResult
	err = runtime.RunWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.RunClient(runtime.Context(), secureConn, auth.ClientConfig{
			ReferenceIdentity:      cfg.ReferenceIdentity,
			Username:               cfg.Username,
			ClientIdentityProvider: cfg.ClientIdentityProvider,
			VerifyServerHostKey:    cfg.VerifyServerHostKey,
			Logger:                 logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "authenticate client")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("client authenticated server", "reference_identity", result.ReferenceIdentity, "server_fingerprint", result.ServerHostKey.FingerprintSHA256())

	sess, err := session.New(secureConn, cfg.SessionConfig, session.Options{
		Runtime: runtime,
		Logger:  logger,
	})
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	return &Client{Session: sess, Auth: result}, nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
