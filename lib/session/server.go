package session

import (
	"context"
	"net"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/transport"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

type ServerConfig struct {
	HostSigner       auth.Signer
	AuthorizeClient  auth.ClientAuthorizer
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	Config           Config
	Logger           *charmlog.Logger
}

func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate server session config")
	}
	if err := cfg.Config.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate server session mux config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting server session accept", "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := NewRuntime(ctx, conn, logger)

	var messageTransport *transport.Transport
	err := runtime.RunWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeServerWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.SetTarget(messageTransport)
	logger.Debug("server noise transport established", "remote", remoteAddrString(conn))

	var result auth.Result
	err = runtime.RunWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateServer(runtime.Context(), messageTransport, messageTransport.ChannelBinding(), auth.ServerConfig{
			HostSigner:      cfg.HostSigner,
			AuthorizeClient: cfg.AuthorizeClient,
			Logger:          logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "authenticate server")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("server session authenticated", "reference_identity", result.ReferenceIdentity, "username", result.ClientIdentity.Username, "client_fingerprint", result.ClientIdentity.PublicKey.FingerprintSHA256())

	return New(messageTransport, metadataFromAuthResult(result), cfg.Config, Options{
		Runtime: runtime,
		Logger:  logger,
	})
}

func EstablishServer(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	return Accept(ctx, conn, cfg)
}
