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

type ClientConfig struct {
	ReferenceIdentity   string
	Username            string
	ClientSigner        auth.Signer
	VerifyServerHostKey auth.HostKeyVerifier
	HandshakeTimeout    time.Duration
	AuthTimeout         time.Duration
	Config              Config
	Logger              *charmlog.Logger
}

func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate client session config")
	}
	if err := cfg.Config.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate client session mux config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting client session connect", "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := NewRuntime(ctx, conn, logger)

	var messageTransport *transport.Transport
	err := runtime.RunWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeClientWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.SetTarget(messageTransport)
	logger.Debug("client noise transport established", "remote", remoteAddrString(conn))

	var result auth.Result
	err = runtime.RunWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateClient(runtime.Context(), messageTransport, messageTransport.ChannelBinding(), auth.ClientConfig{
			ReferenceIdentity:   cfg.ReferenceIdentity,
			Username:            cfg.Username,
			ClientSigner:        cfg.ClientSigner,
			VerifyServerHostKey: cfg.VerifyServerHostKey,
			Logger:              logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "authenticate client")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("client session authenticated", "reference_identity", result.ReferenceIdentity, "server_fingerprint", result.ServerHostKey.FingerprintSHA256())

	return New(messageTransport, metadataFromAuthResult(result), cfg.Config, Options{
		Runtime: runtime,
		Logger:  logger,
	})
}

func EstablishClient(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	return Connect(ctx, conn, cfg)
}
