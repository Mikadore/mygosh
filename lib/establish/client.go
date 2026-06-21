package establish

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/transport"
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
}

type Client struct {
	*session.Session
	Auth auth.ClientResult
}

// Connect is the client-side establishment path. It consumes socket ownership,
// performs transport and auth setup, binds the post-auth mux, activates it,
// and returns the active session plus auth result.
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
	logger := slog.Default().With("component", "establish", "role", "client")
	prepared, err := session.Prepare(cfg.SessionConfig, nil)
	if err != nil {
		return nil, err
	}
	logger.Debug("starting client connection", "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := newRuntime(ctx, conn, "client")

	var secureConn *transport.Transport
	err = runtime.RunWithTimeout(lifecycleHandshaking, handshakeTimeout, func() error {
		var err error
		secureConn, err = transport.HandshakeClient(conn)
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.SetOwner(secureConn)
	runtime.SetPhase(lifecycleAuthPending)
	logger.Debug("client noise transport established", "remote", remoteAddrString(conn))

	var result auth.ClientResult
	err = runtime.RunWithTimeout(lifecycleAuthPending, authTimeout, func() error {
		var err error
		result, err = auth.RunClient(runtime.Context(), secureConn, auth.ClientConfig{
			ReferenceIdentity:      cfg.ReferenceIdentity,
			Username:               cfg.Username,
			ClientIdentityProvider: cfg.ClientIdentityProvider,
			VerifyServerHostKey:    cfg.VerifyServerHostKey,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "authenticate client")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("client authenticated server", "reference_identity", result.ReferenceIdentity, "server_fingerprint", result.ServerHostKey.FingerprintSHA256())

	runtime.SetPhase(lifecyclePostAuthStarting)
	sess, err := prepared.Bind(runtime.Context(), secureConn)
	if err != nil {
		_ = runtime.Fail(err)
		return nil, err
	}
	runtime.SetOwner(sess)
	sess.Activate()
	if cause := context.Cause(runtime.Context()); cause != nil {
		_ = runtime.Fail(cause)
		return nil, cause
	}
	runtime.Release()
	return &Client{Session: sess, Auth: result}, nil
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
