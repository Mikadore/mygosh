package establish

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

type ServerConfig struct {
	HostKeyProvider  auth.HostKeyProvider
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	SessionConfig    session.Config
	Logger           *slog.Logger
}

type Server struct {
	*session.Session
	VerifiedClient auth.VerifiedClient
}

type pendingState uint8

const (
	pendingUndecided pendingState = iota
	pendingAccepted
	pendingRejected
	pendingClosed
)

// PendingServer keeps the complete authentication deadline active while app
// policy evaluates the verified client. No post-auth mux is exposed until
// Accept has sent the wire success response.
type PendingServer struct {
	mu sync.Mutex

	ctx        context.Context
	cancelAuth context.CancelFunc
	stopAuth   func() bool
	runtime    *session.Runtime
	secureConn *transport.Transport
	auth       *auth.PendingServerAuth
	cfg        ServerConfig
	logger     *slog.Logger
	state      pendingState
	server     *Server
}

func BeginAccept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*PendingServer, error) {
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

	authCtx, cancelAuth := context.WithTimeout(runtime.Context(), authTimeout)
	stopAuth := context.AfterFunc(authCtx, func() {
		if cause := context.Cause(authCtx); cause != nil {
			_ = runtime.Fail(cause)
		}
	})

	pendingAuth, err := auth.BeginServer(authCtx, secureConn, auth.ServerConfig{
		HostKeyProvider: cfg.HostKeyProvider,
		Logger:          logger,
	})
	if err != nil {
		stopAuth()
		cancelAuth()
		wrapped := runtime.WrapError(err, "verify client authentication")
		_ = runtime.Close()
		return nil, wrapped
	}

	verified := pendingAuth.VerifiedClient()
	logger.Debug(
		"server verified client proof",
		"reference_identity", verified.HostIdentity(),
		"username", verified.RequestedUsername(),
		"client_fingerprint", verified.ProvenKey().FingerprintSHA256(),
	)

	return &PendingServer{
		ctx:        authCtx,
		cancelAuth: cancelAuth,
		stopAuth:   stopAuth,
		runtime:    runtime,
		secureConn: secureConn,
		auth:       pendingAuth,
		cfg:        cfg,
		logger:     logger,
	}, nil
}

func (p *PendingServer) Context() context.Context {
	if p == nil || p.ctx == nil {
		return context.Background()
	}
	return p.ctx
}

func (p *PendingServer) VerifiedClient() auth.VerifiedClient {
	if p == nil || p.auth == nil {
		return auth.VerifiedClient{}
	}
	return p.auth.VerifiedClient()
}

func (p *PendingServer) Accept() (*Server, error) {
	if err := p.claim(pendingAccepted); err != nil {
		return nil, err
	}
	if err := context.Cause(p.ctx); err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}
	if err := p.auth.Accept(); err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}
	if err := p.completeAuthDeadline(); err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}

	sess, err := session.New(p.secureConn, p.cfg.SessionConfig, session.Options{
		Runtime: p.runtime,
		Logger:  p.logger,
	})
	if err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}
	server := &Server{
		Session:        sess,
		VerifiedClient: p.auth.VerifiedClient(),
	}

	p.mu.Lock()
	p.server = server
	p.mu.Unlock()
	return server, nil
}

func (p *PendingServer) Reject() error {
	if err := p.claim(pendingRejected); err != nil {
		return err
	}
	err := p.auth.Reject()
	deadlineErr := p.completeAuthDeadline()
	closeErr := p.runtime.Close()
	return errors.Join(err, deadlineErr, closeErr)
}

func (p *PendingServer) Close() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	if p.state == pendingClosed {
		p.mu.Unlock()
		return nil
	}
	if p.state == pendingUndecided {
		p.state = pendingClosed
	}
	server := p.server
	p.mu.Unlock()

	_ = p.completeAuthDeadline()
	if server != nil {
		return server.Close()
	}
	return p.runtime.Close()
}

func (p *PendingServer) claim(next pendingState) error {
	if p == nil {
		return eris.New("pending server establishment is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != pendingUndecided {
		return auth.ErrDecisionMade
	}
	p.state = next
	return nil
}

func (p *PendingServer) completeAuthDeadline() error {
	if p == nil {
		return nil
	}
	if p.stopAuth != nil {
		p.stopAuth()
	}
	cause := context.Cause(p.ctx)
	if p.cancelAuth != nil {
		p.cancelAuth()
	}
	return cause
}
