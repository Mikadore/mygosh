package establish

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session"
	"github.com/Mikadore/mygosh/lib/transport"
	"github.com/rotisserie/eris"
)

type ServerConfig struct {
	HostKey          keys.Keypair
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	SessionConfig    session.Config
}

type Server struct{ *session.Session }

type pendingState uint8

const (
	pendingUndecided pendingState = iota
	pendingAccepted
	pendingRejected
	pendingClosed
)

// PendingServer keeps the complete authentication deadline active while app
// policy evaluates the verified client. No post-auth mux is exposed until
// Accept has bound the prepared session, sent wire success, and activated it.
type PendingServer struct {
	mu sync.Mutex

	ctx         context.Context
	cancelAuth  context.CancelFunc
	stopAuth    func() bool
	runtime     *runtime
	secureConn  *transport.Transport
	auth        *auth.PendingServerAuth
	cfg         ServerConfig
	state       pendingState
	server      *Server
	transferred bool
}

func BeginAccept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*PendingServer, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate server connection config")
	}

	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := slog.Default().With("component", "establish", "role", "server")
	logger.Debug("starting server connection", "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := newRuntime(ctx, conn, "server")

	var secureConn *transport.Transport
	err := runtime.RunWithTimeout(lifecycleHandshaking, handshakeTimeout, func() error {
		var err error
		secureConn, err = transport.HandshakeServer(conn)
		return err
	})
	if err != nil {
		wrapped := runtime.WrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.SetOwner(secureConn)
	runtime.SetPhase(lifecycleAuthPending)
	logger.Debug("server noise transport established", "remote", remoteAddrString(conn))

	authCtx, cancelAuth := context.WithTimeout(runtime.Context(), authTimeout)
	stopAuth := context.AfterFunc(authCtx, func() {
		if cause := context.Cause(authCtx); cause != nil {
			_ = runtime.Fail(cause)
		}
	})

	pendingAuth, err := auth.BeginServer(authCtx, secureConn, auth.ServerConfig{
		HostKey: cfg.HostKey,
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

func (p *PendingServer) Accept(prepared *session.Prepared) (*Server, error) {
	if err := p.claim(pendingAccepted); err != nil {
		return nil, err
	}
	if prepared == nil {
		var err error
		prepared, err = session.Prepare(p.cfg.SessionConfig, nil)
		if err != nil {
			_ = p.runtime.Fail(err)
			return nil, err
		}
	}
	if err := context.Cause(p.ctx); err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}

	p.runtime.SetPhase(lifecyclePostAuthStarting)
	sess, err := prepared.Bind(p.runtime.Context(), p.secureConn)
	if err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}
	p.runtime.SetOwner(sess)

	if err := p.completeAuthDeadline(); err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}
	if err := p.auth.Accept(); err != nil {
		_ = p.runtime.Fail(err)
		return nil, err
	}
	sess.Activate()
	if cause := context.Cause(p.runtime.Context()); cause != nil {
		_ = p.runtime.Fail(cause)
		return nil, cause
	}
	p.runtime.Release()
	server := &Server{Session: sess}

	p.mu.Lock()
	p.server = server
	p.transferred = true
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
	if p.transferred {
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
