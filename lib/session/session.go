package session

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

type Role string

const (
	RoleClient Role = "client"
	RoleServer Role = "server"
)

type ClientConfig struct {
	ReferenceIdentity   string
	Username            string
	ClientIdentity      keys.Keypair
	VerifyServerHostKey auth.HostKeyVerifier
	HandshakeTimeout    time.Duration
	AuthTimeout         time.Duration
	Logger              *charmlog.Logger
}

type ServerConfig struct {
	HostKey          keys.Keypair
	AuthorizeClient  auth.AuthorizeClientFunc
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	Logger           *charmlog.Logger
}

type Metadata struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientIdentity    auth.ClientIdentity
}

type Session struct {
	runtime   *connRuntime
	role      Role
	transport *transport.Transport
	metadata  Metadata
	logger    *charmlog.Logger
}

func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate client session config")
	}
	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting session connect", "role", RoleClient, "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := newConnRuntime(ctx, conn, logger)

	var messageTransport *transport.Transport
	err := runtime.runWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeClientWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.setTarget(messageTransport)
	logger.Debug("noise transport established", "role", RoleClient, "remote", remoteAddrString(conn))

	var result auth.Result
	err = runtime.runWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateClient(messageTransport, messageTransport.ChannelBinding(), auth.ClientConfig{
			ReferenceIdentity:   cfg.ReferenceIdentity,
			Username:            cfg.Username,
			ClientIdentity:      cfg.ClientIdentity,
			VerifyServerHostKey: cfg.VerifyServerHostKey,
			Logger:              logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "authenticate client")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("session connect authenticated", "role", RoleClient, "reference_identity", result.ReferenceIdentity, "server_fingerprint", result.ServerHostKey.FingerprintSHA256())

	return &Session{
		runtime:   runtime,
		role:      RoleClient,
		transport: messageTransport,
		metadata:  metadataFromAuthResult(result),
		logger:    logger,
	}, nil
}

func Accept(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateTimeouts(cfg.HandshakeTimeout, cfg.AuthTimeout); err != nil {
		return nil, eris.Wrap(err, "validate server session config")
	}
	handshakeTimeout := resolveTimeout(cfg.HandshakeTimeout, defaultHandshakeTimeout)
	authTimeout := resolveTimeout(cfg.AuthTimeout, defaultAuthTimeout)
	logger := logging.Resolve(cfg.Logger)
	ctx = logging.IntoContext(ctx, logger)
	logger.Debug("starting session accept", "role", RoleServer, "remote", remoteAddrString(conn), "handshake_timeout", handshakeTimeout, "auth_timeout", authTimeout)

	runtime := newConnRuntime(ctx, conn, logger)

	var messageTransport *transport.Transport
	err := runtime.runWithTimeout("handshake", handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeServerWithLogger(conn, logger)
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.setTarget(messageTransport)
	logger.Debug("noise transport established", "role", RoleServer, "remote", remoteAddrString(conn))

	var result auth.Result
	err = runtime.runWithTimeout("auth", authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateServer(messageTransport, messageTransport.ChannelBinding(), auth.ServerConfig{
			HostKey:         cfg.HostKey,
			AuthorizeClient: cfg.AuthorizeClient,
			Logger:          logger,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "authenticate server")
		_ = runtime.Close()
		return nil, wrapped
	}
	logger.Debug("session accept authenticated", "role", RoleServer, "reference_identity", result.ReferenceIdentity, "username", result.ClientIdentity.Username, "client_fingerprint", result.ClientIdentity.PublicKey.FingerprintSHA256())

	return &Session{
		runtime:   runtime,
		role:      RoleServer,
		transport: messageTransport,
		metadata:  metadataFromAuthResult(result),
		logger:    logger,
	}, nil
}

func EstablishClient(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	return Connect(ctx, conn, cfg)
}

func EstablishServer(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	return Accept(ctx, conn, cfg)
}

func (s *Session) Role() Role {
	return s.role
}

func (s *Session) Metadata() Metadata {
	return cloneMetadata(s.metadata)
}

func (s *Session) Run(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	logger := logging.Resolve(s.logger)
	logger.Debug("session run loop started", "role", s.role, "reference_identity", s.metadata.ReferenceIdentity)

	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-stopCh:
		}
	}()
	defer close(stopCh)

	for {
		var frame sessionpb.Envelope
		if err := transport.ReceiveProto(s.transport, &frame); err != nil {
			if eris.Is(err, io.EOF) {
				logger.Debug("session stream closed", "role", s.role)
				return nil
			}
			if s.runtime != nil {
				return s.runtime.wrapError(err, "receive session frame")
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return eris.Wrap(err, "receive session frame")
		}

		logger.Debug("received unsupported session frame", "role", s.role, "frame_kind", envelopeKind(&frame))
		return eris.Errorf("session protocol not implemented: received %T", frame.Kind)
	}
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.runtime != nil {
		return s.runtime.Close()
	}
	return s.transport.Close()
}

func metadataFromAuthResult(result auth.Result) Metadata {
	return Metadata{
		ReferenceIdentity: result.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(result.ServerHostKey),
		ClientIdentity:    cloneClientIdentity(result.ClientIdentity),
	}
}

func cloneMetadata(meta Metadata) Metadata {
	return Metadata{
		ReferenceIdentity: meta.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(meta.ServerHostKey),
		ClientIdentity:    cloneClientIdentity(meta.ClientIdentity),
	}
}

func cloneClientIdentity(identity auth.ClientIdentity) auth.ClientIdentity {
	return auth.ClientIdentity{
		Username:  identity.Username,
		PublicKey: clonePublicKey(identity.PublicKey),
	}
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     append([]byte(nil), key.Bytes...),
		Comment:   key.Comment,
	}
}

func validateTimeouts(handshakeTimeout time.Duration, authTimeout time.Duration) error {
	if handshakeTimeout < 0 {
		return eris.New("handshake timeout must not be negative")
	}
	if authTimeout < 0 {
		return eris.New("auth timeout must not be negative")
	}
	return nil
}

func remoteAddrString(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func envelopeKind(frame *sessionpb.Envelope) string {
	if frame == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", frame.Kind)
}
