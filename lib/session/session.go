package session

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/session/sessionpb"
	"github.com/Mikadore/mygosh/lib/transport"
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
}

type ServerConfig struct {
	HostKey          keys.Keypair
	AuthorizeClient  auth.AuthorizeClientFunc
	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
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

	runtime := newConnRuntime(ctx, conn)

	var messageTransport *transport.Transport
	err := runtime.runWithTimeout(handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeClient(conn)
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.setTarget(messageTransport)

	var result auth.Result
	err = runtime.runWithTimeout(authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateClient(messageTransport, messageTransport.ChannelBinding(), auth.ClientConfig{
			ReferenceIdentity:   cfg.ReferenceIdentity,
			Username:            cfg.Username,
			ClientIdentity:      cfg.ClientIdentity,
			VerifyServerHostKey: cfg.VerifyServerHostKey,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "authenticate client")
		_ = runtime.Close()
		return nil, wrapped
	}

	return &Session{
		runtime:   runtime,
		role:      RoleClient,
		transport: messageTransport,
		metadata:  metadataFromAuthResult(result),
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

	runtime := newConnRuntime(ctx, conn)

	var messageTransport *transport.Transport
	err := runtime.runWithTimeout(handshakeTimeout, func() error {
		var err error
		messageTransport, err = transport.HandshakeServer(conn)
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "establish noise transport")
		_ = runtime.Close()
		return nil, wrapped
	}
	runtime.setTarget(messageTransport)

	var result auth.Result
	err = runtime.runWithTimeout(authTimeout, func() error {
		var err error
		result, err = auth.AuthenticateServer(messageTransport, messageTransport.ChannelBinding(), auth.ServerConfig{
			HostKey:         cfg.HostKey,
			AuthorizeClient: cfg.AuthorizeClient,
		})
		return err
	})
	if err != nil {
		wrapped := runtime.wrapError(err, "authenticate server")
		_ = runtime.Close()
		return nil, wrapped
	}

	return &Session{
		runtime:   runtime,
		role:      RoleServer,
		transport: messageTransport,
		metadata:  metadataFromAuthResult(result),
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
