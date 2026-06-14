package session

import (
	"context"
	"io"
	"net"

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
}

type ServerConfig struct {
	HostKey         keys.Keypair
	AuthorizeClient auth.AuthorizeClientFunc
}

type Metadata struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientIdentity    auth.ClientIdentity
}

type Session struct {
	role      Role
	transport *transport.Transport
	metadata  Metadata
}

func Connect(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	stopWatchingContext := watchContextCancellation(ctx, conn)
	defer stopWatchingContext()

	stream, err := transport.HandshakeClient(conn)
	if err != nil {
		return nil, preferContextError(ctx, eris.Wrap(err, "establish noise transport"))
	}

	messageTransport := transport.NewTransport(stream)
	result, err := auth.AuthenticateClient(messageTransport, stream.ChannelBinding(), auth.ClientConfig{
		ReferenceIdentity:   cfg.ReferenceIdentity,
		Username:            cfg.Username,
		ClientIdentity:      cfg.ClientIdentity,
		VerifyServerHostKey: cfg.VerifyServerHostKey,
	})
	if err != nil {
		return nil, preferContextError(ctx, eris.Wrap(err, "authenticate client"))
	}

	return &Session{
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

	stopWatchingContext := watchContextCancellation(ctx, conn)
	defer stopWatchingContext()

	stream, err := transport.HandshakeServer(conn)
	if err != nil {
		return nil, preferContextError(ctx, eris.Wrap(err, "establish noise transport"))
	}

	messageTransport := transport.NewTransport(stream)
	result, err := auth.AuthenticateServer(messageTransport, stream.ChannelBinding(), auth.ServerConfig{
		HostKey:         cfg.HostKey,
		AuthorizeClient: cfg.AuthorizeClient,
	})
	if err != nil {
		return nil, preferContextError(ctx, eris.Wrap(err, "authenticate server"))
	}

	return &Session{
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

	stopWatchingContext := watchContextCancellation(ctx, s.transport)
	defer stopWatchingContext()

	for {
		var frame sessionpb.Envelope
		if err := s.transport.Receive(&frame); err != nil {
			if eris.Is(err, io.EOF) {
				return nil
			}
			return preferContextError(ctx, eris.Wrap(err, "receive session frame"))
		}

		return eris.Errorf("session protocol not implemented: received %T", frame.Kind)
	}
}

func (s *Session) Close() error {
	if s == nil {
		return nil
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
