package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"

	"github.com/Mikadore/mygosh/lib/auth"
	"github.com/Mikadore/mygosh/lib/auth/authpb"
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

type HostKeyVerifier func(referenceIdentity string, hostKey keys.PublicKey) error

type AuthorizeClientFunc func(principal ClientPrincipal) error

type ClientConfig struct {
	ReferenceIdentity   string
	Username            string
	Service             string
	ClientIdentity      keys.Keypair
	VerifyServerHostKey HostKeyVerifier
}

func (c ClientConfig) Validate() error {
	if c.ReferenceIdentity == "" {
		return eris.New("reference identity is required")
	}
	if c.Username == "" {
		return eris.New("username is required")
	}
	if c.Service == "" {
		return eris.New("service is required")
	}
	if !(&c.ClientIdentity).IsSigning() {
		return eris.New("client identity must be an ed25519 signing key")
	}
	if c.VerifyServerHostKey == nil {
		return eris.New("server host key verifier is required")
	}
	return nil
}

type ServerConfig struct {
	HostKey         keys.Keypair
	AuthorizeClient AuthorizeClientFunc
}

func (c ServerConfig) Validate() error {
	if !(&c.HostKey).IsSigning() {
		return eris.New("server host key must be an ed25519 signing key")
	}
	if c.AuthorizeClient == nil {
		return eris.New("client authorizer is required")
	}
	return nil
}

type ClientPrincipal struct {
	Username  string
	Service   string
	PublicKey keys.PublicKey
}

type Metadata struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientPrincipal   ClientPrincipal
}

type Session struct {
	role      Role
	transport *transport.Transport
	metadata  Metadata
}

func (s *Session) Role() Role {
	return s.role
}

func (s *Session) Transport() *transport.Transport {
	return s.transport
}

func (s *Session) Metadata() Metadata {
	return cloneMetadata(s.metadata)
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	return s.transport.Close()
}

func EstablishClient(ctx context.Context, conn net.Conn, cfg ClientConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate client session config")
	}

	stopWatchingContext := watchContextCancellation(ctx, conn)
	defer stopWatchingContext()

	stream, err := transport.HandshakeClient(conn)
	if err != nil {
		return nil, preferContextError(ctx, eris.Wrap(err, "establish noise transport"))
	}

	machine := newAuthMachine(RoleClient, transport.NewTransport(stream), stream.ChannelBinding())
	session, err := machine.establishClient(cfg)
	if err != nil {
		return nil, preferContextError(ctx, err)
	}
	return session, nil
}

func EstablishServer(ctx context.Context, conn net.Conn, cfg ServerConfig) (*Session, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, eris.Wrap(err, "validate server session config")
	}

	stopWatchingContext := watchContextCancellation(ctx, conn)
	defer stopWatchingContext()

	stream, err := transport.HandshakeServer(conn)
	if err != nil {
		return nil, preferContextError(ctx, eris.Wrap(err, "establish noise transport"))
	}

	machine := newAuthMachine(RoleServer, transport.NewTransport(stream), stream.ChannelBinding())
	session, err := machine.establishServer(cfg)
	if err != nil {
		return nil, preferContextError(ctx, err)
	}
	return session, nil
}

type authState string

const (
	authStateNoiseEstablished authState = "noise-established"
	authStateHostAuthInitSent authState = "host-auth-init-sent"
	authStateHostAuthInitRecv authState = "host-auth-init-received"
	authStateServerAuthSent   authState = "server-auth-sent"
	authStateServerAuthRecv   authState = "server-auth-received"
	authStateClientAuthSent   authState = "client-auth-sent"
	authStateClientAuthRecv   authState = "client-auth-received"
	authStateAuthenticated    authState = "authenticated"
)

type authMachine struct {
	role           Role
	state          authState
	transport      *transport.Transport
	channelBinding []byte
}

func newAuthMachine(role Role, messageTransport *transport.Transport, channelBinding []byte) *authMachine {
	return &authMachine{
		role:           role,
		state:          authStateNoiseEstablished,
		transport:      messageTransport,
		channelBinding: append([]byte(nil), channelBinding...),
	}
}

func (m *authMachine) advance(expected authState, next authState) error {
	if m.state != expected {
		return eris.Errorf("%s auth state %q cannot transition to %q", m.role, m.state, next)
	}
	m.state = next
	return nil
}

func (m *authMachine) establishClient(cfg ClientConfig) (*Session, error) {
	clientNonce, err := randomBytes(auth.NonceSize)
	if err != nil {
		return nil, eris.Wrap(err, "generate client nonce")
	}

	hostAuthInit := &authpb.HostAuthInit{
		MygoshAuthVersion: auth.ProtocolVersion,
		ClientNonce:       clientNonce,
		ReferenceIdentity: cfg.ReferenceIdentity,
	}
	hostAuthInitHash, err := auth.HashHostAuthInit(hostAuthInit)
	if err != nil {
		return nil, eris.Wrap(err, "hash host auth init")
	}

	if err := m.transport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_HostAuthInit{
			HostAuthInit: hostAuthInit,
		},
	}); err != nil {
		return nil, eris.Wrap(err, "send host auth init")
	}
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitSent); err != nil {
		return nil, err
	}

	serverAuth, err := receiveServerAuth(m.transport)
	if err != nil {
		return nil, err
	}
	if err := m.advance(authStateHostAuthInitSent, authStateServerAuthRecv); err != nil {
		return nil, err
	}

	serverHostKey, err := keys.ParsePublicKey(serverAuth.GetServerHostKey())
	if err != nil {
		return nil, eris.Wrap(err, "parse server host key")
	}
	if !(&serverHostKey).IsSigning() {
		return nil, eris.New("server host key must be an ed25519 signing key")
	}

	serverAuthPayload, err := auth.ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    serverAuth.GetServerHostKey(),
		ServerNonce:      serverAuth.GetServerNonce(),
	}.MarshalBinary()
	if err != nil {
		return nil, eris.Wrap(err, "encode server auth payload")
	}
	if !(&serverHostKey).Verify(serverAuthPayload, serverAuth.GetSignature()) {
		return nil, eris.New("server auth signature verification failed")
	}
	if err := cfg.VerifyServerHostKey(cfg.ReferenceIdentity, serverHostKey); err != nil {
		return nil, eris.Wrap(err, "verify server host key")
	}

	serverAuthHash, err := auth.HashServerAuthMessage(serverAuth)
	if err != nil {
		return nil, eris.Wrap(err, "hash server auth")
	}

	clientPublicKeyBlob, err := cfg.ClientIdentity.PublicKey().MarshalBinary()
	if err != nil {
		return nil, eris.Wrap(err, "encode client public key")
	}

	clientAuthPayload, err := auth.ClientAuthToSign{
		ChannelBinding:        m.channelBinding,
		HostAuthInitHash:      hostAuthInitHash,
		ServerAuthHash:        serverAuthHash,
		Username:              cfg.Username,
		Service:               cfg.Service,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(cfg.ClientIdentity.Algorithm),
	}.MarshalBinary()
	if err != nil {
		return nil, eris.Wrap(err, "encode client auth payload")
	}

	clientAuthRequest := &authpb.ClientAuthRequest{
		Username:              cfg.Username,
		Service:               cfg.Service,
		ClientPublicKeyOrCert: clientPublicKeyBlob,
		ClientSigAlg:          string(cfg.ClientIdentity.Algorithm),
		Signature:             (&cfg.ClientIdentity).Sign(clientAuthPayload),
	}

	if err := m.transport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ClientAuthRequest{
			ClientAuthRequest: clientAuthRequest,
		},
	}); err != nil {
		return nil, eris.Wrap(err, "send client auth request")
	}
	if err := m.advance(authStateServerAuthRecv, authStateClientAuthSent); err != nil {
		return nil, err
	}
	if err := m.advance(authStateClientAuthSent, authStateAuthenticated); err != nil {
		return nil, err
	}

	return &Session{
		role:      RoleClient,
		transport: m.transport,
		metadata: Metadata{
			ReferenceIdentity: cfg.ReferenceIdentity,
			ServerHostKey:     clonePublicKey(serverHostKey),
		},
	}, nil
}

func (m *authMachine) establishServer(cfg ServerConfig) (*Session, error) {
	hostAuthInit, err := receiveHostAuthInit(m.transport)
	if err != nil {
		return nil, err
	}
	if err := m.advance(authStateNoiseEstablished, authStateHostAuthInitRecv); err != nil {
		return nil, err
	}
	if hostAuthInit.GetMygoshAuthVersion() != auth.ProtocolVersion {
		err := eris.Errorf("unsupported auth version %q", hostAuthInit.GetMygoshAuthVersion())
		sendWireError(m.transport, "unsupported-auth-version", err.Error())
		return nil, err
	}

	hostAuthInitHash, err := auth.HashHostAuthInit(hostAuthInit)
	if err != nil {
		return nil, eris.Wrap(err, "hash host auth init")
	}

	hostPublicKey := cfg.HostKey.PublicKey()
	hostPublicKeyBlob, err := hostPublicKey.MarshalBinary()
	if err != nil {
		return nil, eris.Wrap(err, "encode server host key")
	}

	serverNonce, err := randomBytes(auth.NonceSize)
	if err != nil {
		return nil, eris.Wrap(err, "generate server nonce")
	}

	serverAuthPayload, err := auth.ServerAuthToSign{
		ChannelBinding:   m.channelBinding,
		HostAuthInitHash: hostAuthInitHash,
		ServerHostKey:    hostPublicKeyBlob,
		ServerNonce:      serverNonce,
	}.MarshalBinary()
	if err != nil {
		return nil, eris.Wrap(err, "encode server auth payload")
	}

	serverAuthMsg := &authpb.ServerAuth{
		ServerHostKey: hostPublicKeyBlob,
		ServerNonce:   serverNonce,
		Signature:     (&cfg.HostKey).Sign(serverAuthPayload),
	}
	if err := m.transport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_ServerAuth{
			ServerAuth: serverAuthMsg,
		},
	}); err != nil {
		return nil, eris.Wrap(err, "send server auth")
	}
	if err := m.advance(authStateHostAuthInitRecv, authStateServerAuthSent); err != nil {
		return nil, err
	}

	serverAuthHash, err := auth.HashServerAuthMessage(serverAuthMsg)
	if err != nil {
		return nil, eris.Wrap(err, "hash server auth")
	}

	clientAuthRequest, err := receiveClientAuthRequest(m.transport)
	if err != nil {
		return nil, err
	}
	if err := m.advance(authStateServerAuthSent, authStateClientAuthRecv); err != nil {
		return nil, err
	}

	clientPublicKey, err := keys.ParsePublicKey(clientAuthRequest.GetClientPublicKeyOrCert())
	if err != nil {
		sendWireError(m.transport, "invalid-client-key", "invalid client public key")
		return nil, eris.Wrap(err, "parse client public key")
	}
	if !(&clientPublicKey).IsSigning() {
		err := eris.New("client public key must be an ed25519 signing key")
		sendWireError(m.transport, "invalid-client-key", err.Error())
		return nil, err
	}
	if clientAuthRequest.GetClientSigAlg() != string(clientPublicKey.Algorithm) {
		err := eris.Errorf("client signature algorithm %q does not match key algorithm %q", clientAuthRequest.GetClientSigAlg(), clientPublicKey.Algorithm)
		sendWireError(m.transport, "invalid-client-sig-alg", err.Error())
		return nil, err
	}

	clientAuthPayload, err := auth.ClientAuthToSign{
		ChannelBinding:        m.channelBinding,
		HostAuthInitHash:      hostAuthInitHash,
		ServerAuthHash:        serverAuthHash,
		Username:              clientAuthRequest.GetUsername(),
		Service:               clientAuthRequest.GetService(),
		ClientPublicKeyOrCert: clientAuthRequest.GetClientPublicKeyOrCert(),
		ClientSigAlg:          clientAuthRequest.GetClientSigAlg(),
	}.MarshalBinary()
	if err != nil {
		sendWireError(m.transport, "invalid-client-auth", "failed to encode client auth payload")
		return nil, eris.Wrap(err, "encode client auth payload")
	}
	if !(&clientPublicKey).Verify(clientAuthPayload, clientAuthRequest.GetSignature()) {
		err := eris.New("client auth signature verification failed")
		sendWireError(m.transport, "invalid-client-signature", err.Error())
		return nil, err
	}

	principal := ClientPrincipal{
		Username:  clientAuthRequest.GetUsername(),
		Service:   clientAuthRequest.GetService(),
		PublicKey: clonePublicKey(clientPublicKey),
	}
	if err := cfg.AuthorizeClient(principal); err != nil {
		sendWireError(m.transport, "unauthorized-client", err.Error())
		return nil, eris.Wrap(err, "authorize client")
	}

	if err := m.advance(authStateClientAuthRecv, authStateAuthenticated); err != nil {
		return nil, err
	}

	return &Session{
		role:      RoleServer,
		transport: m.transport,
		metadata: Metadata{
			ReferenceIdentity: hostAuthInit.GetReferenceIdentity(),
			ServerHostKey:     clonePublicKey(hostPublicKey),
			ClientPrincipal:   principal,
		},
	}, nil
}

func receiveHostAuthInit(messageTransport *transport.Transport) (*authpb.HostAuthInit, error) {
	envelope, err := messageTransport.Receive()
	if err != nil {
		return nil, eris.Wrap(err, "receive host auth init")
	}

	switch kind := envelope.Kind.(type) {
	case *sessionpb.Envelope_HostAuthInit:
		return kind.HostAuthInit, nil
	case *sessionpb.Envelope_Err:
		return nil, eris.Errorf("peer rejected auth: %s", kind.Err.GetMessage())
	default:
		return nil, eris.Errorf("expected host auth init, got %T", kind)
	}
}

func receiveServerAuth(messageTransport *transport.Transport) (*authpb.ServerAuth, error) {
	envelope, err := messageTransport.Receive()
	if err != nil {
		return nil, eris.Wrap(err, "receive server auth")
	}

	switch kind := envelope.Kind.(type) {
	case *sessionpb.Envelope_ServerAuth:
		return kind.ServerAuth, nil
	case *sessionpb.Envelope_Err:
		return nil, eris.Errorf("server rejected auth: %s", kind.Err.GetMessage())
	default:
		return nil, eris.Errorf("expected server auth, got %T", kind)
	}
}

func receiveClientAuthRequest(messageTransport *transport.Transport) (*authpb.ClientAuthRequest, error) {
	envelope, err := messageTransport.Receive()
	if err != nil {
		return nil, eris.Wrap(err, "receive client auth request")
	}

	switch kind := envelope.Kind.(type) {
	case *sessionpb.Envelope_ClientAuthRequest:
		return kind.ClientAuthRequest, nil
	case *sessionpb.Envelope_Err:
		return nil, eris.Errorf("peer rejected auth: %s", kind.Err.GetMessage())
	default:
		return nil, eris.Errorf("expected client auth request, got %T", kind)
	}
}

func sendWireError(messageTransport *transport.Transport, code string, message string) {
	_ = messageTransport.Send(&sessionpb.Envelope{
		Kind: &sessionpb.Envelope_Err{
			Err: &sessionpb.Error{
				Code:    code,
				Message: message,
			},
		},
	})
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     append([]byte(nil), key.Bytes...),
	}
}

func cloneMetadata(meta Metadata) Metadata {
	return Metadata{
		ReferenceIdentity: meta.ReferenceIdentity,
		ServerHostKey:     clonePublicKey(meta.ServerHostKey),
		ClientPrincipal: ClientPrincipal{
			Username:  meta.ClientPrincipal.Username,
			Service:   meta.ClientPrincipal.Service,
			PublicKey: clonePublicKey(meta.ClientPrincipal.PublicKey),
		},
	}
}

func ExactHostKeyVerifier(referenceIdentity string, expected keys.PublicKey) HostKeyVerifier {
	expected = clonePublicKey(expected)
	return func(actualReferenceIdentity string, actualHostKey keys.PublicKey) error {
		if actualReferenceIdentity != referenceIdentity {
			return eris.Errorf("reference identity %q does not match expected %q", actualReferenceIdentity, referenceIdentity)
		}
		if actualHostKey.Algorithm != expected.Algorithm || !bytes.Equal(actualHostKey.Bytes, expected.Bytes) {
			return eris.Errorf("unexpected host key fingerprint %s", actualHostKey.FingerprintSHA256())
		}
		return nil
	}
}
