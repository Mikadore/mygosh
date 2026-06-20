package auth

import (
	"bytes"
	"context"
	"log/slog"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/wire"
	"github.com/rotisserie/eris"
)

type ClientIdentityRequest struct {
	ReferenceIdentity string
	Username          string
	ServerHostKey     keys.PublicKey
}

// ClientIdentityProvider selects the client identity after the peer host key is
// known.
type ClientIdentityProvider interface {
	ClientIdentity(ctx context.Context, req ClientIdentityRequest) (keys.Keypair, error)
}

type ClientIdentityProviderFunc func(ctx context.Context, req ClientIdentityRequest) (keys.Keypair, error)

func (f ClientIdentityProviderFunc) ClientIdentity(ctx context.Context, req ClientIdentityRequest) (keys.Keypair, error) {
	if f == nil {
		return keys.Keypair{}, eris.New("client identity provider is required")
	}
	return f(ctx, req)
}

func StaticClientIdentityProvider(keypair keys.Keypair) ClientIdentityProvider {
	return ClientIdentityProviderFunc(func(_ context.Context, _ ClientIdentityRequest) (keys.Keypair, error) {
		if err := keypair.Validate(); err != nil {
			return keys.Keypair{}, eris.Wrap(err, "client identity key")
		}
		return cloneKeypair(keypair), nil
	})
}

type HostKeyVerificationRequest struct {
	ReferenceIdentity string
	HostKey           keys.PublicKey
}

// HostKeyVerifier is called by the client during auth because the protocol must
// stop before client signing if the presented server key is not trusted.
type HostKeyVerifier interface {
	VerifyHostKey(ctx context.Context, req HostKeyVerificationRequest) error
}

type HostKeyVerifierFunc func(ctx context.Context, req HostKeyVerificationRequest) error

func (f HostKeyVerifierFunc) VerifyHostKey(ctx context.Context, req HostKeyVerificationRequest) error {
	if f == nil {
		return eris.New("host key verifier is required")
	}
	return f(ctx, req)
}

type ClientConfig struct {
	ReferenceIdentity      string
	Username               string
	ClientIdentityProvider ClientIdentityProvider
	VerifyServerHostKey    HostKeyVerifier
	Logger                 *slog.Logger
}

func (c ClientConfig) Validate() error {
	if c.ReferenceIdentity == "" {
		return eris.New("reference identity is required")
	}
	if c.Username == "" {
		return eris.New("username is required")
	}
	if c.ClientIdentityProvider == nil {
		return eris.New("client identity provider is required")
	}
	if c.VerifyServerHostKey == nil {
		return eris.New("server host key verifier is required")
	}
	return nil
}

type ServerConfig struct {
	HostKey keys.Keypair
	Logger  *slog.Logger
}

// BoundFramer is the framed auth channel plus the Noise channel binding used
// by signed authentication transcripts.
type BoundFramer interface {
	wire.Framer
	ChannelBinding() []byte
}

func (c ServerConfig) Validate() error {
	if err := c.HostKey.Validate(); err != nil {
		return eris.Wrap(err, "server host key")
	}
	return nil
}

type ClientIdentity struct {
	Username  string
	PublicKey keys.PublicKey
}

type ClientResult struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientIdentity    ClientIdentity
}

// VerifiedClient is the immutable result of successful client cryptographic
// proof. Local account and service authorization deliberately happen outside
// this package before the pending decision is accepted.
type VerifiedClient struct {
	hostIdentity      string
	requestedUsername string
	provenKey         keys.PublicKey
	serverKey         keys.PublicKey
}

func NewVerifiedClient(hostIdentity string, requestedUsername string, provenKey keys.PublicKey, serverKey keys.PublicKey) (VerifiedClient, error) {
	if hostIdentity == "" {
		return VerifiedClient{}, eris.New("host identity is required")
	}
	if requestedUsername == "" {
		return VerifiedClient{}, eris.New("requested username is required")
	}
	if err := provenKey.Validate(); err != nil {
		return VerifiedClient{}, eris.Wrap(err, "proved client key")
	}
	if err := serverKey.Validate(); err != nil {
		return VerifiedClient{}, eris.Wrap(err, "server key")
	}
	return VerifiedClient{
		hostIdentity:      hostIdentity,
		requestedUsername: requestedUsername,
		provenKey:         clonePublicKey(provenKey),
		serverKey:         clonePublicKey(serverKey),
	}, nil
}

func (v VerifiedClient) HostIdentity() string {
	return v.hostIdentity
}

func (v VerifiedClient) RequestedUsername() string {
	return v.requestedUsername
}

func (v VerifiedClient) ProvenKey() keys.PublicKey {
	return clonePublicKey(v.provenKey)
}

func (v VerifiedClient) ServerKey() keys.PublicKey {
	return clonePublicKey(v.serverKey)
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
	role           string
	state          authState
	conn           BoundFramer
	channelBinding []byte
	logger         *slog.Logger
}

func newAuthMachine(role string, conn BoundFramer, logger *slog.Logger) *authMachine {
	return &authMachine{
		role:           role,
		state:          authStateNoiseEstablished,
		conn:           conn,
		channelBinding: cloneBytes(conn.ChannelBinding()),
		logger:         logging.Resolve(logger),
	}
}

func (m *authMachine) debug(message string, keyvals ...any) {
	fields := append([]any{"role", m.role, "state", m.state}, keyvals...)
	m.logger.Debug(message, fields...)
}

func (m *authMachine) info(message string, keyvals ...any) {
	fields := append([]any{"role", m.role, "state", m.state}, keyvals...)
	m.logger.Info(message, fields...)
}

func (m *authMachine) advance(expected authState, next authState) error {
	if m.state != expected {
		return eris.Errorf("%s auth state %q cannot transition to %q", m.role, m.state, next)
	}
	m.state = next
	m.debug("auth state advanced", "from", expected, "to", next)
	return nil
}

func receiveHostAuthInit(messageTransport wire.Framer) (*authpb.HostAuthInit, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive host auth init")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_HostAuthInit:
		return kind.HostAuthInit, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("peer rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected host auth init, got %T", kind)
	}
}

func receiveServerAuth(messageTransport wire.Framer) (*authpb.ServerAuth, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive server auth")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_ServerAuth:
		return kind.ServerAuth, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("server rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected server auth, got %T", kind)
	}
}

func receiveClientAuthRequest(messageTransport wire.Framer) (*authpb.ClientAuthRequest, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive client auth request")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_ClientAuthRequest:
		return kind.ClientAuthRequest, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("peer rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected client auth request, got %T", kind)
	}
}

func receiveClientAuthResponse(messageTransport wire.Framer) (*authpb.ClientAuthResponse, error) {
	frame, err := receiveAuthFrame(messageTransport)
	if err != nil {
		return nil, eris.Wrap(err, "receive client auth response")
	}

	switch kind := frame.Kind.(type) {
	case *authpb.AuthFrame_ClientAuthResponse:
		return kind.ClientAuthResponse, nil
	case *authpb.AuthFrame_Error:
		return nil, eris.Errorf("server rejected auth: %s", kind.Error.GetMessage())
	default:
		return nil, eris.Errorf("expected client auth response, got %T", kind)
	}
}

func receiveAuthFrame(messageTransport wire.Framer) (*authpb.AuthFrame, error) {
	var frame authpb.AuthFrame
	if err := wire.ReceiveProto(messageTransport, &frame); err != nil {
		return nil, eris.Wrap(err, "receive auth frame")
	}
	return &frame, nil
}

func sendAuthFrame(messageTransport wire.Framer, frame *authpb.AuthFrame) error {
	return wire.SendProto(messageTransport, frame)
}

func sendAuthError(messageTransport wire.Framer, code string, message string) {
	_ = sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_Error{
			Error: &authpb.AuthError{
				Code:    code,
				Message: message,
			},
		},
	})
}

func sendClientAuthOK(messageTransport wire.Framer) error {
	return sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ClientAuthResponse{
			ClientAuthResponse: &authpb.ClientAuthResponse{
				Result: &authpb.ClientAuthResponse_Ok{
					Ok: &authpb.AuthSuccess{},
				},
			},
		},
	})
}

func sendClientAuthReject(messageTransport wire.Framer, code string, message string) error {
	return sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_ClientAuthResponse{
			ClientAuthResponse: &authpb.ClientAuthResponse{
				Result: &authpb.ClientAuthResponse_Reject{
					Reject: &authpb.AuthReject{
						Code:    code,
						Message: message,
					},
				},
			},
		},
	})
}

func ExactHostKeyVerifier(referenceIdentity string, expected keys.PublicKey) HostKeyVerifier {
	expected = clonePublicKey(expected)
	return HostKeyVerifierFunc(func(_ context.Context, req HostKeyVerificationRequest) error {
		if req.ReferenceIdentity != referenceIdentity {
			return eris.Errorf("reference identity %q does not match expected %q", req.ReferenceIdentity, referenceIdentity)
		}
		if req.HostKey.Algorithm != expected.Algorithm || !bytes.Equal(req.HostKey.Bytes, expected.Bytes) {
			return eris.Errorf("unexpected host key fingerprint %s", req.HostKey.FingerprintSHA256())
		}
		return nil
	})
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     cloneBytes(key.Bytes),
		Comment:   key.Comment,
	}
}

func cloneKeypair(keypair keys.Keypair) keys.Keypair {
	return keys.Keypair{
		Public:  cloneBytes(keypair.Public),
		Private: cloneBytes(keypair.Private),
		Comment: keypair.Comment,
	}
}
