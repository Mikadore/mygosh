package auth

import (
	"bytes"
	"context"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/transport"
	usermodel "github.com/Mikadore/mygosh/lib/user"
	charmlog "github.com/charmbracelet/log"
	"github.com/rotisserie/eris"
)

type Signer interface {
	PublicKey() keys.PublicKey
	Sign(ctx context.Context, payload []byte) (keys.Signature, error)
}

type KeypairSigner struct {
	keypair keys.Keypair
}

func NewKeypairSigner(keypair keys.Keypair) Signer {
	return KeypairSigner{keypair: keypair}
}

func (s KeypairSigner) PublicKey() keys.PublicKey {
	return s.keypair.PublicKey()
}

func (s KeypairSigner) Sign(_ context.Context, payload []byte) (keys.Signature, error) {
	if !(&s.keypair).IsSigning() {
		return nil, eris.New("signer must be an ed25519 signing key")
	}
	return (&s.keypair).Sign(payload), nil
}

type HostKeyRequest struct {
	ReferenceIdentity string
}

// HostKeyProvider is deliberately separate from auth policy: it supplies the
// server signing capability selected for the client's reference identity.
type HostKeyProvider interface {
	HostSigner(ctx context.Context, req HostKeyRequest) (Signer, error)
}

type HostKeyProviderFunc func(ctx context.Context, req HostKeyRequest) (Signer, error)

func (f HostKeyProviderFunc) HostSigner(ctx context.Context, req HostKeyRequest) (Signer, error) {
	if f == nil {
		return nil, eris.New("host key provider is required")
	}
	return f(ctx, req)
}

func StaticHostKeyProvider(signer Signer) HostKeyProvider {
	return HostKeyProviderFunc(func(_ context.Context, _ HostKeyRequest) (Signer, error) {
		if signer == nil {
			return nil, eris.New("server host signer is required")
		}
		return signer, nil
	})
}

type ClientIdentityRequest struct {
	ReferenceIdentity string
	Username          string
	ServerHostKey     keys.PublicKey
}

// ClientIdentityProvider selects the client signing capability after the peer
// host key is known. Future implementations can delegate signing over IPC.
type ClientIdentityProvider interface {
	ClientSigner(ctx context.Context, req ClientIdentityRequest) (Signer, error)
}

type ClientIdentityProviderFunc func(ctx context.Context, req ClientIdentityRequest) (Signer, error)

func (f ClientIdentityProviderFunc) ClientSigner(ctx context.Context, req ClientIdentityRequest) (Signer, error) {
	if f == nil {
		return nil, eris.New("client identity provider is required")
	}
	return f(ctx, req)
}

func StaticClientIdentityProvider(signer Signer) ClientIdentityProvider {
	return ClientIdentityProviderFunc(func(_ context.Context, _ ClientIdentityRequest) (Signer, error) {
		if signer == nil {
			return nil, eris.New("client signer is required")
		}
		return signer, nil
	})
}

type HostKeyVerificationRequest struct {
	ReferenceIdentity string
	HostKey           keys.PublicKey
}

type HostKeyVerificationResult struct {
	Source string
}

// HostKeyVerifier is called by the client during auth because the protocol must
// stop before client signing if the presented server key is not trusted.
type HostKeyVerifier interface {
	VerifyHostKey(ctx context.Context, req HostKeyVerificationRequest) (HostKeyVerificationResult, error)
}

type HostKeyVerifierFunc func(ctx context.Context, req HostKeyVerificationRequest) (HostKeyVerificationResult, error)

func (f HostKeyVerifierFunc) VerifyHostKey(ctx context.Context, req HostKeyVerificationRequest) (HostKeyVerificationResult, error) {
	if f == nil {
		return HostKeyVerificationResult{}, eris.New("host key verifier is required")
	}
	return f(ctx, req)
}

type ClientKeyAuthorizationRequest struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	Identity          ClientIdentity
}

type ClientKeyAuthorizationResult struct {
	Source  string
	Account usermodel.Account
}

// ClientKeyAuthorizer is still part of the auth exchange because the server
// must send an auth OK/reject response before any session channel can open.
// Successful authorization may also return actionable local account metadata
// for later session, permission, and execution decisions.
type ClientKeyAuthorizer interface {
	AuthorizeClientKey(ctx context.Context, req ClientKeyAuthorizationRequest) (ClientKeyAuthorizationResult, error)
}

type ClientKeyAuthorizerFunc func(ctx context.Context, req ClientKeyAuthorizationRequest) (ClientKeyAuthorizationResult, error)

func (f ClientKeyAuthorizerFunc) AuthorizeClientKey(ctx context.Context, req ClientKeyAuthorizationRequest) (ClientKeyAuthorizationResult, error) {
	if f == nil {
		return ClientKeyAuthorizationResult{}, eris.New("client key authorizer is required")
	}
	return f(ctx, req)
}

type ClientConfig struct {
	ReferenceIdentity      string
	Username               string
	ClientIdentityProvider ClientIdentityProvider
	VerifyServerHostKey    HostKeyVerifier
	Logger                 *charmlog.Logger
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
	HostKeyProvider    HostKeyProvider
	AuthorizeClientKey ClientKeyAuthorizer
	Logger             *charmlog.Logger
}

func (c ServerConfig) Validate() error {
	if c.HostKeyProvider == nil {
		return eris.New("server host key provider is required")
	}
	if c.AuthorizeClientKey == nil {
		return eris.New("client key authorizer is required")
	}
	return nil
}

type ClientIdentity struct {
	Username  string
	PublicKey keys.PublicKey
}

type ClientResult struct {
	ReferenceIdentity   string
	ServerHostKey       keys.PublicKey
	ClientIdentity      ClientIdentity
	HostKeyVerification HostKeyVerificationResult
}

type ServerResult struct {
	ReferenceIdentity      string
	ServerHostKey          keys.PublicKey
	ClientIdentity         ClientIdentity
	ClientKeyAuthorization ClientKeyAuthorizationResult
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
	conn           transport.BoundFramer
	channelBinding []byte
	logger         *charmlog.Logger
}

func newAuthMachine(role string, conn transport.BoundFramer, logger *charmlog.Logger) *authMachine {
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

func receiveHostAuthInit(messageTransport transport.Framer) (*authpb.HostAuthInit, error) {
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

func receiveServerAuth(messageTransport transport.Framer) (*authpb.ServerAuth, error) {
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

func receiveClientAuthRequest(messageTransport transport.Framer) (*authpb.ClientAuthRequest, error) {
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

func receiveClientAuthResponse(messageTransport transport.Framer) (*authpb.ClientAuthResponse, error) {
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

func receiveAuthFrame(messageTransport transport.Framer) (*authpb.AuthFrame, error) {
	var frame authpb.AuthFrame
	if err := transport.ReceiveProto(messageTransport, &frame); err != nil {
		return nil, eris.Wrap(err, "receive auth frame")
	}
	return &frame, nil
}

func sendAuthFrame(messageTransport transport.Framer, frame *authpb.AuthFrame) error {
	return transport.SendProto(messageTransport, frame)
}

func sendAuthError(messageTransport transport.Framer, code string, message string) {
	_ = sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_Error{
			Error: &authpb.AuthError{
				Code:    code,
				Message: message,
			},
		},
	})
}

func sendClientAuthOK(messageTransport transport.Framer) error {
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

func sendClientAuthReject(messageTransport transport.Framer, code string, message string) {
	_ = sendAuthFrame(messageTransport, &authpb.AuthFrame{
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
	return HostKeyVerifierFunc(func(_ context.Context, req HostKeyVerificationRequest) (HostKeyVerificationResult, error) {
		if req.ReferenceIdentity != referenceIdentity {
			return HostKeyVerificationResult{}, eris.Errorf("reference identity %q does not match expected %q", req.ReferenceIdentity, referenceIdentity)
		}
		if req.HostKey.Algorithm != expected.Algorithm || !bytes.Equal(req.HostKey.Bytes, expected.Bytes) {
			return HostKeyVerificationResult{}, eris.Errorf("unexpected host key fingerprint %s", req.HostKey.FingerprintSHA256())
		}
		return HostKeyVerificationResult{}, nil
	})
}

func clonePublicKey(key keys.PublicKey) keys.PublicKey {
	return keys.PublicKey{
		Algorithm: key.Algorithm,
		Bytes:     cloneBytes(key.Bytes),
		Comment:   key.Comment,
	}
}
