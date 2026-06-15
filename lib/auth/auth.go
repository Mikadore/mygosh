package auth

import (
	"bytes"
	"context"

	"github.com/Mikadore/mygosh/lib/auth/authpb"
	"github.com/Mikadore/mygosh/lib/keys"
	"github.com/Mikadore/mygosh/lib/logging"
	"github.com/Mikadore/mygosh/lib/transport"
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

type HostKeyVerificationRequest struct {
	ReferenceIdentity string
	HostKey           keys.PublicKey
}

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

type ClientAuthorizationRequest struct {
	Identity ClientIdentity
}

type ClientAuthorizer interface {
	AuthorizeClient(ctx context.Context, req ClientAuthorizationRequest) error
}

type ClientAuthorizerFunc func(ctx context.Context, req ClientAuthorizationRequest) error

func (f ClientAuthorizerFunc) AuthorizeClient(ctx context.Context, req ClientAuthorizationRequest) error {
	if f == nil {
		return eris.New("client authorizer is required")
	}
	return f(ctx, req)
}

type ClientConfig struct {
	ReferenceIdentity   string
	Username            string
	ClientSigner        Signer
	VerifyServerHostKey HostKeyVerifier
	Logger              *charmlog.Logger
}

func (c ClientConfig) Validate() error {
	if c.ReferenceIdentity == "" {
		return eris.New("reference identity is required")
	}
	if c.Username == "" {
		return eris.New("username is required")
	}
	if c.ClientSigner == nil {
		return eris.New("client signer is required")
	}
	clientPublicKey := c.ClientSigner.PublicKey()
	if !(&clientPublicKey).IsSigning() {
		return eris.New("client signer must expose an ed25519 signing key")
	}
	if c.VerifyServerHostKey == nil {
		return eris.New("server host key verifier is required")
	}
	return nil
}

type ServerConfig struct {
	HostSigner      Signer
	AuthorizeClient ClientAuthorizer
	Logger          *charmlog.Logger
}

func (c ServerConfig) Validate() error {
	if c.HostSigner == nil {
		return eris.New("server host signer is required")
	}
	hostPublicKey := c.HostSigner.PublicKey()
	if !(&hostPublicKey).IsSigning() {
		return eris.New("server host signer must expose an ed25519 signing key")
	}
	if c.AuthorizeClient == nil {
		return eris.New("client authorizer is required")
	}
	return nil
}

type ClientIdentity struct {
	Username  string
	PublicKey keys.PublicKey
}

type Result struct {
	ReferenceIdentity string
	ServerHostKey     keys.PublicKey
	ClientIdentity    ClientIdentity
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
	transport      *transport.Transport
	channelBinding []byte
	logger         *charmlog.Logger
}

func newAuthMachine(role string, messageTransport *transport.Transport, channelBinding []byte, logger *charmlog.Logger) *authMachine {
	return &authMachine{
		role:           role,
		state:          authStateNoiseEstablished,
		transport:      messageTransport,
		channelBinding: cloneBytes(channelBinding),
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

func receiveHostAuthInit(messageTransport *transport.Transport) (*authpb.HostAuthInit, error) {
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

func receiveServerAuth(messageTransport *transport.Transport) (*authpb.ServerAuth, error) {
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

func receiveClientAuthRequest(messageTransport *transport.Transport) (*authpb.ClientAuthRequest, error) {
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

func receiveClientAuthResponse(messageTransport *transport.Transport) (*authpb.ClientAuthResponse, error) {
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

func receiveAuthFrame(messageTransport *transport.Transport) (*authpb.AuthFrame, error) {
	var frame authpb.AuthFrame
	if err := transport.ReceiveProto(messageTransport, &frame); err != nil {
		return nil, eris.Wrap(err, "receive auth frame")
	}
	return &frame, nil
}

func sendAuthFrame(messageTransport *transport.Transport, frame *authpb.AuthFrame) error {
	return transport.SendProto(messageTransport, frame)
}

func sendAuthError(messageTransport *transport.Transport, code string, message string) {
	_ = sendAuthFrame(messageTransport, &authpb.AuthFrame{
		Kind: &authpb.AuthFrame_Error{
			Error: &authpb.AuthError{
				Code:    code,
				Message: message,
			},
		},
	})
}

func sendClientAuthOK(messageTransport *transport.Transport) error {
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

func sendClientAuthReject(messageTransport *transport.Transport, code string, message string) {
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
